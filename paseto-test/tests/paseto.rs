use libtest_mimic::{Arguments, Failed, Trial};
use paseto_core::key::Key;
use paseto_core::tokens::{DecryptedToken, EncryptedToken, SignedToken, VerifiedToken};
use paseto_core::version::Version;
use paseto_json::Json;
use paseto_test::{Bool, TestFile, read_test};
use serde::Deserialize;

fn main() {
    let mut args = Arguments::from_args();
    args.test_threads = Some(1);

    let mut tests = vec![];

    PasetoTest::add_tests::<paseto_v3::V3>("paseto-v3", &mut tests);
    PasetoTest::add_tests::<paseto_v4::V4>("paseto-v4", &mut tests);
    PasetoTest::add_tests::<paseto_v4_sodium::V4>("paseto-v4-sodium", &mut tests);

    libtest_mimic::run(&args, tests).exit();
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "kebab-case")]
struct PasetoTest {
    token: String,
    footer: String,
    implicit_assertion: String,
    #[serde(flatten)]
    purpose: PasetoPurpose,
    #[serde(flatten)]
    result: TestResult,
}

impl PasetoTest {
    fn add_tests<V: Version>(name: &str, tests: &mut Vec<Trial>) {
        let test_file: TestFile<Self> = read_test(&format!("{}.json", V::PASETO_HEADER));
        for test in test_file.tests {
            let name = format!("{name}::{}", test.name);
            tests.push(Trial::test(name, || test.test_data.test::<V>(test.name)));
        }
    }

    fn test<V: Version>(self, name: String) -> Result<(), Failed> {
        match self {
            PasetoTest {
                token,
                footer,
                implicit_assertion,
                purpose: PasetoPurpose::Local { key, .. },
                result: TestResult::Failure { .. },
            } => {
                let key = hex::decode(key).unwrap();
                let key = V::LocalKey::decode(&key).unwrap();

                let Ok(token): Result<EncryptedToken<V, Json<serde_json::Value>, Vec<u8>>, _> =
                    token.parse()
                else {
                    return Ok(());
                };
                assert_eq!(token.unverified_footer(), footer.as_bytes());

                match token.decrypt_with_aad(&key, implicit_assertion.as_bytes()) {
                    Ok(_) => Err("decrypting token should fail".into()),
                    Err(_) => Ok(()),
                }
            }
            PasetoTest {
                token: token_str,
                footer,
                implicit_assertion,
                purpose: PasetoPurpose::Local { nonce, key },
                result: TestResult::Success { payload, .. },
            } => {
                let key = hex::decode(key).unwrap();
                let key = V::LocalKey::decode(&key).unwrap();

                let token: EncryptedToken<V, Json<serde_json::Value>, Vec<u8>> =
                    token_str.parse().unwrap();
                assert_eq!(token.unverified_footer(), footer.as_bytes());

                let decrypted_token = token
                    .decrypt_with_aad(&key, implicit_assertion.as_bytes())
                    .unwrap();

                let payload: serde_json::Value = serde_json::from_str(&payload).unwrap();
                assert_eq!(decrypted_token.message.0, payload);

                let token = DecryptedToken::<V, _>::new(decrypted_token.message)
                    .with_footer(decrypted_token.footer);
                let token = token
                    .dangerous_seal_with_nonce(
                        &key,
                        implicit_assertion.as_bytes(),
                        hex::decode(nonce).unwrap(),
                    )
                    .unwrap();

                assert_eq!(token.to_string(), token_str);

                Ok(())
            }
            PasetoTest {
                token,
                footer,
                implicit_assertion,
                purpose: PasetoPurpose::Public { public_key, .. },
                result: TestResult::Failure { .. },
            } => {
                let public_key = hex::decode(public_key).unwrap();
                let public_key = V::PublicKey::decode(&public_key).unwrap();

                let Ok(token): Result<SignedToken<V, Json<serde_json::Value>, Vec<u8>>, _> =
                    token.parse()
                else {
                    return Ok(());
                };
                assert_eq!(token.unverified_footer(), footer.as_bytes());

                match token.verify_with_aad(&public_key, implicit_assertion.as_bytes()) {
                    Ok(_) => Err("verifying token should fail".into()),
                    Err(_) => Ok(()),
                }
            }
            PasetoTest {
                token: token_str,
                footer,
                implicit_assertion,
                purpose:
                    PasetoPurpose::Public {
                        public_key,
                        secret_key,
                    },
                result: TestResult::Success { payload, .. },
            } => {
                let public_key = hex::decode(public_key).unwrap();
                let secret_key = hex::decode(secret_key).unwrap();

                let public_key = V::PublicKey::decode(&public_key).unwrap();
                let secret_key = V::SecretKey::decode(&secret_key).unwrap();

                let token: SignedToken<V, Json<serde_json::Value>, Vec<u8>> =
                    token_str.parse().unwrap();
                assert_eq!(token.unverified_footer(), footer.as_bytes());

                let token = token
                    .verify_with_aad(&public_key, implicit_assertion.as_bytes())
                    .unwrap();

                let payload: serde_json::Value = serde_json::from_str(&payload).unwrap();
                assert_eq!(token.message.0, payload);

                let token = VerifiedToken::<V, _>::new(token.message).with_footer(token.footer);
                let token = token
                    .sign_with_aad(&secret_key, implicit_assertion.as_bytes())
                    .unwrap();

                // 3-S-1 and 3-S-3 are not using deterministic signatures.
                match &*name {
                    "3-S-1" | "3-S-2" | "3-S-3" => {}
                    _ => assert_eq!(token.to_string(), token_str),
                };

                token
                    .verify_with_aad(&public_key, implicit_assertion.as_bytes())
                    .unwrap();

                Ok(())
            }
        }
    }
}

#[derive(Deserialize, Debug)]
#[serde(untagged)]
enum PasetoPurpose {
    #[serde(rename_all = "kebab-case")]
    Local { nonce: String, key: String },
    #[serde(rename_all = "kebab-case")]
    Public {
        public_key: String,
        secret_key: String,
    },
}

#[derive(Deserialize, Debug)]
#[serde(untagged)]
enum TestResult {
    #[serde(rename_all = "kebab-case")]
    Success {
        #[allow(dead_code)]
        expect_fail: Bool<false>,
        payload: String,
    },
    #[serde(rename_all = "kebab-case")]
    Failure {
        #[allow(dead_code)]
        expect_fail: Bool<true>,
        #[allow(dead_code)]
        payload: (),
    },
}
