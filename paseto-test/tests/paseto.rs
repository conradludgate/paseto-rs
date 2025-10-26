use libtest_mimic::{Arguments, Failed, Trial};
use paseto_core::key::HasKey;
use paseto_core::validation::NoValidation;
use paseto_core::version::{Local, Public, SealingVersion, Secret};
use paseto_core::{
    EncryptedToken, LocalKey, PublicKey, SecretKey, SignedToken, UnencryptedToken, UnsignedToken,
};
use paseto_json::Json;
use paseto_test::{Bool, TestFile, read_test};
use serde::Deserialize;

fn main() {
    let mut args = Arguments::from_args();
    args.test_threads = Some(1);

    let mut tests = vec![];

    PasetoTest::<paseto_v1::core::V1>::add_tests("paseto-v1", &mut tests);
    PasetoTest::<paseto_v2::core::V2>::add_tests("paseto-v2", &mut tests);
    PasetoTest::<paseto_v3::core::V3>::add_tests("paseto-v3", &mut tests);
    PasetoTest::<paseto_v3_aws_lc::core::V3>::add_tests("paseto-v3-aws-lc", &mut tests);
    PasetoTest::<paseto_v4::core::V4>::add_tests("paseto-v4", &mut tests);
    PasetoTest::<paseto_v4_sodium::core::V4>::add_tests("paseto-v4-sodium", &mut tests);

    libtest_mimic::run(&args, tests).exit();
}

#[derive(Deserialize)]
#[serde(rename_all = "kebab-case", bound = "")]
struct PasetoTest<V: SealingVersion<Local> + SealingVersion<Public>> {
    token: String,
    footer: String,
    implicit_assertion: String,
    #[serde(flatten)]
    purpose: PasetoPurpose<V>,
    #[serde(flatten)]
    result: TestResult,
}

impl<V> PasetoTest<V>
where
    V: SealingVersion<Local> + SealingVersion<Public>,
    V: HasKey<Local, Key: Send>,
    V: HasKey<Public, Key: Send>,
    V: HasKey<Secret, Key: Send>,
{
    fn add_tests(name: &str, tests: &mut Vec<Trial>) {
        let test_file: TestFile<Self> = read_test(&format!("{}.json", V::HEADER));
        for test in test_file.tests {
            let name = format!("{name}::{}", test.name);
            tests.push(Trial::test(name, || test.get_test().test(test.name)));
        }
    }

    fn test(self, name: String) -> Result<(), Failed> {
        match self {
            PasetoTest {
                token,
                footer,
                implicit_assertion,
                purpose: PasetoPurpose::Local { key, .. },
                result: TestResult::Failure { .. },
            } => {
                let Ok(token): Result<EncryptedToken<V, Json<serde_json::Value>, Vec<u8>>, _> =
                    token.parse()
                else {
                    return Ok(());
                };
                assert_eq!(token.unverified_footer(), footer.as_bytes());

                match token.decrypt_with_aad(
                    &key,
                    implicit_assertion.as_bytes(),
                    &NoValidation::dangerous_no_validation(),
                ) {
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
                let token: EncryptedToken<V, Json<serde_json::Value>, Vec<u8>> =
                    token_str.parse().unwrap();
                assert_eq!(token.unverified_footer(), footer.as_bytes());

                let decrypted_token = token
                    .decrypt_with_aad(
                        &key,
                        implicit_assertion.as_bytes(),
                        &NoValidation::dangerous_no_validation(),
                    )
                    .unwrap();

                let payload: serde_json::Value = serde_json::from_str(&payload).unwrap();
                assert_eq!(decrypted_token.claims.0, payload);

                let token = UnencryptedToken::<V, _>::new(decrypted_token.claims)
                    .with_footer(decrypted_token.footer);

                let token = token
                    .dangerous_seal_with_nonce(&key, implicit_assertion.as_bytes(), nonce)
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
                let Ok(token): Result<SignedToken<V, Json<serde_json::Value>, Vec<u8>>, _> =
                    token.parse()
                else {
                    return Ok(());
                };
                assert_eq!(token.unverified_footer(), footer.as_bytes());

                match token.verify_with_aad(
                    &public_key,
                    implicit_assertion.as_bytes(),
                    &NoValidation::dangerous_no_validation(),
                ) {
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
                let token: SignedToken<V, Json<serde_json::Value>, Vec<u8>> =
                    token_str.parse().unwrap();
                assert_eq!(token.unverified_footer(), footer.as_bytes());

                let token = token
                    .verify_with_aad(
                        &public_key,
                        implicit_assertion.as_bytes(),
                        &NoValidation::dangerous_no_validation(),
                    )
                    .unwrap();

                let payload: serde_json::Value = serde_json::from_str(&payload).unwrap();
                assert_eq!(token.claims.0, payload);

                let token = UnsignedToken::<V, _>::new(token.claims).with_footer(token.footer);
                let token = token
                    .sign_with_aad(&secret_key, implicit_assertion.as_bytes())
                    .unwrap();

                match &*name {
                    // RSA uses PSS which is not deterministic.
                    "1-S-1" | "1-S-2" | "1-S-3" => {}
                    // 3-S-1 and 3-S-3 are not using deterministic signatures.
                    "3-S-1" | "3-S-2" | "3-S-3" => {}
                    _ => assert_eq!(token.to_string(), token_str),
                };

                token
                    .verify_with_aad(
                        &public_key,
                        implicit_assertion.as_bytes(),
                        &NoValidation::dangerous_no_validation(),
                    )
                    .unwrap();

                Ok(())
            }
        }
    }
}

#[derive(Deserialize)]
#[serde(untagged, bound = "")]
enum PasetoPurpose<V: SealingVersion<Local> + SealingVersion<Public>> {
    #[serde(rename_all = "kebab-case")]
    Local {
        #[serde(deserialize_with = "paseto_test::deserialize_hex")]
        nonce: Vec<u8>,
        #[serde(deserialize_with = "paseto_test::deserialize_key")]
        key: LocalKey<V>,
    },
    #[serde(rename_all = "kebab-case")]
    Public {
        #[serde(deserialize_with = "paseto_test::deserialize_key")]
        public_key: PublicKey<V>,
        #[serde(deserialize_with = "paseto_test::deserialize_key")]
        secret_key: SecretKey<V>,
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
