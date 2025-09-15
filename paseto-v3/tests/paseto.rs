use std::fs;

use libtest_mimic::{Arguments, Failed, Trial};
use paseto_json::Json;
use paseto_v3::{
    DecryptedToken, EncryptedToken, LocalKey, PublicKey, SecretKey, SignedToken, VerifiedToken,
};
use rand_core::impls::{next_u32_via_fill, next_u64_via_fill};
use serde::{
    Deserialize,
    de::{DeserializeOwned, Visitor},
};

fn main() {
    let mut args = Arguments::from_args();
    args.test_threads = Some(1);

    let mut tests = vec![];

    PasetoTest::add_tests(&mut tests);
    libtest_mimic::run(&args, tests).exit();
}

fn read_test<Test: DeserializeOwned>(v: &str) -> TestFile<Test> {
    let path = format!("tests/vectors/{v}");
    let file = fs::read_to_string(path).unwrap();
    serde_json::from_str(&file).unwrap()
}

#[derive(Deserialize)]
struct TestFile<T> {
    tests: Vec<Test<T>>,
}

#[derive(Deserialize)]
struct Test<T> {
    name: String,
    #[serde(flatten)]
    test_data: T,
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
    fn add_tests(tests: &mut Vec<Trial>) {
        let test_file: TestFile<Self> = read_test("v3.json");
        for test in test_file.tests {
            tests.push(Trial::test(test.name.clone(), || {
                test.test_data.test(test.name)
            }));
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
                let key = hex::decode(key).unwrap();
                let key = LocalKey::from_bytes(key.try_into().unwrap());

                let Ok(token): Result<EncryptedToken<Json<serde_json::Value>, Vec<u8>>, _> =
                    token.parse()
                else {
                    return Ok(());
                };
                assert_eq!(token.unverified_footer(), footer.as_bytes());

                match token.decrypt(&key, implicit_assertion.as_bytes()) {
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
                let key = LocalKey::from_bytes(key.try_into().unwrap());

                let token: EncryptedToken<Json<serde_json::Value>, Vec<u8>> =
                    token_str.parse().unwrap();
                assert_eq!(token.unverified_footer(), footer.as_bytes());

                let decrypted_token = token.decrypt(&key, implicit_assertion.as_bytes()).unwrap();

                let payload: serde_json::Value = serde_json::from_str(&payload).unwrap();
                assert_eq!(decrypted_token.message.0, payload);

                let nonce: [u8; 32] = hex::decode(nonce).unwrap().try_into().unwrap();

                let token = DecryptedToken::new(decrypted_token.message)
                    .with_footer(decrypted_token.footer);
                let token = token
                    .encrypt(
                        &key,
                        implicit_assertion.as_bytes(),
                        FakeRng {
                            bytes: nonce,
                            start: 0,
                        },
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
                let public_key = PublicKey::from_sec1_bytes(&public_key).unwrap();

                let Ok(token): Result<SignedToken<Json<serde_json::Value>, Vec<u8>>, _> =
                    token.parse()
                else {
                    return Ok(());
                };
                assert_eq!(token.unverified_footer(), footer.as_bytes());

                match token.verify(&public_key, implicit_assertion.as_bytes()) {
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

                let public_key = PublicKey::from_sec1_bytes(&public_key).unwrap();
                let secret_key = SecretKey::from_bytes(&secret_key).unwrap();

                let token: SignedToken<Json<serde_json::Value>, Vec<u8>> =
                    token_str.parse().unwrap();
                assert_eq!(token.unverified_footer(), footer.as_bytes());

                let token = token
                    .verify(&public_key, implicit_assertion.as_bytes())
                    .unwrap();

                let payload: serde_json::Value = serde_json::from_str(&payload).unwrap();
                assert_eq!(token.message.0, payload);

                let token = VerifiedToken::new(token.message).with_footer(token.footer);
                let token = token
                    .sign(&secret_key, implicit_assertion.as_bytes(), FakeRng::new([]))
                    .unwrap();

                // 3-S-1 and 3-S-3 are not using deterministic signatures.
                let token_str = match &*name {
                    "3-S-1" => {
                        "v3.public.eyJkYXRhIjoidGhpcyBpcyBhIHNpZ25lZCBtZXNzYWdlIiwiZXhwIjoiMjAyMi0wMS0wMVQwMDowMDowMCswMDowMCJ9qqEwwrKHKi5lJ7b9MBKc0G4MGZy0ptUiMv3lAUAaz-JY_zjoqBSIxMxhfAoeNYiSNQgr7UcEF1xwpZKxhyY-wbsthTWhto85XytcCWlRUCrs3ct_Wd23Tuq_0i-1My8S"
                    }
                    "3-S-3" => {
                        "v3.public.eyJkYXRhIjoidGhpcyBpcyBhIHNpZ25lZCBtZXNzYWdlIiwiZXhwIjoiMjAyMi0wMS0wMVQwMDowMDowMCswMDowMCJ94SjWIbjmS7715GjLSnHnpJrC9Z-cnwK45dmvnVvCRQDCCKAXaKEopTajX0DKYx1XVUFfjsigVTj09_kd-HhxpCcaSBXyVi5DeSg1b8Wcl174ytw9OzjHe15_AxELCuhc.eyJraWQiOiJkWWtJU3lseFFlZWNFY0hFTGZ6Rjg4VVpyd2JMb2xOaUNkcHpVSEd3OVVxbiJ9"
                    }
                    _ => &token_str,
                };

                assert_eq!(token.to_string(), token_str);

                token
                    .verify(&public_key, implicit_assertion.as_bytes())
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

#[derive(Debug)]
struct Bool<const B: bool>;

impl<'a, const B: bool> Deserialize<'a> for Bool<B> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'a>,
    {
        struct BoolVisitor<const B: bool>;

        impl<'a, const B: bool> Visitor<'a> for BoolVisitor<B> {
            type Value = Bool<B>;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                write!(formatter, "{B}")
            }

            fn visit_bool<E>(self, v: bool) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                (v == B)
                    .then_some(Bool)
                    .ok_or_else(|| E::custom(format!("expected {B}, got {v}")))
            }
        }

        deserializer.deserialize_bool(BoolVisitor)
    }
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

#[derive(Clone, Debug)]
/// a consistent rng store
struct FakeRng<const N: usize> {
    pub bytes: [u8; N],
    pub start: usize,
}

impl<const N: usize> FakeRng<N> {
    fn new(bytes: [u8; N]) -> Self {
        Self { bytes, start: 0 }
    }
}

impl<const N: usize> rand_core::RngCore for FakeRng<N> {
    fn next_u32(&mut self) -> u32 {
        next_u32_via_fill(self)
    }

    fn next_u64(&mut self) -> u64 {
        next_u64_via_fill(self)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        let remaining = N - self.start;
        let requested = dest.len();
        if requested > remaining {
            panic!("not enough entropy");
        }
        dest.copy_from_slice(&self.bytes[self.start..self.start + requested]);
        self.start += requested;
    }
}

// not really
impl<const N: usize> rand_core::CryptoRng for FakeRng<N> {}
