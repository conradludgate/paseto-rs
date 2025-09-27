use std::str::FromStr;

use libtest_mimic::{Arguments, Failed, Trial};
use paseto_core::key::{Key, KeyText};
use paseto_core::version::{Local, Marker, PaserkVersion, Public, Secret};
use paseto_test::{Bool, TestFile, read_test};
use serde::Deserialize;

fn main() {
    let args = Arguments::from_args();

    let mut tests = vec![];

    add_all_tests::<paseto_v3::core::V3>("paseto-v3", &mut tests);
    add_all_tests::<paseto_v3_aws_lc::core::V3>("paseto-v3-aws-lc", &mut tests);
    add_all_tests::<paseto_v4::core::V4>("paseto-v4", &mut tests);
    add_all_tests::<paseto_v4_sodium::core::V4>("paseto-v4-sodium", &mut tests);

    libtest_mimic::run(&args, tests).exit();
}

fn add_all_tests<V: PaserkVersion>(name: &str, tests: &mut Vec<Trial>)
where
    V::LocalKey: Send + 'static,
    V::PublicKey: Send + 'static,
    V::SecretKey: Send + 'static,
{
    KeyTest::<V, Local>::add_tests(name, tests);
    KeyTest::<V, Secret>::add_tests(name, tests);
    KeyTest::<V, Public>::add_tests(name, tests);
}

#[derive(Deserialize)]
#[serde(untagged, bound = "")]
enum KeyTest<V: PaserkVersion, K: Marker> {
    #[serde(rename_all = "kebab-case")]
    Success {
        #[expect(unused)]
        expect_fail: Bool<false>,
        paserk: String,
        #[serde(deserialize_with = "paseto_test::deserialize_key")]
        key: Key<V, K>,
    },
    #[serde(rename_all = "kebab-case")]
    PaserkFailure {
        #[expect(unused)]
        expect_fail: Bool<true>,
        comment: String,
        paserk: String,
        #[expect(unused)]
        key: (),
    },
    #[serde(rename_all = "kebab-case")]
    KeyFailure {
        #[expect(unused)]
        expect_fail: Bool<true>,
        comment: String,
        #[expect(unused)]
        paserk: (),
        #[serde(deserialize_with = "paseto_test::deserialize_hex")]
        key: Vec<u8>,
    },
}

impl<V: PaserkVersion, K: Marker> KeyTest<V, K>
where
    K::Key<V>: Send + 'static,
{
    fn add_tests(name: &str, tests: &mut Vec<Trial>) {
        let test_file: TestFile<Self> =
            read_test(&format!("{}{}json", V::PASERK_HEADER, K::HEADER));
        for test in test_file.tests {
            let name = format!("{name}::{}", test.name);
            tests.push(Trial::test(name, || test.test_data.test()));
        }
    }

    fn test(self) -> Result<(), Failed> {
        match self {
            KeyTest::Success { paserk, key, .. } => {
                let paserk2 = key.expose_key();
                if paserk != paserk2.to_string() {
                    return Err("encode failed".into());
                }

                let paserk: KeyText<V, K> = paserk.parse()?;
                if paserk != paserk2 {
                    return Err("decode failed".into());
                }

                _ = paserk.decode()?;

                Ok(())
            }
            KeyTest::PaserkFailure {
                paserk, comment, ..
            } => match KeyText::<V, K>::from_str(&paserk) {
                Ok(_) => Err(comment.into()),
                Err(_) => Ok(()),
            },
            KeyTest::KeyFailure { key, comment, .. } => match Key::<V, K>::from_raw_bytes(&key) {
                Ok(_) => Err(comment.into()),
                Err(_) => Ok(()),
            },
        }
    }
}
