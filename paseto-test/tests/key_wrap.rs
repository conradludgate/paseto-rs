use std::str::FromStr;

use libtest_mimic::{Arguments, Failed, Trial};
use paseto_core::LocalKey;
use paseto_core::key::Key;
use paseto_core::paserk::{PieWrapVersion, PieWrappedKey};
use paseto_core::version::{Local, SealingMarker, Secret};
use paseto_test::{Bool, TestFile, eq_keys, read_test};
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

fn add_all_tests<V: PieWrapVersion>(name: &str, tests: &mut Vec<Trial>)
where
    V::LocalKey: Send + 'static,
    V::PublicKey: Send + 'static,
    V::SecretKey: Send + 'static,
{
    WrapTest::<V, Local>::add_tests(name, tests);
    WrapTest::<V, Secret>::add_tests(name, tests);
}

#[derive(Deserialize)]
#[serde(untagged, bound = "")]
enum WrapTest<V: PieWrapVersion, K: SealingMarker> {
    #[serde(rename_all = "kebab-case")]
    Success {
        #[expect(unused)]
        expect_fail: Bool<false>,
        #[serde(deserialize_with = "paseto_test::deserialize_key")]
        unwrapped: Key<V, K>,
        #[serde(deserialize_with = "paseto_test::deserialize_key")]
        wrapping_key: LocalKey<V>,
        paserk: String,
    },
    #[serde(rename_all = "kebab-case")]
    Failure {
        #[expect(unused)]
        expect_fail: Bool<true>,
        comment: String,
        #[expect(unused)]
        unwrapped: (),
        #[serde(deserialize_with = "paseto_test::deserialize_key")]
        wrapping_key: LocalKey<V>,
        paserk: String,
    },
}

impl<V: PieWrapVersion, K: SealingMarker> WrapTest<V, K>
where
    V::LocalKey: Send,
    K::Key<V>: Send,
{
    fn add_tests(name: &str, tests: &mut Vec<Trial>) {
        let test_file: TestFile<Self> =
            read_test(&format!("{}{}json", V::PASERK_HEADER, K::PIE_WRAP_HEADER));
        for test in test_file.tests {
            let name = format!("{name}::{}", test.name);
            tests.push(Trial::test(name, || test.test_data.test()));
        }
    }

    fn test(self) -> Result<(), Failed> {
        match self {
            Self::Success {
                unwrapped,
                wrapping_key,
                paserk,
                ..
            } => {
                let wrapped: PieWrappedKey<V, K> = paserk.parse()?;
                let key = wrapped.unwrap(&wrapping_key)?;

                assert!(eq_keys(&key, &unwrapped));

                let wrapped = unwrapped.wrap_pie(&wrapping_key)?;

                let key2 = wrapped.unwrap(&wrapping_key)?;
                assert!(eq_keys(&key, &key2));

                Ok(())
            }
            Self::Failure {
                comment,
                wrapping_key,
                paserk,
                ..
            } => {
                let key = match PieWrappedKey::<V, K>::from_str(&paserk) {
                    Ok(key) => key,
                    Err(_) => return Ok(()),
                };

                match key.unwrap(&wrapping_key) {
                    Ok(_) => Err(comment.into()),
                    Err(_) => Ok(()),
                }
            }
        }
    }
}
