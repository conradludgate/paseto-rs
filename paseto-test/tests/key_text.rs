use std::str::FromStr;

use libtest_mimic::{Arguments, Failed, Trial};
use paseto_core::key::{HasKey, Key, KeyType};
use paseto_core::paserk::KeyText;
use paseto_core::version::{Local, Public, Secret, Version};
use paseto_test::{Bool, TestFile, read_test};
use serde::Deserialize;

fn main() {
    let args = Arguments::from_args();

    let mut tests = vec![];

    add_all_tests::<paseto_v1::core::V1>("paseto-v1", &mut tests);
    add_all_tests::<paseto_v2::core::V2>("paseto-v2", &mut tests);
    add_all_tests::<paseto_v3::core::V3>("paseto-v3", &mut tests);
    add_all_tests::<paseto_v3_aws_lc::core::V3>("paseto-v3-aws-lc", &mut tests);
    add_all_tests::<paseto_v4::core::V4>("paseto-v4", &mut tests);
    add_all_tests::<paseto_v4_sodium::core::V4>("paseto-v4-sodium", &mut tests);

    libtest_mimic::run(&args, tests).exit();
}

fn add_all_tests<V>(name: &str, tests: &mut Vec<Trial>)
where
    V: Version
        + HasKey<Local, Key: Send + 'static>
        + HasKey<Public, Key: Send + 'static>
        + HasKey<Secret, Key: Send + 'static>,
{
    KeyTest::<V, Local>::add_tests(name, tests);
    KeyTest::<V, Secret>::add_tests(name, tests);
    KeyTest::<V, Public>::add_tests(name, tests);
}

#[derive(Deserialize)]
#[serde(untagged, bound = "")]
enum KeyTest<V: Version + HasKey<K>, K: KeyType> {
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
        key: String,
    },
}

impl<V: HasKey<K>, K: KeyType> KeyTest<V, K>
where
    V::Key: Send + 'static,
{
    fn add_tests(name: &str, tests: &mut Vec<Trial>) {
        let test_file: TestFile<Self> =
            read_test(&format!("{}{}json", V::PASERK_HEADER, K::HEADER));
        for test in test_file.tests {
            let name = format!("{name}::{}", test.name);
            tests.push(Trial::test(name, move || test.get_test().test()));
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

                let _: Key<V, K> = paserk.try_into()?;

                Ok(())
            }
            KeyTest::PaserkFailure {
                paserk, comment, ..
            } => match KeyText::<V, K>::from_str(&paserk) {
                Ok(_) => Err(comment.into()),
                Err(_) => Ok(()),
            },
            KeyTest::KeyFailure { key, comment, .. } => {
                match paseto_test::deserialize_key(serde_json::Value::String(key)) {
                    Ok(Key::<V, K> { .. }) => Err(comment.into()),
                    Err(_) => Ok(()),
                }
            }
        }
    }
}
