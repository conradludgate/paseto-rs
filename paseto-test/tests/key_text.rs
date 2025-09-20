use std::str::FromStr;

use libtest_mimic::{Arguments, Failed, Trial};
use paseto_core::key::{Key, KeyText};
use paseto_core::version::{Marker, Version};
use paseto_test::{TestFile, read_test};
use serde::Deserialize;

fn main() {
    let args = Arguments::from_args();

    let mut tests = vec![];

    KeyTest::add_all_tests::<paseto_v3::V3>("paseto-v3", &mut tests);
    KeyTest::add_all_tests::<paseto_v4::V4>("paseto-v4", &mut tests);
    KeyTest::add_all_tests::<paseto_v4_sodium::V4>("paseto-v4-sodium", &mut tests);

    libtest_mimic::run(&args, tests).exit();
}

#[derive(Deserialize)]
struct KeyTest {
    paserk: Option<String>,
    key: Option<String>,
    comment: Option<String>,
}

impl KeyTest {
    fn add_all_tests<V: Version>(name: &str, tests: &mut Vec<Trial>) {
        Self::add_tests::<V, V::LocalKey>(name, tests);
        Self::add_tests::<V, V::SecretKey>(name, tests);
        Self::add_tests::<V, V::PublicKey>(name, tests);
    }

    fn add_tests<V: Version, K: Key<Version = V>>(name: &str, tests: &mut Vec<Trial>) {
        let test_file: TestFile<Self> = read_test(&format!(
            "{}{}json",
            V::PASERK_HEADER,
            <K::KeyType as Marker>::HEADER
        ));
        for test in test_file.tests {
            let name = format!("{name}::{}", test.name);
            tests.push(Trial::test(name, || test.test_data.test::<V, K>()));
        }
    }

    fn test<V: Version, K: Key<Version = V>>(self) -> Result<(), Failed> {
        match (self.key, self.paserk) {
            (Some(key), Some(paserk)) => {
                let key = K::decode(&hex::decode(&key)?)?;

                let paserk2 = KeyText::from(&key);
                if paserk != paserk2.to_string() {
                    return Err("encode failed".into());
                }

                let paserk: KeyText<K> = paserk.parse()?;
                if paserk != paserk2 {
                    return Err("decode failed".into());
                }

                _ = paserk.decode()?;

                Ok(())
            }
            (None, Some(paserk)) => match KeyText::<K>::from_str(&paserk) {
                Ok(_) => Err(self.comment.unwrap().into()),
                Err(_) => Ok(()),
            },
            (Some(_), None) => Ok(()),
            (None, None) => Ok(()),
        }
    }
}
