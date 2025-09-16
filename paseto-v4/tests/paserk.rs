use std::{fs, str::FromStr};

use libtest_mimic::{Arguments, Failed, Trial};
use paseto_core::{
    key::{Key, KeyId, KeyText},
    version::Marker,
};
use paseto_v4::{LocalKey, PublicKey, SecretKey, V4};
use serde::{Deserialize, de::DeserializeOwned};

fn main() {
    let args = Arguments::from_args();

    let mut tests = vec![];

    IdTest::add_all_tests(&mut tests);
    KeyTest::add_all_tests(&mut tests);

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

#[derive(Deserialize)]
struct IdTest {
    paserk: Option<String>,
    key: String,
}

impl IdTest {
    fn add_all_tests(tests: &mut Vec<Trial>) {
        Self::add_tests::<LocalKey>(tests);
        Self::add_tests::<SecretKey>(tests);
        Self::add_tests::<PublicKey>(tests);
    }

    fn add_tests<K: Key<Version = V4>>(tests: &mut Vec<Trial>) {
        let test_file: TestFile<Self> =
            read_test(&format!("k4{}json", <K::KeyType as Marker>::ID_HEADER));
        for test in test_file.tests {
            tests.push(Trial::test(test.name, || test.test_data.test::<K>()));
        }
    }

    fn test<K: Key<Version = V4>>(self) -> Result<(), Failed> {
        if let Some(paserk) = self.paserk {
            let key = K::decode(&hex::decode(&self.key)?)?;

            let kid = KeyId::from(&KeyText::from(&key));
            let kid2: KeyId<K> = paserk.parse()?;

            if kid != kid2 {
                return Err("decode failed".into());
            }
            if kid.to_string() != paserk {
                return Err("encode failed".into());
            }
        }
        Ok(())
    }
}

#[derive(Deserialize)]
struct KeyTest {
    paserk: Option<String>,
    key: Option<String>,
    comment: Option<String>,
}

impl KeyTest {
    fn add_all_tests(tests: &mut Vec<Trial>) {
        Self::add_tests::<LocalKey>(tests);
        Self::add_tests::<SecretKey>(tests);
        Self::add_tests::<PublicKey>(tests);
    }

    fn add_tests<K: Key<Version = V4>>(tests: &mut Vec<Trial>) {
        let test_file: TestFile<Self> =
            read_test(&format!("k4{}json", <K::KeyType as Marker>::HEADER));
        for test in test_file.tests {
            tests.push(Trial::test(test.name, || test.test_data.test::<K>()));
        }
    }

    fn test<K: Key<Version = V4>>(self) -> Result<(), Failed> {
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
