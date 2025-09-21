use libtest_mimic::{Arguments, Failed, Trial};
use paseto_core::key::{Key, KeyId, KeyText};
use paseto_core::version::{Marker, Version};
use paseto_test::{TestFile, read_test};
use serde::Deserialize;

fn main() {
    let args = Arguments::from_args();

    let mut tests = vec![];

    IdTest::add_all_tests::<paseto_v3::V3>("paseto-v3", &mut tests);
    IdTest::add_all_tests::<paseto_v3_aws_lc::V3>("paseto-v3-aws-lc", &mut tests);
    IdTest::add_all_tests::<paseto_v4::V4>("paseto-v4", &mut tests);
    IdTest::add_all_tests::<paseto_v4_sodium::V4>("paseto-v4-sodium", &mut tests);

    libtest_mimic::run(&args, tests).exit();
}

#[derive(Deserialize)]
struct IdTest {
    paserk: Option<String>,
    key: String,
}

impl IdTest {
    fn add_all_tests<V: Version>(name: &str, tests: &mut Vec<Trial>) {
        Self::add_tests::<V, V::LocalKey>(name, tests);
        Self::add_tests::<V, V::SecretKey>(name, tests);
        Self::add_tests::<V, V::PublicKey>(name, tests);
    }

    fn add_tests<V: Version, K: Key<Version = V>>(name: &str, tests: &mut Vec<Trial>) {
        let test_file: TestFile<Self> = read_test(&format!(
            "{}{}json",
            V::PASERK_HEADER,
            <K::KeyType as Marker>::ID_HEADER
        ));
        for test in test_file.tests {
            let name = format!("{name}::{}", test.name);
            tests.push(Trial::test(name, || test.test_data.test::<V, K>()));
        }
    }

    fn test<V: Version, K: Key<Version = V>>(self) -> Result<(), Failed> {
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
