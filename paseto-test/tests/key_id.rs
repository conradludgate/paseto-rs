use libtest_mimic::{Arguments, Failed, Trial};
use paseto_core::key::{Key, KeyId, KeyText};
use paseto_core::version::{Marker, PaserkVersion};
use paseto_test::{Bool, TestFile, read_test};
use serde::Deserialize;

fn main() {
    let args = Arguments::from_args();

    let mut tests = vec![];

    add_all_tests::<paseto_v3::V3>("paseto-v3", &mut tests);
    add_all_tests::<paseto_v3_aws_lc::V3>("paseto-v3-aws-lc", &mut tests);
    add_all_tests::<paseto_v4::V4>("paseto-v4", &mut tests);
    add_all_tests::<paseto_v4_sodium::V4>("paseto-v4-sodium", &mut tests);

    libtest_mimic::run(&args, tests).exit();
}

#[derive(Deserialize)]
#[serde(untagged, bound = "")]
enum IdTest<K: Key> {
    #[serde(rename_all = "kebab-case")]
    Success {
        #[expect(unused)]
        expect_fail: Bool<false>,
        paserk: String,
        #[serde(deserialize_with = "paseto_test::deserialize_key")]
        key: K,
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

fn add_all_tests<V: PaserkVersion>(name: &str, tests: &mut Vec<Trial>)
where
    V::LocalKey: Send + 'static,
    V::PublicKey: Send + 'static,
    V::SecretKey: Send + 'static,
{
    IdTest::<V::LocalKey>::add_tests(name, tests);
    IdTest::<V::SecretKey>::add_tests(name, tests);
    IdTest::<V::PublicKey>::add_tests(name, tests);
}

impl<K: Key + Send + 'static> IdTest<K>
where
    K::Version: PaserkVersion,
{
    fn add_tests(name: &str, tests: &mut Vec<Trial>) {
        let test_file: TestFile<Self> = read_test(&format!(
            "{}{}json",
            <K::Version as PaserkVersion>::PASERK_HEADER,
            <K::KeyType as Marker>::ID_HEADER
        ));
        for test in test_file.tests {
            let name = format!("{name}::{}", test.name);
            tests.push(Trial::test(name, || test.test_data.test()));
        }
    }

    fn test(self) -> Result<(), Failed> {
        match self {
            IdTest::Success { paserk, key, .. } => {
                let kid = KeyId::from(&KeyText::from(&key));
                let kid2: KeyId<K> = paserk.parse()?;

                if kid != kid2 {
                    return Err("decode failed".into());
                }
                if kid.to_string() != paserk {
                    return Err("encode failed".into());
                }

                Ok(())
            }
            IdTest::KeyFailure { key, comment, .. } => match K::decode(&key) {
                Ok(_) => Err(comment.into()),
                Err(_) => Ok(()),
            },
        }
    }
}
