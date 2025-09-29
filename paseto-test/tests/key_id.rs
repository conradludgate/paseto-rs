use libtest_mimic::{Arguments, Failed, Trial};
use paseto_core::key::Key;
use paseto_core::paserk::{IdVersion, KeyId};
use paseto_core::version::{Local, Marker, Public, Secret};
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

#[derive(Deserialize)]
#[serde(untagged, bound = "")]
enum IdTest<V: IdVersion, K: Marker> {
    #[serde(rename_all = "kebab-case")]
    Success {
        #[expect(unused)]
        expect_fail: Bool<false>,
        paserk: String,
        #[serde(deserialize_with = "paseto_test::deserialize_key")]
        key: Key<V, K>,
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

fn add_all_tests<V: IdVersion>(name: &str, tests: &mut Vec<Trial>)
where
    V::LocalKey: Send + 'static,
    V::PublicKey: Send + 'static,
    V::SecretKey: Send + 'static,
{
    IdTest::<V, Local>::add_tests(name, tests);
    IdTest::<V, Secret>::add_tests(name, tests);
    IdTest::<V, Public>::add_tests(name, tests);
}

impl<V: IdVersion, K: Marker> IdTest<V, K>
where
    K::Key<V>: Send + 'static,
{
    fn add_tests(name: &str, tests: &mut Vec<Trial>) {
        let test_file: TestFile<Self> =
            read_test(&format!("{}{}json", V::PASERK_HEADER, K::ID_HEADER));
        for test in test_file.tests {
            let name = format!("{name}::{}", test.name);
            tests.push(Trial::test(name, || test.test_data.test()));
        }
    }

    fn test(self) -> Result<(), Failed> {
        match self {
            IdTest::Success { paserk, key, .. } => {
                let kid = key.id();
                let kid2: KeyId<V, K> = paserk.parse()?;

                if kid != kid2 {
                    return Err("decode failed".into());
                }
                if kid.to_string() != paserk {
                    return Err("encode failed".into());
                }

                Ok(())
            }
            IdTest::KeyFailure { key, comment, .. } => match Key::<V, K>::from_raw_bytes(&key) {
                Ok(_) => Err(comment.into()),
                Err(_) => Ok(()),
            },
        }
    }
}
