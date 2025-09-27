use std::str::FromStr;

use libtest_mimic::{Arguments, Failed, Trial};
use paseto_core::key::{Key, SealedKey};
use paseto_core::version::{Marker, PaserkVersion};
use paseto_core::{LocalKey, PublicKey, SecretKey};
use paseto_test::{Bool, TestFile, read_test};
use serde::Deserialize;

fn main() {
    let args = Arguments::from_args();

    let mut tests = vec![];

    SealTest::<paseto_v3::core::V3>::add_tests("paseto-v3", &mut tests);
    SealTest::<paseto_v3_aws_lc::core::V3>::add_tests("paseto-v3-aws-lc", &mut tests);
    SealTest::<paseto_v4::core::V4>::add_tests("paseto-v4", &mut tests);
    SealTest::<paseto_v4_sodium::core::V4>::add_tests("paseto-v4-sodium", &mut tests);

    libtest_mimic::run(&args, tests).exit();
}

#[derive(Deserialize)]
#[serde(untagged, bound = "")]
enum SealTest<V: PaserkVersion> {
    #[serde(rename_all = "kebab-case")]
    Success {
        #[expect(unused)]
        expect_fail: Bool<false>,
        #[serde(deserialize_with = "paseto_test::deserialize_key")]
        sealing_secret_key: SecretKey<V>,
        #[serde(deserialize_with = "paseto_test::deserialize_key")]
        sealing_public_key: PublicKey<V>,
        #[serde(deserialize_with = "paseto_test::deserialize_key")]
        unsealed: LocalKey<V>,
        paserk: String,
    },
    #[serde(rename_all = "kebab-case")]
    Failure {
        #[expect(unused)]
        expect_fail: Bool<true>,
        comment: String,
        #[serde(deserialize_with = "paseto_test::deserialize_key")]
        sealing_secret_key: SecretKey<V>,
        #[expect(unused)]
        unsealed: (),
        paserk: String,
    },
}

fn eq_keys<V: PaserkVersion, K: Marker>(k1: &Key<V, K>, k2: &Key<V, K>) -> bool {
    k1.expose_key() == k2.expose_key()
}

impl<V: PaserkVersion + 'static> SealTest<V>
where
    V::LocalKey: Send,
    V::PublicKey: Send,
    V::SecretKey: Send,
{
    fn add_tests(name: &str, tests: &mut Vec<Trial>) {
        let test_file: TestFile<Self> = read_test(&format!("{}.seal.json", V::PASERK_HEADER,));
        for test in test_file.tests {
            let name = format!("{name}::{}", test.name);
            tests.push(Trial::test(name, || test.test_data.test()));
        }
    }

    fn test(self) -> Result<(), Failed> {
        match self {
            Self::Success {
                sealing_secret_key,
                sealing_public_key,
                unsealed,
                paserk,
                ..
            } => {
                let sealed: SealedKey<V> = paserk.parse()?;
                let key = sealing_secret_key.unseal(sealed)?;

                assert!(eq_keys(&key, &unsealed));

                let sealed = sealing_public_key.seal(unsealed)?;

                let key2 = sealing_secret_key.unseal(sealed)?;
                assert!(eq_keys(&key, &key2));

                Ok(())
            }
            Self::Failure {
                comment,
                sealing_secret_key,
                paserk,
                ..
            } => {
                let key = match SealedKey::<V>::from_str(&paserk) {
                    Ok(key) => key,
                    Err(_) => return Ok(()),
                };

                match sealing_secret_key.unseal(key) {
                    Ok(_) => Err(comment.into()),
                    Err(_) => Ok(()),
                }
            }
        }
    }
}
