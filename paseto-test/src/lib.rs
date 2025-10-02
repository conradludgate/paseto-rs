use paseto_core::key::{HasKey, Key, KeyType};
use paseto_core::paserk::KeyText;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Deserializer};

pub fn read_test<Test: DeserializeOwned>(v: &str) -> TestFile<Test> {
    let path = format!("tests/vectors/{v}");
    let file = std::fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("reading {v} should succeed: {e:?}"));
    serde_json::from_str(&file).unwrap_or_else(|e| panic!("parsing {v} should succeed: {e:?}"))
}

#[derive(Deserialize)]
pub struct TestFile<T> {
    pub tests: Vec<Test<T>>,
}

#[derive(Deserialize)]
pub struct Test<T> {
    pub name: String,
    #[serde(flatten)]
    pub test_data: T,
}

#[derive(Debug)]
pub struct Bool<const B: bool>;

impl<'a, const B: bool> Deserialize<'a> for Bool<B> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'a>,
    {
        struct BoolVisitor<const B: bool>;

        impl<'a, const B: bool> serde::de::Visitor<'a> for BoolVisitor<B> {
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

pub fn deserialize_hex<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
    let s = String::deserialize(d)?;
    hex::decode(s).map_err(serde::de::Error::custom)
}

pub fn deserialize_key<'de, D: Deserializer<'de>, V: HasKey<K>, K: KeyType>(
    d: D,
) -> Result<Key<V, K>, D::Error> {
    KeyText::<V, K>::from_raw_bytes(&deserialize_hex(d)?)
        .try_into()
        .map_err(serde::de::Error::custom)
}

pub fn eq_keys<V: HasKey<K>, K: KeyType>(k1: &Key<V, K>, k2: &Key<V, K>) -> bool {
    k1.expose_key() == k2.expose_key()
}
