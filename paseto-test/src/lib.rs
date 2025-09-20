use rand::rand_core::impls::{next_u32_via_fill, next_u64_via_fill};
use rand::rand_core::{self};
use serde::Deserialize;
use serde::de::DeserializeOwned;

pub fn read_test<Test: DeserializeOwned>(v: &str) -> TestFile<Test> {
    let path = format!("tests/vectors/{v}");
    let file = std::fs::read_to_string(path).unwrap();
    serde_json::from_str(&file).unwrap()
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

#[derive(Clone, Debug)]
/// a consistent rng store
pub struct FakeRng<const N: usize> {
    bytes: [u8; N],
    start: usize,
}

impl<const N: usize> FakeRng<N> {
    pub fn new(bytes: [u8; N]) -> Self {
        Self { bytes, start: 0 }
    }
}

impl<const N: usize> rand_core::RngCore for FakeRng<N> {
    fn next_u32(&mut self) -> u32 {
        next_u32_via_fill(self)
    }

    fn next_u64(&mut self) -> u64 {
        next_u64_via_fill(self)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        let remaining = N - self.start;
        let requested = dest.len();
        if requested > remaining {
            panic!("not enough entropy");
        }
        dest.copy_from_slice(&self.bytes[self.start..self.start + requested]);
        self.start += requested;
    }
}

// not really
impl<const N: usize> rand_core::CryptoRng for FakeRng<N> {}
