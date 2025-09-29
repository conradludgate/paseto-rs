mod local;
mod pie_wrap;
mod pke;
mod public;
mod pw_wrap;

use generic_array::typenum::{IsLessOrEqual, LeEq, NonZero, U32, U64};
use generic_array::{ArrayLength, GenericArray};

pub struct V4;

#[derive(Clone)]
pub struct LocalKey(GenericArray<u8, U32>);

pub struct SecretKey(
    ed25519_dalek::SecretKey,
    ed25519_dalek::hazmat::ExpandedSecretKey,
);

#[derive(Clone)]
pub struct PublicKey(pub(super) ed25519_dalek::VerifyingKey);

impl paseto_core::version::Version for V4 {
    const HEADER: &'static str = "v4";

    type LocalKey = LocalKey;
    type PublicKey = PublicKey;
    type SecretKey = SecretKey;
}

impl paseto_core::paserk::PaserkVersion for V4 {
    const PASERK_HEADER: &'static str = "k4";

    fn hash_key(key_header: &'static str, key_data: &[u8]) -> [u8; 33] {
        use digest::consts::U33;
        use digest::{FixedOutput, Update};

        let mut ctx = blake2::Blake2b::<U33>::default();
        ctx.update(Self::PASERK_HEADER.as_bytes());
        ctx.update(key_header.as_bytes());
        ctx.update(key_data);
        ctx.finalize_fixed().into()
    }
}

struct PreAuthEncodeDigest<'a, M: digest::Update>(pub &'a mut M);
impl<'a, M: digest::Update> paseto_core::pae::WriteBytes for PreAuthEncodeDigest<'a, M> {
    fn write(&mut self, slice: &[u8]) {
        self.0.update(slice)
    }
}

fn kdf<O>(key: &[u8], sep: &'static [u8], nonce: &[u8]) -> GenericArray<u8, O>
where
    O: ArrayLength<u8> + IsLessOrEqual<U64>,
    LeEq<O, U64>: NonZero,
{
    use digest::Mac;

    let mut mac = blake2::Blake2bMac::<O>::new_from_slice(key).expect("key should be valid");
    mac.update(sep);
    mac.update(nonce);
    mac.finalize().into_bytes()
}
