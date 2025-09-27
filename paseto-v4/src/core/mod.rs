mod local;
mod pke;
mod public;

use generic_array::GenericArray;
use generic_array::typenum::U32;
use paseto_core::PasetoError;

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

impl paseto_core::version::PaserkVersion for V4 {
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

    fn seal_key(sealing_key: &PublicKey, key: LocalKey) -> Result<Box<[u8]>, PasetoError> {
        pke::seal_key(sealing_key, key)
    }

    fn unseal_key(
        sealing_key: &SecretKey,
        mut key_data: Box<[u8]>,
    ) -> Result<LocalKey, PasetoError> {
        pke::unseal_key(sealing_key, &mut key_data)
    }
}

struct PreAuthEncodeDigest<'a, M: digest::Update>(pub &'a mut M);
impl<'a, M: digest::Update> paseto_core::pae::WriteBytes for PreAuthEncodeDigest<'a, M> {
    fn write(&mut self, slice: &[u8]) {
        self.0.update(slice)
    }
}
