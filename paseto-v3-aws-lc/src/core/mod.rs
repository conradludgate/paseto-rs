mod local;
mod pke;
mod public;

use aws_lc_rs::cipher::{EncryptingKey, UnboundCipherKey};
use aws_lc_rs::iv::FixedLength;
use paseto_core::PasetoError;

use crate::lc::{SigningKey, VerifyingKey};

pub struct V3;
#[derive(Clone)]
pub struct SecretKey(SigningKey);
#[derive(Clone)]
pub struct PublicKey(VerifyingKey);

#[derive(Clone)]
pub struct LocalKey([u8; 32]);

impl paseto_core::version::Version for V3 {
    const HEADER: &'static str = "v3";

    type LocalKey = LocalKey;
    type PublicKey = PublicKey;
    type SecretKey = SecretKey;
}

impl paseto_core::version::PaserkVersion for V3 {
    const PASERK_HEADER: &'static str = "k3";

    fn hash_key(key_header: &'static str, key_data: &[u8]) -> [u8; 33] {
        use aws_lc_rs::digest::{self, SHA384};

        let mut ctx = digest::Context::new(&SHA384);
        ctx.update(Self::PASERK_HEADER.as_bytes());
        ctx.update(key_header.as_bytes());
        ctx.update(key_data);
        let hash = ctx.finish();
        assert_eq!(hash.as_ref().len(), 48);

        hash.as_ref()[..33].try_into().unwrap()
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

struct Cipher(UnboundCipherKey, FixedLength<16>);
impl Cipher {
    fn apply_keystream(self, inout: &mut [u8]) -> Result<(), PasetoError> {
        EncryptingKey::ctr(self.0)
            .map_err(|_| PasetoError::CryptoError)?
            .less_safe_encrypt(inout, aws_lc_rs::cipher::EncryptionContext::Iv128(self.1))
            .map_err(|_| PasetoError::CryptoError)?;
        Ok(())
    }
}
