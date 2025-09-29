mod local;
mod pie_wrap;
mod pke;
mod public;

use p384::ecdsa::{SigningKey, VerifyingKey};

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

impl paseto_core::paserk::PaserkVersion for V3 {
    const PASERK_HEADER: &'static str = "k3";

    fn hash_key(key_header: &'static str, key_data: &[u8]) -> [u8; 33] {
        use sha2::{Digest, Sha384};

        let mut ctx = Sha384::new();
        ctx.update(Self::PASERK_HEADER.as_bytes());
        ctx.update(key_header.as_bytes());
        ctx.update(key_data);
        let hash = ctx.finalize();
        assert_eq!(hash.len(), 48);

        hash[..33].try_into().unwrap()
    }
}
