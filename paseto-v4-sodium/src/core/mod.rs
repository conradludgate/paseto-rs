mod local;
mod pke;
mod public;

use libsodium_rs::crypto_sign;

pub struct V4;

#[derive(Clone)]
pub struct SecretKey(crypto_sign::SecretKey);

#[derive(Clone)]
pub struct PublicKey(crypto_sign::PublicKey);

#[derive(Clone)]
pub struct LocalKey([u8; 32]);

impl paseto_core::version::Version for V4 {
    const HEADER: &'static str = "v4";

    type LocalKey = LocalKey;
    type PublicKey = PublicKey;
    type SecretKey = SecretKey;
}

impl paseto_core::version::PaserkVersion for V4 {
    const PASERK_HEADER: &'static str = "k4";

    fn hash_key(key_header: &'static str, key_data: &[u8]) -> [u8; 33] {
        let mut ctx = libsodium_rs::crypto_generichash::State::new(None, 33)
            .expect("hash size should be valid");
        ctx.update(Self::PASERK_HEADER.as_bytes());
        ctx.update(key_header.as_bytes());
        ctx.update(key_data);
        ctx.finalize().try_into().expect("hash should be 33 bytes")
    }
}
