mod local;
mod pie_wrap;
mod pke;
mod public;
mod pw_wrap;

use libsodium_rs::{crypto_generichash, crypto_sign};

pub struct V4;

#[derive(Clone)]
pub struct SecretKey(crypto_sign::SecretKey);

#[derive(Clone)]
pub struct PublicKey(crypto_sign::PublicKey);

#[derive(Clone)]
pub struct LocalKey([u8; 32]);

impl paseto_core::version::Version for V4 {
    const HEADER: &'static str = "v4";
    const PASERK_HEADER: &'static str = "k4";

    type LocalKey = LocalKey;
    type PublicKey = PublicKey;
    type SecretKey = SecretKey;
    type PkeSecretKey = SecretKey;
    type PkePublicKey = PublicKey;
}

impl paseto_core::paserk::IdVersion for V4 {
    fn hash_key(key_header: &'static str, key_data: &[u8]) -> [u8; 33] {
        let mut ctx = crypto_generichash::State::new(None, 33).expect("hash size should be valid");
        ctx.update(b"k4");
        ctx.update(key_header.as_bytes());
        ctx.update(key_data);
        ctx.finalize().try_into().expect("hash should be 33 bytes")
    }
}

fn kdf(key: &[u8], sep: &'static [u8], nonce: &[u8], len: usize) -> Vec<u8> {
    let mut ctx =
        crypto_generichash::State::new(Some(key), len).expect("could not construct hasher");
    ctx.update(sep);
    ctx.update(nonce);
    ctx.finalize()
}
