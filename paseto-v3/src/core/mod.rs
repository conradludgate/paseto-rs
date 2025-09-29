#[cfg(feature = "decrypting")]
mod local;
#[cfg(feature = "pie-wrap")]
mod pie_wrap;
#[cfg(feature = "pke")]
mod pke;
#[cfg(feature = "verifying")]
mod public;

use paseto_core::version;

pub struct V3;

#[cfg(feature = "signing")]
#[derive(Clone)]
pub struct SecretKey(p384::ecdsa::SigningKey);
#[cfg(feature = "verifying")]
#[derive(Clone)]
pub struct PublicKey(p384::ecdsa::VerifyingKey);

#[cfg(feature = "decrypting")]
#[derive(Clone)]
pub struct LocalKey([u8; 32]);

impl version::Version for V3 {
    const HEADER: &'static str = "v3";
    const PASERK_HEADER: &'static str = "k3";

    #[cfg(feature = "decrypting")]
    type LocalKey = LocalKey;

    #[cfg(not(feature = "decrypting"))]
    type LocalKey = paseto_core::key::Unimplemented<Self, version::Local>;

    #[cfg(feature = "signing")]
    type SecretKey = SecretKey;

    #[cfg(not(feature = "signing"))]
    type SecretKey = paseto_core::key::Unimplemented<Self, version::Secret>;

    #[cfg(feature = "verifying")]
    type PublicKey = PublicKey;

    #[cfg(not(feature = "verifying"))]
    type PublicKey = paseto_core::key::Unimplemented<Self, version::Public>;
}

#[cfg(feature = "id")]
impl paseto_core::paserk::IdVersion for V3 {
    fn hash_key(key_header: &'static str, key_data: &[u8]) -> [u8; 33] {
        use sha2::{Digest, Sha384};

        let mut ctx = Sha384::new();
        ctx.update(b"k3");
        ctx.update(key_header.as_bytes());
        ctx.update(key_data);
        let hash = ctx.finalize();
        assert_eq!(hash.len(), 48);

        hash[..33].try_into().unwrap()
    }
}
