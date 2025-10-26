#[cfg(feature = "decrypting")]
mod local;
#[cfg(feature = "pie-wrap")]
mod pie_wrap;
#[cfg(feature = "pke")]
mod pke;
#[cfg(feature = "verifying")]
mod public;
#[cfg(feature = "pbkw")]
mod pw_wrap;

use paseto_core::version;

pub struct V1;

#[cfg(feature = "signing")]
#[derive(Clone)]
pub struct SecretKey(rsa::pss::SigningKey<sha2::Sha384>);
#[cfg(feature = "verifying")]
#[derive(Clone)]
pub struct PublicKey(rsa::pss::VerifyingKey<sha2::Sha384>);

#[cfg(feature = "decrypting")]
#[derive(Clone)]
pub struct LocalKey([u8; 32]);

impl version::Version for V1 {
    const HEADER: &'static str = "v1";
    const PASERK_HEADER: &'static str = "k1";
}

#[cfg(feature = "id")]
impl paseto_core::paserk::IdVersion for V1 {
    fn hash_key(key_header: &'static str, key_data: &[u8]) -> [u8; 33] {
        use sha2::{Digest, Sha384};

        let mut ctx = Sha384::new();
        ctx.update(b"k1");
        ctx.update(key_header.as_bytes());
        ctx.update(key_data);
        let hash = ctx.finalize();
        assert_eq!(hash.len(), 48);

        hash[..33].try_into().unwrap()
    }
}
