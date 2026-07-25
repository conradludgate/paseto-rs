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

pub struct V5;

#[cfg(feature = "decrypting")]
#[derive(Clone)]
#[cfg_attr(feature = "zeroize", derive(zeroize::Zeroize, zeroize::ZeroizeOnDrop))]
pub struct LocalKey([u8; 32]);

#[cfg(feature = "signing")]
pub struct SecretKey {
    seed: [u8; 32],
    signing: ml_dsa::SigningKey<ml_dsa::MlDsa87>,
}

#[cfg(feature = "verifying")]
#[derive(Clone)]
pub struct PublicKey(ml_dsa::VerifyingKey<ml_dsa::MlDsa87>);

#[cfg(feature = "signing")]
impl Clone for SecretKey {
    fn clone(&self) -> Self {
        Self {
            seed: self.seed,
            signing: self.signing.clone(),
        }
    }
}

#[cfg(feature = "pke")]
#[derive(Clone)]
pub struct PkeSecretKey(pub(super) ml_kem::DecapsulationKey1024);

#[cfg(feature = "pke")]
#[derive(Clone)]
pub struct PkePublicKey(pub(super) ml_kem::EncapsulationKey1024);

impl version::Version for V5 {
    const HEADER: &'static str = "v5";
    const PASERK_HEADER: &'static str = "k5";
}

#[cfg(feature = "id")]
impl paseto_core::paserk::IdVersion for V5 {
    fn hash_key(key_header: &'static str, key_data: &[u8]) -> [u8; 33] {
        use sha2::{Digest, Sha384};

        let mut ctx = Sha384::new();
        ctx.update(b"k5");
        ctx.update(key_header.as_bytes());
        ctx.update(key_data);
        let hash = ctx.finalize();

        hash[..33].try_into().unwrap()
    }
}
