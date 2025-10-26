use paseto_core::version;

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

pub struct V2;

#[cfg(feature = "decrypting")]
#[derive(Clone)]
pub struct LocalKey([u8; 32]);

#[cfg(feature = "signing")]
pub struct SecretKey(
    ed25519_dalek::SecretKey,
    ed25519_dalek::hazmat::ExpandedSecretKey,
);

#[cfg(feature = "verifying")]
#[derive(Clone)]
pub struct PublicKey(pub(super) ed25519_dalek::VerifyingKey);

impl version::Version for V2 {
    const HEADER: &'static str = "v2";
    const PASERK_HEADER: &'static str = "k2";
}

#[cfg(feature = "id")]
impl paseto_core::paserk::IdVersion for V2 {
    fn hash_key(key_header: &'static str, key_data: &[u8]) -> [u8; 33] {
        use digest::consts::U33;
        use digest::{FixedOutput, Update};

        let mut ctx = blake2::Blake2b::<U33>::default();
        ctx.update(b"k2");
        ctx.update(key_header.as_bytes());
        ctx.update(key_data);
        ctx.finalize_fixed().into()
    }
}
