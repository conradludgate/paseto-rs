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

pub struct V6;

#[cfg(feature = "decrypting")]
#[derive(Clone)]
#[cfg_attr(feature = "zeroize", derive(zeroize::Zeroize, zeroize::ZeroizeOnDrop))]
pub struct LocalKey([u8; 32]);

#[cfg(feature = "signing")]
#[derive(Clone)]
pub struct SecretKey(pub(super) slh_dsa::SigningKey<slh_dsa::Sha2_128s>);

#[cfg(feature = "verifying")]
#[derive(Clone)]
pub struct PublicKey(pub(super) slh_dsa::VerifyingKey<slh_dsa::Sha2_128s>);

#[cfg(feature = "pke")]
#[derive(Clone)]
pub struct PkeSecretKey(pub(super) x_wing::DecapsulationKey);

#[cfg(feature = "pke")]
#[derive(Clone)]
pub struct PkePublicKey(pub(super) x_wing::EncapsulationKey);

impl version::Version for V6 {
    const HEADER: &'static str = "v6";
    const PASERK_HEADER: &'static str = "k6";
}

#[cfg(feature = "id")]
impl paseto_core::paserk::IdVersion for V6 {
    fn hash_key(key_header: &'static str, key_data: &[u8]) -> [u8; 33] {
        use digest::consts::U33;
        use digest::{FixedOutput, Update};

        let mut ctx = blake2::Blake2b::<U33>::default();
        ctx.update(b"k6");
        ctx.update(key_header.as_bytes());
        ctx.update(key_data);
        ctx.finalize_fixed().into()
    }
}

#[cfg(feature = "decrypting")]
struct PreAuthEncodeDigest<'a, M: digest::Update>(pub &'a mut M);
#[cfg(feature = "decrypting")]
impl<M: digest::Update> paseto_core::pae::WriteBytes for PreAuthEncodeDigest<'_, M> {
    fn write(&mut self, slice: &[u8]) {
        self.0.update(slice);
    }
}

#[cfg(feature = "decrypting")]
fn kdf<O>(key: &[u8], sep: &'static [u8], nonce: &[u8]) -> hybrid_array::Array<u8, O>
where
    O: hybrid_array::ArraySize
        + blake2::digest::typenum::IsLessOrEqual<
            hybrid_array::sizes::U64,
            Output = blake2::digest::typenum::True,
        >,
{
    use digest::{KeyInit, Mac};

    let mut mac = blake2::Blake2bMac::<O>::new_from_slice(key).expect("key should be valid");
    mac.update(sep);
    mac.update(nonce);
    mac.finalize().into_bytes()
}
