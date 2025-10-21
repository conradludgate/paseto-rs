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
    const PASERK_HEADER: &'static str = "k4";
}

#[cfg(feature = "id")]
impl paseto_core::paserk::IdVersion for V2 {
    fn hash_key(key_header: &'static str, key_data: &[u8]) -> [u8; 33] {
        use digest::consts::U33;
        use digest::{FixedOutput, Update};

        let mut ctx = blake2::Blake2b::<U33>::default();
        ctx.update(b"k4");
        ctx.update(key_header.as_bytes());
        ctx.update(key_data);
        ctx.finalize_fixed().into()
    }
}

#[cfg(any(feature = "decrypting", feature = "signing"))]
struct PreAuthEncodeDigest<'a, M: digest::Update>(pub &'a mut M);
#[cfg(any(feature = "decrypting", feature = "signing"))]
impl<M: digest::Update> paseto_core::pae::WriteBytes for PreAuthEncodeDigest<'_, M> {
    fn write(&mut self, slice: &[u8]) {
        self.0.update(slice);
    }
}

#[cfg(feature = "decrypting")]
fn kdf<O>(key: &[u8], sep: &'static [u8], nonce: &[u8]) -> generic_array::GenericArray<u8, O>
where
    O: generic_array::ArrayLength<u8>
        + generic_array::typenum::IsLessOrEqual<generic_array::typenum::U64>,
    generic_array::typenum::LeEq<O, generic_array::typenum::U64>: generic_array::typenum::NonZero,
{
    use digest::Mac;

    let mut mac = blake2::Blake2bMac::<O>::new_from_slice(key).expect("key should be valid");
    mac.update(sep);
    mac.update(nonce);
    mac.finalize().into_bytes()
}
