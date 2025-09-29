use alloc::vec::Vec;

use cipher::StreamCipher;
use digest::Mac;
use generic_array::GenericArray;
use generic_array::sequence::Split;
use generic_array::typenum::U48;
use paseto_core::PasetoError;
use paseto_core::paserk::PwWrapVersion;
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned, big_endian};

use super::V3;

fn wrap_keys(
    pass: &[u8],
    prefix: &Prefix,
) -> (ctr::Ctr64BE<aes::Aes256>, hmac::Hmac<sha2::Sha384>) {
    use cipher::KeyIvInit;

    let key = pbkdf2::pbkdf2_array::<hmac::Hmac<sha2::Sha384>, 32>(
        pass,
        &prefix.salt,
        prefix.params.iterations.get(),
    )
    .expect("HMAC accepts all password length inputs");

    let (ek, _) = kdf(&key, 0xFF).split();
    let ak = kdf(&key, 0xFE);

    let cipher = ctr::Ctr64BE::<aes::Aes256>::new(&ek, (&prefix.nonce).into());
    let mac = hmac::Hmac::new_from_slice(&ak).expect("key should be valid");
    (cipher, mac)
}

#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C)]
struct Prefix {
    salt: [u8; 32],
    params: Params,
    nonce: [u8; 16],
}

#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C)]
struct Suffix {
    tag: [u8; 48],
}

#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned, Clone, Copy)]
#[repr(C)]
pub struct Params {
    iterations: big_endian::U32,
}

impl Default for Params {
    fn default() -> Self {
        const {
            Self {
                iterations: big_endian::U32::new(100_000),
            }
        }
    }
}

impl PwWrapVersion for V3 {
    type Params = Params;

    fn pw_wrap_key(
        header: &'static str,
        pass: &[u8],
        params: &Params,
        mut key_data: Vec<u8>,
    ) -> Result<Vec<u8>, PasetoError> {
        let mut out =
            Vec::with_capacity(size_of::<Prefix>() + key_data.len() + size_of::<Suffix>());
        out.extend_from_slice(&[0; size_of::<Prefix>()]);
        let prefix = Prefix::mut_from_bytes(&mut out).expect("should be correct size");

        prefix.params = *params;
        getrandom::fill(&mut prefix.salt).map_err(|_| PasetoError::CryptoError)?;
        getrandom::fill(&mut prefix.nonce).map_err(|_| PasetoError::CryptoError)?;

        let (mut cipher, mut mac) = wrap_keys(pass, prefix);
        cipher.apply_keystream(&mut key_data);
        auth(&mut mac, header, prefix, &key_data);

        out.extend_from_slice(&key_data);
        out.extend_from_slice(&mac.finalize().into_bytes());
        Ok(out)
    }

    fn get_params(key_data: &[u8]) -> Result<Self::Params, PasetoError> {
        let (prefix, _) = Prefix::ref_from_prefix(key_data).map_err(|_| PasetoError::InvalidKey)?;
        Ok(prefix.params)
    }

    fn pw_unwrap_key<'key>(
        header: &'static str,
        pass: &[u8],
        key_data: &'key mut [u8],
    ) -> Result<&'key [u8], PasetoError> {
        let (prefix, ciphertext) =
            Prefix::mut_from_prefix(key_data).map_err(|_| PasetoError::InvalidKey)?;
        let (ciphertext, suffix) =
            Suffix::mut_from_suffix(ciphertext).map_err(|_| PasetoError::InvalidKey)?;

        let (mut cipher, mut mac) = wrap_keys(pass, prefix);
        auth(&mut mac, header, prefix, ciphertext);
        mac.verify((&suffix.tag).into())
            .map_err(|_| PasetoError::CryptoError)?;

        cipher.apply_keystream(ciphertext);

        Ok(ciphertext)
    }
}

fn kdf(key: &[u8], sep: u8) -> GenericArray<u8, U48> {
    use digest::Digest;

    let mut mac = sha2::Sha384::default();
    mac.update([sep]);
    mac.update(key);
    mac.finalize()
}

fn auth(
    mac: &mut hmac::Hmac<sha2::Sha384>,
    header: &'static str,
    prefix: &Prefix,
    ciphertext: &[u8],
) {
    mac.update(b"k3");
    mac.update(header.as_bytes());
    mac.update(prefix.as_bytes());
    mac.update(ciphertext);
}
