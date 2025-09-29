use std::num::NonZeroU32;

use aws_lc_rs::cipher::{AES_256, UnboundCipherKey};
use aws_lc_rs::digest::Digest;
use aws_lc_rs::hmac::HMAC_SHA384;
use aws_lc_rs::iv::FixedLength;
use aws_lc_rs::pbkdf2::PBKDF2_HMAC_SHA384;
use aws_lc_rs::rand::{SecureRandom, SystemRandom};
use aws_lc_rs::{constant_time, hmac, pbkdf2};
use paseto_core::PasetoError;
use paseto_core::paserk::PwWrapVersion;
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned, big_endian};

use super::V3;
use crate::core::Cipher;

fn wrap_keys(pass: &[u8], prefix: &Prefix) -> Result<(Cipher, hmac::Context), PasetoError> {
    let mut key = [0; 32];
    let iter = NonZeroU32::new(prefix.params.iterations.get()).ok_or(PasetoError::InvalidKey)?;
    pbkdf2::derive(PBKDF2_HMAC_SHA384, iter, &prefix.salt, pass, &mut key);

    let ek = kdf(&key, 0xFF);
    let ak = kdf(&key, 0xFE);

    let key = UnboundCipherKey::new(&AES_256, &ek.as_ref()[..32])
        .map_err(|_| PasetoError::CryptoError)?;
    let iv = FixedLength::from(prefix.nonce);
    let mac = hmac::Context::with_key(&hmac::Key::new(HMAC_SHA384, ak.as_ref()));

    Ok((Cipher(key, iv), mac))
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
                iterations: big_endian::U32::new(100000),
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
        SystemRandom::new()
            .fill(&mut prefix.salt)
            .map_err(|_| PasetoError::CryptoError)?;
        SystemRandom::new()
            .fill(&mut prefix.nonce)
            .map_err(|_| PasetoError::CryptoError)?;

        let (cipher, mut mac) = wrap_keys(pass, prefix)?;
        cipher.apply_keystream(&mut key_data)?;
        auth(&mut mac, header, prefix, &key_data);

        out.extend_from_slice(&key_data);
        out.extend_from_slice(mac.sign().as_ref());
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

        let (cipher, mut mac) = wrap_keys(pass, prefix)?;
        auth(&mut mac, header, prefix, ciphertext);
        constant_time::verify_slices_are_equal(mac.sign().as_ref(), &suffix.tag)
            .map_err(|_| PasetoError::CryptoError)?;

        cipher.apply_keystream(ciphertext)?;

        Ok(ciphertext)
    }
}

fn kdf(key: &[u8], sep: u8) -> Digest {
    use aws_lc_rs::digest::{self, SHA384};

    let mut ctx = digest::Context::new(&SHA384);
    ctx.update(&[sep]);
    ctx.update(key);
    ctx.finish()
}

fn auth(mac: &mut hmac::Context, header: &'static str, prefix: &Prefix, ciphertext: &[u8]) {
    mac.update(b"k3");
    mac.update(header.as_bytes());
    mac.update(prefix.as_bytes());
    mac.update(ciphertext);
}
