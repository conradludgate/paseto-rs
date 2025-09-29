use libsodium_rs::crypto_pwhash::{self, ALG_ARGON2ID13};
use libsodium_rs::crypto_stream::{self, xchacha20};
use libsodium_rs::utils::compare;
use libsodium_rs::{crypto_generichash, random};
use paseto_core::PasetoError;
use paseto_core::paserk::PwWrapVersion;
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned, big_endian};

use super::V4;

fn wrap_keys(
    pass: &[u8],
    prefix: &Prefix,
) -> Result<(crypto_stream::Key, crypto_generichash::State), PasetoError> {
    if prefix.params.para.get() != 1 {
        return Err(PasetoError::InvalidKey);
    }
    let key = crypto_pwhash::pwhash(
        32,
        pass,
        &prefix.salt,
        u64::from(prefix.params.time.get()),
        usize::try_from(prefix.params.mem.get()).map_err(|_| PasetoError::InvalidKey)?,
        ALG_ARGON2ID13,
    )
    .map_err(|_| PasetoError::CryptoError)?;

    let ek = kdf(&key, 0xFF)?;
    let ak = kdf(&key, 0xFE)?;

    let ek = crypto_stream::Key::from_slice(&ek).expect("32 byte key should be valid");
    let mac = crypto_generichash::State::new(Some(&ak), 32).expect("invalid mac");
    Ok((ek, mac))
}

#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned, Clone, Copy)]
#[repr(C)]
pub struct Params {
    mem: big_endian::U64,
    time: big_endian::U32,
    para: big_endian::U32,
}

#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C)]
struct Prefix {
    salt: [u8; 16],
    params: Params,
    nonce: [u8; 24],
}

#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C)]
struct Suffix {
    tag: [u8; 32],
}

impl Default for Params {
    fn default() -> Self {
        const {
            Self {
                mem: big_endian::U64::new(crypto_pwhash::MEMLIMIT_INTERACTIVE as u64),
                time: big_endian::U32::new(crypto_pwhash::OPSLIMIT_INTERACTIVE as u32),
                para: big_endian::U32::new(1),
            }
        }
    }
}

impl PwWrapVersion for V4 {
    type Params = Params;

    fn pw_wrap_key(
        header: &'static str,
        pass: &[u8],
        params: &Params,
        key_data: Vec<u8>,
    ) -> Result<Vec<u8>, PasetoError> {
        let mut out =
            Vec::with_capacity(size_of::<Prefix>() + key_data.len() + size_of::<Suffix>());
        out.extend_from_slice(&[0; size_of::<Prefix>()]);
        let prefix = Prefix::mut_from_bytes(&mut out).expect("should be correct size");

        prefix.params = *params;
        random::fill_bytes(&mut prefix.salt);
        random::fill_bytes(&mut prefix.nonce);

        let (ek, mut mac) = wrap_keys(pass, prefix)?;

        let ciphertext =
            xchacha20::stream_xor(&key_data, &xchacha20::Nonce::from(prefix.nonce), &ek)
                .map_err(|_| PasetoError::CryptoError)?;

        auth(&mut mac, header, prefix, &ciphertext);

        out.extend_from_slice(&ciphertext);
        out.extend_from_slice(&mac.finalize());
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

        let (ek, mut mac) = wrap_keys(pass, prefix)?;
        auth(&mut mac, header, prefix, ciphertext);
        if compare(&mac.finalize(), &suffix.tag) != 0 {
            return Err(PasetoError::CryptoError);
        }

        let plaintext =
            xchacha20::stream_xor(ciphertext, &xchacha20::Nonce::from(prefix.nonce), &ek)
                .map_err(|_| PasetoError::CryptoError)?;
        ciphertext.copy_from_slice(&plaintext);

        Ok(ciphertext)
    }
}

fn kdf(key: &[u8], sep: u8) -> Result<Vec<u8>, PasetoError> {
    let mut ctx = crypto_generichash::State::new(None, 32).map_err(|_| PasetoError::CryptoError)?;
    ctx.update(&[sep]);
    ctx.update(key);
    Ok(ctx.finalize())
}

fn auth(
    mac: &mut crypto_generichash::State,
    header: &'static str,
    prefix: &Prefix,
    ciphertext: &[u8],
) {
    mac.update(b"k4");
    mac.update(header.as_bytes());
    mac.update(prefix.as_bytes());
    mac.update(ciphertext);
}
