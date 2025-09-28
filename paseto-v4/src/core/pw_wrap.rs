use alloc::vec::Vec;

use blake2::Blake2bMac;
use chacha20::XChaCha20;
use cipher::StreamCipher;
use digest::Mac;
use generic_array::GenericArray;
use generic_array::typenum::U32;
use paseto_core::PasetoError;
use paseto_core::version::PwWrapVersion;
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned, big_endian};

use super::V4;

fn wrap_keys(
    pass: &[u8],
    params: &Params,
    salt: &[u8; 16],
    nonce: &[u8; 24],
) -> Result<(XChaCha20, Blake2bMac<U32>), PasetoError> {
    use cipher::KeyIvInit;

    let mut key = [0u8; 32];
    params
        .pbkdf()?
        .hash_password_into(pass, salt, &mut key)
        .map_err(|_| PasetoError::CryptoError)?;

    let ek = kdf(&key, &[0xFF]);
    let ak = kdf(&key, &[0xFE]);

    let cipher = XChaCha20::new(&ek, nonce.into());
    let mac = blake2::Blake2bMac::new_from_slice(&ak).expect("key should be valid");
    Ok((cipher, mac))
}

#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C)]
pub struct Params {
    mem: big_endian::U64,
    time: big_endian::U32,
    para: big_endian::U32,
}

impl Default for Params {
    fn default() -> Self {
        const {
            Self {
                mem: big_endian::U64::new(argon2::Params::DEFAULT_M_COST as u64 * 1024),
                time: big_endian::U32::new(argon2::Params::DEFAULT_T_COST),
                para: big_endian::U32::new(argon2::Params::DEFAULT_P_COST),
            }
        }
    }
}

impl Params {
    fn pbkdf(&self) -> Result<argon2::Argon2<'static>, PasetoError> {
        let mem = self.mem.get();
        if !mem.is_multiple_of(1024) {
            return Err(PasetoError::InvalidKey);
        }
        let mem = mem / 1024;
        let mem = u32::try_from(mem).map_err(|_| PasetoError::InvalidKey)?;

        let params = argon2::ParamsBuilder::new()
            .m_cost(mem)
            .p_cost(self.para.get())
            .t_cost(self.time.get())
            .build()
            .map_err(|_| PasetoError::InvalidKey)?;

        Ok(argon2::Argon2::new(
            argon2::Algorithm::Argon2id,
            argon2::Version::V0x13,
            params,
        ))
    }
}

impl PwWrapVersion for V4 {
    type Params = Params;

    fn pw_wrap_key(
        header: &'static str,
        pass: &[u8],
        params: &Params,
        mut key_data: Vec<u8>,
    ) -> Result<Vec<u8>, PasetoError> {
        let mut salt = [0u8; 16];
        let mut nonce = [0u8; 24];
        getrandom::fill(&mut salt).map_err(|_| PasetoError::CryptoError)?;
        getrandom::fill(&mut nonce).map_err(|_| PasetoError::CryptoError)?;

        let (mut cipher, mut mac) = wrap_keys(pass, params, &salt, &nonce)?;
        cipher.apply_keystream(&mut key_data);
        auth(&mut mac, header, &salt, params, &nonce, &key_data);

        let mut out = Vec::with_capacity(88 + key_data.len());
        out.extend_from_slice(&salt);
        out.extend_from_slice(params.as_bytes());
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&key_data);
        out.extend_from_slice(&mac.finalize().into_bytes());
        Ok(out)
    }

    fn get_params(key_data: &[u8]) -> Result<Self::Params, PasetoError> {
        let params = key_data.get(16..32).ok_or(PasetoError::InvalidKey)?;
        Ok(Params::read_from_bytes(params).expect("should be the correct size"))
    }

    fn pw_unwrap_key<'key>(
        header: &'static str,
        pass: &[u8],
        key_data: &'key mut [u8],
    ) -> Result<&'key [u8], PasetoError> {
        let (salt, ciphertext) = key_data
            .split_first_chunk_mut()
            .ok_or(PasetoError::InvalidKey)?;
        let (params, ciphertext) = ciphertext
            .split_first_chunk_mut::<16>()
            .ok_or(PasetoError::InvalidKey)?;
        let (nonce, ciphertext) = ciphertext
            .split_first_chunk_mut()
            .ok_or(PasetoError::InvalidKey)?;
        let (ciphertext, tag) = ciphertext
            .split_last_chunk_mut()
            .ok_or(PasetoError::InvalidKey)?;
        let tag: &[u8; 32] = tag;

        let params = Params::ref_from_bytes(params).expect("should be the correct size");

        let (mut cipher, mut mac) = wrap_keys(pass, params, salt, nonce)?;
        auth(&mut mac, header, salt, params, nonce, ciphertext);
        mac.verify(tag.into())
            .map_err(|_| PasetoError::CryptoError)?;

        cipher.apply_keystream(ciphertext);

        Ok(ciphertext)
    }
}

fn kdf(key: &[u8], sep: &'static [u8]) -> GenericArray<u8, U32> {
    use digest::Digest;

    let mut mac = blake2::Blake2b::<U32>::default();
    mac.update(sep);
    mac.update(key);
    mac.finalize()
}

fn auth(
    mac: &mut blake2::Blake2bMac<U32>,
    header: &'static str,
    salt: &[u8],
    params: &Params,
    nonce: &[u8],
    ciphertext: &[u8],
) {
    mac.update(b"k4");
    mac.update(header.as_bytes());
    mac.update(salt);
    mac.update(params.as_bytes());
    mac.update(nonce);
    mac.update(ciphertext);
}
