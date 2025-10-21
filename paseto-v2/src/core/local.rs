use alloc::boxed::Box;
#[cfg(feature = "encrypting")]
use alloc::vec::Vec;

use chacha20poly1305::XChaCha20Poly1305;
use digest::Mac;
use generic_array::typenum::U24;
use paseto_core::PasetoError;
use paseto_core::key::HasKey;
use paseto_core::pae::pre_auth_encode;
use paseto_core::version::Local;

use super::{LocalKey, V2};

impl LocalKey {
    pub fn as_raw_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn from_raw_bytes(b: [u8; 32]) -> Self {
        Self(b)
    }
}

impl HasKey<Local> for V2 {
    type Key = LocalKey;

    fn decode(bytes: &[u8]) -> Result<LocalKey, PasetoError> {
        bytes
            .try_into()
            .map(LocalKey)
            .map_err(|_| PasetoError::InvalidKey)
    }
    fn encode(key: &LocalKey) -> Box<[u8]> {
        key.0.to_vec().into_boxed_slice()
    }
}

#[cfg(feature = "encrypting")]
impl paseto_core::version::SealingVersion<Local> for V2 {
    fn unsealing_key(key: &LocalKey) -> LocalKey {
        LocalKey(key.0)
    }

    fn random() -> Result<LocalKey, PasetoError> {
        let mut bytes = [0; 32];
        getrandom::fill(&mut bytes).map_err(|_| PasetoError::CryptoError)?;
        Ok(LocalKey(bytes))
    }

    fn nonce() -> Result<Vec<u8>, PasetoError> {
        let mut nonce = [0; 32];
        getrandom::fill(&mut nonce).map_err(|_| PasetoError::CryptoError)?;

        let mut payload = Vec::with_capacity(64);
        payload.extend_from_slice(&nonce);
        Ok(payload)
    }

    fn dangerous_seal_with_nonce(
        key: &LocalKey,
        encoding: &'static str,
        mut payload: Vec<u8>,
        footer: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, PasetoError> {
        use chacha20poly1305::aead::AeadMutInPlace;
        use cipher::KeyInit;

        if !aad.is_empty() {
            return Err(PasetoError::ClaimsError);
        }

        let (nonce, ciphertext) = payload
            .split_first_chunk_mut::<24>()
            .ok_or(PasetoError::CryptoError)?;

        let mut n: blake2::Blake2bMac<U24> =
            digest::Mac::new_from_slice(nonce).expect("24 bytes is less than the 64 bytes max");
        n.update(ciphertext);
        *nonce = n.finalize().into_bytes().into();

        let nonce: &[u8; 24] = nonce;

        let aad = preauth_local(encoding, nonce, footer);
        let tag = XChaCha20Poly1305::new((&key.0).into())
            .encrypt_in_place_detached(nonce.into(), &aad, ciphertext)
            .map_err(|_| PasetoError::CryptoError)?;

        payload.extend_from_slice(&tag);

        Ok(payload)
    }
}

#[cfg(feature = "decrypting")]
impl paseto_core::version::UnsealingVersion<Local> for V2 {
    fn unseal<'a>(
        key: &LocalKey,
        encoding: &'static str,
        payload: &'a mut [u8],
        footer: &[u8],
        aad: &[u8],
    ) -> Result<&'a [u8], PasetoError> {
        use chacha20poly1305::aead::AeadMutInPlace;
        use cipher::KeyInit;

        if !aad.is_empty() {
            return Err(PasetoError::ClaimsError);
        }

        let (ciphertext, tag) = payload
            .split_last_chunk_mut::<16>()
            .ok_or(PasetoError::InvalidToken)?;
        let (nonce, ciphertext) = ciphertext
            .split_first_chunk_mut::<24>()
            .ok_or(PasetoError::InvalidToken)?;
        let nonce: &[u8; 24] = nonce;
        let tag: &[u8; 16] = tag;

        let aad = preauth_local(encoding, nonce, footer);
        XChaCha20Poly1305::new((&key.0).into())
            .decrypt_in_place_detached(nonce.into(), &aad, ciphertext, tag.into())
            .map_err(|_| PasetoError::CryptoError)?;

        Ok(ciphertext)
    }
}

fn preauth_local(encoding: &'static str, nonce: &[u8], footer: &[u8]) -> Vec<u8> {
    use paseto_core::key::KeyType;

    let mut v = Vec::new();
    pre_auth_encode(
        [
            &[
                "v2".as_bytes(),
                encoding.as_bytes(),
                Local::HEADER.as_bytes(),
            ],
            &[nonce],
            &[footer],
        ],
        &mut v,
    );
    v
}
