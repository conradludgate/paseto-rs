use alloc::boxed::Box;
#[cfg(feature = "encrypting")]
use alloc::vec::Vec;

use blake2::Blake2bMac;
use chacha20::XChaCha20;
use cipher::StreamCipher;
use digest::Mac;
use hybrid_array::Array;
use hybrid_array::sizes::{U32, U56};
use paseto_core::PasetoError;
use paseto_core::key::HasKey;
use paseto_core::pae::pre_auth_encode;
use paseto_core::version::Local;

use super::{LocalKey, PreAuthEncodeDigest, V6, kdf};

impl LocalKey {
    pub fn as_raw_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn from_raw_bytes(b: [u8; 32]) -> Self {
        Self(b)
    }
}

impl HasKey<Local> for V6 {
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

impl LocalKey {
    fn keys(&self, nonce: &[u8; 32]) -> (XChaCha20, Blake2bMac<U32>) {
        use cipher::KeyIvInit;
        use digest::KeyInit;

        let ek = secret!(kdf::<U56>(&self.0, b"paseto-encryption-key", nonce));
        let ek_bytes: &Array<u8, U56> = &ek;
        let (ek, n2) = ek_bytes.split::<U32>();
        let ak = secret!(kdf::<U32>(&self.0, b"paseto-auth-key-for-aead", nonce));

        let cipher = XChaCha20::new(&ek, &n2);
        let mac = blake2::Blake2bMac::new_from_slice(&*ak).expect("key should be valid");
        (cipher, mac)
    }
}

#[cfg(feature = "encrypting")]
impl paseto_core::version::SealingVersion<Local> for V6 {
    fn unsealing_key(key: &LocalKey) -> LocalKey {
        LocalKey(key.0)
    }

    fn random() -> Result<LocalKey, PasetoError> {
        let mut bytes = [0; 32];
        getrandom::fill(&mut bytes).map_err(|_| PasetoError::CryptoError)?;
        Ok(LocalKey(bytes))
    }

    fn nonce() -> Result<[u8; 32], PasetoError> {
        let mut nonce = [0; 32];
        getrandom::fill(&mut nonce).map_err(|_| PasetoError::CryptoError)?;
        Ok(nonce)
    }

    fn dangerous_seal_with_nonce(
        key: &LocalKey,
        encoding: &'static str,
        mut payload: Vec<u8>,
        footer: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, PasetoError> {
        let (nonce, ciphertext) = payload.split_at_mut(32);
        let nonce: &[u8] = nonce;
        let nonce: &[u8; 32] = nonce.try_into().unwrap();

        let (mut cipher, mut mac) = key.keys(nonce);
        cipher.apply_keystream(ciphertext);
        preauth_local(&mut mac, encoding, nonce, ciphertext, footer, aad);
        payload.extend_from_slice(&mac.finalize().into_bytes());

        Ok(payload)
    }
}

#[cfg(feature = "decrypting")]
impl paseto_core::version::UnsealingVersion<Local> for V6 {
    type Nonce = [u8; 32];
    type Tag = [u8; 32];

    fn unseal<'a>(
        key: &LocalKey,
        encoding: &'static str,
        payload: &'a mut [u8],
        footer: &[u8],
        aad: &[u8],
    ) -> Result<&'a [u8], PasetoError> {
        let (ciphertext, tag) = payload
            .split_last_chunk_mut::<32>()
            .ok_or(PasetoError::InvalidToken)?;
        let (nonce, ciphertext) = ciphertext
            .split_first_chunk_mut::<32>()
            .ok_or(PasetoError::InvalidToken)?;
        let nonce: &[u8; 32] = nonce;
        let tag: &[u8; 32] = tag;

        let (mut cipher, mut mac) = key.keys(nonce);
        preauth_local(&mut mac, encoding, nonce, ciphertext, footer, aad);
        mac.verify(tag.into())
            .map_err(|_| PasetoError::CryptoError)?;
        cipher.apply_keystream(ciphertext);

        Ok(ciphertext)
    }
}

fn preauth_local(
    mac: &mut blake2::Blake2bMac<U32>,
    encoding: &'static str,
    nonce: &[u8],
    ciphertext: &[u8],
    footer: &[u8],
    aad: &[u8],
) {
    use paseto_core::key::KeyType;
    pre_auth_encode(
        [
            &[
                "v6".as_bytes(),
                encoding.as_bytes(),
                Local::HEADER.as_bytes(),
            ],
            &[nonce],
            &[ciphertext],
            &[footer],
            &[aad],
        ],
        PreAuthEncodeDigest(mac),
    );
}
