use alloc::boxed::Box;
#[cfg(feature = "encrypting")]
use alloc::vec::Vec;

use blake2::Blake2bMac;
use chacha20::XChaCha20;
use cipher::StreamCipher;
use digest::Mac;
use generic_array::GenericArray;
use generic_array::sequence::Split;
use generic_array::typenum::{U32, U56};
use paseto_core::PasetoError;
use paseto_core::key::KeyEncoding;
use paseto_core::pae::pre_auth_encode;
use paseto_core::version::Local;

use super::{LocalKey, PreAuthEncodeDigest, V4, kdf};

#[cfg(feature = "decrypting")]
impl KeyEncoding for LocalKey {
    type Version = V4;
    type KeyType = Local;

    fn decode(bytes: &[u8]) -> Result<Self, PasetoError> {
        bytes
            .try_into()
            .map_err(|_| PasetoError::InvalidKey)
            .map(Self)
    }
    fn encode(&self) -> Box<[u8]> {
        self.0.to_vec().into_boxed_slice()
    }
}

impl LocalKey {
    fn keys(&self, nonce: &GenericArray<u8, U32>) -> (XChaCha20, Blake2bMac<U32>) {
        use cipher::KeyIvInit;
        use digest::Mac;

        let (ek, n2) = kdf::<U56>(&self.0, b"paseto-encryption-key", nonce).split();
        let ak: GenericArray<u8, U32> = kdf(&self.0, b"paseto-auth-key-for-aead", nonce);

        let cipher = XChaCha20::new(&ek, &n2);
        let mac = blake2::Blake2bMac::new_from_slice(&ak).expect("key should be valid");
        (cipher, mac)
    }
}

#[cfg(feature = "encrypting")]
impl paseto_core::version::SealingVersion<Local> for V4 {
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
        let (nonce, ciphertext) = payload.split_at_mut(32);
        let nonce: &[u8] = nonce;

        let (mut cipher, mut mac) = key.keys(nonce.into());
        cipher.apply_keystream(ciphertext);
        preauth_local(&mut mac, encoding, nonce, ciphertext, footer, aad);
        payload.extend_from_slice(&mac.finalize().into_bytes());

        Ok(payload)
    }
}

#[cfg(feature = "decrypting")]
impl paseto_core::version::UnsealingVersion<Local> for V4 {
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

        let (mut cipher, mut mac) = key.keys(nonce.into());
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
                "v4".as_bytes(),
                encoding.as_bytes(),
                Local::HEADER.as_bytes(),
            ],
            &[nonce],
            &[ciphertext],
            &[footer],
            &[aad],
        ],
        PreAuthEncodeDigest(mac),
    )
}
