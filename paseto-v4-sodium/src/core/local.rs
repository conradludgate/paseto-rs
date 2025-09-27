use libsodium_rs::crypto_stream::{self, xchacha20};
use libsodium_rs::utils::compare;
use libsodium_rs::{crypto_generichash, random};
use paseto_core::PasetoError;
use paseto_core::key::{KeyKind, SealingKey, UnsealingKey};
use paseto_core::pae::pre_auth_encode;
use paseto_core::version::{Local, Marker};

use super::{LocalKey, V4};

impl KeyKind for LocalKey {
    type Version = V4;
    type KeyType = Local;

    fn decode(bytes: &[u8]) -> Result<Self, PasetoError> {
        bytes
            .try_into()
            .map(Self)
            .map_err(|_| PasetoError::InvalidKey)
    }
    fn encode(&self) -> Box<[u8]> {
        self.0.to_vec().into_boxed_slice()
    }
}

impl LocalKey {
    fn keys(
        &self,
        nonce: &[u8; 32],
    ) -> (
        crypto_stream::Key,
        xchacha20::Nonce,
        crypto_generichash::State,
    ) {
        let ekn2 = kdf(&self.0, "paseto-encryption-key", nonce, 56);
        let ak = kdf(&self.0, "paseto-auth-key-for-aead", nonce, 32);

        let (ek, n2) = ekn2
            .split_last_chunk::<24>()
            .expect("kdf should output 56 bytes");
        let ek = crypto_stream::Key::from_slice(ek).expect("32 byte key should be valid");
        let n2 = xchacha20::Nonce::from_bytes(*n2);
        let mac = crypto_generichash::State::new(Some(&ak), 32).expect("invalid mac");

        (ek, n2, mac)
    }
}

impl SealingKey<Local> for LocalKey {
    fn unsealing_key(&self) -> LocalKey {
        Self(self.0)
    }

    fn random() -> Result<Self, PasetoError> {
        let mut bytes = [0; 32];
        random::fill_bytes(&mut bytes);
        Ok(Self(bytes))
    }

    fn nonce() -> Result<Vec<u8>, PasetoError> {
        Ok(random::bytes(32))
    }

    fn dangerous_seal_with_nonce(
        &self,
        encoding: &'static str,
        mut payload: Vec<u8>,
        footer: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, PasetoError> {
        let (nonce, plaintext) = payload
            .split_first_chunk::<32>()
            .ok_or(PasetoError::InvalidToken)?;
        let (ek, n2, mut mac) = self.keys(nonce);

        let ciphertext =
            xchacha20::stream_xor(plaintext, &n2, &ek).map_err(|_| PasetoError::CryptoError)?;

        preauth_local(&mut mac, encoding, nonce, &ciphertext, footer, aad);

        payload.truncate(32);
        payload.extend_from_slice(&ciphertext);
        payload.extend_from_slice(&mac.finalize());

        Ok(payload)
    }
}

impl UnsealingKey<Local> for LocalKey {
    fn unseal<'a>(
        &self,
        encoding: &'static str,
        payload: &'a mut [u8],
        footer: &[u8],
        aad: &[u8],
    ) -> Result<&'a [u8], PasetoError> {
        let len = payload.len();
        if len < 64 {
            return Err(PasetoError::InvalidToken);
        }

        let (ciphertext, tag) = payload
            .split_last_chunk_mut::<32>()
            .ok_or(PasetoError::InvalidToken)?;
        let (nonce, ciphertext) = ciphertext
            .split_first_chunk_mut::<32>()
            .ok_or(PasetoError::InvalidToken)?;

        let (ek, n2, mut mac) = self.keys(nonce);

        preauth_local(&mut mac, encoding, nonce, ciphertext, footer, aad);
        if compare(&mac.finalize(), tag) != 0 {
            return Err(PasetoError::CryptoError);
        }

        let plaintext =
            xchacha20::stream_xor(ciphertext, &n2, &ek).map_err(|_| PasetoError::CryptoError)?;
        ciphertext.copy_from_slice(&plaintext);

        Ok(ciphertext)
    }
}

fn kdf(key: &[u8], sep: &'static str, nonce: &[u8], len: usize) -> Vec<u8> {
    let mut ctx =
        crypto_generichash::State::new(Some(key), len).expect("could not construct hasher");
    ctx.update(sep.as_bytes());
    ctx.update(nonce);
    ctx.finalize()
}

struct PreAuthEncodeDigest<'a>(pub &'a mut crypto_generichash::State);
impl<'a> paseto_core::pae::WriteBytes for PreAuthEncodeDigest<'a> {
    fn write(&mut self, slice: &[u8]) {
        self.0.update(slice)
    }
}

fn preauth_local(
    mac: &mut crypto_generichash::State,
    encoding: &'static str,
    nonce: &[u8],
    ciphertext: &[u8],
    footer: &[u8],
    aad: &[u8],
) {
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
