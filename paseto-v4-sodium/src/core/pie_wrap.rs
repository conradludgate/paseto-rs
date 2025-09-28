use libsodium_rs::crypto_stream::{self, xchacha20};
use libsodium_rs::utils::compare;
use libsodium_rs::{crypto_generichash, random};
use paseto_core::PasetoError;
use paseto_core::version::PieWrapVersion;

use super::{LocalKey, V4, kdf};

impl LocalKey {
    fn wrap_keys(
        &self,
        nonce: &[u8],
    ) -> (
        crypto_stream::Key,
        xchacha20::Nonce,
        crypto_generichash::State,
    ) {
        let ekn2 = kdf(&self.0, &[0x80], nonce, 56);
        let ak = kdf(&self.0, &[0x81], nonce, 32);

        let (ek, n2) = ekn2
            .split_last_chunk::<24>()
            .expect("kdf should output 56 bytes");
        let ek = crypto_stream::Key::from_slice(ek).expect("32 byte key should be valid");
        let n2 = xchacha20::Nonce::from_bytes(*n2);
        let mac = crypto_generichash::State::new(Some(&ak), 32).expect("invalid mac");

        (ek, n2, mac)
    }
}

impl PieWrapVersion for V4 {
    fn pie_wrap_key(
        header: &'static str,
        wrapping_key: &Self::LocalKey,
        key_data: Vec<u8>,
    ) -> Result<Vec<u8>, PasetoError> {
        let nonce = random::bytes(32);

        let (ek, n2, mut mac) = wrapping_key.wrap_keys(&nonce);

        let ciphertext =
            xchacha20::stream_xor(&key_data, &n2, &ek).map_err(|_| PasetoError::CryptoError)?;

        auth(&mut mac, header, &nonce, &ciphertext);
        let mut out = Vec::with_capacity(64 + ciphertext.len());
        out.extend_from_slice(&mac.finalize());
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&ciphertext);
        Ok(out)
    }

    fn pie_unwrap_key<'key>(
        header: &'static str,
        wrapping_key: &Self::LocalKey,
        key_data: &'key mut [u8],
    ) -> Result<&'key [u8], PasetoError> {
        let (tag, ciphertext) = key_data
            .split_first_chunk_mut::<32>()
            .ok_or(PasetoError::InvalidKey)?;
        let (nonce, ciphertext) = ciphertext
            .split_first_chunk_mut::<32>()
            .ok_or(PasetoError::InvalidKey)?;
        let nonce: &[u8; 32] = nonce;
        let tag: &[u8; 32] = tag;

        let (ek, n2, mut mac) = wrapping_key.wrap_keys(nonce);
        auth(&mut mac, header, nonce, ciphertext);
        if compare(&mac.finalize(), tag) != 0 {
            return Err(PasetoError::CryptoError);
        }

        let plaintext =
            xchacha20::stream_xor(ciphertext, &n2, &ek).map_err(|_| PasetoError::CryptoError)?;
        ciphertext.copy_from_slice(&plaintext);
        Ok(ciphertext)
    }
}

fn auth(
    mac: &mut crypto_generichash::State,
    encoding: &'static str,
    nonce: &[u8],
    ciphertext: &[u8],
) {
    mac.update(b"k4");
    mac.update(encoding.as_bytes());
    mac.update(nonce);
    mac.update(ciphertext);
}
