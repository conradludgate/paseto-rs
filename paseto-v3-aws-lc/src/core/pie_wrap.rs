use aws_lc_rs::cipher::{AES_256, UnboundCipherKey};
use aws_lc_rs::constant_time;
use aws_lc_rs::hmac::{self, HMAC_SHA384};
use aws_lc_rs::iv::FixedLength;
use aws_lc_rs::rand::{SecureRandom, SystemRandom};
use paseto_core::PasetoError;
use paseto_core::paserk::PieWrapVersion;

use super::{Cipher, LocalKey, V3};

impl LocalKey {
    fn wrap_keys(&self, nonce: &[u8]) -> Result<(Cipher, hmac::Key), PasetoError> {
        let aead_key = kdf(&self.0, 0x80, nonce);
        let (ek, n2) = aead_key
            .as_ref()
            .split_last_chunk::<16>()
            .ok_or(PasetoError::CryptoError)?;
        let ak = kdf(&self.0, 0x81, nonce);

        let key = UnboundCipherKey::new(&AES_256, ek).map_err(|_| PasetoError::CryptoError)?;
        let iv = FixedLength::from(n2);
        let mac = hmac::Key::new(HMAC_SHA384, &ak.as_ref()[..32]);

        Ok((Cipher(key, iv), mac))
    }
}

impl PieWrapVersion for V3 {
    fn pie_wrap_key(
        header: &'static str,
        wrapping_key: &Self::LocalKey,
        mut key_data: Vec<u8>,
    ) -> Result<Vec<u8>, PasetoError> {
        let mut nonce = [0u8; 32];
        SystemRandom::new()
            .fill(&mut nonce)
            .map_err(|_| PasetoError::CryptoError)?;

        let (cipher, mut mac) = wrapping_key.wrap_keys(&nonce)?;

        cipher.apply_keystream(&mut key_data)?;
        let tag = auth(&mut mac, header, &nonce, &key_data);

        let mut out = Vec::with_capacity(80 + key_data.len());
        out.extend_from_slice(tag.as_ref());
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&key_data);
        Ok(out)
    }

    fn pie_unwrap_key<'key>(
        header: &'static str,
        wrapping_key: &Self::LocalKey,
        key_data: &'key mut [u8],
    ) -> Result<&'key [u8], PasetoError> {
        let (tag, ciphertext) = key_data
            .split_first_chunk_mut::<48>()
            .ok_or(PasetoError::InvalidKey)?;
        let (nonce, ciphertext) = ciphertext
            .split_first_chunk_mut::<32>()
            .ok_or(PasetoError::InvalidKey)?;

        let (cipher, mut mac) = wrapping_key.wrap_keys(nonce)?;
        let actual_tag = auth(&mut mac, header, nonce, ciphertext);
        constant_time::verify_slices_are_equal(actual_tag.as_ref(), tag)
            .map_err(|_| PasetoError::CryptoError)?;

        cipher.apply_keystream(ciphertext)?;

        Ok(ciphertext)
    }
}

fn kdf(key: &[u8], sep: u8, nonce: &[u8]) -> hmac::Tag {
    let mut mac = hmac::Context::with_key(&hmac::Key::new(HMAC_SHA384, key));
    mac.update(&[sep]);
    mac.update(nonce);
    mac.sign()
}

fn auth(mac: &mut hmac::Key, encoding: &'static str, nonce: &[u8], ciphertext: &[u8]) -> hmac::Tag {
    let mut mac = hmac::Context::with_key(mac);
    mac.update(b"k3");
    mac.update(encoding.as_bytes());
    mac.update(nonce);
    mac.update(ciphertext);
    mac.sign()
}
