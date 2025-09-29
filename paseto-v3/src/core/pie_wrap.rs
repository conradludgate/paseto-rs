use alloc::vec::Vec;

use cipher::StreamCipher;
use digest::Mac;
use generic_array::GenericArray;
use generic_array::sequence::Split;
use generic_array::typenum::U48;
use paseto_core::PasetoError;
use paseto_core::paserk::PieWrapVersion;

use super::{LocalKey, V3};

impl LocalKey {
    fn wrap_keys(&self, nonce: &[u8; 32]) -> (ctr::Ctr64BE<aes::Aes256>, hmac::Hmac<sha2::Sha384>) {
        use cipher::KeyIvInit;
        use digest::Mac;

        let (ek, n2) = kdf(&self.0, 0x80, nonce).split();
        let ak = kdf(&self.0, 0x81, nonce);

        let cipher = ctr::Ctr64BE::<aes::Aes256>::new(&ek, &n2);
        let mac = hmac::Hmac::new_from_slice(&ak[..32]).expect("key should be valid");
        (cipher, mac)
    }
}

impl PieWrapVersion for V3 {
    fn pie_wrap_key(
        header: &'static str,
        wrapping_key: &Self::LocalKey,
        mut key_data: Vec<u8>,
    ) -> Result<Vec<u8>, PasetoError> {
        let mut nonce = [0u8; 32];
        getrandom::fill(&mut nonce).map_err(|_| PasetoError::CryptoError)?;

        let (mut cipher, mut mac) = wrapping_key.wrap_keys(&nonce);

        cipher.apply_keystream(&mut key_data);
        auth(&mut mac, header, &nonce, &key_data);

        let mut out = Vec::with_capacity(80 + key_data.len());
        out.extend_from_slice(&mac.finalize().into_bytes());
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
            .split_first_chunk_mut()
            .ok_or(PasetoError::InvalidKey)?;
        let (nonce, ciphertext) = ciphertext
            .split_first_chunk_mut()
            .ok_or(PasetoError::InvalidKey)?;
        let tag: &[u8; 48] = tag;

        let (mut cipher, mut mac) = wrapping_key.wrap_keys(nonce);
        auth(&mut mac, header, nonce, ciphertext);
        mac.verify(tag.into())
            .map_err(|_| PasetoError::CryptoError)?;

        cipher.apply_keystream(ciphertext);

        Ok(ciphertext)
    }
}

fn kdf(key: &[u8], sep: u8, nonce: &[u8]) -> GenericArray<u8, U48> {
    let mut mac = hmac::Hmac::<sha2::Sha384>::new_from_slice(key).expect("key should be valid");
    mac.update(&[sep]);
    mac.update(nonce);
    mac.finalize().into_bytes()
}

fn auth(
    mac: &mut hmac::Hmac<sha2::Sha384>,
    encoding: &'static str,
    nonce: &[u8],
    ciphertext: &[u8],
) {
    mac.update(b"k3");
    mac.update(encoding.as_bytes());
    mac.update(nonce);
    mac.update(ciphertext);
}
