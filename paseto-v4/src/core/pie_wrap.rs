use alloc::vec::Vec;

use blake2::Blake2bMac;
use chacha20::XChaCha20;
use cipher::StreamCipher;
use digest::Mac;
use generic_array::GenericArray;
use generic_array::sequence::Split;
use generic_array::typenum::{U32, U56};
use paseto_core::PasetoError;
use paseto_core::version::PieWrapVersion;

use super::{LocalKey, V4, kdf};

impl LocalKey {
    fn wrap_keys(&self, nonce: &GenericArray<u8, U32>) -> (XChaCha20, Blake2bMac<U32>) {
        use cipher::KeyIvInit;
        use digest::Mac;

        let (ek, n2) = kdf::<U56>(&self.0, &[0x80], nonce).split();
        let ak: GenericArray<u8, U32> = kdf(&self.0, &[0x81], nonce);

        let cipher = XChaCha20::new(&ek, &n2);
        let mac = blake2::Blake2bMac::new_from_slice(&ak).expect("key should be valid");
        (cipher, mac)
    }
}

impl PieWrapVersion for V4 {
    fn pie_wrap_key(
        header: &'static str,
        wrapping_key: &Self::LocalKey,
        mut key_data: Vec<u8>,
    ) -> Result<Vec<u8>, PasetoError> {
        let mut nonce = GenericArray::default();
        getrandom::fill(&mut nonce).map_err(|_| PasetoError::CryptoError)?;
        let (mut cipher, mut mac) = wrapping_key.wrap_keys(&nonce);
        cipher.apply_keystream(&mut key_data);
        auth(&mut mac, header, &nonce, &key_data);
        let mut out = Vec::with_capacity(64 + key_data.len());
        out.extend_from_slice(&mac.finalize().into_bytes());
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&key_data);
        Ok(out)
    }

    fn pie_unwrap_key(
        header: &'static str,
        wrapping_key: &Self::LocalKey,
        mut key_data: Vec<u8>,
    ) -> Result<Vec<u8>, PasetoError> {
        let (tag, ciphertext) = key_data
            .split_first_chunk_mut::<32>()
            .ok_or(PasetoError::InvalidKey)?;
        let (nonce, ciphertext) = ciphertext
            .split_first_chunk_mut::<32>()
            .ok_or(PasetoError::InvalidKey)?;
        let nonce: &[u8; 32] = nonce;
        let tag: &[u8; 32] = tag;

        let (mut cipher, mut mac) = wrapping_key.wrap_keys(nonce.into());
        auth(&mut mac, header, nonce, ciphertext);
        mac.verify(tag.into())
            .map_err(|_| PasetoError::CryptoError)?;

        cipher.apply_keystream(ciphertext);
        key_data.drain(0..64);

        Ok(key_data)
    }
}

fn auth(
    mac: &mut blake2::Blake2bMac<U32>,
    encoding: &'static str,
    nonce: &[u8],
    ciphertext: &[u8],
) {
    mac.update(b"k4");
    mac.update(encoding.as_bytes());
    mac.update(nonce);
    mac.update(ciphertext);
}
