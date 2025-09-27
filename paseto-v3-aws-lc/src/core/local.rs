use aws_lc_rs::cipher::{AES_256, UnboundCipherKey};
use aws_lc_rs::constant_time;
use aws_lc_rs::hkdf::{self, HKDF_SHA384, KeyType};
use aws_lc_rs::hmac::{self, HMAC_SHA384};
use aws_lc_rs::iv::FixedLength;
use aws_lc_rs::rand::{SecureRandom, SystemRandom};
use paseto_core::PasetoError;
use paseto_core::key::{KeyKind, SealingKey, UnsealingKey};
use paseto_core::pae::{WriteBytes, pre_auth_encode};
use paseto_core::version::{Local, Marker};

use super::{Cipher, LocalKey, V3};

impl KeyKind for LocalKey {
    type Version = V3;
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
    fn keys(&self, nonce: &[u8]) -> Result<(Cipher, hmac::Key), PasetoError> {
        let aead_key = kdf::<48>(&self.0, "paseto-encryption-key", nonce)?;
        let (ek, n2) = aead_key
            .split_last_chunk::<16>()
            .ok_or(PasetoError::CryptoError)?;
        let ak = kdf::<48>(&self.0, "paseto-auth-key-for-aead", nonce)?;

        let key = UnboundCipherKey::new(&AES_256, ek).map_err(|_| PasetoError::CryptoError)?;
        let iv = FixedLength::from(n2);
        let mac = hmac::Key::new(HMAC_SHA384, &ak);

        Ok((Cipher(key, iv), mac))
    }
}

impl SealingKey<Local> for LocalKey {
    fn unsealing_key(&self) -> LocalKey {
        Self(self.0)
    }

    fn random() -> Result<Self, PasetoError> {
        let mut bytes = [0; 32];
        SystemRandom::new()
            .fill(&mut bytes)
            .map_err(|_| PasetoError::CryptoError)?;
        Ok(Self(bytes))
    }

    fn nonce() -> Result<Vec<u8>, PasetoError> {
        let mut nonce = [0; 32];
        SystemRandom::new()
            .fill(&mut nonce)
            .map_err(|_| PasetoError::CryptoError)?;

        let mut payload = Vec::with_capacity(80);
        payload.extend_from_slice(&nonce);
        Ok(payload)
    }

    fn dangerous_seal_with_nonce(
        &self,
        encoding: &'static str,
        mut payload: Vec<u8>,
        footer: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, PasetoError> {
        let (nonce, ciphertext) = payload.split_at_mut(32);

        let (cipher, mac) = self.keys(nonce)?;

        cipher.apply_keystream(ciphertext)?;
        let tag = preauth_local(mac, encoding, nonce, ciphertext, footer, aad);
        payload.extend_from_slice(tag.as_ref());

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
        if len < 80 {
            return Err(PasetoError::InvalidToken);
        }

        let (ciphertext, tag) = payload.split_at_mut(len - 48);
        let (nonce, ciphertext) = ciphertext.split_at_mut(32);

        let (cipher, mac) = self.keys(nonce)?;

        let actual_tag = preauth_local(mac, encoding, nonce, ciphertext, footer, aad);
        constant_time::verify_slices_are_equal(actual_tag.as_ref(), tag)
            .map_err(|_| PasetoError::CryptoError)?;

        cipher.apply_keystream(ciphertext)?;

        Ok(ciphertext)
    }
}

fn kdf<const N: usize>(
    key: &[u8],
    sep: &'static str,
    nonce: &[u8],
) -> Result<[u8; N], PasetoError> {
    struct Len<const N: usize>;
    impl<const N: usize> KeyType for Len<N> {
        fn len(&self) -> usize {
            N
        }
    }

    let ikm = [sep.as_bytes(), nonce];
    let prk = hkdf::Salt::new(HKDF_SHA384, &[]).extract(key);
    let okm = prk
        .expand(&ikm, Len::<N>)
        .map_err(|_| PasetoError::CryptoError)?;

    let mut output = [0; N];
    okm.fill(&mut output)
        .map_err(|_| PasetoError::CryptoError)?;
    Ok(output)
}

fn preauth_local(
    mac: hmac::Key,
    encoding: &'static str,
    nonce: &[u8],
    ciphertext: &[u8],
    footer: &[u8],
    aad: &[u8],
) -> hmac::Tag {
    struct Context(hmac::Context);
    impl WriteBytes for Context {
        fn write(&mut self, slice: &[u8]) {
            self.0.update(slice)
        }
    }

    let mut ctx = Context(hmac::Context::with_key(&mac));

    pre_auth_encode(
        [
            &[
                "v3".as_bytes(),
                encoding.as_bytes(),
                Local::HEADER.as_bytes(),
            ],
            &[nonce],
            &[ciphertext],
            &[footer],
            &[aad],
        ],
        &mut ctx,
    );

    ctx.0.sign()
}
