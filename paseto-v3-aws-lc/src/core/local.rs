use aws_lc_rs::cipher::{AES_256, UnboundCipherKey};
use aws_lc_rs::constant_time;
use aws_lc_rs::hkdf::{self, HKDF_SHA384, KeyType};
use aws_lc_rs::hmac::{self, HMAC_SHA384};
use aws_lc_rs::iv::FixedLength;
use aws_lc_rs::rand::{SecureRandom, SystemRandom};
use paseto_core::PasetoError;
use paseto_core::key::KeyEncoding;
use paseto_core::pae::{WriteBytes, pre_auth_encode};
use paseto_core::version::Local;

use super::{Cipher, LocalKey, V3};

impl KeyEncoding for LocalKey {
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
    fn keys(&self, nonce: &[u8]) -> Result<(Cipher, hmac::Context), PasetoError> {
        let aead_key = kdf(&self.0, "paseto-encryption-key", nonce)?;
        let (ek, n2) = aead_key
            .split_last_chunk::<16>()
            .ok_or(PasetoError::CryptoError)?;
        let ak = kdf(&self.0, "paseto-auth-key-for-aead", nonce)?;

        let key = UnboundCipherKey::new(&AES_256, ek).map_err(|_| PasetoError::CryptoError)?;
        let iv = FixedLength::from(n2);
        let mac = hmac::Context::with_key(&hmac::Key::new(HMAC_SHA384, &ak));

        Ok((Cipher(key, iv), mac))
    }
}

impl paseto_core::version::SealingVersion<Local> for V3 {
    fn unsealing_key(key: &LocalKey) -> LocalKey {
        LocalKey(key.0)
    }

    fn random() -> Result<LocalKey, PasetoError> {
        let mut bytes = [0; 32];
        SystemRandom::new()
            .fill(&mut bytes)
            .map_err(|_| PasetoError::CryptoError)?;
        Ok(LocalKey(bytes))
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
        key: &LocalKey,
        encoding: &'static str,
        mut payload: Vec<u8>,
        footer: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, PasetoError> {
        let (nonce, ciphertext) = payload.split_at_mut(32);

        let (cipher, mut mac) = key.keys(nonce)?;

        cipher.apply_keystream(ciphertext)?;
        preauth_local(&mut mac, encoding, nonce, ciphertext, footer, aad);
        payload.extend_from_slice(mac.sign().as_ref());

        Ok(payload)
    }
}

impl paseto_core::version::UnsealingVersion<Local> for V3 {
    fn unseal<'a>(
        key: &LocalKey,
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

        let (cipher, mut mac) = key.keys(nonce)?;

        preauth_local(&mut mac, encoding, nonce, ciphertext, footer, aad);
        constant_time::verify_slices_are_equal(mac.sign().as_ref(), tag)
            .map_err(|_| PasetoError::CryptoError)?;

        cipher.apply_keystream(ciphertext)?;

        Ok(ciphertext)
    }
}

fn kdf(key: &[u8], sep: &'static str, nonce: &[u8]) -> Result<[u8; 48], PasetoError> {
    struct Len;
    impl KeyType for Len {
        fn len(&self) -> usize {
            48
        }
    }

    let ikm = [sep.as_bytes(), nonce];
    let prk = hkdf::Salt::new(HKDF_SHA384, &[]).extract(key);
    let okm = prk
        .expand(&ikm, Len)
        .map_err(|_| PasetoError::CryptoError)?;

    let mut output = [0; 48];
    okm.fill(&mut output)
        .map_err(|_| PasetoError::CryptoError)?;
    Ok(output)
}

fn preauth_local(
    mac: &mut hmac::Context,
    encoding: &'static str,
    nonce: &[u8],
    ciphertext: &[u8],
    footer: &[u8],
    aad: &[u8],
) {
    use paseto_core::key::KeyType;

    struct Context<'a>(&'a mut hmac::Context);
    impl WriteBytes for Context<'_> {
        fn write(&mut self, slice: &[u8]) {
            self.0.update(slice);
        }
    }

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
        Context(mac),
    );
}
