use libsodium_rs::{crypto_sign, random};
use paseto_core::PasetoError;
use paseto_core::key::KeyEncoding;
use paseto_core::pae::pre_auth_encode;
use paseto_core::version::{Public, Secret};

use super::{PublicKey, SecretKey, V4};

impl KeyEncoding for PublicKey {
    type Version = V4;
    type KeyType = Public;

    fn decode(bytes: &[u8]) -> Result<Self, PasetoError> {
        crypto_sign::PublicKey::from_bytes(bytes)
            .map(Self)
            .map_err(|_| PasetoError::InvalidKey)
    }
    fn encode(&self) -> Box<[u8]> {
        self.0.as_bytes().to_vec().into_boxed_slice()
    }
}

impl KeyEncoding for SecretKey {
    type Version = V4;
    type KeyType = Secret;

    fn decode(bytes: &[u8]) -> Result<Self, PasetoError> {
        crypto_sign::SecretKey::from_bytes(bytes)
            .map(Self)
            .map_err(|_| PasetoError::InvalidKey)
    }

    fn encode(&self) -> Box<[u8]> {
        self.0.as_bytes().to_vec().into_boxed_slice()
    }
}

impl SecretKey {
    pub(crate) fn unsealing_key(&self) -> PublicKey {
        let public_key = self
            .0
            .as_bytes()
            .last_chunk()
            .expect("secret key ends with the public key");
        PublicKey(crypto_sign::PublicKey::from_bytes_exact(*public_key))
    }
}

impl paseto_core::version::SealingVersion<Public> for V4 {
    fn unsealing_key(key: &SecretKey) -> PublicKey {
        key.unsealing_key()
    }

    fn random() -> Result<SecretKey, PasetoError> {
        let mut secret_key = [0; 32];
        loop {
            random::fill_bytes(&mut secret_key);
            if let Ok(key) = crypto_sign::keypair_from_seed(&secret_key) {
                break Ok(SecretKey(key.secret_key));
            }
        }
    }

    fn nonce() -> Result<Vec<u8>, PasetoError> {
        Ok(Vec::with_capacity(32))
    }

    fn dangerous_seal_with_nonce(
        key: &SecretKey,
        encoding: &'static str,
        mut payload: Vec<u8>,
        footer: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, PasetoError> {
        let bytes = preauth_public(encoding, &payload, footer, aad);
        let sig =
            crypto_sign::sign_detached(&bytes, &key.0).map_err(|_| PasetoError::CryptoError)?;
        payload.extend_from_slice(&sig);
        Ok(payload)
    }
}

impl paseto_core::version::UnsealingVersion<Public> for V4 {
    fn unseal<'a>(
        key: &PublicKey,
        encoding: &'static str,
        payload: &'a mut [u8],
        footer: &[u8],
        aad: &[u8],
    ) -> Result<&'a [u8], PasetoError> {
        let (cleartext, tag) = payload
            .split_last_chunk::<64>()
            .ok_or(PasetoError::InvalidToken)?;
        let bytes = preauth_public(encoding, cleartext, footer, aad);
        if !crypto_sign::verify_detached(tag, &bytes, &key.0) {
            return Err(PasetoError::CryptoError);
        }

        Ok(cleartext)
    }
}

fn preauth_public(encoding: &'static str, cleartext: &[u8], footer: &[u8], aad: &[u8]) -> Vec<u8> {
    use paseto_core::key::KeyType;
    let mut out = Vec::new();
    pre_auth_encode(
        [
            &[
                "v4".as_bytes(),
                encoding.as_bytes(),
                Public::HEADER.as_bytes(),
            ],
            &[cleartext],
            &[footer],
            &[aad],
        ],
        &mut out,
    );
    out
}
