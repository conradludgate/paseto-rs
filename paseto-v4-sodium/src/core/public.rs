use libsodium_rs::{crypto_sign, random};
use paseto_core::PasetoError;
use paseto_core::key::{KeyKind, SealingKey, UnsealingKey};
use paseto_core::pae::pre_auth_encode;
use paseto_core::version::{Marker, Public, Secret};

use super::{PublicKey, SecretKey, V4};

impl KeyKind for PublicKey {
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

impl KeyKind for SecretKey {
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

impl SealingKey<Public> for SecretKey {
    fn unsealing_key(&self) -> PublicKey {
        let public_key = self
            .0
            .as_bytes()
            .last_chunk()
            .expect("secret key ends with the public key");
        PublicKey(crypto_sign::PublicKey::from_bytes_exact(*public_key))
    }

    fn random() -> Result<Self, PasetoError> {
        let mut secret_key = [0; 32];
        loop {
            random::fill_bytes(&mut secret_key);
            match crypto_sign::keypair_from_seed(&secret_key) {
                Ok(key) => break Ok(Self(key.secret_key)),
                Err(_) => continue,
            }
        }
    }

    fn nonce() -> Result<Vec<u8>, PasetoError> {
        Ok(Vec::with_capacity(32))
    }

    fn dangerous_seal_with_nonce(
        &self,
        encoding: &'static str,
        mut payload: Vec<u8>,
        footer: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, PasetoError> {
        let bytes = preauth_public(encoding, &payload, footer, aad);
        let sig =
            crypto_sign::sign_detached(&bytes, &self.0).map_err(|_| PasetoError::CryptoError)?;
        payload.extend_from_slice(&sig);
        Ok(payload)
    }
}

impl UnsealingKey<Public> for PublicKey {
    fn unseal<'a>(
        &self,
        encoding: &'static str,
        payload: &'a mut [u8],
        footer: &[u8],
        aad: &[u8],
    ) -> Result<&'a [u8], PasetoError> {
        let (cleartext, tag) = payload
            .split_last_chunk::<64>()
            .ok_or(PasetoError::InvalidToken)?;
        let bytes = preauth_public(encoding, cleartext, footer, aad);
        if !crypto_sign::verify_detached(tag, &bytes, &self.0) {
            return Err(PasetoError::CryptoError);
        }

        Ok(cleartext)
    }
}

fn preauth_public(encoding: &'static str, cleartext: &[u8], footer: &[u8], aad: &[u8]) -> Vec<u8> {
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
