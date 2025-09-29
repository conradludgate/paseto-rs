use alloc::boxed::Box;
#[cfg(feature = "signing")]
use alloc::vec::Vec;

use digest::Digest;
use p384::ecdsa::Signature;
use paseto_core::PasetoError;
use paseto_core::key::KeyKind;
use paseto_core::pae::{WriteBytes, pre_auth_encode};
use paseto_core::version::{Marker, Public};

#[cfg(feature = "signing")]
use super::SecretKey;
use super::{PublicKey, V3};

impl KeyKind for PublicKey {
    type Version = V3;
    type KeyType = Public;

    fn decode(bytes: &[u8]) -> Result<Self, PasetoError> {
        p384::ecdsa::VerifyingKey::from_sec1_bytes(bytes)
            .map(Self)
            .map_err(|_| PasetoError::InvalidKey)
    }
    fn encode(&self) -> Box<[u8]> {
        self.0
            .to_encoded_point(true)
            .as_bytes()
            .to_vec()
            .into_boxed_slice()
    }
}

#[cfg(feature = "signing")]
impl KeyKind for SecretKey {
    type Version = V3;
    type KeyType = paseto_core::version::Secret;

    fn decode(bytes: &[u8]) -> Result<Self, PasetoError> {
        if bytes.len() != 48 {
            return Err(PasetoError::InvalidKey);
        }
        let sk = p384::SecretKey::from_slice(bytes).map_err(|_| PasetoError::InvalidKey)?;
        Ok(SecretKey(sk.into()))
    }
    fn encode(&self) -> Box<[u8]> {
        self.0.to_bytes().to_vec().into_boxed_slice()
    }
}

#[cfg(feature = "signing")]
impl SecretKey {
    pub(crate) fn random() -> Result<Self, PasetoError> {
        let mut bytes = generic_array::GenericArray::default();
        loop {
            getrandom::fill(&mut bytes).map_err(|_| PasetoError::CryptoError)?;
            match p384::ecdsa::SigningKey::from_bytes(&bytes).map(Self) {
                Err(_) => continue,
                Ok(key) => break Ok(key),
            }
        }
    }
}

#[cfg(feature = "signing")]
impl paseto_core::version::SealingVersion<Public> for V3 {
    fn unsealing_key(key: &crate::SecretKey) -> crate::PublicKey {
        crate::PublicKey::from_inner(PublicKey(*key.as_inner().0.verifying_key()))
    }

    fn random() -> Result<crate::SecretKey, PasetoError> {
        SecretKey::random().map(crate::SecretKey::from_inner)
    }

    fn nonce() -> Result<Vec<u8>, PasetoError> {
        Ok(Vec::with_capacity(96))
    }

    fn dangerous_seal_with_nonce(
        key: &crate::SecretKey,
        encoding: &'static str,
        mut payload: Vec<u8>,
        footer: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, PasetoError> {
        use p384::ecdsa::signature::DigestSigner;

        let digest = preauth_public(
            key.as_inner().0.verifying_key(),
            encoding,
            &payload,
            footer,
            aad,
        );
        let signature: Signature = key.as_inner().0.sign_digest(digest);
        let signature = signature.normalize_s().unwrap_or(signature);

        payload.extend_from_slice(&signature.to_bytes());

        Ok(payload)
    }
}

impl paseto_core::version::UnsealingVersion<Public> for V3 {
    fn unseal<'a>(
        key: &crate::PublicKey,
        encoding: &'static str,
        payload: &'a mut [u8],
        footer: &[u8],
        aad: &[u8],
    ) -> Result<&'a [u8], PasetoError> {
        use p384::ecdsa::signature::DigestVerifier;

        let (cleartext, tag) = payload
            .split_last_chunk::<96>()
            .ok_or(PasetoError::InvalidToken)?;

        let signature =
            Signature::from_bytes(tag[..].into()).map_err(|_| PasetoError::InvalidToken)?;
        let digest = preauth_public(&key.as_inner().0, encoding, cleartext, footer, aad);
        DigestVerifier::<sha2::Sha384, Signature>::verify_digest(
            &key.as_inner().0,
            digest,
            &signature,
        )
        .map_err(|_| PasetoError::CryptoError)?;

        Ok(cleartext)
    }
}
fn preauth_public(
    key: &p384::ecdsa::VerifyingKey,
    encoding: &'static str,
    cleartext: &[u8],
    footer: &[u8],
    aad: &[u8],
) -> sha2::Sha384 {
    struct Context(sha2::Sha384);
    impl WriteBytes for Context {
        fn write(&mut self, slice: &[u8]) {
            self.0.update(slice)
        }
    }

    let key = key.to_encoded_point(true);

    let mut ctx = Context(sha2::Sha384::new());
    pre_auth_encode(
        [
            &[key.as_bytes()],
            &[
                "v3".as_bytes(),
                encoding.as_bytes(),
                Public::HEADER.as_bytes(),
            ],
            &[cleartext],
            &[footer],
            &[aad],
        ],
        &mut ctx,
    );
    ctx.0
}
