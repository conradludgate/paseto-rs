use alloc::boxed::Box;
#[cfg(feature = "signing")]
use alloc::vec::Vec;

use digest::Digest;
use paseto_core::PasetoError;
use paseto_core::key::HasKey;
use paseto_core::pae::{WriteBytes, pre_auth_encode};
use paseto_core::version::Public;
use rsa::pss::Signature;
#[cfg(feature = "signing")]
use rsa::rand_core::OsRng;
use rsa::traits::PublicKeyParts;

#[cfg(feature = "signing")]
use super::SecretKey;
use super::{PublicKey, V1};

impl HasKey<Public> for V1 {
    type Key = PublicKey;

    fn decode(bytes: &[u8]) -> Result<PublicKey, PasetoError> {
        use rsa::pkcs8::spki::DecodePublicKey;

        let key = if let Ok(key) = rsa::RsaPublicKey::from_public_key_der(bytes) {
            key
        } else {
            let s = str::from_utf8(bytes).map_err(|_| PasetoError::InvalidKey)?;
            rsa::RsaPublicKey::from_public_key_pem(s).map_err(|_| PasetoError::InvalidKey)?
        };

        if key.n().bits() != 2048 {
            return Err(PasetoError::InvalidKey);
        }

        Ok(PublicKey(rsa::pss::VerifyingKey::new(key)))
    }
    fn encode(key: &PublicKey) -> Box<[u8]> {
        use rsa::pkcs8::spki::EncodePublicKey;

        key.0
            .to_public_key_der()
            .expect("encoding to spki der should succeed")
            .into_vec()
            .into_boxed_slice()
    }
}

#[cfg(feature = "signing")]
impl HasKey<paseto_core::version::Secret> for V1 {
    type Key = SecretKey;

    fn decode(bytes: &[u8]) -> Result<SecretKey, PasetoError> {
        use rsa::pkcs1::DecodeRsaPrivateKey;

        let key = if let Ok(key) = rsa::RsaPrivateKey::from_pkcs1_der(bytes) {
            key
        } else {
            let s = str::from_utf8(bytes).map_err(|_| PasetoError::InvalidKey)?;
            rsa::RsaPrivateKey::from_pkcs1_pem(s).map_err(|_| PasetoError::InvalidKey)?
        };

        if key.n().bits() != 2048 {
            return Err(PasetoError::InvalidKey);
        }

        Ok(SecretKey(rsa::pss::SigningKey::new(key)))
    }
    fn encode(key: &SecretKey) -> Box<[u8]> {
        use rsa::pkcs1::EncodeRsaPrivateKey;

        key.0
            .to_pkcs1_der()
            .expect("encoding to pkcs1 der should succeed")
            .as_bytes()
            .to_vec()
            .into_boxed_slice()
    }
}

#[cfg(feature = "signing")]
impl SecretKey {
    pub(crate) fn random() -> Result<Self, PasetoError> {
        use rsa::rand_core::OsRng;

        rsa::pss::SigningKey::random(&mut OsRng, 2048)
            .map_err(|_| PasetoError::InvalidKey)
            .map(Self)
    }
}

#[cfg(feature = "signing")]
impl paseto_core::version::SealingVersion<Public> for V1 {
    fn unsealing_key(key: &SecretKey) -> PublicKey {
        use rsa::signature::Keypair;

        PublicKey(key.0.verifying_key())
    }

    fn random() -> Result<SecretKey, PasetoError> {
        SecretKey::random()
    }

    fn nonce() -> Result<Vec<u8>, PasetoError> {
        Ok(Vec::with_capacity(96))
    }

    fn dangerous_seal_with_nonce(
        key: &SecretKey,
        encoding: &'static str,
        mut payload: Vec<u8>,
        footer: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, PasetoError> {
        use rsa::signature::RandomizedDigestSigner;

        if !aad.is_empty() {
            return Err(PasetoError::ClaimsError);
        }

        let digest = preauth_public(encoding, &payload, footer);
        let signature: Box<[u8]> = key
            .0
            .try_sign_digest_with_rng(&mut OsRng, digest)
            .map_err(|_| PasetoError::CryptoError)?
            .into();

        payload.extend_from_slice(&signature);

        Ok(payload)
    }
}

impl paseto_core::version::UnsealingVersion<Public> for V1 {
    fn unseal<'a>(
        key: &PublicKey,
        encoding: &'static str,
        payload: &'a mut [u8],
        footer: &[u8],
        aad: &[u8],
    ) -> Result<&'a [u8], PasetoError> {
        use rsa::signature::DigestVerifier;

        if !aad.is_empty() {
            return Err(PasetoError::ClaimsError);
        }

        let (cleartext, tag) = payload
            .split_last_chunk::<256>()
            .ok_or(PasetoError::InvalidToken)?;

        let signature = Signature::try_from(&tag[..]).map_err(|_| PasetoError::InvalidToken)?;
        let digest = preauth_public(encoding, cleartext, footer);
        DigestVerifier::<sha2::Sha384, Signature>::verify_digest(&key.0, digest, &signature)
            .map_err(|_| PasetoError::CryptoError)?;

        Ok(cleartext)
    }
}
fn preauth_public(encoding: &'static str, cleartext: &[u8], footer: &[u8]) -> sha2::Sha384 {
    use paseto_core::key::KeyType;
    struct Context(sha2::Sha384);
    impl WriteBytes for Context {
        fn write(&mut self, slice: &[u8]) {
            self.0.update(slice);
        }
    }

    let mut ctx = Context(sha2::Sha384::new());
    pre_auth_encode(
        [
            &[
                "v1".as_bytes(),
                encoding.as_bytes(),
                Public::HEADER.as_bytes(),
            ],
            &[cleartext],
            &[footer],
        ],
        &mut ctx,
    );
    ctx.0
}
