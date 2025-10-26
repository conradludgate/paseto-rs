use alloc::boxed::Box;
#[cfg(feature = "signing")]
use alloc::vec::Vec;

use ed25519_dalek::Signature;
use paseto_core::PasetoError;
use paseto_core::key::{HasKey, KeyType};
use paseto_core::pae::{WriteBytes, pre_auth_encode};
use paseto_core::version::Public;
#[cfg(feature = "signing")]
use paseto_core::version::Secret;

#[cfg(feature = "signing")]
use super::SecretKey;
use super::{PublicKey, V2};

#[cfg(feature = "verifying")]
impl HasKey<Public> for V2 {
    type Key = PublicKey;

    fn decode(bytes: &[u8]) -> Result<PublicKey, PasetoError> {
        let key = bytes.try_into().map_err(|_| PasetoError::InvalidKey)?;
        ed25519_dalek::VerifyingKey::from_bytes(&key)
            .map(PublicKey)
            .map_err(|_| PasetoError::InvalidKey)
    }
    fn encode(key: &PublicKey) -> Box<[u8]> {
        key.0.as_bytes().to_vec().into_boxed_slice()
    }
}

#[cfg(feature = "signing")]
impl HasKey<Secret> for V2 {
    type Key = SecretKey;

    fn decode(bytes: &[u8]) -> Result<SecretKey, PasetoError> {
        let (secret_key, verifying_key) = bytes
            .split_first_chunk::<32>()
            .ok_or(PasetoError::InvalidKey)?;

        let esk = ed25519_dalek::hazmat::ExpandedSecretKey::from(secret_key);

        let verifying_key = <V2 as HasKey<Public>>::decode(verifying_key)?;
        let pubkey = ed25519_dalek::VerifyingKey::from(&esk);

        if pubkey != verifying_key.0 {
            return Err(PasetoError::InvalidKey);
        }

        Ok(SecretKey(*secret_key, esk))
    }
    fn encode(key: &SecretKey) -> Box<[u8]> {
        let pubkey = ed25519_dalek::VerifyingKey::from(&key.1);
        let mut bytes = Vec::with_capacity(64);
        bytes.extend_from_slice(&key.0);
        bytes.extend_from_slice(pubkey.as_bytes());
        bytes.into_boxed_slice()
    }
}

#[cfg(feature = "signing")]
impl Clone for super::SecretKey {
    fn clone(&self) -> Self {
        let esk = ed25519_dalek::hazmat::ExpandedSecretKey {
            scalar: self.1.scalar,
            hash_prefix: self.1.hash_prefix,
        };
        Self(self.0, esk)
    }
}

#[cfg(feature = "signing")]
impl paseto_core::version::SealingVersion<Public> for V2 {
    fn unsealing_key(key: &SecretKey) -> PublicKey {
        PublicKey((&key.1).into())
    }

    fn random() -> Result<SecretKey, PasetoError> {
        let mut secret_key = [0; 32];
        getrandom::fill(&mut secret_key).map_err(|_| PasetoError::CryptoError)?;

        let esk = ed25519_dalek::hazmat::ExpandedSecretKey::from(&secret_key);
        Ok(SecretKey(secret_key, esk))
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
        if !aad.is_empty() {
            return Err(PasetoError::ClaimsError);
        }

        let signature = preauth_secret(&key.1, encoding, &payload, footer);
        payload.extend_from_slice(&signature.to_bytes());
        Ok(payload)
    }
}

#[cfg(feature = "verifying")]
impl paseto_core::version::UnsealingVersion<Public> for V2 {
    fn unseal<'a>(
        key: &PublicKey,
        encoding: &'static str,
        payload: &'a mut [u8],
        footer: &[u8],
        aad: &[u8],
    ) -> Result<&'a [u8], PasetoError> {
        if !aad.is_empty() {
            return Err(PasetoError::ClaimsError);
        }

        let len = payload.len();
        if len < 64 {
            return Err(PasetoError::InvalidToken);
        }

        let (cleartext, tag) = payload.split_at(len - 64);
        let signature = Signature::from_bytes(tag.try_into().unwrap());
        let verifier = key
            .0
            .verify_stream(&signature)
            .map_err(|_| PasetoError::CryptoError)?;

        preauth_public(verifier, encoding, cleartext, footer)
            .finalize_and_verify()
            .map_err(|_| PasetoError::CryptoError)?;

        Ok(cleartext)
    }
}

fn preauth_public(
    verifier: ed25519_dalek::StreamVerifier,
    encoding: &'static str,
    cleartext: &[u8],
    footer: &[u8],
) -> ed25519_dalek::StreamVerifier {
    #[repr(transparent)]
    pub struct StreamVerifier(pub ed25519_dalek::StreamVerifier);

    impl WriteBytes for StreamVerifier {
        fn write(&mut self, slice: &[u8]) {
            self.0.update(slice);
        }
    }

    let mut sv = StreamVerifier(verifier);
    pre_auth_encode(
        [
            &[
                "v2".as_bytes(),
                encoding.as_bytes(),
                Public::HEADER.as_bytes(),
            ],
            &[cleartext],
            &[footer],
        ],
        &mut sv,
    );

    sv.0
}

#[cfg(feature = "signing")]
fn preauth_secret(
    esk: &ed25519_dalek::hazmat::ExpandedSecretKey,
    encoding: &'static str,
    cleartext: &[u8],
    footer: &[u8],
) -> Signature {
    let vk = ed25519_dalek::VerifyingKey::from(esk);

    ed25519_dalek::hazmat::raw_sign_byupdate::<sha2::Sha512, _>(
        esk,
        |ctx| {
            pre_auth_encode(
                [
                    &[
                        "v2".as_bytes(),
                        encoding.as_bytes(),
                        Public::HEADER.as_bytes(),
                    ],
                    &[cleartext],
                    &[footer],
                ],
                PreAuthEncodeDigest(ctx),
            );
            Ok(())
        },
        &vk,
    )
    .expect("should not error")
}

#[cfg(feature = "signing")]
struct PreAuthEncodeDigest<'a, M: digest::Update>(pub &'a mut M);

#[cfg(feature = "signing")]
impl<M: digest::Update> paseto_core::pae::WriteBytes for PreAuthEncodeDigest<'_, M> {
    fn write(&mut self, slice: &[u8]) {
        self.0.update(slice);
    }
}
