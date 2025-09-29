use alloc::boxed::Box;
#[cfg(feature = "signing")]
use alloc::vec::Vec;

use ed25519_dalek::Signature;
use paseto_core::PasetoError;
use paseto_core::key::{KeyEncoding, KeyType};
use paseto_core::pae::{WriteBytes, pre_auth_encode};
use paseto_core::version::Public;
#[cfg(feature = "signing")]
use paseto_core::version::Secret;

#[cfg(feature = "signing")]
use super::{PreAuthEncodeDigest, SecretKey};
use super::{PublicKey, V4};

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

#[cfg(feature = "verifying")]
impl KeyEncoding for PublicKey {
    type Version = V4;
    type KeyType = Public;

    fn decode(bytes: &[u8]) -> Result<Self, PasetoError> {
        let key = bytes.try_into().map_err(|_| PasetoError::InvalidKey)?;
        ed25519_dalek::VerifyingKey::from_bytes(&key)
            .map(PublicKey)
            .map_err(|_| PasetoError::InvalidKey)
    }
    fn encode(&self) -> Box<[u8]> {
        self.0.as_bytes().to_vec().into_boxed_slice()
    }
}

#[cfg(feature = "signing")]
impl KeyEncoding for SecretKey {
    type Version = V4;
    type KeyType = Secret;

    fn decode(bytes: &[u8]) -> Result<Self, PasetoError> {
        let (secret_key, verifying_key) = bytes
            .split_first_chunk::<32>()
            .ok_or(PasetoError::InvalidKey)?;

        let esk = ed25519_dalek::hazmat::ExpandedSecretKey::from(secret_key);

        let verifying_key = PublicKey::decode(verifying_key)?;
        let pubkey = ed25519_dalek::VerifyingKey::from(&esk);

        if pubkey != verifying_key.0 {
            return Err(PasetoError::InvalidKey);
        }

        Ok(Self(*secret_key, esk))
    }

    fn encode(&self) -> Box<[u8]> {
        let pubkey = ed25519_dalek::VerifyingKey::from(&self.1);
        let mut bytes = Vec::with_capacity(64);
        bytes.extend_from_slice(&self.0);
        bytes.extend_from_slice(pubkey.as_bytes());
        bytes.into_boxed_slice()
    }
}

#[cfg(feature = "signing")]
impl paseto_core::version::SealingVersion<Public> for V4 {
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
        let signature = preauth_secret(&key.1, encoding, &payload, footer, aad);
        payload.extend_from_slice(&signature.to_bytes());
        Ok(payload)
    }
}

#[cfg(feature = "verifying")]
impl paseto_core::version::UnsealingVersion<Public> for V4 {
    fn unseal<'a>(
        key: &PublicKey,
        encoding: &'static str,
        payload: &'a mut [u8],
        footer: &[u8],
        aad: &[u8],
    ) -> Result<&'a [u8], PasetoError> {
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

        preauth_public(verifier, encoding, cleartext, footer, aad)
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
    aad: &[u8],
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
                "v4".as_bytes(),
                encoding.as_bytes(),
                Public::HEADER.as_bytes(),
            ],
            &[cleartext],
            &[footer],
            &[aad],
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
    aad: &[u8],
) -> Signature {
    let vk = ed25519_dalek::VerifyingKey::from(esk);

    ed25519_dalek::hazmat::raw_sign_byupdate::<sha2::Sha512, _>(
        esk,
        |ctx| {
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
                PreAuthEncodeDigest(ctx),
            );
            Ok(())
        },
        &vk,
    )
    .expect("should not error")
}
