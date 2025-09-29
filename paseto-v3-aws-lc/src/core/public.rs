use aws_lc_rs::digest::{self, Digest, SHA384};
use aws_lc_rs::rand::{SecureRandom, SystemRandom};
use paseto_core::PasetoError;
use paseto_core::key::KeyEncoding;
use paseto_core::pae::{WriteBytes, pre_auth_encode};
use paseto_core::version::{Public, Secret};

use super::{PublicKey, SecretKey, V3};
use crate::lc::{Signature, SigningKey, VerifyingKey};

impl KeyEncoding for PublicKey {
    type Version = V3;
    type KeyType = Public;

    fn decode(bytes: &[u8]) -> Result<Self, PasetoError> {
        let pk = VerifyingKey::from_sec1_bytes(bytes)?;
        Ok(PublicKey(pk))
    }
    fn encode(&self) -> Box<[u8]> {
        self.0.compressed_pub_key().to_vec().into_boxed_slice()
    }
}

impl KeyEncoding for SecretKey {
    type Version = V3;
    type KeyType = Secret;

    fn decode(bytes: &[u8]) -> Result<Self, PasetoError> {
        if bytes.len() != 48 {
            return Err(PasetoError::InvalidKey);
        }
        SigningKey::from_sec1_bytes(bytes).map(Self)
    }
    fn encode(&self) -> Box<[u8]> {
        self.0.encode().to_vec().into_boxed_slice()
    }
}

impl SecretKey {
    pub(crate) fn random() -> Result<Self, PasetoError> {
        let mut bytes = [0; 48];
        loop {
            SystemRandom::new()
                .fill(&mut bytes)
                .map_err(|_| PasetoError::CryptoError)?;
            match SigningKey::from_sec1_bytes(&bytes).map(Self) {
                Err(PasetoError::InvalidKey) => {}
                res => break res,
            }
        }
    }
}

impl paseto_core::version::SealingVersion<Public> for V3 {
    fn unsealing_key(key: &SecretKey) -> PublicKey {
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
        let digest = preauth_public(&key.0.compressed_pub_key(), encoding, &payload, footer, aad);
        let signature = key.0.sign(digest.as_ref())?;
        signature.append_to_vec(&mut payload)?;

        Ok(payload)
    }
}

impl paseto_core::version::UnsealingVersion<Public> for V3 {
    fn unseal<'a>(
        key: &PublicKey,
        encoding: &'static str,
        payload: &'a mut [u8],
        footer: &[u8],
        aad: &[u8],
    ) -> Result<&'a [u8], PasetoError> {
        let len = payload.len();
        if len < 96 {
            return Err(PasetoError::InvalidToken);
        }

        let (cleartext, tag) = payload.split_at(len - 96);
        let signature = Signature::from_bytes(tag).map_err(|_| PasetoError::InvalidToken)?;
        let digest = preauth_public(
            &key.0.compressed_pub_key(),
            encoding,
            cleartext,
            footer,
            aad,
        );
        key.0
            .verify(digest.as_ref(), &signature)
            .map_err(|_| PasetoError::CryptoError)?;

        Ok(cleartext)
    }
}

fn preauth_public(
    key: &[u8; 49],
    encoding: &'static str,
    cleartext: &[u8],
    footer: &[u8],
    aad: &[u8],
) -> Digest {
    use paseto_core::key::KeyType;
    struct Context(digest::Context);
    impl WriteBytes for Context {
        fn write(&mut self, slice: &[u8]) {
            self.0.update(slice);
        }
    }

    let mut ctx = Context(digest::Context::new(&SHA384));
    pre_auth_encode(
        [
            &[key],
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
    ctx.0.finish()
}
