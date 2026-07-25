use aws_lc_rs::digest::{self, Digest, SHA384};
use aws_lc_rs::rand::{SecureRandom, SystemRandom};
use paseto_core::PasetoError;
use paseto_core::key::HasKey;
use paseto_core::pae::{WriteBytes, pre_auth_encode};
use paseto_core::version::{Public, Secret};

use super::{PublicKey, SecretKey, V3};
use crate::lc::{SigningKey, VerifyingKey};

impl HasKey<Public> for V3 {
    type Key = PublicKey;

    fn decode(bytes: &[u8]) -> Result<PublicKey, PasetoError> {
        let pk = VerifyingKey::from_sec1_bytes(bytes)?;
        Ok(PublicKey(pk))
    }
    fn encode(key: &PublicKey) -> Box<[u8]> {
        key.0.compressed_pub_key().to_vec().into_boxed_slice()
    }
}

impl HasKey<Secret> for V3 {
    type Key = SecretKey;

    fn decode(bytes: &[u8]) -> Result<SecretKey, PasetoError> {
        if bytes.len() != 48 {
            return Err(PasetoError::InvalidKey);
        }
        SigningKey::from_sec1_bytes(bytes).map(SecretKey)
    }
    fn encode(key: &SecretKey) -> Box<[u8]> {
        key.0.encode().to_vec().into_boxed_slice()
    }
}

impl paseto_core::version::SealingVersion<Public> for V3 {
    fn unsealing_key(key: &SecretKey) -> PublicKey {
        PublicKey(key.0.verifying_key())
    }

    fn random() -> Result<SecretKey, PasetoError> {
        let mut bytes = [0; 48];
        let res = loop {
            if SystemRandom::new().fill(&mut bytes).is_err() {
                break Err(PasetoError::CryptoError);
            }

            let result = SigningKey::from_sec1_bytes(&bytes).map(SecretKey);

            match result {
                Err(PasetoError::InvalidKey) => {}
                res => break res,
            }
        };

        #[cfg(feature = "zeroize")]
        zeroize::Zeroize::zeroize(&mut bytes);

        res
    }

    fn nonce() -> Result<[u8; 0], PasetoError> {
        Ok([])
    }

    fn dangerous_seal_with_nonce(
        key: &SecretKey,
        encoding: &'static str,
        mut payload: Vec<u8>,
        footer: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, PasetoError> {
        let digest = preauth_public(&key.0.compressed_pub_key(), encoding, &payload, footer, aad);
        let signature = key.0.sign(&digest)?;
        payload.extend_from_slice(&signature);

        Ok(payload)
    }
}

impl paseto_core::version::UnsealingVersion<Public> for V3 {
    type Nonce = [u8; 0];
    type Tag = [u8; 96];

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
        let digest = preauth_public(
            &key.0.compressed_pub_key(),
            encoding,
            cleartext,
            footer,
            aad,
        );
        key.0.verify(&digest, tag)?;

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
