use generic_array::GenericArray;
use p384::ecdsa::signature::{DigestSigner, DigestVerifier};
use p384::ecdsa::{Signature, SigningKey, VerifyingKey};
use paseto_core::PasetoError;
use paseto_core::key::{KeyKind, SealingKey, UnsealingKey};
use paseto_core::pae::{WriteBytes, pre_auth_encode};
use paseto_core::version::{Marker, Public, Secret};
use sha2::{Digest, Sha384};

use super::{PublicKey, SecretKey, V3};

impl KeyKind for PublicKey {
    type Version = V3;
    type KeyType = Public;

    fn decode(bytes: &[u8]) -> Result<Self, PasetoError> {
        VerifyingKey::from_sec1_bytes(bytes)
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

impl KeyKind for SecretKey {
    type Version = V3;
    type KeyType = Secret;

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

impl SealingKey<Public> for SecretKey {
    fn unsealing_key(&self) -> PublicKey {
        PublicKey(*self.0.verifying_key())
    }

    fn random() -> Result<Self, PasetoError> {
        let mut bytes = GenericArray::default();
        loop {
            getrandom::fill(&mut bytes).map_err(|_| PasetoError::CryptoError)?;
            match SigningKey::from_bytes(&bytes).map(Self) {
                Err(_) => continue,
                Ok(key) => break Ok(key),
            }
        }
    }

    fn nonce() -> Result<Vec<u8>, PasetoError> {
        Ok(Vec::with_capacity(96))
    }

    fn dangerous_seal_with_nonce(
        &self,
        encoding: &'static str,
        mut payload: Vec<u8>,
        footer: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, PasetoError> {
        let digest = preauth_public(self.0.verifying_key(), encoding, &payload, footer, aad);
        let signature: Signature = self.0.sign_digest(digest);
        let signature = signature.normalize_s().unwrap_or(signature);

        payload.extend_from_slice(&signature.to_bytes());

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
            .split_last_chunk::<96>()
            .ok_or(PasetoError::InvalidToken)?;

        let signature =
            Signature::from_bytes(tag[..].into()).map_err(|_| PasetoError::InvalidToken)?;
        let digest = preauth_public(&self.0, encoding, cleartext, footer, aad);
        DigestVerifier::<Sha384, Signature>::verify_digest(&self.0, digest, &signature)
            .map_err(|_| PasetoError::CryptoError)?;

        Ok(cleartext)
    }
}

fn preauth_public(
    key: &VerifyingKey,
    encoding: &'static str,
    cleartext: &[u8],
    footer: &[u8],
    aad: &[u8],
) -> Sha384 {
    struct Context(Sha384);
    impl WriteBytes for Context {
        fn write(&mut self, slice: &[u8]) {
            self.0.update(slice)
        }
    }

    let key = key.to_encoded_point(true);

    let mut ctx = Context(Sha384::new());
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
