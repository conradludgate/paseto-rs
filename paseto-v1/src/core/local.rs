use alloc::boxed::Box;
#[cfg(feature = "encrypting")]
use alloc::vec::Vec;

use cipher::StreamCipher;
use generic_array::GenericArray;
use generic_array::sequence::Split;
use generic_array::typenum::{U16, U32};
use hmac::Mac;
use paseto_core::PasetoError;
use paseto_core::key::HasKey;
use paseto_core::pae::{WriteBytes, pre_auth_encode};
use paseto_core::version::Local;

use super::{LocalKey, V1};

impl LocalKey {
    pub fn as_raw_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn from_raw_bytes(b: [u8; 32]) -> Self {
        Self(b)
    }
}

impl HasKey<Local> for V1 {
    type Key = LocalKey;

    fn decode(bytes: &[u8]) -> Result<LocalKey, PasetoError> {
        bytes
            .try_into()
            .map(LocalKey)
            .map_err(|_| PasetoError::InvalidKey)
    }
    fn encode(key: &LocalKey) -> Box<[u8]> {
        key.0.to_vec().into_boxed_slice()
    }
}

impl LocalKey {
    fn keys(&self, nonce: &[u8; 32]) -> (ctr::Ctr64BE<aes::Aes256>, hmac::Hmac<sha2::Sha384>) {
        use cipher::KeyIvInit;
        use digest::Mac;

        let nonce: &GenericArray<u8, U32> = nonce.into();
        let (n1, n2) = nonce.split();

        let ek = kdf(&self.0, b"paseto-encryption-key", n1);
        let ak = kdf(&self.0, b"paseto-auth-key-for-aead", n1);

        let cipher = ctr::Ctr64BE::<aes::Aes256>::new(&ek, n2);
        let mac = hmac::Hmac::new_from_slice(&ak).expect("key should be valid");
        (cipher, mac)
    }
}

#[cfg(feature = "encrypting")]
impl paseto_core::version::SealingVersion<Local> for V1 {
    fn unsealing_key(key: &LocalKey) -> LocalKey {
        LocalKey(key.0)
    }

    fn random() -> Result<LocalKey, PasetoError> {
        let mut bytes = [0; 32];
        getrandom::fill(&mut bytes).map_err(|_| PasetoError::CryptoError)?;
        Ok(LocalKey(bytes))
    }

    fn nonce() -> Result<Vec<u8>, PasetoError> {
        let mut nonce = [0; 32];
        getrandom::fill(&mut nonce).map_err(|_| PasetoError::CryptoError)?;

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
        if !aad.is_empty() {
            return Err(PasetoError::ClaimsError);
        }

        let (nonce, ciphertext) = payload
            .split_first_chunk_mut::<32>()
            .ok_or(PasetoError::InvalidToken)?;

        let mut n: hmac::Hmac<sha2::Sha384> =
            digest::Mac::new_from_slice(nonce).expect("all sized keys are valid with hmac");
        n.update(ciphertext);
        *nonce = n.finalize().into_bytes()[0..32]
            .try_into()
            .expect("nonce is 32 bytes");

        let (mut cipher, mut mac) = key.keys(nonce);
        cipher.apply_keystream(ciphertext);
        preauth_local(&mut mac, encoding, nonce, ciphertext, footer);
        payload.extend_from_slice(&mac.finalize().into_bytes());

        Ok(payload)
    }
}

#[cfg(feature = "decrypting")]
impl paseto_core::version::UnsealingVersion<Local> for V1 {
    fn unseal<'a>(
        key: &LocalKey,
        encoding: &'static str,
        payload: &'a mut [u8],
        footer: &[u8],
        aad: &[u8],
    ) -> Result<&'a [u8], PasetoError> {
        if !aad.is_empty() {
            return Err(PasetoError::ClaimsError);
        }

        let len = payload.len();
        if len < 80 {
            return Err(PasetoError::InvalidToken);
        }

        let (ciphertext, tag) = payload
            .split_last_chunk_mut::<48>()
            .ok_or(PasetoError::InvalidToken)?;
        let (nonce, ciphertext) = ciphertext
            .split_first_chunk_mut::<32>()
            .ok_or(PasetoError::InvalidToken)?;

        let (mut cipher, mut mac) = key.keys(nonce);
        preauth_local(&mut mac, encoding, nonce, ciphertext, footer);
        mac.verify_slice(tag)
            .map_err(|_| PasetoError::CryptoError)?;
        cipher.apply_keystream(ciphertext);

        Ok(ciphertext)
    }
}

fn kdf(key: &[u8], sep: &'static [u8], nonce: &GenericArray<u8, U16>) -> GenericArray<u8, U32> {
    let mut output = GenericArray::<u8, U32>::default();
    hkdf::Hkdf::<sha2::Sha384>::new(Some(nonce), key)
        .expand(sep, &mut output)
        .unwrap();
    output
}

fn preauth_local(
    mac: &mut hmac::Hmac<sha2::Sha384>,
    encoding: &'static str,
    nonce: &[u8],
    ciphertext: &[u8],
    footer: &[u8],
) {
    use paseto_core::key::KeyType;
    struct Context<'a>(&'a mut hmac::Hmac<sha2::Sha384>);
    impl WriteBytes for Context<'_> {
        fn write(&mut self, slice: &[u8]) {
            self.0.update(slice);
        }
    }

    pre_auth_encode(
        [
            &[
                "v1".as_bytes(),
                encoding.as_bytes(),
                Local::HEADER.as_bytes(),
            ],
            &[nonce],
            &[ciphertext],
            &[footer],
        ],
        Context(mac),
    );
}
