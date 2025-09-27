use blake2::Blake2bMac;
use chacha20::XChaCha20;
use cipher::{ArrayLength, StreamCipher};
use digest::Mac;
use digest::consts::{U32, U56, U64};
use digest::typenum::{IsLessOrEqual, LeEq, NonZero};
use generic_array::GenericArray;
use generic_array::sequence::Split;
use paseto_core::PasetoError;
use paseto_core::key::{KeyKind, SealingKey, UnsealingKey};
use paseto_core::pae::pre_auth_encode;
use paseto_core::version::{Local, Marker};

use super::{LocalKey, PreAuthEncodeDigest, V4};

impl KeyKind for LocalKey {
    type Version = V4;
    type KeyType = Local;

    fn decode(bytes: &[u8]) -> Result<Self, PasetoError> {
        if bytes.len() != 32 {
            return Err(PasetoError::InvalidKey);
        }
        Ok(Self(*GenericArray::from_slice(bytes)))
    }
    fn encode(&self) -> Box<[u8]> {
        self.0.to_vec().into_boxed_slice()
    }
}

impl LocalKey {
    fn keys(&self, nonce: &GenericArray<u8, U32>) -> (XChaCha20, Blake2bMac<U32>) {
        use cipher::KeyIvInit;
        use digest::Mac;

        let (ek, n2) = kdf::<U56>(&self.0, "paseto-encryption-key", nonce).split();
        let ak: GenericArray<u8, U32> = kdf(&self.0, "paseto-auth-key-for-aead", nonce);

        let cipher = XChaCha20::new(&ek, &n2);
        let mac = blake2::Blake2bMac::new_from_slice(&ak).expect("key should be valid");
        (cipher, mac)
    }
}

impl SealingKey<Local> for LocalKey {
    fn unsealing_key(&self) -> LocalKey {
        Self(self.0)
    }

    fn random() -> Result<Self, PasetoError> {
        let mut bytes = [0; 32];
        getrandom::fill(&mut bytes).map_err(|_| PasetoError::CryptoError)?;
        Ok(Self(bytes.into()))
    }

    fn nonce() -> Result<Vec<u8>, PasetoError> {
        let mut nonce = [0; 32];
        getrandom::fill(&mut nonce).map_err(|_| PasetoError::CryptoError)?;

        let mut payload = Vec::with_capacity(64);
        payload.extend_from_slice(&nonce);
        Ok(payload)
    }

    fn dangerous_seal_with_nonce(
        &self,
        encoding: &'static str,
        mut payload: Vec<u8>,
        footer: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, PasetoError> {
        let (nonce, ciphertext) = payload.split_at_mut(32);
        let nonce: &[u8] = nonce;

        let (mut cipher, mut mac) = self.keys(nonce.into());
        cipher.apply_keystream(ciphertext);
        preauth_local(&mut mac, encoding, nonce, ciphertext, footer, aad);
        payload.extend_from_slice(&mac.finalize().into_bytes());

        Ok(payload)
    }
}

impl UnsealingKey<Local> for LocalKey {
    fn unseal<'a>(
        &self,
        encoding: &'static str,
        payload: &'a mut [u8],
        footer: &[u8],
        aad: &[u8],
    ) -> Result<&'a [u8], PasetoError> {
        let len = payload.len();
        if len < 64 {
            return Err(PasetoError::InvalidToken);
        }

        let (ciphertext, tag) = payload.split_at_mut(len - 32);
        let (nonce, ciphertext) = ciphertext.split_at_mut(32);
        let nonce: &[u8] = nonce;

        let (mut cipher, mut mac) = self.keys(nonce.into());
        preauth_local(&mut mac, encoding, nonce, ciphertext, footer, aad);
        mac.verify_slice(tag)
            .map_err(|_| PasetoError::CryptoError)?;
        cipher.apply_keystream(ciphertext);

        Ok(ciphertext)
    }
}

fn kdf<O>(key: &[u8], sep: &'static str, nonce: &[u8]) -> GenericArray<u8, O>
where
    O: ArrayLength<u8> + IsLessOrEqual<U64>,
    LeEq<O, U64>: NonZero,
{
    use digest::Mac;

    let mut mac = blake2::Blake2bMac::<O>::new_from_slice(key).expect("key should be valid");
    mac.update(sep.as_bytes());
    mac.update(nonce);
    mac.finalize().into_bytes()
}

fn preauth_local(
    mac: &mut blake2::Blake2bMac<U32>,
    encoding: &'static str,
    nonce: &[u8],
    ciphertext: &[u8],
    footer: &[u8],
    aad: &[u8],
) {
    pre_auth_encode(
        [
            &[
                "v4".as_bytes(),
                encoding.as_bytes(),
                Local::HEADER.as_bytes(),
            ],
            &[nonce],
            &[ciphertext],
            &[footer],
            &[aad],
        ],
        PreAuthEncodeDigest(mac),
    )
}
