use cipher::{ArrayLength, StreamCipher};
use generic_array::GenericArray;
use generic_array::sequence::Split;
use hmac::{Hmac, Mac};
use p384::U48;
use paseto_core::PasetoError;
use paseto_core::key::{KeyKind, SealingKey, UnsealingKey};
use paseto_core::pae::{WriteBytes, pre_auth_encode};
use paseto_core::version::{Local, Marker};
use sha2::Sha384;

use super::{LocalKey, V3};

impl KeyKind for LocalKey {
    type Version = V3;
    type KeyType = Local;

    fn decode(bytes: &[u8]) -> Result<Self, PasetoError> {
        bytes
            .try_into()
            .map(Self)
            .map_err(|_| PasetoError::InvalidKey)
    }
    fn encode(&self) -> Box<[u8]> {
        self.0.to_vec().into_boxed_slice()
    }
}

impl LocalKey {
    fn keys(&self, nonce: &[u8; 32]) -> (ctr::Ctr64BE<aes::Aes256>, hmac::Hmac<sha2::Sha384>) {
        use cipher::KeyIvInit;
        use digest::Mac;

        let (ek, n2) = kdf::<U48>(&self.0, "paseto-encryption-key", nonce).split();
        let ak: GenericArray<u8, U48> = kdf(&self.0, "paseto-auth-key-for-aead", nonce);

        let cipher = ctr::Ctr64BE::<aes::Aes256>::new(&ek, &n2);
        let mac = hmac::Hmac::new_from_slice(&ak).expect("key should be valid");
        (cipher, mac)
    }
}

impl SealingKey<Local> for LocalKey {
    fn unsealing_key(&self) -> Self {
        Self(self.0)
    }

    fn random() -> Result<Self, PasetoError> {
        let mut bytes = [0; 32];
        getrandom::fill(&mut bytes).map_err(|_| PasetoError::CryptoError)?;
        Ok(Self(bytes))
    }

    fn nonce() -> Result<Vec<u8>, PasetoError> {
        let mut nonce = [0; 32];
        getrandom::fill(&mut nonce).map_err(|_| PasetoError::CryptoError)?;

        let mut payload = Vec::with_capacity(80);
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
        let (nonce, ciphertext) = payload
            .split_first_chunk_mut::<32>()
            .ok_or(PasetoError::InvalidToken)?;

        let (mut cipher, mac) = self.keys(nonce);
        cipher.apply_keystream(ciphertext);
        let mac = preauth_local(mac, encoding, nonce, ciphertext, footer, aad);
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
        if len < 80 {
            return Err(PasetoError::InvalidToken);
        }

        let (ciphertext, tag) = payload
            .split_last_chunk_mut::<48>()
            .ok_or(PasetoError::InvalidToken)?;
        let (nonce, ciphertext) = ciphertext
            .split_first_chunk_mut::<32>()
            .ok_or(PasetoError::InvalidToken)?;

        let (mut cipher, mac) = self.keys(nonce);
        let mac = preauth_local(mac, encoding, nonce, ciphertext, footer, aad);
        mac.verify_slice(tag)
            .map_err(|_| PasetoError::CryptoError)?;
        cipher.apply_keystream(ciphertext);

        Ok(ciphertext)
    }
}
fn kdf<O>(key: &[u8], sep: &'static str, nonce: &[u8]) -> GenericArray<u8, O>
where
    O: ArrayLength<u8>,
{
    let mut output = GenericArray::<u8, O>::default();
    hkdf::Hkdf::<sha2::Sha384>::new(None, key)
        .expand_multi_info(&[sep.as_bytes(), nonce], &mut output)
        .unwrap();
    output
}
fn preauth_local(
    mac: Hmac<Sha384>,
    encoding: &'static str,
    nonce: &[u8],
    ciphertext: &[u8],
    footer: &[u8],
    aad: &[u8],
) -> Hmac<Sha384> {
    struct Context(Hmac<Sha384>);
    impl WriteBytes for Context {
        fn write(&mut self, slice: &[u8]) {
            self.0.update(slice)
        }
    }

    let mut ctx = Context(mac);

    pre_auth_encode(
        [
            &[
                "v3".as_bytes(),
                encoding.as_bytes(),
                Local::HEADER.as_bytes(),
            ],
            &[nonce],
            &[ciphertext],
            &[footer],
            &[aad],
        ],
        &mut ctx,
    );

    ctx.0
}
