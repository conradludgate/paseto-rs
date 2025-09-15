mod pae;

use cipher::{ArrayLength, StreamCipher};
use digest::{
    Mac,
    consts::{U32, U48},
};
use generic_array::{GenericArray, sequence::Split};
use p384::ecdsa::signature::{DigestSigner, DigestVerifier};
use paseto_core::{
    PasetoError,
    version::{Local, Public, Purpose, SealingKey, UnsealingKey},
};

pub struct SecretKey(p384::ecdsa::SigningKey);
pub struct PublicKey(p384::ecdsa::VerifyingKey);
pub struct LocalKey(GenericArray<u8, U32>);

pub struct V3;
impl paseto_core::version::Version for V3 {
    const PASETO_HEADER: &'static str = "v3";
    const PASERK_HEADER: &'static str = "k3";

    type LocalKey = LocalKey;
    type PublicKey = PublicKey;
    type SecretKey = SecretKey;
}

pub type SignedToken<M, F = ()> = paseto_core::tokens::SignedToken<V3, M, F>;
pub type EncryptedToken<M, F = ()> = paseto_core::tokens::EncryptedToken<V3, M, F>;
pub type VerifiedToken<M, F = ()> = paseto_core::tokens::VerifiedToken<V3, M, F>;
pub type DecryptedToken<M, F = ()> = paseto_core::tokens::DecryptedToken<V3, M, F>;

impl LocalKey {
    fn keys(
        &self,
        nonce: &GenericArray<u8, U32>,
    ) -> (ctr::Ctr64BE<aes::Aes256>, hmac::Hmac<sha2::Sha384>) {
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
    fn nonce(mut rng: impl rand::TryCryptoRng) -> Result<Vec<u8>, PasetoError> {
        let mut nonce = [0; 32];
        rng.try_fill_bytes(&mut nonce)
            .map_err(|_| PasetoError::CryptoError)?;

        let mut payload = Vec::with_capacity(80);
        payload.extend_from_slice(&nonce);
        Ok(payload)
    }

    fn seal(
        &self,
        encoding: &'static str,
        mut payload: Vec<u8>,
        footer: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, PasetoError> {
        let (nonce, ciphertext) = payload.split_at_mut(32);
        let nonce: &[u8] = nonce;

        let (mut cipher, mac) = self.keys(nonce.into());
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

        let (ciphertext, tag) = payload.split_at_mut(len - 48);
        let (nonce, ciphertext) = ciphertext.split_at_mut(32);
        let nonce: &[u8] = nonce;

        let (mut cipher, mac) = self.keys(nonce.into());
        let mac = preauth_local(mac, encoding, nonce, ciphertext, footer, aad);
        mac.verify_slice(tag)
            .map_err(|_| PasetoError::CryptoError)?;
        cipher.apply_keystream(ciphertext);

        Ok(ciphertext)
    }
}

impl SealingKey<Public> for SecretKey {
    fn nonce(_: impl rand::TryCryptoRng) -> Result<Vec<u8>, PasetoError> {
        Ok(Vec::with_capacity(96))
    }

    fn seal(
        &self,
        encoding: &'static str,
        mut payload: Vec<u8>,
        footer: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, PasetoError> {
        let digest = preauth_public(self.0.verifying_key(), encoding, &payload, footer, aad);
        let signature: p384::ecdsa::Signature = self.0.sign_digest(digest);
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
        let len = payload.len();
        if len < 96 {
            return Err(PasetoError::InvalidToken);
        }

        let (cleartext, tag) = payload.split_at(len - 96);
        let signature = p384::ecdsa::Signature::from_bytes(tag.into())
            .map_err(|_| PasetoError::InvalidToken)?;
        let digest = preauth_public(&self.0, encoding, cleartext, footer, aad);
        self.0
            .verify_digest(digest, &signature)
            .map_err(|_| PasetoError::CryptoError)?;

        Ok(cleartext)
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
    mac: hmac::Hmac<sha2::Sha384>,
    encoding: &'static str,
    nonce: &[u8],
    ciphertext: &[u8],
    footer: &[u8],
    aad: &[u8],
) -> hmac::Hmac<sha2::Sha384> {
    pae::pae(
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
        pae::Digest(mac),
    )
    .0
}

fn preauth_public(
    key: &p384::ecdsa::VerifyingKey,
    encoding: &'static str,
    cleartext: &[u8],
    footer: &[u8],
    aad: &[u8],
) -> sha2::Sha384 {
    let key = key.to_encoded_point(true);

    pae::pae(
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
        pae::Digest(sha2::Sha384::default()),
    )
    .0
}

impl SecretKey {
    /// Decode a PEM encoded SEC1 p384 Secret Key
    ///
    /// ```
    /// use paseto_v3::SecretKey;
    ///
    /// let private_key = "-----BEGIN EC PRIVATE KEY-----
    /// MIGkAgEBBDAhUb6WGhABE1MTj0x7E/5acgyap23kh7hUAVoAavKyfhYcmI3n1Q7L
    /// JpHxNb792H6gBwYFK4EEACKhZANiAAT5H7mTSOyjfILDtSuavZfalI3doM8pRUlb
    /// TzNyYLqM9iVmajpc0JRXvKuBtGtYi7Yft+eqFr6BuzGrdb4Z1vkvRcI504m0qKiE
    /// zjhi6u4sNgzW23rrVkRYkb2oE3SJPko=
    /// -----END EC PRIVATE KEY-----";
    ///
    /// let _key = SecretKey::from_sec1_pem(private_key).unwrap();
    /// ```
    pub fn from_sec1_pem(s: &str) -> Result<Self, PasetoError> {
        let sk = p384::SecretKey::from_sec1_pem(s).map_err(|_| PasetoError::InvalidKey)?;
        Ok(Self(sk.into()))
    }

    /// Decode a secret key from raw bytes
    pub fn from_bytes(s: &[u8]) -> Result<Self, PasetoError> {
        let sk = p384::SecretKey::from_slice(s).map_err(|_| PasetoError::InvalidKey)?;
        Ok(Self(sk.into()))
    }

    /// Get the corresponding V3 public key for this V3 secret key
    pub fn public_key(&self) -> PublicKey {
        PublicKey(*self.0.verifying_key())
    }
}

impl PublicKey {
    /// Decode a PEM encoded p384 Public Key
    ///
    /// ```
    /// use paseto_v3::PublicKey;
    ///
    /// let public_key = "-----BEGIN PUBLIC KEY-----
    /// MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAE+R+5k0jso3yCw7Urmr2X2pSN3aDPKUVJ
    /// W08zcmC6jPYlZmo6XNCUV7yrgbRrWIu2H7fnqha+gbsxq3W+Gdb5L0XCOdOJtKio
    /// hM44YuruLDYM1tt661ZEWJG9qBN0iT5K
    /// -----END PUBLIC KEY-----";
    ///
    /// let _key = PublicKey::from_public_key_pem(public_key).unwrap();
    /// ```
    pub fn from_public_key_pem(s: &str) -> Result<Self, PasetoError> {
        use p384::pkcs8::DecodePublicKey;
        let pk = p384::PublicKey::from_public_key_pem(s).map_err(|_| PasetoError::InvalidKey)?;
        Ok(Self(pk.into()))
    }

    /// Decode a public key from raw bytes
    pub fn from_sec1_bytes(s: &[u8]) -> Result<Self, PasetoError> {
        let pk = p384::PublicKey::from_sec1_bytes(s).map_err(|_| PasetoError::InvalidKey)?;
        Ok(Self(pk.into()))
    }
}

impl LocalKey {
    /// Create a V4 local key from raw bytes
    pub fn from_bytes(key: [u8; 32]) -> Self {
        LocalKey(key.into())
    }

    /// Get the raw bytes from this key
    pub fn into_bytes(&self) -> [u8; 32] {
        self.0.into()
    }
}
