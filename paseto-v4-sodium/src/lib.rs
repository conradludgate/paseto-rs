//! PASETO v4 (sodium)
//!
//!
//! ```
//! use paseto_v4_sodium::{SecretKey, PublicKey, SealingKey, SignedToken, VerifiedToken};
//! use paseto_json::{RegisteredClaims, jiff};
//! use rand::rngs::OsRng;
//!
//! // create a new keypair
//! let secret_key = SecretKey::random(&mut OsRng).unwrap();
//! let public_key = secret_key.unsealing_key();
//!
//! // create a set of token claims
//! let now = jiff::Timestamp::now();
//! let claims = RegisteredClaims {
//!     iss: Some("https://paseto.conrad.cafe/".to_string()),
//!     iat: Some(now),
//!     nbf: Some(now),
//!     exp: Some(now + std::time::Duration::from_secs(3600)),
//!     sub: Some("conradludgate".to_string()),
//!     ..RegisteredClaims::default()
//! };
//!
//! // create and sign a new token
//! let signed_token = VerifiedToken::new(claims).sign(&secret_key, &[], &mut OsRng).unwrap();
//!
//! // serialize the token.
//! let token = signed_token.to_string();
//!
//! // serialize the public key.
//! let key = public_key.to_string();
//!
//! // ...
//!
//! // parse the token
//! let signed_token: SignedToken<RegisteredClaims> = token.parse().unwrap();
//!
//! // parse the key
//! let public_key: PublicKey = key.parse().unwrap();
//!
//! // verify the token
//! let verified_token = signed_token.verify(&public_key, &[]).unwrap();
//!
//! // TODO: verify the claims
//! let now = jiff::Timestamp::now();
//! if let Some(exp) = verified_token.message.exp && exp < now {
//!     panic!("expired");
//! }
//! if let Some(nbf) = verified_token.message.nbf && now < nbf {
//!     panic!("not yet available");
//! }
//! ```

use core::fmt;

use libsodium_rs::crypto_stream::{self, xchacha20};
use libsodium_rs::utils::compare;
use libsodium_rs::{crypto_generichash, crypto_sign, ensure_init};
pub use paseto_core::PasetoError;
use paseto_core::key::KeyText;
pub use paseto_core::key::{Key, SealingKey, UnsealingKey};
use paseto_core::pae::{WriteBytes, pre_auth_encode};
use paseto_core::rand_core;
use paseto_core::version::{Local, Marker, Public, Secret};

#[derive(Clone)]
pub struct SecretKey(crypto_sign::SecretKey);

#[derive(Clone)]
pub struct PublicKey(crypto_sign::PublicKey);

#[derive(Clone)]
pub struct LocalKey([u8; 32]);

pub struct V4;
impl paseto_core::version::Version for V4 {
    const PASETO_HEADER: &'static str = "v4";
    const PASERK_HEADER: &'static str = "k4";

    type LocalKey = LocalKey;
    type PublicKey = PublicKey;
    type SecretKey = SecretKey;

    fn hash_key(key_header: &'static str, key_data: &[u8]) -> [u8; 33] {
        ensure_init().expect("failed to init libsodium");
        let mut ctx = crypto_generichash::State::new(None, 33).expect("hash size should be valid");
        ctx.update(Self::PASERK_HEADER.as_bytes());
        ctx.update(key_header.as_bytes());
        ctx.update(key_data);
        ctx.finalize().try_into().expect("hash should be 33 bytes")
    }
}

pub type SignedToken<M, F = ()> = paseto_core::tokens::SignedToken<V4, M, F>;
pub type EncryptedToken<M, F = ()> = paseto_core::tokens::EncryptedToken<V4, M, F>;
pub type VerifiedToken<M, F = ()> = paseto_core::tokens::VerifiedToken<V4, M, F>;
pub type DecryptedToken<M, F = ()> = paseto_core::tokens::DecryptedToken<V4, M, F>;

impl Key for LocalKey {
    type Version = V4;
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

impl core::str::FromStr for LocalKey {
    type Err = PasetoError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        KeyText::from_str(s).and_then(|k| k.decode())
    }
}

impl Key for PublicKey {
    type Version = V4;
    type KeyType = Public;

    fn decode(bytes: &[u8]) -> Result<Self, PasetoError> {
        crypto_sign::PublicKey::from_bytes(bytes)
            .map(Self)
            .map_err(|_| PasetoError::InvalidKey)
    }
    fn encode(&self) -> Box<[u8]> {
        self.0.as_bytes().to_vec().into_boxed_slice()
    }
}

impl fmt::Display for PublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        KeyText::from(self).fmt(f)
    }
}

impl core::str::FromStr for PublicKey {
    type Err = PasetoError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        KeyText::from_str(s).and_then(|k| k.decode())
    }
}

impl Key for SecretKey {
    type Version = V4;
    type KeyType = Secret;

    fn decode(bytes: &[u8]) -> Result<Self, PasetoError> {
        crypto_sign::SecretKey::from_bytes(bytes)
            .map(Self)
            .map_err(|_| PasetoError::InvalidKey)
    }

    fn encode(&self) -> Box<[u8]> {
        self.0.as_bytes().to_vec().into_boxed_slice()
    }
}

impl core::str::FromStr for SecretKey {
    type Err = PasetoError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        KeyText::from_str(s).and_then(|k| k.decode())
    }
}

impl LocalKey {
    fn keys(
        &self,
        nonce: &[u8; 32],
    ) -> (
        crypto_stream::Key,
        xchacha20::Nonce,
        crypto_generichash::State,
    ) {
        ensure_init().expect("failed to init libsodium");

        let ekn2 = kdf(&self.0, "paseto-encryption-key", nonce, 56);
        let ak = kdf(&self.0, "paseto-auth-key-for-aead", nonce, 32);

        let (ek, n2) = ekn2
            .split_last_chunk::<24>()
            .expect("kdf should output 56 bytes");
        let ek = crypto_stream::Key::from_slice(ek).expect("32 byte key should be valid");
        let n2 = xchacha20::Nonce::from_bytes(*n2);
        let mac = crypto_generichash::State::new(Some(&ak), 32).expect("invalid mac");

        (ek, n2, mac)
    }
}

impl SealingKey<Local> for LocalKey {
    type UnsealingKey = Self;
    fn unsealing_key(&self) -> Self::UnsealingKey {
        Self(self.0)
    }

    fn random(rng: &mut impl rand_core::TryCryptoRng) -> Result<Self, PasetoError> {
        let mut bytes = [0; 32];
        rng.try_fill_bytes(&mut bytes)
            .map_err(|_| PasetoError::CryptoError)?;
        Ok(Self(bytes))
    }

    fn nonce(rng: &mut impl rand_core::TryCryptoRng) -> Result<Vec<u8>, PasetoError> {
        let mut nonce = [0; 32];
        rng.try_fill_bytes(&mut nonce)
            .map_err(|_| PasetoError::CryptoError)?;

        let mut payload = Vec::with_capacity(64);
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
        let (nonce, plaintext) = payload
            .split_first_chunk::<32>()
            .ok_or(PasetoError::InvalidToken)?;
        let (ek, n2, mut mac) = self.keys(nonce);

        let ciphertext =
            xchacha20::stream_xor(plaintext, &n2, &ek).map_err(|_| PasetoError::CryptoError)?;

        preauth_local(&mut mac, encoding, nonce, &ciphertext, footer, aad);

        payload.truncate(32);
        payload.extend_from_slice(&ciphertext);
        payload.extend_from_slice(&mac.finalize());

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

        let (ciphertext, tag) = payload
            .split_last_chunk_mut::<32>()
            .ok_or(PasetoError::InvalidToken)?;
        let (nonce, ciphertext) = ciphertext
            .split_first_chunk_mut::<32>()
            .ok_or(PasetoError::InvalidToken)?;

        let (ek, n2, mut mac) = self.keys(nonce);

        preauth_local(&mut mac, encoding, nonce, ciphertext, footer, aad);
        if compare(&mac.finalize(), tag) != 0 {
            return Err(PasetoError::CryptoError);
        }

        let plaintext =
            xchacha20::stream_xor(ciphertext, &n2, &ek).map_err(|_| PasetoError::CryptoError)?;
        ciphertext.copy_from_slice(&plaintext);

        Ok(ciphertext)
    }
}

impl SealingKey<Public> for SecretKey {
    type UnsealingKey = PublicKey;
    fn unsealing_key(&self) -> Self::UnsealingKey {
        let public_key = self
            .0
            .as_bytes()
            .last_chunk()
            .expect("secret key ends with the public key");
        PublicKey(crypto_sign::PublicKey::from_bytes_exact(*public_key))
    }

    fn random(rng: &mut impl rand_core::TryCryptoRng) -> Result<Self, PasetoError> {
        let mut secret_key = [0; 32];
        loop {
            rng.try_fill_bytes(&mut secret_key)
                .map_err(|_| PasetoError::CryptoError)?;
            match crypto_sign::keypair_from_seed(&secret_key) {
                Ok(key) => break Ok(Self(key.secret_key)),
                Err(_) => continue,
            }
        }
    }

    fn nonce(_: &mut impl rand_core::TryCryptoRng) -> Result<Vec<u8>, PasetoError> {
        Ok(Vec::with_capacity(32))
    }

    fn seal(
        &self,
        encoding: &'static str,
        mut payload: Vec<u8>,
        footer: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, PasetoError> {
        ensure_init().expect("failed to init libsodium");
        let bytes = preauth_public(encoding, &payload, footer, aad);
        let sig =
            crypto_sign::sign_detached(&bytes, &self.0).map_err(|_| PasetoError::CryptoError)?;
        payload.extend_from_slice(&sig);
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
            .split_last_chunk::<64>()
            .ok_or(PasetoError::InvalidToken)?;
        let bytes = preauth_public(encoding, cleartext, footer, aad);
        if !crypto_sign::verify_detached(tag, &bytes, &self.0) {
            return Err(PasetoError::CryptoError);
        }

        Ok(cleartext)
    }
}

fn kdf(key: &[u8], sep: &'static str, nonce: &[u8], len: usize) -> Vec<u8> {
    let mut ctx =
        crypto_generichash::State::new(Some(key), len).expect("could not construct hasher");
    ctx.update(sep.as_bytes());
    ctx.update(nonce);
    ctx.finalize()
}

struct PreAuthEncodeDigest<'a>(pub &'a mut crypto_generichash::State);
impl<'a> WriteBytes for PreAuthEncodeDigest<'a> {
    fn write(&mut self, slice: &[u8]) {
        self.0.update(slice)
    }
}

fn preauth_local(
    mac: &mut crypto_generichash::State,
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

fn preauth_public(encoding: &'static str, cleartext: &[u8], footer: &[u8], aad: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
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
        &mut out,
    );
    out
}

impl LocalKey {
    /// Create a V4 local key from raw bytes
    pub fn from_bytes(key: [u8; 32]) -> Self {
        LocalKey(key)
    }

    /// Get the raw bytes from this key
    pub fn into_bytes(&self) -> [u8; 32] {
        self.0
    }
}
