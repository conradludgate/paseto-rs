//! PASETO v4 (libsodium)
//!
//! ```
//! use paseto_v4_sodium::{SignedToken, VerifiedToken};
//! use paseto_v4_sodium::libsodium;
//! use paseto_v4_sodium::key::{SecretKey, PublicKey, SealingKey};
//! use paseto_json::{RegisteredClaims, jiff};
//! use rand::rngs::OsRng;
//!
//! // init libsodium
//! libsodium::ensure_init().expect("libsodium should initialise successfully");
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
//! let signed_token = VerifiedToken::new(claims).sign(&secret_key, &mut OsRng).unwrap();
//!
//! // serialize the token.
//! let token = signed_token.to_string();
//! // "v4.public.eyJpc3MiOiJodHRwczovL3Bhc2V0by5jb25yYWQuY2FmZS8iLCJzdWIiOiJjb25yYWRsdWRnYXRlIiwiYXVkIjpudWxsLCJleHAiOiIyMDI1LTA5LTIwVDEyOjAxOjEzLjcyMjQ3OVoiLCJuYmYiOiIyMDI1LTA5LTIwVDExOjAxOjEzLjcyMjQ3OVoiLCJpYXQiOiIyMDI1LTA5LTIwVDExOjAxOjEzLjcyMjQ3OVoiLCJqdGkiOm51bGx9N7O1CAXQpQ3rpxhq6xFZt32z27VSL8suiek38-5W4LRGr1tDmKcP0_xrlp5-kdE6o7B_K8KU-6Fwmu0hzrkiDQ"
//!
//! // serialize the public key.
//! let key = public_key.to_string();
//! // "k4.public.xRPdFzRvXY-H-6L3S2I3_TmdMKu6XwLKLSR10lZ-yfk"
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
//! let verified_token = signed_token.verify(&public_key).unwrap();
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

pub struct V4;
impl paseto_core::version::Version for V4 {
    const PASETO_HEADER: &'static str = "v4";
    const PASERK_HEADER: &'static str = "k4";

    type LocalKey = key::LocalKey;
    type PublicKey = key::PublicKey;
    type SecretKey = key::SecretKey;

    fn hash_key(key_header: &'static str, key_data: &[u8]) -> [u8; 33] {
        let mut ctx = libsodium_rs::crypto_generichash::State::new(None, 33)
            .expect("hash size should be valid");
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

pub use libsodium_rs as libsodium;

pub mod key {
    use core::fmt;

    use libsodium_rs::crypto_stream::{self, xchacha20};
    use libsodium_rs::utils::compare;
    use libsodium_rs::{crypto_generichash, crypto_sign};
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

    impl Key for LocalKey {
        type Version = crate::V4;
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
        type Version = crate::V4;
        type KeyType = Public;

        /// Decode a PEM encoded SEC1 Ed25519 Secret Key
        ///
        /// ```
        /// use paseto_v4_sodium::key::{PublicKey, Key};
        ///
        /// let public_key = "b7715bd661458d928654d3e832f53ff5c9480542e0e3d4c9b032c768c7ce6023";
        /// let public_key = hex::decode(&public_key).unwrap();
        ///
        /// let _key = PublicKey::decode(&public_key).unwrap();
        /// ```
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
        type Version = crate::V4;
        type KeyType = Secret;

        /// Decode an Ed25519 Secret Keypair
        ///
        /// ```
        /// use paseto_v4_sodium::key::{SecretKey, Key};
        ///
        /// let private_key = "407796f4bc4b8184e9fe0c54b336822d34823092ad873d87ba14c3efb9db8c1db7715bd661458d928654d3e832f53ff5c9480542e0e3d4c9b032c768c7ce6023";
        /// let private_key = hex::decode(&private_key).unwrap();
        ///
        /// let _key = SecretKey::decode(&private_key).unwrap();
        /// ```
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

            let plaintext = xchacha20::stream_xor(ciphertext, &n2, &ek)
                .map_err(|_| PasetoError::CryptoError)?;
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
            let bytes = preauth_public(encoding, &payload, footer, aad);
            let sig = crypto_sign::sign_detached(&bytes, &self.0)
                .map_err(|_| PasetoError::CryptoError)?;
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

    fn preauth_public(
        encoding: &'static str,
        cleartext: &[u8],
        footer: &[u8],
        aad: &[u8],
    ) -> Vec<u8> {
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
}
