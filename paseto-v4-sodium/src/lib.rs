//! PASETO v4 (libsodium)
//!
//! ```
//! use paseto_v4_sodium::{SignedToken, VerifiedToken, SecretKey, PublicKey};
//! use paseto_v4_sodium::libsodium;
//! use paseto_json::{RegisteredClaims, Time, MustExpire, FromIssuer, ForSubject, Validate};
//! use std::time::Duration;
//!
//! // init libsodium
//! libsodium::ensure_init().expect("libsodium should initialise successfully");
//!
//! // create a new keypair
//! let secret_key = SecretKey::random().unwrap();
//! let public_key = secret_key.public_key();
//!
//! // create a set of token claims
//! let claims = RegisteredClaims::now(Duration::from_secs(3600))
//!     .from_issuer("https://paseto.conrad.cafe/".to_string())
//!     .for_subject("conradludgate".to_string());
//!
//! // create and sign a new token
//! let signed_token = VerifiedToken::new(claims).sign(&secret_key).unwrap();
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
//! // verify the token signature and validate the claims.
//! let validation = Time::now()
//!     .then(MustExpire)
//!     .then(FromIssuer("https://paseto.conrad.cafe/"))
//!     .then(ForSubject("conradludgate"));
//! let verified_token = signed_token.verify(&public_key, &validation).unwrap();
//! ```

pub use paseto_core::PasetoError;

pub struct V4;
impl paseto_core::version::Version for V4 {
    const HEADER: &'static str = "v4";

    type LocalKey = key::LocalKey;
    type PublicKey = key::PublicKey;
    type SecretKey = key::SecretKey;
}

impl paseto_core::version::PaserkVersion for V4 {
    const PASERK_HEADER: &'static str = "k4";

    fn hash_key(key_header: &'static str, key_data: &[u8]) -> [u8; 33] {
        let mut ctx = libsodium_rs::crypto_generichash::State::new(None, 33)
            .expect("hash size should be valid");
        ctx.update(Self::PASERK_HEADER.as_bytes());
        ctx.update(key_header.as_bytes());
        ctx.update(key_data);
        ctx.finalize().try_into().expect("hash should be 33 bytes")
    }

    fn seal_key(
        sealing_key: &key::PublicKey,
        key: key::LocalKey,
    ) -> Result<Box<[u8]>, PasetoError> {
        key::seal_key(sealing_key, key)
    }

    fn unseal_key(
        sealing_key: &key::SecretKey,
        key_data: Box<[u8]>,
    ) -> Result<key::LocalKey, PasetoError> {
        key::unseal_key(sealing_key, &key_data)
    }
}

/// A token with publically readable data, but not yet verified
pub type SignedToken<M, F = ()> = paseto_core::SignedToken<V4, M, F>;
/// A token with secret data
pub type EncryptedToken<M, F = ()> = paseto_core::EncryptedToken<V4, M, F>;
/// A [`SignedToken`] that has been verified
pub type VerifiedToken<M, F = ()> = paseto_core::VerifiedToken<V4, M, F>;
/// An [`EncryptedToken`] that has been decrypted
pub type DecryptedToken<M, F = ()> = paseto_core::DecryptedToken<V4, M, F>;

pub type LocalKey = paseto_core::LocalKey<V4>;
pub type PublicKey = paseto_core::PublicKey<V4>;
pub type SecretKey = paseto_core::SecretKey<V4>;
pub type KeyId<K> = paseto_core::key::KeyId<V4, K>;
pub type KeyText<K> = paseto_core::key::KeyText<V4, K>;
pub type SealedKey = paseto_core::key::SealedKey<V4>;

pub use libsodium_rs as libsodium;

pub mod key {

    use libsodium_rs::crypto_stream::{self, xchacha20};
    use libsodium_rs::utils::compare;
    use libsodium_rs::{crypto_generichash, crypto_sign, random};
    use paseto_core::PasetoError;
    use paseto_core::key::{KeyKind, SealingKey, UnsealingKey};
    use paseto_core::pae::{WriteBytes, pre_auth_encode};
    use paseto_core::version::{Local, Marker, Public, Secret};

    #[derive(Clone)]
    pub struct SecretKey(crypto_sign::SecretKey);

    #[derive(Clone)]
    pub struct PublicKey(crypto_sign::PublicKey);

    #[derive(Clone)]
    pub struct LocalKey([u8; 32]);

    impl KeyKind for LocalKey {
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

    impl KeyKind for PublicKey {
        type Version = crate::V4;
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

    impl KeyKind for SecretKey {
        type Version = crate::V4;
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
        fn unsealing_key(&self) -> LocalKey {
            Self(self.0)
        }

        fn random() -> Result<Self, PasetoError> {
            let mut bytes = [0; 32];
            random::fill_bytes(&mut bytes);
            Ok(Self(bytes))
        }

        fn nonce() -> Result<Vec<u8>, PasetoError> {
            Ok(random::bytes(32))
        }

        fn dangerous_seal_with_nonce(
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
        fn unsealing_key(&self) -> PublicKey {
            let public_key = self
                .0
                .as_bytes()
                .last_chunk()
                .expect("secret key ends with the public key");
            PublicKey(crypto_sign::PublicKey::from_bytes_exact(*public_key))
        }

        fn random() -> Result<Self, PasetoError> {
            let mut secret_key = [0; 32];
            loop {
                random::fill_bytes(&mut secret_key);
                match crypto_sign::keypair_from_seed(&secret_key) {
                    Ok(key) => break Ok(Self(key.secret_key)),
                    Err(_) => continue,
                }
            }
        }

        fn nonce() -> Result<Vec<u8>, PasetoError> {
            Ok(Vec::with_capacity(32))
        }

        fn dangerous_seal_with_nonce(
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

    pub(super) fn seal_key(
        sealing_key: &PublicKey,
        key: LocalKey,
    ) -> Result<Box<[u8]>, PasetoError> {
        use libsodium_rs::crypto_box;
        use libsodium_rs::crypto_scalarmult::curve25519;

        // Given a plaintext data key (pdk), and an Ed25519 public key (pk).
        let xpk = crypto_sign::ed25519_pk_to_curve25519(&sealing_key.0)
            .map_err(|_| PasetoError::CryptoError)?;

        let (epk, esk) = crypto_box::KeyPair::generate().into_tuple();

        // diffie hellman exchange
        let xk =
            curve25519::scalarmult(esk.as_bytes(), &xpk).map_err(|_| PasetoError::CryptoError)?;

        let mut ek = crypto_generichash::State::new(None, 32).unwrap();
        ek.update(b"\x01k4.seal.");
        ek.update(&xk);
        ek.update(epk.as_bytes());
        ek.update(&xpk);
        let ek =
            crypto_stream::Key::from_slice(&ek.finalize()).map_err(|_| PasetoError::CryptoError)?;

        let mut n = crypto_generichash::State::new(None, 24).unwrap();
        n.update(epk.as_bytes());
        n.update(&xpk);
        let n = xchacha20::Nonce::try_from_slice(&n.finalize())
            .map_err(|_| PasetoError::CryptoError)?;

        let edk = xchacha20::stream_xor(&key.0, &n, &ek).map_err(|_| PasetoError::CryptoError)?;

        let mut ak = crypto_generichash::State::new(None, 32).unwrap();
        ak.update(b"\x02k4.seal.");
        ak.update(&xk);
        ak.update(epk.as_bytes());
        ak.update(&xpk);
        let ak = ak.finalize();

        let mut tag = crypto_generichash::State::new(Some(&ak), 32).unwrap();
        tag.update(b"k4.seal.");
        tag.update(epk.as_bytes());
        tag.update(&edk);
        let tag = tag.finalize();

        let mut output = Vec::with_capacity(96);
        output.extend_from_slice(&tag);
        output.extend_from_slice(epk.as_bytes());
        output.extend_from_slice(&edk);

        Ok(output.into_boxed_slice())
    }

    pub(super) fn unseal_key(
        unsealing_key: &SecretKey,
        key_data: &[u8],
    ) -> Result<LocalKey, PasetoError> {
        use libsodium_rs::crypto_scalarmult::curve25519;

        let (tag, key_data) = key_data
            .split_first_chunk::<32>()
            .ok_or(PasetoError::InvalidKey)?;
        let (epk, edk) = key_data
            .split_first_chunk::<32>()
            .ok_or(PasetoError::InvalidKey)?;
        let edk: &[u8; 32] = edk.try_into().map_err(|_| PasetoError::InvalidKey)?;

        let xpk = crypto_sign::ed25519_pk_to_curve25519(&unsealing_key.unsealing_key().0)
            .map_err(|_| PasetoError::CryptoError)?;
        let xsk = crypto_sign::ed25519_sk_to_curve25519(&unsealing_key.0)
            .map_err(|_| PasetoError::CryptoError)?;

        // diffie hellman exchange
        let xk = curve25519::scalarmult(&xsk, epk).map_err(|_| PasetoError::CryptoError)?;

        let mut ak = crypto_generichash::State::new(None, 32).unwrap();
        ak.update(b"\x02k4.seal.");
        ak.update(&xk);
        ak.update(epk);
        ak.update(&xpk);
        let ak = ak.finalize();

        let mut t2 = crypto_generichash::State::new(Some(&ak), 32).unwrap();
        t2.update(b"k4.seal.");
        t2.update(epk);
        t2.update(edk);

        // step 6: Compare t2 with t, using a constant-time compare function. If it does not match, abort.
        if compare(&t2.finalize(), tag) != 0 {
            return Err(PasetoError::CryptoError);
        }

        let mut ek = crypto_generichash::State::new(None, 32).unwrap();
        ek.update(b"\x01k4.seal.");
        ek.update(&xk);
        ek.update(epk);
        ek.update(&xpk);
        let ek =
            crypto_stream::Key::from_slice(&ek.finalize()).map_err(|_| PasetoError::CryptoError)?;

        let mut n = crypto_generichash::State::new(None, 24).unwrap();
        n.update(epk);
        n.update(&xpk);
        let n = xchacha20::Nonce::try_from_slice(&n.finalize())
            .map_err(|_| PasetoError::CryptoError)?;

        let edk = xchacha20::stream_xor(edk, &n, &ek).map_err(|_| PasetoError::CryptoError)?;
        edk.try_into()
            .map_err(|_| PasetoError::CryptoError)
            .map(LocalKey)
    }
}
