//! PASETO v4 (RustCrypto)
//!
//! ```
//! use paseto_v4::{SignedToken, VerifiedToken};
//! use paseto_v4::key::{SecretKey, PublicKey, SealingKey};
//! use paseto_json::RegisteredClaims;
//! use std::time::Duration;
//!
//! // create a new keypair
//! let secret_key = SecretKey::random().unwrap();
//! let public_key = secret_key.unsealing_key();
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
//! // verify the token
//! let verified_token = signed_token.verify(&public_key).unwrap();
//!
//! // verify the claims
//! verified_token.claims.validate_time().unwrap();
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
        use digest::consts::U33;
        use digest::{FixedOutput, Update};

        let mut ctx = blake2::Blake2b::<U33>::default();
        ctx.update(Self::PASERK_HEADER.as_bytes());
        ctx.update(key_header.as_bytes());
        ctx.update(key_data);
        ctx.finalize_fixed().into()
    }

    fn seal_key(
        sealing_key: &key::PublicKey,
        key: key::LocalKey,
    ) -> Result<Box<[u8]>, PasetoError> {
        key::seal_key(sealing_key, key)
    }

    fn unseal_key(
        sealing_key: &key::SecretKey,
        mut key_data: Box<[u8]>,
    ) -> Result<key::LocalKey, PasetoError> {
        key::unseal_key(sealing_key, &mut key_data)
    }
}

/// A token with publically readable data, but not yet verified
pub type SignedToken<M, F = ()> = paseto_core::tokens::SignedToken<V4, M, F>;
/// A token with secret data
pub type EncryptedToken<M, F = ()> = paseto_core::tokens::EncryptedToken<V4, M, F>;
/// A [`SignedToken`] that has been verified
pub type VerifiedToken<M, F = ()> = paseto_core::tokens::VerifiedToken<V4, M, F>;
/// An [`EncryptedToken`] that has been decrypted
pub type DecryptedToken<M, F = ()> = paseto_core::tokens::DecryptedToken<V4, M, F>;

pub mod key {
    use core::fmt;

    use blake2::Blake2bMac;
    use chacha20::XChaCha20;
    use cipher::{ArrayLength, StreamCipher};
    use curve25519_dalek::EdwardsPoint;
    use digest::Mac;
    use digest::consts::{U32, U56, U64};
    use digest::typenum::{IsLessOrEqual, LeEq, NonZero};
    use ed25519_dalek::Signature;
    use generic_array::GenericArray;
    use generic_array::sequence::Split;
    use paseto_core::PasetoError;
    pub use paseto_core::key::{Key, KeyId, KeyText, SealingKey, UnsealingKey};
    use paseto_core::pae::{WriteBytes, pre_auth_encode};
    use paseto_core::version::{Local, Marker, Public, Secret};

    pub struct SecretKey(
        ed25519_dalek::SecretKey,
        ed25519_dalek::hazmat::ExpandedSecretKey,
    );

    impl Clone for SecretKey {
        fn clone(&self) -> Self {
            let esk = ed25519_dalek::hazmat::ExpandedSecretKey::from(&self.0);
            Self(self.0, esk)
        }
    }

    #[derive(Clone)]
    pub struct PublicKey(ed25519_dalek::VerifyingKey);

    #[derive(Clone)]
    pub struct LocalKey(GenericArray<u8, U32>);

    impl Key for LocalKey {
        type Version = crate::V4;
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
        /// use paseto_v4::key::{PublicKey, Key};
        ///
        /// let public_key = "b7715bd661458d928654d3e832f53ff5c9480542e0e3d4c9b032c768c7ce6023";
        /// let public_key = hex::decode(&public_key).unwrap();
        ///
        /// let _key = PublicKey::decode(&public_key).unwrap();
        /// ```
        fn decode(bytes: &[u8]) -> Result<Self, PasetoError> {
            let key = bytes.try_into().map_err(|_| PasetoError::InvalidKey)?;
            ed25519_dalek::VerifyingKey::from_bytes(&key)
                .map(PublicKey)
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
        /// use paseto_v4::key::{SecretKey, Key};
        ///
        /// let private_key = "407796f4bc4b8184e9fe0c54b336822d34823092ad873d87ba14c3efb9db8c1db7715bd661458d928654d3e832f53ff5c9480542e0e3d4c9b032c768c7ce6023";
        /// let private_key = hex::decode(&private_key).unwrap();
        ///
        /// let _key = SecretKey::decode(&private_key).unwrap();
        /// ```
        fn decode(bytes: &[u8]) -> Result<Self, PasetoError> {
            let (secret_key, verifying_key) = bytes
                .split_first_chunk::<32>()
                .ok_or(PasetoError::InvalidKey)?;

            let esk = ed25519_dalek::hazmat::ExpandedSecretKey::from(secret_key);
            let key = Self(*secret_key, esk);

            let verifying_key = PublicKey::decode(verifying_key)?;

            if key.unsealing_key().0 != verifying_key.0 {
                return Err(PasetoError::InvalidKey);
            }

            Ok(key)
        }

        fn encode(&self) -> Box<[u8]> {
            let mut bytes = Vec::with_capacity(64);
            bytes.extend_from_slice(&self.0);
            bytes.extend_from_slice(self.unsealing_key().0.as_bytes());
            bytes.into_boxed_slice()
        }
    }

    impl core::str::FromStr for SecretKey {
        type Err = PasetoError;
        fn from_str(s: &str) -> Result<Self, Self::Err> {
            KeyText::from_str(s).and_then(|k| k.decode())
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
        type UnsealingKey = Self;
        fn unsealing_key(&self) -> Self::UnsealingKey {
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

    impl SealingKey<Public> for SecretKey {
        type UnsealingKey = PublicKey;
        fn unsealing_key(&self) -> Self::UnsealingKey {
            PublicKey((&self.1).into())
        }

        fn random() -> Result<Self, PasetoError> {
            let mut secret_key = [0; 32];
            getrandom::fill(&mut secret_key).map_err(|_| PasetoError::CryptoError)?;

            let esk = ed25519_dalek::hazmat::ExpandedSecretKey::from(&secret_key);
            Ok(Self(secret_key, esk))
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
            let signature = preauth_secret(&self.0, encoding, &payload, footer, aad);
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
            if len < 64 {
                return Err(PasetoError::InvalidToken);
            }

            let (cleartext, tag) = payload.split_at(len - 64);
            let signature = Signature::from_bytes(tag.try_into().unwrap());
            let verifier = self
                .0
                .verify_stream(&signature)
                .map_err(|_| PasetoError::CryptoError)?;

            preauth_public(verifier, encoding, cleartext, footer, aad)
                .finalize_and_verify()
                .map_err(|_| PasetoError::CryptoError)?;

            Ok(cleartext)
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

    struct PreAuthEncodeDigest<'a, M: digest::Update>(pub &'a mut M);
    impl<'a, M: digest::Update> WriteBytes for PreAuthEncodeDigest<'a, M> {
        fn write(&mut self, slice: &[u8]) {
            self.0.update(slice)
        }
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

    fn preauth_public(
        verifier: ed25519_dalek::StreamVerifier,
        encoding: &'static str,
        cleartext: &[u8],
        footer: &[u8],
        aad: &[u8],
    ) -> ed25519_dalek::StreamVerifier {
        #[repr(transparent)]
        pub struct StreamVerifier(pub ed25519_dalek::StreamVerifier);

        impl WriteBytes for StreamVerifier {
            fn write(&mut self, slice: &[u8]) {
                self.0.update(slice);
            }
        }

        let mut sv = StreamVerifier(verifier);
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
            &mut sv,
        );

        sv.0
    }

    fn preauth_secret(
        secret_key: &ed25519_dalek::SecretKey,
        encoding: &'static str,
        cleartext: &[u8],
        footer: &[u8],
        aad: &[u8],
    ) -> Signature {
        let esk = ed25519_dalek::hazmat::ExpandedSecretKey::from(secret_key);
        let vk = ed25519_dalek::VerifyingKey::from(&esk);

        ed25519_dalek::hazmat::raw_sign_byupdate::<sha2::Sha512, _>(
            &esk,
            |ctx| {
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
                    PreAuthEncodeDigest(ctx),
                );
                Ok(())
            },
            &vk,
        )
        .expect("should not error")
    }

    pub(super) fn seal_key(
        sealing_key: &PublicKey,
        key: LocalKey,
    ) -> Result<Box<[u8]>, PasetoError> {
        use cipher::KeyIvInit;
        use curve25519_dalek::{
            edwards::CompressedEdwardsY,
            scalar::{Scalar, clamp_integer},
        };
        use digest::Digest;

        // Given a plaintext data key (pdk), and an Ed25519 public key (pk).
        let pk = CompressedEdwardsY(*sealing_key.0.as_bytes());

        // step 1: Calculate the birationally-equivalent X25519 public key (xpk) from pk.
        let xpk = pk.decompress().unwrap().to_montgomery();

        let esk = Scalar::from_bytes_mod_order(clamp_integer({
            let mut esk = [0; 32];
            getrandom::fill(&mut esk).map_err(|_| PasetoError::CryptoError)?;
            esk
        }));
        let epk = EdwardsPoint::mul_base(&esk).to_montgomery();

        // diffie hellman exchange
        let xk = esk * xpk;

        let mut ek = blake2::Blake2b::new();
        ek.update(b"\x01k4.seal.");
        ek.update(xk.as_bytes());
        ek.update(epk.as_bytes());
        ek.update(xpk.as_bytes());
        let ek = ek.finalize();

        let mut n = blake2::Blake2b::new();
        n.update(epk.as_bytes());
        n.update(xpk.as_bytes());
        let n = n.finalize();

        let mut edk = key.0;
        chacha20::XChaCha20::new(&ek, &n).apply_keystream(&mut edk);

        let mut ak = blake2::Blake2b::<U32>::new();
        ak.update(b"\x02k4.seal.");
        ak.update(xk.as_bytes());
        ak.update(epk.as_bytes());
        ak.update(xpk.as_bytes());
        let ak = ak.finalize();

        let mut tag = blake2::Blake2bMac::<U32>::new_from_slice(&ak).unwrap();
        tag.update(b"k4.seal.");
        tag.update(epk.as_bytes());
        tag.update(&edk);
        let tag = tag.finalize().into_bytes();

        let mut output = Vec::with_capacity(96);
        output.extend_from_slice(&tag);
        output.extend_from_slice(epk.as_bytes());
        output.extend_from_slice(&edk);

        Ok(output.into_boxed_slice())
    }

    pub(super) fn unseal_key(
        unsealing_key: &SecretKey,
        key_data: &mut [u8],
    ) -> Result<LocalKey, PasetoError> {
        use cipher::KeyIvInit;
        use digest::Digest;

        let (tag, key_data) = key_data
            .split_first_chunk_mut::<32>()
            .ok_or(PasetoError::InvalidKey)?;
        let (epk, edk) = key_data
            .split_first_chunk_mut::<32>()
            .ok_or(PasetoError::InvalidKey)?;
        let edk: &mut [u8; 32] = edk.try_into().map_err(|_| PasetoError::InvalidKey)?;

        let epk = curve25519_dalek::MontgomeryPoint(*epk);

        // expand pk/sk pair from ed25519 to x25519
        let xpk = EdwardsPoint::mul_base(&unsealing_key.1.scalar).to_montgomery();

        // diffie hellman exchange
        let xk = unsealing_key.1.scalar * epk;

        let mut ak = blake2::Blake2b::<U32>::new();
        ak.update(b"\x02k4.seal.");
        ak.update(xk.as_bytes());
        ak.update(epk.as_bytes());
        ak.update(xpk.as_bytes());
        let ak = ak.finalize();

        let mut t2 = blake2::Blake2bMac::<U32>::new_from_slice(&ak).unwrap();
        t2.update(b"k4.seal.");
        t2.update(epk.as_bytes());
        t2.update(edk);

        // step 6: Compare t2 with t, using a constant-time compare function. If it does not match, abort.
        t2.verify((&*tag).into())
            .map_err(|_| PasetoError::CryptoError)?;

        let mut ek = blake2::Blake2b::new();
        ek.update(b"\x01k4.seal.");
        ek.update(xk.as_bytes());
        ek.update(epk.as_bytes());
        ek.update(xpk.as_bytes());
        let ek = ek.finalize();

        let mut n = blake2::Blake2b::new();
        n.update(epk.as_bytes());
        n.update(xpk.as_bytes());
        let n = n.finalize();

        chacha20::XChaCha20::new(&ek, &n).apply_keystream(edk);

        Ok(LocalKey((*edk).into()))
    }
}
