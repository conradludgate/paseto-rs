//! PASETO v3 (RustCrypto)
//!
//! ```
//! use paseto_v3::{SignedToken, VerifiedToken};
//! use paseto_v3::key::{SecretKey, PublicKey, SealingKey};
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
//! // "v3.public..."
//!
//! // serialize the public key.
//! let key = public_key.to_string();
//! // "k3.public..."
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

pub struct V3;
impl paseto_core::version::Version for V3 {
    const HEADER: &'static str = "v3";

    type LocalKey = key::LocalKey;
    type PublicKey = key::PublicKey;
    type SecretKey = key::SecretKey;
}

impl paseto_core::version::PaserkVersion for V3 {
    const PASERK_HEADER: &'static str = "k3";

    fn hash_key(key_header: &'static str, key_data: &[u8]) -> [u8; 33] {
        use sha2::{Digest, Sha384};

        let mut ctx = Sha384::new();
        ctx.update(Self::PASERK_HEADER.as_bytes());
        ctx.update(key_header.as_bytes());
        ctx.update(key_data);
        let hash = ctx.finalize();
        assert_eq!(hash.len(), 48);

        hash[..33].try_into().unwrap()
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
pub type SignedToken<M, F = ()> = paseto_core::tokens::SignedToken<V3, M, F>;
/// A token with secret data
pub type EncryptedToken<M, F = ()> = paseto_core::tokens::EncryptedToken<V3, M, F>;
/// A [`SignedToken`] that has been verified
pub type VerifiedToken<M, F = ()> = paseto_core::tokens::VerifiedToken<V3, M, F>;
/// An [`EncryptedToken`] that has been decrypted
pub type DecryptedToken<M, F = ()> = paseto_core::tokens::DecryptedToken<V3, M, F>;

pub mod key {
    use core::fmt;

    use cipher::{ArrayLength, StreamCipher};
    use generic_array::GenericArray;
    use generic_array::sequence::Split;
    use hmac::{Hmac, Mac};
    use p384::U48;
    use p384::ecdsa::signature::{DigestSigner, DigestVerifier};
    use p384::ecdsa::{Signature, SigningKey, VerifyingKey};
    use paseto_core::PasetoError;
    pub use paseto_core::key::{Key, KeyId, KeyText, SealingKey, UnsealingKey};
    use paseto_core::pae::{WriteBytes, pre_auth_encode};
    use paseto_core::version::{Local, Marker, Public, Secret};
    use sha2::{Digest, Sha384};

    #[derive(Clone)]
    pub struct SecretKey(SigningKey);
    #[derive(Clone)]
    pub struct PublicKey(VerifyingKey);

    #[derive(Clone)]
    pub struct LocalKey([u8; 32]);

    impl Key for LocalKey {
        type Version = crate::V3;
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
        type Version = crate::V3;
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
        type Version = crate::V3;
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

    impl core::str::FromStr for SecretKey {
        type Err = PasetoError;
        fn from_str(s: &str) -> Result<Self, Self::Err> {
            KeyText::from_str(s).and_then(|k| k.decode())
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
        type UnsealingKey = Self;
        fn unsealing_key(&self) -> Self::UnsealingKey {
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

    impl SealingKey<Public> for SecretKey {
        type UnsealingKey = PublicKey;
        fn unsealing_key(&self) -> Self::UnsealingKey {
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

    pub(super) fn seal_key(
        sealing_key: &PublicKey,
        key: LocalKey,
    ) -> Result<Box<[u8]>, PasetoError> {
        use cipher::KeyIvInit;
        use p384::EncodedPoint;
        use p384::ecdh::diffie_hellman;
        use p384::elliptic_curve::sec1::ToEncodedPoint;

        let pk = sealing_key.0.to_encoded_point(true);

        let esk = p384::SecretKey::from(SecretKey::random()?.0);
        let epk: EncodedPoint = esk.public_key().to_encoded_point(true);
        // let epk_point = AffinePoint::try_from(&epk).map_err(|_| PasetoError::CryptoError)?;
        // let epk = epk.as_bytes();

        let xk = diffie_hellman(esk.to_nonzero_scalar(), sealing_key.0.as_affine());

        let mut ek = sha2::Sha384::new();
        ek.update(b"\x01k3.seal.");
        ek.update(xk.raw_secret_bytes());
        ek.update(epk);
        ek.update(pk.as_bytes());
        let (ek, n) = ek.finalize().split();

        let mut ak = sha2::Sha384::new();
        ak.update(b"\x02k3.seal.");
        ak.update(xk.raw_secret_bytes());
        ak.update(epk);
        ak.update(pk.as_bytes());
        let ak = ak.finalize();

        let mut edk = key.0;
        ctr::Ctr64BE::<aes::Aes256>::new(&ek, &n).apply_keystream(&mut edk);

        let mut tag = hmac::Hmac::<sha2::Sha384>::new_from_slice(&ak).unwrap();
        tag.update(b"k3.seal.");
        tag.update(epk.as_bytes());
        tag.update(&edk);
        let tag = tag.finalize().into_bytes();

        let mut output = Vec::with_capacity(48 + 49 + 32);
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
        use p384::ecdh::diffie_hellman;
        use p384::{AffinePoint, EncodedPoint};

        let (tag, key_data) = key_data
            .split_first_chunk_mut::<48>()
            .ok_or(PasetoError::InvalidKey)?;
        let (epk, edk) = key_data
            .split_first_chunk_mut::<49>()
            .ok_or(PasetoError::InvalidKey)?;

        let epk: &[u8; 49] = &*epk;
        let edk: &mut [u8; 32] = edk.try_into().map_err(|_| PasetoError::InvalidKey)?;

        let sk = p384::SecretKey::from(&unsealing_key.0);

        let pk: EncodedPoint = sk.public_key().into();
        let pk = pk.compress();

        let epk_point = EncodedPoint::from_bytes(epk).map_err(|_| PasetoError::CryptoError)?;
        let epk_point = AffinePoint::try_from(&epk_point).map_err(|_| PasetoError::CryptoError)?;

        let xk = diffie_hellman(sk.to_nonzero_scalar(), epk_point);

        let mut ak = sha2::Sha384::new();
        ak.update(b"\x02k3.seal.");
        ak.update(xk.raw_secret_bytes());
        ak.update(epk);
        ak.update(pk.as_bytes());
        let ak = ak.finalize();

        let mut t2 = hmac::Hmac::<sha2::Sha384>::new_from_slice(&ak).unwrap();
        t2.update(b"k3.seal.");
        t2.update(epk);
        t2.update(edk);

        // step 6: Compare t2 with t, using a constant-time compare function. If it does not match, abort.
        t2.verify((&*tag).into())
            .map_err(|_| PasetoError::CryptoError)?;

        let mut ek = sha2::Sha384::new();
        ek.update(b"\x01k3.seal.");
        ek.update(xk.raw_secret_bytes());
        ek.update(epk);
        ek.update(pk.as_bytes());
        let (ek, n) = ek.finalize().split();

        ctr::Ctr64BE::<aes::Aes256>::new(&ek, &n).apply_keystream(edk);

        Ok(LocalKey(*edk))
    }
}
