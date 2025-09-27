//! PASETO v3 (aws-lc-rs)
//!
//! ```
//! use paseto_v3_aws_lc::{SignedToken, VerifiedToken, SecretKey, PublicKey};
//! use paseto_json::{RegisteredClaims, Time, MustExpire, FromIssuer, ForSubject, Validate};
//! use std::time::Duration;
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
//! // verify the token signature and validate the claims.
//! let validation = Time::now()
//!     .then(MustExpire)
//!     .then(FromIssuer("https://paseto.conrad.cafe/"))
//!     .then(ForSubject("conradludgate"));
//! let verified_token = signed_token.verify(&public_key, &validation).unwrap();
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
        use aws_lc_rs::digest::{self, SHA384};

        let mut ctx = digest::Context::new(&SHA384);
        ctx.update(Self::PASERK_HEADER.as_bytes());
        ctx.update(key_header.as_bytes());
        ctx.update(key_data);
        let hash = ctx.finish();
        assert_eq!(hash.as_ref().len(), 48);

        hash.as_ref()[..33].try_into().unwrap()
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
pub type SignedToken<M, F = ()> = paseto_core::SignedToken<V3, M, F>;
/// A token with secret data
pub type EncryptedToken<M, F = ()> = paseto_core::EncryptedToken<V3, M, F>;
/// A [`SignedToken`] that has been verified
pub type VerifiedToken<M, F = ()> = paseto_core::VerifiedToken<V3, M, F>;
/// An [`EncryptedToken`] that has been decrypted
pub type DecryptedToken<M, F = ()> = paseto_core::DecryptedToken<V3, M, F>;

pub type LocalKey = paseto_core::LocalKey<V3>;
pub type PublicKey = paseto_core::PublicKey<V3>;
pub type SecretKey = paseto_core::SecretKey<V3>;
pub type KeyId<K> = paseto_core::key::KeyId<V3, K>;
pub type KeyText<K> = paseto_core::key::KeyText<V3, K>;
pub type SealedKey = paseto_core::key::SealedKey<V3>;

mod lc;
pub mod key {
    use aws_lc_rs::cipher::{AES_256, EncryptingKey, UnboundCipherKey};
    use aws_lc_rs::constant_time;
    use aws_lc_rs::digest::{self, Digest, SHA384};
    use aws_lc_rs::hkdf::{self, HKDF_SHA384, KeyType};
    use aws_lc_rs::hmac::{self, HMAC_SHA384};
    use aws_lc_rs::iv::FixedLength;
    use aws_lc_rs::rand::{SecureRandom, SystemRandom};
    use paseto_core::PasetoError;
    use paseto_core::key::{KeyKind, SealingKey, UnsealingKey};
    use paseto_core::pae::{WriteBytes, pre_auth_encode};
    use paseto_core::version::{Local, Marker, Public, Secret};

    use crate::lc::{Signature, SigningKey, VerifyingKey};

    #[derive(Clone)]
    pub struct SecretKey(SigningKey);
    #[derive(Clone)]
    pub struct PublicKey(VerifyingKey);

    #[derive(Clone)]
    pub struct LocalKey([u8; 32]);

    impl KeyKind for LocalKey {
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

    impl KeyKind for PublicKey {
        type Version = crate::V3;
        type KeyType = Public;

        fn decode(bytes: &[u8]) -> Result<Self, PasetoError> {
            let pk = VerifyingKey::from_sec1_bytes(bytes)?;
            Ok(PublicKey(pk))
        }
        fn encode(&self) -> Box<[u8]> {
            self.0.compressed_pub_key().to_vec().into_boxed_slice()
        }
    }

    impl KeyKind for SecretKey {
        type Version = crate::V3;
        type KeyType = Secret;

        fn decode(bytes: &[u8]) -> Result<Self, PasetoError> {
            if bytes.len() != 48 {
                return Err(PasetoError::InvalidKey);
            }
            SigningKey::from_sec1_bytes(bytes).map(Self)
        }
        fn encode(&self) -> Box<[u8]> {
            self.0.encode().to_vec().into_boxed_slice()
        }
    }

    struct Cipher(UnboundCipherKey, FixedLength<16>);
    impl Cipher {
        fn apply_keystream(self, inout: &mut [u8]) -> Result<(), PasetoError> {
            EncryptingKey::ctr(self.0)
                .map_err(|_| PasetoError::CryptoError)?
                .less_safe_encrypt(inout, aws_lc_rs::cipher::EncryptionContext::Iv128(self.1))
                .map_err(|_| PasetoError::CryptoError)?;
            Ok(())
        }
    }

    impl LocalKey {
        fn keys(&self, nonce: &[u8]) -> Result<(Cipher, hmac::Key), PasetoError> {
            let aead_key = kdf::<48>(&self.0, "paseto-encryption-key", nonce)?;
            let (ek, n2) = aead_key
                .split_last_chunk::<16>()
                .ok_or(PasetoError::CryptoError)?;
            let ak = kdf::<48>(&self.0, "paseto-auth-key-for-aead", nonce)?;

            let key = UnboundCipherKey::new(&AES_256, ek).map_err(|_| PasetoError::CryptoError)?;
            let iv = FixedLength::from(n2);
            let mac = hmac::Key::new(HMAC_SHA384, &ak);

            Ok((Cipher(key, iv), mac))
        }
    }

    impl SealingKey<Local> for LocalKey {
        fn unsealing_key(&self) -> LocalKey {
            Self(self.0)
        }

        fn random() -> Result<Self, PasetoError> {
            let mut bytes = [0; 32];
            SystemRandom::new()
                .fill(&mut bytes)
                .map_err(|_| PasetoError::CryptoError)?;
            Ok(Self(bytes))
        }

        fn nonce() -> Result<Vec<u8>, PasetoError> {
            let mut nonce = [0; 32];
            SystemRandom::new()
                .fill(&mut nonce)
                .map_err(|_| PasetoError::CryptoError)?;

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
            let (nonce, ciphertext) = payload.split_at_mut(32);

            let (cipher, mac) = self.keys(nonce)?;

            cipher.apply_keystream(ciphertext)?;
            let tag = preauth_local(mac, encoding, nonce, ciphertext, footer, aad);
            payload.extend_from_slice(tag.as_ref());

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

            let (cipher, mac) = self.keys(nonce)?;

            let actual_tag = preauth_local(mac, encoding, nonce, ciphertext, footer, aad);
            constant_time::verify_slices_are_equal(actual_tag.as_ref(), tag)
                .map_err(|_| PasetoError::CryptoError)?;

            cipher.apply_keystream(ciphertext)?;

            Ok(ciphertext)
        }
    }

    impl SealingKey<Public> for SecretKey {
        fn unsealing_key(&self) -> PublicKey {
            PublicKey(self.0.verifying_key())
        }

        fn random() -> Result<Self, PasetoError> {
            let mut bytes = [0; 48];
            loop {
                SystemRandom::new()
                    .fill(&mut bytes)
                    .map_err(|_| PasetoError::CryptoError)?;
                match SigningKey::from_sec1_bytes(&bytes).map(Self) {
                    Err(PasetoError::InvalidKey) => continue,
                    res => break res,
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
            let digest = preauth_public(
                &self.0.compressed_pub_key(),
                encoding,
                &payload,
                footer,
                aad,
            );
            let signature = self.0.sign(digest.as_ref())?;
            signature.append_to_vec(&mut payload)?;

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
            let signature = Signature::from_bytes(tag).map_err(|_| PasetoError::InvalidToken)?;
            let digest = preauth_public(
                &self.0.compressed_pub_key(),
                encoding,
                cleartext,
                footer,
                aad,
            );
            self.0
                .verify(digest.as_ref(), &signature)
                .map_err(|_| PasetoError::CryptoError)?;

            Ok(cleartext)
        }
    }

    fn kdf<const N: usize>(
        key: &[u8],
        sep: &'static str,
        nonce: &[u8],
    ) -> Result<[u8; N], PasetoError> {
        struct Len<const N: usize>;
        impl<const N: usize> KeyType for Len<N> {
            fn len(&self) -> usize {
                N
            }
        }

        let ikm = [sep.as_bytes(), nonce];
        let prk = hkdf::Salt::new(HKDF_SHA384, &[]).extract(key);
        let okm = prk
            .expand(&ikm, Len::<N>)
            .map_err(|_| PasetoError::CryptoError)?;

        let mut output = [0; N];
        okm.fill(&mut output)
            .map_err(|_| PasetoError::CryptoError)?;
        Ok(output)
    }

    fn preauth_local(
        mac: hmac::Key,
        encoding: &'static str,
        nonce: &[u8],
        ciphertext: &[u8],
        footer: &[u8],
        aad: &[u8],
    ) -> hmac::Tag {
        struct Context(hmac::Context);
        impl WriteBytes for Context {
            fn write(&mut self, slice: &[u8]) {
                self.0.update(slice)
            }
        }

        let mut ctx = Context(hmac::Context::with_key(&mac));

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

        ctx.0.sign()
    }

    fn preauth_public(
        key: &[u8; 49],
        encoding: &'static str,
        cleartext: &[u8],
        footer: &[u8],
        aad: &[u8],
    ) -> Digest {
        struct Context(digest::Context);
        impl WriteBytes for Context {
            fn write(&mut self, slice: &[u8]) {
                self.0.update(slice)
            }
        }

        let mut ctx = Context(digest::Context::new(&SHA384));
        pre_auth_encode(
            [
                &[key],
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
        ctx.0.finish()
    }

    fn seal_keys(
        xk: &[u8; 48],
        epk: &[u8; 49],
        pk: &[u8; 49],
    ) -> Result<(Cipher, hmac::Key), PasetoError> {
        let mut ek = digest::Context::new(&SHA384);
        ek.update(b"\x01k3.seal.");
        ek.update(xk);
        ek.update(epk);
        ek.update(pk);
        let ek = ek.finish();
        let (ek, n) = ek
            .as_ref()
            .split_last_chunk::<16>()
            .ok_or(PasetoError::CryptoError)?;

        let mut ak = digest::Context::new(&SHA384);
        ak.update(b"\x02k3.seal.");
        ak.update(xk);
        ak.update(epk);
        ak.update(pk);
        let ak = ak.finish();

        let key = UnboundCipherKey::new(&AES_256, ek).map_err(|_| PasetoError::CryptoError)?;
        let iv = FixedLength::from(n);
        let mac = hmac::Key::new(HMAC_SHA384, ak.as_ref());

        Ok((Cipher(key, iv), mac))
    }

    pub(super) fn seal_key(
        sealing_key: &PublicKey,
        key: LocalKey,
    ) -> Result<Box<[u8]>, PasetoError> {
        let pk = sealing_key.0.compressed_pub_key();

        let esk = SecretKey::random()?.0;
        let epk = esk.verifying_key().compressed_pub_key();

        let xk = esk.diffie_hellman(&sealing_key.0)?;

        let (cipher, mac) = seal_keys(&xk, &epk, &pk)?;

        let mut edk = key.0;
        cipher.apply_keystream(&mut edk)?;

        let mut tag = hmac::Context::with_key(&mac);
        tag.update(b"k3.seal.");
        tag.update(&epk);
        tag.update(&edk);
        let tag = tag.sign();

        let mut output = Vec::with_capacity(48 + 49 + 32);
        output.extend_from_slice(tag.as_ref());
        output.extend_from_slice(&epk);
        output.extend_from_slice(&edk);

        Ok(output.into_boxed_slice())
    }

    pub(super) fn unseal_key(
        unsealing_key: &SecretKey,
        key_data: &mut [u8],
    ) -> Result<LocalKey, PasetoError> {
        let (tag, key_data) = key_data
            .split_first_chunk_mut::<48>()
            .ok_or(PasetoError::InvalidKey)?;
        let (epk, edk) = key_data
            .split_first_chunk_mut::<49>()
            .ok_or(PasetoError::InvalidKey)?;

        let epk: &[u8; 49] = &*epk;
        let edk: &mut [u8; 32] = edk.try_into().map_err(|_| PasetoError::InvalidKey)?;

        let epk_point = VerifyingKey::from_sec1_bytes(epk)?;
        let xk = unsealing_key.0.diffie_hellman(&epk_point)?;

        let pk = unsealing_key.0.compressed_pub_key();
        let (cipher, mac) = seal_keys(&xk, epk, &pk)?;

        let mut t2 = hmac::Context::with_key(&mac);
        t2.update(b"k3.seal.");
        t2.update(epk);
        t2.update(edk);
        let t2 = t2.sign();

        // step 6: Compare t2 with t, using a constant-time compare function. If it does not match, abort.
        constant_time::verify_slices_are_equal(t2.as_ref(), tag)
            .map_err(|_| PasetoError::CryptoError)?;

        cipher.apply_keystream(edk)?;
        Ok(LocalKey(*edk))
    }
}
