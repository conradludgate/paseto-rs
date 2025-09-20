use core::fmt;

use aws_lc_rs::cipher::{AES_256, DecryptingKey, EncryptingKey, UnboundCipherKey};
use aws_lc_rs::constant_time;
use aws_lc_rs::digest::{self, Digest, SHA384};
use aws_lc_rs::hkdf::{self, HKDF_SHA384, KeyType};
use aws_lc_rs::hmac::{self, HMAC_SHA384};
use aws_lc_rs::iv::FixedLength;
use p384::ecdsa::signature::hazmat::{PrehashSigner, PrehashVerifier};
use paseto_core::key::{Key, KeyText, SealingKey, UnsealingKey};
use paseto_core::pae::{WriteBytes, pre_auth_encode};
use paseto_core::version::{Local, Marker, Public, Secret};
use paseto_core::{PasetoError, rand_core};

#[derive(Clone)]
pub struct SecretKey(p384::ecdsa::SigningKey);
#[derive(Clone)]
pub struct PublicKey(p384::ecdsa::VerifyingKey);
#[derive(Clone)]
pub struct LocalKey([u8; 32]);

pub struct V3;
impl paseto_core::version::Version for V3 {
    const PASETO_HEADER: &'static str = "v3";
    const PASERK_HEADER: &'static str = "k3";

    type LocalKey = LocalKey;
    type PublicKey = PublicKey;
    type SecretKey = SecretKey;

    fn hash_key(key_header: &'static str, key_data: &[u8]) -> [u8; 33] {
        let mut ctx = digest::Context::new(&SHA384);
        ctx.update(Self::PASERK_HEADER.as_bytes());
        ctx.update(key_header.as_bytes());
        ctx.update(key_data);
        let hash = ctx.finish();
        assert_eq!(hash.as_ref().len(), 48);

        hash.as_ref()[..33].try_into().unwrap()
    }
}

pub type SignedToken<M, F = ()> = paseto_core::tokens::SignedToken<V3, M, F>;
pub type EncryptedToken<M, F = ()> = paseto_core::tokens::EncryptedToken<V3, M, F>;
pub type VerifiedToken<M, F = ()> = paseto_core::tokens::VerifiedToken<V3, M, F>;
pub type DecryptedToken<M, F = ()> = paseto_core::tokens::DecryptedToken<V3, M, F>;

impl Key for LocalKey {
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

impl core::str::FromStr for LocalKey {
    type Err = PasetoError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        KeyText::from_str(s).and_then(|k| k.decode())
    }
}

impl Key for PublicKey {
    type Version = V3;
    type KeyType = Public;

    fn decode(bytes: &[u8]) -> Result<Self, PasetoError> {
        Self::from_sec1_bytes(bytes)
    }
    fn encode(&self) -> Box<[u8]> {
        self.0.to_encoded_point(true).to_bytes()
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
    type Version = V3;
    type KeyType = Secret;

    fn decode(bytes: &[u8]) -> Result<Self, PasetoError> {
        Self::from_bytes(bytes)
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
    fn keys(
        &self,
        nonce: &[u8],
    ) -> Result<((UnboundCipherKey, FixedLength<16>), hmac::Key), PasetoError> {
        let aead_key = kdf::<48>(&self.0, "paseto-encryption-key", nonce)?;
        let (ek, n2) = aead_key
            .split_last_chunk::<16>()
            .ok_or(PasetoError::CryptoError)?;
        let ak = kdf::<48>(&self.0, "paseto-auth-key-for-aead", nonce)?;

        let key = UnboundCipherKey::new(&AES_256, ek).map_err(|_| PasetoError::CryptoError)?;
        let iv = FixedLength::from(n2);
        let mac = hmac::Key::new(HMAC_SHA384, &ak);

        Ok(((key, iv), mac))
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

        let ((key, iv), mac) = self.keys(nonce)?;

        EncryptingKey::ctr(key)
            .map_err(|_| PasetoError::CryptoError)?
            .less_safe_encrypt(ciphertext, aws_lc_rs::cipher::EncryptionContext::Iv128(iv))
            .map_err(|_| PasetoError::CryptoError)?;

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

        let ((key, iv), mac) = self.keys(nonce)?;

        let actual_tag = preauth_local(mac, encoding, nonce, ciphertext, footer, aad);
        constant_time::verify_slices_are_equal(actual_tag.as_ref(), tag)
            .map_err(|_| PasetoError::CryptoError)?;

        DecryptingKey::ctr(key)
            .map_err(|_| PasetoError::CryptoError)?
            .decrypt(ciphertext, aws_lc_rs::cipher::DecryptionContext::Iv128(iv))
            .map_err(|_| PasetoError::CryptoError)?;

        Ok(ciphertext)
    }
}

impl SealingKey<Public> for SecretKey {
    type UnsealingKey = PublicKey;
    fn unsealing_key(&self) -> Self::UnsealingKey {
        PublicKey(*self.0.verifying_key())
    }

    fn random(rng: &mut impl rand_core::TryCryptoRng) -> Result<Self, PasetoError> {
        let mut bytes = [0; 48];
        loop {
            rng.try_fill_bytes(&mut bytes)
                .map_err(|_| PasetoError::CryptoError)?;
            match p384::ecdsa::SigningKey::from_bytes(&bytes.into()) {
                Err(_) => continue,
                Ok(key) => break Ok(Self(key)),
            }
        }
    }

    fn nonce(_: &mut impl rand_core::TryCryptoRng) -> Result<Vec<u8>, PasetoError> {
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
        let signature: p384::ecdsa::Signature = self
            .0
            .sign_prehash(digest.as_ref())
            .map_err(|_| PasetoError::CryptoError)?;
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
            .verify_prehash(digest.as_ref(), &signature)
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
    key: &p384::ecdsa::VerifyingKey,
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

    let key = key.to_encoded_point(true);

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

    ctx.0.finish()
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
        LocalKey(key)
    }

    /// Get the raw bytes from this key
    pub fn into_bytes(&self) -> [u8; 32] {
        self.0
    }
}
