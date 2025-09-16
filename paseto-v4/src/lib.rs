use blake2::{Blake2b, Blake2bMac};
use chacha20::XChaCha20;
use cipher::{ArrayLength, StreamCipher};
use digest::{
    Mac,
    consts::{U32, U33, U56, U64},
    typenum::{IsLessOrEqual, LeEq, NonZero},
};
use ed25519_dalek::Signature;
use generic_array::{GenericArray, sequence::Split};
use paseto_core::{
    PasetoError,
    key::{Key, SealingKey, UnsealingKey},
    version::{Local, Marker, Public, Secret},
};
use paseto_core::{
    pae::{WriteBytes, pre_auth_encode},
    rand_core,
};

pub struct SecretKey(
    ed25519_dalek::SecretKey,
    ed25519_dalek::hazmat::ExpandedSecretKey,
);

pub struct PublicKey(ed25519_dalek::VerifyingKey);

pub struct LocalKey(GenericArray<u8, U32>);

pub struct V4;
impl paseto_core::version::Version for V4 {
    const PASETO_HEADER: &'static str = "v4";
    const PASERK_HEADER: &'static str = "k4";

    type LocalKey = LocalKey;
    type PublicKey = PublicKey;
    type SecretKey = SecretKey;

    fn hash_key(key_header: &'static str, key_data: &[u8]) -> [u8; 33] {
        use digest::{FixedOutput, Update};

        let mut ctx = Blake2b::<U33>::default();
        ctx.update(Self::PASERK_HEADER.as_bytes());
        ctx.update(key_header.as_bytes());
        ctx.update(key_data);
        ctx.finalize_fixed().into()
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
        if bytes.len() != 32 {
            return Err(PasetoError::InvalidKey);
        }
        Ok(Self(*GenericArray::from_slice(bytes)))
    }
    fn encode(&self) -> Box<[u8]> {
        self.0.to_vec().into_boxed_slice()
    }
}

impl Key for PublicKey {
    type Version = V4;
    type KeyType = Public;

    fn decode(bytes: &[u8]) -> Result<Self, PasetoError> {
        Self::from_public_key(bytes)
    }
    fn encode(&self) -> Box<[u8]> {
        self.0.as_bytes().to_vec().into_boxed_slice()
    }
}

impl Key for SecretKey {
    type Version = V4;
    type KeyType = Secret;

    fn decode(bytes: &[u8]) -> Result<Self, PasetoError> {
        Self::from_keypair_bytes(bytes)
    }

    fn encode(&self) -> Box<[u8]> {
        let mut bytes = Vec::with_capacity(64);
        bytes.extend_from_slice(&self.0);
        bytes.extend_from_slice(self.public_key().0.as_bytes());
        bytes.into_boxed_slice()
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
    fn nonce(mut rng: impl rand_core::TryCryptoRng) -> Result<Vec<u8>, PasetoError> {
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
    fn nonce(_: impl rand_core::TryCryptoRng) -> Result<Vec<u8>, PasetoError> {
        Ok(Vec::with_capacity(32))
    }

    fn seal(
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

pub struct PreAuthEncodeDigest<'a, M: digest::Update>(pub &'a mut M);
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

impl SecretKey {
    /// Decode an Ed25519 Secret Keypair
    ///
    /// ```
    /// use paseto_v4::SecretKey;
    ///
    /// let private_key = "407796f4bc4b8184e9fe0c54b336822d34823092ad873d87ba14c3efb9db8c1db7715bd661458d928654d3e832f53ff5c9480542e0e3d4c9b032c768c7ce6023";
    /// let private_key = hex::decode(&private_key).unwrap();
    ///
    /// let _key = SecretKey::from_keypair_bytes(&private_key).unwrap();
    /// ```
    pub fn from_keypair_bytes(key: &[u8]) -> Result<Self, PasetoError> {
        let (secret_key, verifying_key) = key
            .split_first_chunk::<32>()
            .ok_or(PasetoError::InvalidKey)?;
        let key = Self::from_secret_key(*secret_key);
        let verifying_key = PublicKey::from_public_key(verifying_key)?;

        if key.public_key().0 != verifying_key.0 {
            return Err(PasetoError::InvalidKey);
        }

        Ok(key)
    }

    /// Create a new secret key from the byte array
    ///
    /// ```
    /// use paseto_v4::SecretKey;
    ///
    /// let private_key = "407796f4bc4b8184e9fe0c54b336822d34823092ad873d87ba14c3efb9db8c1d";
    /// let private_key = hex::decode(&private_key).unwrap();
    /// let private_key: [u8; 32] = private_key.try_into().unwrap();
    ///
    /// let _key = SecretKey::from_secret_key(private_key);
    /// ```
    pub fn from_secret_key(key: [u8; 32]) -> Self {
        let esk = ed25519_dalek::hazmat::ExpandedSecretKey::from(&key);
        Self(key, esk)
    }

    /// Get the corresponding V4 public key for this V4 secret key
    pub fn public_key(&self) -> PublicKey {
        PublicKey((&self.1).into())
    }
}

impl PublicKey {
    /// Decode a PEM encoded SEC1 Ed25519 Secret Key
    ///
    /// ```
    /// use paseto_v4::PublicKey;
    ///
    /// let public_key = "b7715bd661458d928654d3e832f53ff5c9480542e0e3d4c9b032c768c7ce6023";
    /// let public_key = hex::decode(&public_key).unwrap();
    ///
    /// let _key = PublicKey::from_public_key(&public_key);
    /// ```
    pub fn from_public_key(key: &[u8]) -> Result<Self, PasetoError> {
        let key = key.try_into().map_err(|_| PasetoError::InvalidKey)?;
        ed25519_dalek::VerifyingKey::from_bytes(&key)
            .map(Self)
            .map_err(|_| PasetoError::InvalidKey)
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
