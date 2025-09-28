use core::fmt;
use std::hash::Hash;
use std::marker::PhantomData;
use std::str::FromStr;

use crate::PasetoError;
use crate::version::{Local, Marker, PaserkVersion, Public, Purpose, Secret, Version};

/// Defines a PASERK key type
pub trait KeyKind: Sized {
    type Version: Version;
    type KeyType: Marker;

    fn encode(&self) -> Box<[u8]>;
    fn decode(bytes: &[u8]) -> Result<Self, PasetoError>;
}

/// Generic key type.
pub struct Key<V: Version, K: Marker>(pub(crate) K::Key<V>);

impl<V: Version, K: Marker> Clone for Key<V, K>
where
    K::Key<V>: Clone,
{
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

/// Private key used for [`encryption`](crate::DecryptedToken::encrypt) and [`decryptiom`](crate::EncryptedToken::decrypt)
pub type LocalKey<V> = Key<V, Local>;
/// Public key used for signature [`verification`](crate::SignedToken::verify)
pub type PublicKey<V> = Key<V, Public>;
/// Private key used for token [`signing`](crate::VerifiedToken::sign)
pub type SecretKey<V> = Key<V, Secret>;

impl<V: PaserkVersion, K: Marker> FromStr for Key<V, K> {
    type Err = PasetoError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        KeyText::<V, K>::from_str(s).and_then(|k| k.decode())
    }
}

impl<V: Version, K: Marker> Key<V, K> {
    pub fn from_raw_bytes(b: &[u8]) -> Result<Self, PasetoError> {
        KeyKind::decode(b).map(Self)
    }

    pub fn into_raw_bytes(&self) -> Box<[u8]> {
        self.0.encode()
    }
}

impl<V: Version> SecretKey<V> {
    pub fn random() -> Result<Self, PasetoError> {
        SealingKey::random().map(Self)
    }

    pub fn public_key(&self) -> PublicKey<V> {
        Key(self.0.unsealing_key())
    }
}

impl<V: Version> LocalKey<V> {
    pub fn random() -> Result<Self, PasetoError> {
        SealingKey::random().map(Self)
    }
}

impl<V: PaserkVersion> fmt::Display for PublicKey<V> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.expose_key().fmt(f)
    }
}

impl<V: PaserkVersion, K: Marker> Key<V, K> {
    pub fn expose_key(&self) -> KeyText<V, K> {
        KeyText {
            data: self.0.encode(),
            _key: PhantomData,
        }
    }

    pub fn id(&self) -> KeyId<V, K> {
        KeyId::from(&self.expose_key())
    }
}

/// Defines a secret PASETO key that can be used to create PASETO tokens.
///
/// We define "sealing" as encrypting or deriving a new signature.
pub trait SealingKey<P: Purpose>: KeyKind {
    /// Generate the key that can unseal the tokens this key will seal.
    fn unsealing_key(&self) -> <P::UnsealingMarker as Marker>::Key<Self::Version>;

    /// Generate a random key
    fn random() -> Result<Self, PasetoError>;

    /// Do not call this method directly.
    fn nonce() -> Result<Vec<u8>, PasetoError>;

    /// Do not call this method directly. Use [`UnsealedToken::seal`](crate::tokens::UnsealedToken::seal) instead.
    fn dangerous_seal_with_nonce(
        &self,
        encoding: &'static str,
        nonce: Vec<u8>,
        footer: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, PasetoError>;
}

/// Defines a PASETO key that can be used to validate and read PASETO tokens.
///
/// We define "unsealing" as decrypting or validating a signature.
pub trait UnsealingKey<Purpose>: KeyKind {
    fn unseal<'a>(
        &self,
        encoding: &'static str,
        payload: &'a mut [u8],
        footer: &[u8],
        aad: &[u8],
    ) -> Result<&'a [u8], PasetoError>;
}

/// A short ID for a key.
pub struct KeyId<V: PaserkVersion, K: Marker> {
    pub(crate) id: [u8; 33],
    _key: PhantomData<(V, K)>,
}

impl<V: PaserkVersion, K: Marker> Copy for KeyId<V, K> {}

impl<V: PaserkVersion, K: Marker> Clone for KeyId<V, K> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<V: PaserkVersion, K: Marker> PartialEq for KeyId<V, K> {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
    }
}

impl<V: PaserkVersion, K: Marker> PartialOrd for KeyId<V, K> {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl<V: PaserkVersion, K: Marker> Eq for KeyId<V, K> {}

impl<V: PaserkVersion, K: Marker> Ord for KeyId<V, K> {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.id.cmp(&other.id)
    }
}

impl<V: PaserkVersion, K: Marker> Hash for KeyId<V, K> {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.id.hash(state);
    }
}

impl<V: PaserkVersion, K: Marker> From<&KeyText<V, K>> for KeyId<V, K> {
    fn from(value: &KeyText<V, K>) -> Self {
        Self {
            id: V::hash_key(K::ID_HEADER, value.to_string().as_bytes()),
            _key: value._key,
        }
    }
}

/// A plaintext encoding of a key.
///
/// Be advised that this encoding has no extra security, so it is not safe to transport as is.
pub struct KeyText<V: PaserkVersion, K: Marker> {
    data: Box<[u8]>,
    _key: PhantomData<(V, K)>,
}

impl<V: PaserkVersion, K: Marker> PartialEq for KeyText<V, K> {
    fn eq(&self, other: &Self) -> bool {
        self.data == other.data
    }
}

impl<V: PaserkVersion, K: Marker> PartialOrd for KeyText<V, K> {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl<V: PaserkVersion, K: Marker> Eq for KeyText<V, K> {}

impl<V: PaserkVersion, K: Marker> Ord for KeyText<V, K> {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.data.cmp(&other.data)
    }
}

impl<V: PaserkVersion, K: Marker> Hash for KeyText<V, K> {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.data.hash(state);
    }
}

impl<V: PaserkVersion, K: Marker> KeyText<V, K> {
    pub fn decode(&self) -> Result<Key<V, K>, PasetoError> {
        <K::Key<V>>::decode(&self.data).map(Key)
    }
}

impl<V: PaserkVersion, K: Marker> fmt::Display for KeyId<V, K> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(V::PASERK_HEADER)?;
        f.write_str(K::ID_HEADER)?;
        crate::base64::write_to_fmt(&self.id, f)
    }
}

impl<V: PaserkVersion, K: Marker> std::str::FromStr for KeyId<V, K> {
    type Err = PasetoError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s
            .strip_prefix(V::PASERK_HEADER)
            .ok_or(PasetoError::InvalidKey)?;
        let s = s
            .strip_prefix(K::ID_HEADER)
            .ok_or(PasetoError::InvalidKey)?;

        let mut id = [0u8; 33];
        if crate::base64::decode(s, &mut id)?.len() != 33 {
            return Err(PasetoError::InvalidKey);
        }

        Ok(Self {
            id,
            _key: PhantomData,
        })
    }
}

impl<V: PaserkVersion, K: Marker> fmt::Display for KeyText<V, K> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(V::PASERK_HEADER)?;
        f.write_str(K::HEADER)?;
        crate::base64::write_to_fmt(&self.data, f)
    }
}

impl<V: PaserkVersion, K: Marker> std::str::FromStr for KeyText<V, K> {
    type Err = PasetoError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s
            .strip_prefix(V::PASERK_HEADER)
            .ok_or(PasetoError::InvalidKey)?;
        let s = s.strip_prefix(K::HEADER).ok_or(PasetoError::InvalidKey)?;

        let data = crate::base64::decode_vec(s)?.into_boxed_slice();

        Ok(Self {
            data,
            _key: PhantomData,
        })
    }
}

/// An asymmetrically encrypted [`LocalKey`].
///
/// * Encrypted using [`PublicKey::seal`]
/// * Decrypted using [`SecretKey::unseal`]
pub struct SealedKey<V: PaserkVersion> {
    key_data: Box<[u8]>,
    _version: PhantomData<V>,
}

impl<V: PaserkVersion> Clone for SealedKey<V> {
    fn clone(&self) -> Self {
        Self {
            key_data: self.key_data.clone(),
            _version: self._version,
        }
    }
}

impl<V: PaserkVersion> fmt::Display for SealedKey<V> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(V::PASERK_HEADER)?;
        f.write_str(".seal.")?;
        crate::base64::write_to_fmt(&self.key_data, f)
    }
}

impl<V: PaserkVersion> std::str::FromStr for SealedKey<V> {
    type Err = PasetoError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s
            .strip_prefix(V::PASERK_HEADER)
            .ok_or(PasetoError::InvalidKey)?;
        let s = s.strip_prefix(".seal.").ok_or(PasetoError::InvalidKey)?;

        Ok(SealedKey {
            key_data: crate::base64::decode_vec(s)?.into_boxed_slice(),
            _version: PhantomData,
        })
    }
}

impl<V: PaserkVersion> PublicKey<V> {
    pub fn seal(&self, key: LocalKey<V>) -> Result<SealedKey<V>, PasetoError> {
        V::seal_key(&self.0, key.0).map(|key_data| SealedKey {
            key_data,
            _version: PhantomData,
        })
    }
}

impl<V: PaserkVersion> SecretKey<V> {
    pub fn unseal(&self, key: SealedKey<V>) -> Result<LocalKey<V>, PasetoError> {
        V::unseal_key(&self.0, key.key_data).map(Key)
    }
}
