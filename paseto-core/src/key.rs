use core::fmt;
use std::hash::Hash;
use std::marker::PhantomData;

use crate::PasetoError;
use crate::version::{self, Marker, PaserkVersion};

/// Defines a PASERK key type
pub trait Key: Sized {
    type Version: version::Version;
    type KeyType: Marker;

    fn encode(&self) -> Box<[u8]>;
    fn decode(bytes: &[u8]) -> Result<Self, PasetoError>;
}

/// Defines a secret PASETO key that can be used to create PASETO tokens.
///
/// We define "sealing" as encrypting or deriving a new signature.
pub trait SealingKey<Purpose>: Key {
    /// The type of key that can unseal the tokens we will seal.
    type UnsealingKey: UnsealingKey<Purpose, Version = Self::Version>;

    /// Generate the key that can unseal the tokens this key will seal.
    fn unsealing_key(&self) -> Self::UnsealingKey;

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
pub trait UnsealingKey<Purpose>: Key {
    fn unseal<'a>(
        &self,
        encoding: &'static str,
        payload: &'a mut [u8],
        footer: &[u8],
        aad: &[u8],
    ) -> Result<&'a [u8], PasetoError>;
}

/// A short ID for a key.
pub struct KeyId<K: Key> {
    id: [u8; 33],
    _key: PhantomData<K>,
}

impl<K: Key> PartialEq for KeyId<K> {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
    }
}

impl<K: Key> PartialOrd for KeyId<K> {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl<K: Key> Eq for KeyId<K> {}

impl<K: Key> Ord for KeyId<K> {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.id.cmp(&other.id)
    }
}

impl<K: Key> Hash for KeyId<K> {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.id.hash(state);
    }
}

impl<K: Key> From<&KeyText<K>> for KeyId<K>
where
    K::Version: PaserkVersion,
{
    fn from(value: &KeyText<K>) -> Self {
        Self {
            id: <K::Version as PaserkVersion>::hash_key(
                <K::KeyType as Marker>::ID_HEADER,
                value.to_string().as_bytes(),
            ),
            _key: value._key,
        }
    }
}

/// A plaintext encoding of a key.
///
/// Be advised that this encoding has no extra security, so it is not safe to transport as is.
pub struct KeyText<K: Key> {
    data: Box<[u8]>,
    _key: PhantomData<K>,
}

impl<K: Key> PartialEq for KeyText<K> {
    fn eq(&self, other: &Self) -> bool {
        self.data == other.data
    }
}

impl<K: Key> PartialOrd for KeyText<K> {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl<K: Key> Eq for KeyText<K> {}

impl<K: Key> Ord for KeyText<K> {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.data.cmp(&other.data)
    }
}

impl<K: Key> Hash for KeyText<K> {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.data.hash(state);
    }
}

impl<K: Key> KeyText<K> {
    pub fn decode(&self) -> Result<K, PasetoError> {
        K::decode(&self.data)
    }
}

impl<K: Key> From<&K> for KeyText<K> {
    fn from(value: &K) -> Self {
        Self {
            data: value.encode(),
            _key: PhantomData,
        }
    }
}

impl<K: Key> fmt::Display for KeyId<K>
where
    K::Version: PaserkVersion,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(<K::Version as PaserkVersion>::PASERK_HEADER)?;
        f.write_str(<K::KeyType as Marker>::ID_HEADER)?;
        crate::base64::write_to_fmt(&self.id, f)
    }
}

impl<K: Key> std::str::FromStr for KeyId<K>
where
    K::Version: PaserkVersion,
{
    type Err = PasetoError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s
            .strip_prefix(<K::Version as PaserkVersion>::PASERK_HEADER)
            .ok_or(PasetoError::InvalidKey)?;
        let s = s
            .strip_prefix(<K::KeyType as Marker>::ID_HEADER)
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

impl<K: Key> fmt::Display for KeyText<K>
where
    K::Version: PaserkVersion,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(<K::Version as PaserkVersion>::PASERK_HEADER)?;
        f.write_str(<K::KeyType as Marker>::HEADER)?;
        crate::base64::write_to_fmt(&self.data, f)
    }
}

impl<K: Key> std::str::FromStr for KeyText<K>
where
    K::Version: PaserkVersion,
{
    type Err = PasetoError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s
            .strip_prefix(<K::Version as PaserkVersion>::PASERK_HEADER)
            .ok_or(PasetoError::InvalidKey)?;
        let s = s
            .strip_prefix(<K::KeyType as Marker>::HEADER)
            .ok_or(PasetoError::InvalidKey)?;

        let data = crate::base64::decode_vec(s)?.into_boxed_slice();

        Ok(Self {
            data,
            _key: PhantomData,
        })
    }
}

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

impl<V: PaserkVersion> SealedKey<V> {
    pub fn seal(key: V::LocalKey, with: &V::PublicKey) -> Result<Self, PasetoError> {
        V::seal_key(with, key).map(|key_data| SealedKey {
            key_data,
            _version: PhantomData,
        })
    }

    pub fn unseal(self, with: &V::SecretKey) -> Result<V::LocalKey, PasetoError> {
        V::unseal_key(with, self.key_data)
    }
}
