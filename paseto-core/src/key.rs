use core::fmt;
use std::hash::Hash;
use std::marker::PhantomData;

use base64ct::Encoding;
use rand_core::TryCryptoRng;

use crate::PasetoError;
use crate::version::{self, Marker};

/// Defines a PASERK key type
pub trait Key: Clone {
    type Version: version::Version;
    type KeyType: Marker;

    fn encode(&self) -> Box<[u8]>;
    fn decode(bytes: &[u8]) -> Result<Self, PasetoError>;
}

/// Defines a secret PASETO key that can be used to create PASETO tokens.
///
/// We define "sealing" as encrypting or deriving a new signature.
pub trait SealingKey<Purpose>: Key {
    type UnsealingKey: UnsealingKey<Purpose, Version = Self::Version>;
    fn unsealing_key(&self) -> Self::UnsealingKey;

    fn random(rng: &mut impl TryCryptoRng) -> Result<Self, PasetoError>;

    fn nonce(rng: &mut impl TryCryptoRng) -> Result<Vec<u8>, PasetoError>;

    fn seal(
        &self,
        encoding: &'static str,
        payload: Vec<u8>,
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

impl<K: Key> From<&KeyText<K>> for KeyId<K> {
    fn from(value: &KeyText<K>) -> Self {
        Self {
            id: <K::Version as version::Version>::hash_key(
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

impl<K: Key> fmt::Display for KeyId<K> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(<K::Version as version::Version>::PASERK_HEADER)?;
        f.write_str(<K::KeyType as Marker>::ID_HEADER)?;

        let mut id = [0u8; 44];
        let id = &<base64ct::Base64UrlUnpadded as Encoding>::encode(&self.id, &mut id)
            .map_err(|_| fmt::Error)?;
        f.write_str(id)
    }
}

impl<K: Key> std::str::FromStr for KeyId<K> {
    type Err = PasetoError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s
            .strip_prefix(<K::Version as version::Version>::PASERK_HEADER)
            .ok_or(PasetoError::InvalidKey)?;
        let s = s
            .strip_prefix(<K::KeyType as Marker>::ID_HEADER)
            .ok_or(PasetoError::InvalidKey)?;

        let mut id = [0u8; 33];
        let len = <base64ct::Base64UrlUnpadded as Encoding>::decode(s, &mut id)
            .map_err(|_| PasetoError::Base64DecodeError)?
            .len();

        if len != 33 {
            return Err(PasetoError::InvalidKey);
        }

        Ok(Self {
            id,
            _key: PhantomData,
        })
    }
}

impl<K: Key> fmt::Display for KeyText<K> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(<K::Version as version::Version>::PASERK_HEADER)?;
        f.write_str(<K::KeyType as Marker>::HEADER)?;
        f.write_str(&base64ct::Base64UrlUnpadded::encode_string(&self.data))
    }
}

impl<K: Key> std::str::FromStr for KeyText<K> {
    type Err = PasetoError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s
            .strip_prefix(<K::Version as version::Version>::PASERK_HEADER)
            .ok_or(PasetoError::InvalidKey)?;
        let s = s
            .strip_prefix(<K::KeyType as Marker>::HEADER)
            .ok_or(PasetoError::InvalidKey)?;

        let data = base64ct::Base64UrlUnpadded::decode_vec(s)
            .map_err(|_| PasetoError::Base64DecodeError)?
            .into_boxed_slice();

        Ok(Self {
            data,
            _key: PhantomData,
        })
    }
}
