use alloc::string::ToString;
use core::fmt;
use core::marker::PhantomData;

use crate::PasetoError;
use crate::key::KeyType;
use crate::paserk::KeyText;
use crate::version::Version;

/// This PASETO implementation allows extracting key ids
pub trait IdVersion: Version {
    /// How to hash some keydata for creating [`KeyId`]
    fn hash_key(key_header: &'static str, key_data: &[u8]) -> [u8; 33];
}

/// A short ID for a key.
pub struct KeyId<V: IdVersion, K: KeyType> {
    pub(crate) id: [u8; 33],
    _key: PhantomData<(V, K)>,
}

impl<V: IdVersion, K: KeyType> KeyId<V, K> {
    /// View the raw ID bytes for this key id.
    pub fn as_bytes(&self) -> &[u8; 33] {
        &self.id
    }
}

impl<V: IdVersion, K: KeyType> Copy for KeyId<V, K> {}

impl<V: IdVersion, K: KeyType> Clone for KeyId<V, K> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<V: IdVersion, K: KeyType> PartialEq for KeyId<V, K> {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
    }
}

impl<V: IdVersion, K: KeyType> PartialOrd for KeyId<V, K> {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl<V: IdVersion, K: KeyType> Eq for KeyId<V, K> {}

impl<V: IdVersion, K: KeyType> Ord for KeyId<V, K> {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        self.id.cmp(&other.id)
    }
}

impl<V: IdVersion, K: KeyType> core::hash::Hash for KeyId<V, K> {
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
        self.id.hash(state);
    }
}

impl<V: IdVersion, K: KeyType> From<&KeyText<V, K>> for KeyId<V, K> {
    fn from(value: &KeyText<V, K>) -> Self {
        Self {
            id: V::hash_key(K::ID_HEADER, value.to_string().as_bytes()),
            _key: PhantomData,
        }
    }
}

impl<V: IdVersion, K: KeyType> fmt::Display for KeyId<V, K> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(V::PASERK_HEADER)?;
        f.write_str(K::ID_HEADER)?;
        crate::base64::write_to_fmt(&self.id, f)
    }
}

impl<V: IdVersion, K: KeyType> core::str::FromStr for KeyId<V, K> {
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

serde_str!(
    impl<V, K> KeyId<V, K>
    where
        V: IdVersion,
        K: KeyType,
    {
        fn expecting() {
            format_args!("a {}{} PASERK key id", V::PASERK_HEADER, K::ID_HEADER)
        }
    }
);
