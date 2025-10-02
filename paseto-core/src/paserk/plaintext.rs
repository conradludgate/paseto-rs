use alloc::boxed::Box;
use core::fmt;
use core::marker::PhantomData;

use crate::PasetoError;
use crate::key::{HasKey, Key, KeyType};
use crate::version::Version;

/// A plaintext encoding of a key.
///
/// Be advised that this encoding has no extra security, so it is not safe to transport as is.
pub struct KeyText<V: Version, K: KeyType> {
    data: Box<[u8]>,
    _key: PhantomData<(V, K)>,
}

impl<V: HasKey<K>, K: KeyType> Key<V, K> {
    /// Expose the key data such that it can be serialized.
    ///
    /// Be advised that serializing key data can be dangerous. Make sure
    /// they are saved on secure disks or sent on secure connections only.
    pub fn expose_key(&self) -> KeyText<V, K> {
        KeyText {
            data: V::encode(&self.0),
            _key: PhantomData,
        }
    }
}

impl<V: Version, K: KeyType> KeyText<V, K> {
    /// Create a KeyText type from the raw key bytes.
    pub fn from_raw_bytes(b: &[u8]) -> Self {
        KeyText {
            data: b.into(),
            _key: PhantomData,
        }
    }

    /// View the raw key bytes of the key.
    pub fn as_raw_bytes(&self) -> &[u8] {
        &self.data
    }
}

impl<V: Version, K: KeyType> PartialEq for KeyText<V, K> {
    fn eq(&self, other: &Self) -> bool {
        self.data == other.data
    }
}

impl<V: Version, K: KeyType> PartialOrd for KeyText<V, K> {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl<V: Version, K: KeyType> Eq for KeyText<V, K> {}

impl<V: Version, K: KeyType> Ord for KeyText<V, K> {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        self.data.cmp(&other.data)
    }
}

impl<V: Version, K: KeyType> core::hash::Hash for KeyText<V, K> {
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
        self.data.hash(state);
    }
}

impl<V: HasKey<K>, K: KeyType> TryFrom<KeyText<V, K>> for Key<V, K> {
    type Error = PasetoError;
    fn try_from(value: KeyText<V, K>) -> Result<Key<V, K>, PasetoError> {
        V::decode(&value.data).map(Key)
    }
}

impl<V: Version, K: KeyType> fmt::Display for KeyText<V, K> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(V::PASERK_HEADER)?;
        f.write_str(K::HEADER)?;
        crate::base64::write_to_fmt(&self.data, f)
    }
}

impl<V: Version, K: KeyType> core::str::FromStr for KeyText<V, K> {
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

serde_str!(
    impl<V, K> KeyText<V, K>
    where
        V: Version,
        K: KeyType,
    {
        fn expecting() {
            format_args!("a {}{} PASERK key", V::PASERK_HEADER, K::HEADER)
        }
    }
);
