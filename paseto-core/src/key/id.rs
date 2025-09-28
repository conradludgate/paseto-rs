use alloc::string::ToString;
use core::fmt;
use core::marker::PhantomData;

use crate::PasetoError;
use crate::key::KeyText;
use crate::version::{Marker, PaserkVersion};

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
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl<V: PaserkVersion, K: Marker> Eq for KeyId<V, K> {}

impl<V: PaserkVersion, K: Marker> Ord for KeyId<V, K> {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        self.id.cmp(&other.id)
    }
}

impl<V: PaserkVersion, K: Marker> core::hash::Hash for KeyId<V, K> {
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
        self.id.hash(state);
    }
}

impl<V: PaserkVersion, K: Marker> From<&KeyText<V, K>> for KeyId<V, K> {
    fn from(value: &KeyText<V, K>) -> Self {
        Self {
            id: V::hash_key(K::ID_HEADER, value.to_string().as_bytes()),
            _key: PhantomData,
        }
    }
}

impl<V: PaserkVersion, K: Marker> fmt::Display for KeyId<V, K> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(V::PASERK_HEADER)?;
        f.write_str(K::ID_HEADER)?;
        crate::base64::write_to_fmt(&self.id, f)
    }
}

impl<V: PaserkVersion, K: Marker> core::str::FromStr for KeyId<V, K> {
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
        V: PaserkVersion,
        K: Marker,
    {
        fn expecting() {
            format_args!("a {}{} PASERK key id", V::PASERK_HEADER, K::ID_HEADER)
        }
    }
);
