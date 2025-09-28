use alloc::boxed::Box;
use core::fmt;
use core::marker::PhantomData;

use crate::PasetoError;
use crate::key::{Key, KeyKind};
use crate::version::{Marker, PaserkVersion};

/// A plaintext encoding of a key.
///
/// Be advised that this encoding has no extra security, so it is not safe to transport as is.
pub struct KeyText<V: PaserkVersion, K: Marker> {
    data: Box<[u8]>,
    _key: PhantomData<(V, K)>,
}

impl<V: PaserkVersion, K: Marker> Key<V, K> {
    pub fn expose_key(&self) -> KeyText<V, K> {
        KeyText {
            data: self.0.encode(),
            _key: PhantomData,
        }
    }
}

impl<V: PaserkVersion, K: Marker> PartialEq for KeyText<V, K> {
    fn eq(&self, other: &Self) -> bool {
        self.data == other.data
    }
}

impl<V: PaserkVersion, K: Marker> PartialOrd for KeyText<V, K> {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl<V: PaserkVersion, K: Marker> Eq for KeyText<V, K> {}

impl<V: PaserkVersion, K: Marker> Ord for KeyText<V, K> {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        self.data.cmp(&other.data)
    }
}

impl<V: PaserkVersion, K: Marker> core::hash::Hash for KeyText<V, K> {
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
        self.data.hash(state);
    }
}

impl<V: PaserkVersion, K: Marker> KeyText<V, K> {
    pub fn decode(&self) -> Result<Key<V, K>, PasetoError> {
        <K::Key<V>>::decode(&self.data).map(Key)
    }
}

impl<V: PaserkVersion, K: Marker> fmt::Display for KeyText<V, K> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(V::PASERK_HEADER)?;
        f.write_str(K::HEADER)?;
        crate::base64::write_to_fmt(&self.data, f)
    }
}

impl<V: PaserkVersion, K: Marker> core::str::FromStr for KeyText<V, K> {
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
        V: PaserkVersion,
        K: Marker,
    {
        fn expecting() {
            format_args!("a {}{} PASERK key", V::PASERK_HEADER, K::HEADER)
        }
    }
);
