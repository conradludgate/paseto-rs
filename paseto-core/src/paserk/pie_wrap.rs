use alloc::boxed::Box;
use alloc::vec::Vec;
use core::fmt;
use core::marker::PhantomData;

use crate::key::{Key, KeyEncoding, SealingKey};
use crate::version::Version;
use crate::{LocalKey, PasetoError};

/// This PASETO implementation allows encrypting keys using a [`LocalKey`](crate::LocalKey)
pub trait PieWrapVersion: Version {
    /// Wrap the key
    fn pie_wrap_key(
        header: &'static str,
        wrapping_key: &Self::LocalKey,
        key_data: Vec<u8>,
    ) -> Result<Vec<u8>, PasetoError>;

    /// Unwrap the key
    fn pie_unwrap_key<'key>(
        header: &'static str,
        wrapping_key: &Self::LocalKey,
        key_data: &'key mut [u8],
    ) -> Result<&'key [u8], PasetoError>;
}

/// An symmetrically encrypted [`Key`].
///
/// * Encrypted using [`Key::wrap_pie`]
/// * Decrypted using [`PieWrappedKey::unwrap`]
pub struct PieWrappedKey<V: PieWrapVersion, K: SealingKey> {
    key_data: Box<[u8]>,
    _version: PhantomData<(V, K)>,
}

impl<V: PieWrapVersion, K: SealingKey> Key<V, K> {
    pub fn wrap_pie(self, with: &LocalKey<V>) -> Result<PieWrappedKey<V, K>, PasetoError> {
        V::pie_wrap_key(K::PIE_WRAP_HEADER, &with.0, self.0.encode().into_vec()).map(|key_data| {
            PieWrappedKey {
                key_data: key_data.into_boxed_slice(),
                _version: PhantomData,
            }
        })
    }
}

impl<V: PieWrapVersion, K: SealingKey> PieWrappedKey<V, K> {
    pub fn unwrap(mut self, with: &LocalKey<V>) -> Result<Key<V, K>, PasetoError> {
        V::pie_unwrap_key(K::PIE_WRAP_HEADER, &with.0, &mut self.key_data)
            .and_then(KeyEncoding::decode)
            .map(Key)
    }
}

impl<V: PieWrapVersion, K: SealingKey> fmt::Display for PieWrappedKey<V, K> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(V::PASERK_HEADER)?;
        f.write_str(K::PIE_WRAP_HEADER)?;
        crate::base64::write_to_fmt(&self.key_data, f)
    }
}

impl<V: PieWrapVersion, K: SealingKey> core::str::FromStr for PieWrappedKey<V, K> {
    type Err = PasetoError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s
            .strip_prefix(V::PASERK_HEADER)
            .ok_or(PasetoError::InvalidKey)?;
        let s = s
            .strip_prefix(K::PIE_WRAP_HEADER)
            .ok_or(PasetoError::InvalidKey)?;

        Ok(PieWrappedKey {
            key_data: crate::base64::decode_vec(s)?.into_boxed_slice(),
            _version: PhantomData,
        })
    }
}

serde_str!(
    impl<V, K> PieWrappedKey<V, K>
    where
        V: PieWrapVersion,
        K: SealingKey,
    {
        fn expecting() {
            format_args!(
                "a {}{} PASERK wrapped key",
                V::PASERK_HEADER,
                K::PIE_WRAP_HEADER
            )
        }
    }
);
