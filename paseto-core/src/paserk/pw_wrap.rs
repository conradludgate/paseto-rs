use alloc::boxed::Box;
use core::fmt;
use core::marker::PhantomData;

use crate::PasetoError;
use crate::key::{Key, KeyKind};
use crate::paserk::PwWrapVersion;
use crate::version::SealingMarker;

/// An password encrypted [`Key`].
///
/// * Encrypted using [`Key::password_wrap`]
/// * Decrypted using [`PasswordWrappedKey::unwrap`]
pub struct PasswordWrappedKey<V: PwWrapVersion, K: SealingMarker> {
    key_data: Box<[u8]>,
    _version: PhantomData<(V, K)>,
}

impl<V: PwWrapVersion, K: SealingMarker> Key<V, K> {
    pub fn password_wrap(self, pass: &[u8]) -> Result<PasswordWrappedKey<V, K>, PasetoError> {
        self.password_wrap_with_params(pass, &V::Params::default())
    }

    pub fn password_wrap_with_params(
        self,
        pass: &[u8],
        params: &V::Params,
    ) -> Result<PasswordWrappedKey<V, K>, PasetoError> {
        V::pw_wrap_key(K::PW_WRAP_HEADER, pass, params, self.0.encode().into_vec()).map(
            |key_data| PasswordWrappedKey {
                key_data: key_data.into_boxed_slice(),
                _version: PhantomData,
            },
        )
    }
}

impl<V: PwWrapVersion, K: SealingMarker> PasswordWrappedKey<V, K> {
    pub fn params(&self) -> Result<V::Params, PasetoError> {
        V::get_params(&self.key_data)
    }

    pub fn unwrap(mut self, pass: &[u8]) -> Result<Key<V, K>, PasetoError> {
        V::pw_unwrap_key(K::PW_WRAP_HEADER, pass, &mut self.key_data)
            .and_then(KeyKind::decode)
            .map(Key)
    }
}

impl<V: PwWrapVersion, K: SealingMarker> fmt::Display for PasswordWrappedKey<V, K> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(V::PASERK_HEADER)?;
        f.write_str(K::PW_WRAP_HEADER)?;
        crate::base64::write_to_fmt(&self.key_data, f)
    }
}

impl<V: PwWrapVersion, K: SealingMarker> core::str::FromStr for PasswordWrappedKey<V, K> {
    type Err = PasetoError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s
            .strip_prefix(V::PASERK_HEADER)
            .ok_or(PasetoError::InvalidKey)?;
        let s = s
            .strip_prefix(K::PW_WRAP_HEADER)
            .ok_or(PasetoError::InvalidKey)?;

        Ok(PasswordWrappedKey {
            key_data: crate::base64::decode_vec(s)?.into_boxed_slice(),
            _version: PhantomData,
        })
    }
}

serde_str!(
    impl<V, K> PasswordWrappedKey<V, K>
    where
        V: PwWrapVersion,
        K: SealingMarker,
    {
        fn expecting() {
            format_args!(
                "a {}{} PASERK password wrapped key",
                V::PASERK_HEADER,
                K::PW_WRAP_HEADER
            )
        }
    }
);
