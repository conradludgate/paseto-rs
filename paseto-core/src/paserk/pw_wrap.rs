use alloc::boxed::Box;
use alloc::vec::Vec;
use core::fmt;
use core::marker::PhantomData;

use crate::PasetoError;
use crate::key::{Key, KeyEncoding, SealingKey};
use crate::version::Version;

/// This PASETO implementation allows encrypting keys using a password
pub trait PwWrapVersion: Version {
    type Params: Default;

    /// Wrap the key using a password
    fn pw_wrap_key(
        header: &'static str,
        pass: &[u8],
        params: &Self::Params,
        key_data: Vec<u8>,
    ) -> Result<Vec<u8>, PasetoError>;

    /// Extract the params from the
    fn get_params(key_data: &[u8]) -> Result<Self::Params, PasetoError>;

    /// Unwrap the key using a password
    fn pw_unwrap_key<'key>(
        header: &'static str,
        pass: &[u8],
        key_data: &'key mut [u8],
    ) -> Result<&'key [u8], PasetoError>;
}

/// An password encrypted [`Key`].
///
/// * Encrypted using [`Key::password_wrap`]
/// * Decrypted using [`PasswordWrappedKey::unwrap`]
pub struct PasswordWrappedKey<V: PwWrapVersion, K: SealingKey> {
    key_data: Box<[u8]>,
    _version: PhantomData<(V, K)>,
}

impl<V: PwWrapVersion, K: SealingKey> Key<V, K> {
    /// Encrypt the key using the password.
    pub fn password_wrap(self, pass: &[u8]) -> Result<PasswordWrappedKey<V, K>, PasetoError> {
        self.password_wrap_with_params(pass, &V::Params::default())
    }

    /// Encrypt the key using the password, configured with the specified parameters.
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

impl<V: PwWrapVersion, K: SealingKey> PasswordWrappedKey<V, K> {
    /// Extract the parameters the key was encrypted with.
    pub fn params(&self) -> Result<V::Params, PasetoError> {
        V::get_params(&self.key_data)
    }

    /// Decrypt the key using the password.
    pub fn unwrap(mut self, pass: &[u8]) -> Result<Key<V, K>, PasetoError> {
        V::pw_unwrap_key(K::PW_WRAP_HEADER, pass, &mut self.key_data)
            .and_then(KeyEncoding::decode)
            .map(Key)
    }
}

impl<V: PwWrapVersion, K: SealingKey> fmt::Display for PasswordWrappedKey<V, K> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(V::PASERK_HEADER)?;
        f.write_str(K::PW_WRAP_HEADER)?;
        crate::base64::write_to_fmt(&self.key_data, f)
    }
}

impl<V: PwWrapVersion, K: SealingKey> core::str::FromStr for PasswordWrappedKey<V, K> {
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
        K: SealingKey,
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
