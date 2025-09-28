use alloc::boxed::Box;
use core::fmt;
use core::marker::PhantomData;

use crate::key::Key;
use crate::version::PkeVersion;
use crate::{LocalKey, PasetoError, PublicKey, SecretKey};

/// An asymmetrically encrypted [`LocalKey`].
///
/// * Encrypted using [`LocalKey::seal`]
/// * Decrypted using [`SecretKey::unseal`]
pub struct SealedKey<V: PkeVersion> {
    key_data: Box<[u8]>,
    _version: PhantomData<V>,
}

impl<V: PkeVersion> Clone for SealedKey<V> {
    fn clone(&self) -> Self {
        Self {
            key_data: self.key_data.clone(),
            _version: self._version,
        }
    }
}

impl<V: PkeVersion> fmt::Display for SealedKey<V> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(V::PASERK_HEADER)?;
        f.write_str(".seal.")?;
        crate::base64::write_to_fmt(&self.key_data, f)
    }
}

impl<V: PkeVersion> core::str::FromStr for SealedKey<V> {
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

impl<V: PkeVersion> LocalKey<V> {
    pub fn seal(self, with: &PublicKey<V>) -> Result<SealedKey<V>, PasetoError> {
        V::seal_key(&with.0, self.0).map(|key_data| SealedKey {
            key_data,
            _version: PhantomData,
        })
    }
}

impl<V: PkeVersion> SealedKey<V> {
    pub fn unseal(self, with: &SecretKey<V>) -> Result<LocalKey<V>, PasetoError> {
        V::unseal_key(&with.0, self.key_data).map(Key)
    }
}

serde_str!(
    impl<V> SealedKey<V>
    where
        V: PkeVersion,
    {
        fn expecting() {
            format_args!("a {}.seal. PASERK sealed key", V::PASERK_HEADER)
        }
    }
);
