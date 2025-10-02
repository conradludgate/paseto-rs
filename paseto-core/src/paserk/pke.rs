use alloc::boxed::Box;
use core::fmt;
use core::marker::PhantomData;

use crate::key::{HasKey, Key, KeyInner};
use crate::version::{Local, PkePublic, PkeSecret, Version};
use crate::{LocalKey, PasetoError};

/// This PASETO implementation allows encrypting keys using a [`PublicKey`](crate::PublicKey)
pub trait PkeSealingVersion: Version + HasKey<Local> + HasKey<PkePublic> {
    /// Seal the key using the public key
    fn seal_key(
        sealing_key: &KeyInner<Self, PkePublic>,
        key: KeyInner<Self, Local>,
    ) -> Result<Box<[u8]>, PasetoError>;
}

/// This PASETO implementation allows decrypting keys using a [`SecretKey`](crate::SecretKey)
pub trait PkeUnsealingVersion: Version + HasKey<Local> + HasKey<PkeSecret> {
    /// Unseal the key using the secret key
    fn unseal_key(
        sealing_key: &KeyInner<Self, PkeSecret>,
        key_data: Box<[u8]>,
    ) -> Result<KeyInner<Self, Local>, PasetoError>;
}

/// An asymmetrically encrypted [`LocalKey`].
///
/// * Encrypted using [`LocalKey::seal`]
/// * Decrypted using [`SealedKey::unseal`]
pub struct SealedKey<V: Version> {
    key_data: Box<[u8]>,
    _version: PhantomData<V>,
}

impl<V: Version> Clone for SealedKey<V> {
    fn clone(&self) -> Self {
        Self {
            key_data: self.key_data.clone(),
            _version: self._version,
        }
    }
}

impl<V: Version> fmt::Display for SealedKey<V> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(V::PASERK_HEADER)?;
        f.write_str(".seal.")?;
        crate::base64::write_to_fmt(&self.key_data, f)
    }
}

impl<V: Version> core::str::FromStr for SealedKey<V> {
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

impl<V: PkeSealingVersion> LocalKey<V> {
    /// Encrypt the key such that it can only be decrypted by the resspective secret key.
    pub fn seal(self, with: &Key<V, PkePublic>) -> Result<SealedKey<V>, PasetoError> {
        V::seal_key(&with.0, self.0).map(|key_data| SealedKey {
            key_data,
            _version: PhantomData,
        })
    }
}

impl<V: PkeUnsealingVersion> SealedKey<V> {
    /// Decrypt the sealed key.
    pub fn unseal(self, with: &Key<V, PkeSecret>) -> Result<LocalKey<V>, PasetoError> {
        V::unseal_key(&with.0, self.key_data).map(Key)
    }
}

serde_str!(
    impl<V> SealedKey<V>
    where
        V: PkeSealingVersion,
    {
        fn expecting() {
            format_args!("a {}.seal. PASERK sealed key", V::PASERK_HEADER)
        }
    }
);
