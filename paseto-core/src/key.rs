//! Core traits and types for PASETO keys.

use alloc::boxed::Box;
use core::convert::Infallible;
use core::fmt;
use core::marker::PhantomData;

use crate::paserk::{IdVersion, KeyId, KeyText};
use crate::sealed::Sealed;
use crate::version::{Local, Public, SealingVersion, Secret, Version};
use crate::{LocalKey, PasetoError, PublicKey, SecretKey};

pub(crate) type KeyInner<V, K> = <K as KeyType>::Key<V>;

/// Generic key type.
pub struct Key<V: Version, K: KeyType>(pub(crate) KeyInner<V, K>);

impl<V: Version, K: KeyType> Clone for Key<V, K>
where
    K::Key<V>: Clone,
{
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl<V: SealingVersion<Public>> SecretKey<V> {
    /// Generate a random secret key
    pub fn random() -> Result<Self, PasetoError> {
        V::random().map(Self)
    }

    /// Derive the associated public key
    pub fn public_key(&self) -> PublicKey<V> {
        Key(V::unsealing_key(&self.0))
    }
}

impl<V: SealingVersion<Local>> LocalKey<V> {
    /// Generate a random local key
    pub fn random() -> Result<Self, PasetoError> {
        V::random().map(Self)
    }
}

impl<V: Version> fmt::Display for PublicKey<V> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.expose_key().fmt(f)
    }
}

impl<V: Version, K: KeyType> core::str::FromStr for Key<V, K> {
    type Err = PasetoError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        KeyText::<V, K>::from_str(s).and_then(|k| k.try_into())
    }
}

impl<V: IdVersion, K: KeyType> Key<V, K> {
    /// Generate the ID of this key
    pub fn id(&self) -> KeyId<V, K> {
        KeyId::from(&self.expose_key())
    }
}

/// A marker for [`Secret`], [`Public`], and [`Local`]
pub trait KeyType: Send + Sync + Sealed + Sized + 'static {
    /// ".local." or ".public." or ".secret."
    const HEADER: &'static str;
    /// ".lid." or ".pid." or ".sid."
    const ID_HEADER: &'static str;

    /// The key to extract from the version.
    type Key<V: Version>: KeyEncoding<Version = V, KeyType = Self>;
}

/// A marker for [`Secret`] and [`Local`] keys, used for signing and encrypting tokens.
pub trait SealingKey: KeyType {
    const PIE_WRAP_HEADER: &'static str;
    const PW_WRAP_HEADER: &'static str;
}

impl KeyType for Secret {
    const HEADER: &'static str = ".secret.";
    const ID_HEADER: &'static str = ".sid.";

    type Key<V: Version> = V::SecretKey;
}

impl SealingKey for Secret {
    const PIE_WRAP_HEADER: &'static str = ".secret-wrap.pie.";
    const PW_WRAP_HEADER: &'static str = ".secret-pw.";
}

impl KeyType for Public {
    const HEADER: &'static str = ".public.";
    const ID_HEADER: &'static str = ".pid.";

    type Key<V: Version> = V::PublicKey;
}

impl KeyType for Local {
    const HEADER: &'static str = ".local.";
    const ID_HEADER: &'static str = ".lid.";

    type Key<V: Version> = V::LocalKey;
}

impl SealingKey for Local {
    const PIE_WRAP_HEADER: &'static str = ".local-wrap.pie.";
    const PW_WRAP_HEADER: &'static str = ".local-pw.";
}

/// Defines a PASETO key encoding and decoding
pub trait KeyEncoding: Sized {
    /// The version of PASETO this key is bound to.
    type Version: Version;
    /// The kind of key, [`Local`], [`Public`], or [`Secret`].
    type KeyType: KeyType;

    /// Encode the key into bytes.
    fn encode(&self) -> Box<[u8]>;
    /// Decode the key from bytes.
    fn decode(bytes: &[u8]) -> Result<Self, PasetoError>;
}

/// An unimplemented key. Useful if you don't want to implement some of the PASETO operations.
pub struct Unimplemented<V: Version, K: KeyType>(Infallible, PhantomData<(V, K)>);

impl<V: Version, K: KeyType> KeyEncoding for Unimplemented<V, K> {
    type Version = V;
    type KeyType = K;

    fn encode(&self) -> Box<[u8]> {
        match self.0 {}
    }

    fn decode(_: &[u8]) -> Result<Self, PasetoError> {
        unimplemented!("Key type {}{} is not supported", V::HEADER, K::HEADER)
    }
}
