//! Core traits and types for PASETO keys.

use alloc::boxed::Box;
use core::fmt;

use crate::paserk::{IdVersion, KeyId, KeyText};
use crate::sealed::Sealed;
use crate::version::{Local, PkePublic, PkeSecret, Public, SealingVersion, Secret, Version};
use crate::{LocalKey, PasetoError, PublicKey, SecretKey};

pub(crate) type KeyInner<V, K> = <V as HasKey<K>>::Key;

/// Generic key type.
pub struct Key<V: HasKey<K>, K: KeyType>(pub(crate) KeyInner<V, K>);

impl<V: HasKey<K>, K: KeyType> Clone for Key<V, K>
where
    KeyInner<V, K>: Clone,
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

impl<V: SealingVersion<Local>> From<[u8; 32]> for LocalKey<V> {
    fn from(value: [u8; 32]) -> Self {
        Self(V::decode(&value[..]).expect("all 32 bytes should be valid local keys"))
    }
}

impl<V: HasKey<Public>> fmt::Display for PublicKey<V> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.expose_key().fmt(f)
    }
}

impl<V: HasKey<K>, K: KeyType> core::str::FromStr for Key<V, K> {
    type Err = PasetoError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        KeyText::<V, K>::from_str(s).and_then(|k| k.try_into())
    }
}

impl<V: IdVersion + HasKey<K>, K: KeyType> Key<V, K> {
    /// Generate the ID of this key
    pub fn id(&self) -> KeyId<V, K> {
        KeyId::from(&self.expose_key())
    }
}

/// Declares that this PASETO implementation supports the given key type,
/// as well as how to encode/decode the key.
pub trait HasKey<K>: Version {
    type Key;

    /// Encode the key into bytes.
    fn encode(key: &Self::Key) -> Box<[u8]>;

    /// Decode the key from bytes.
    fn decode(bytes: &[u8]) -> Result<Self::Key, PasetoError>;
}

/// A marker for [`Secret`], [`Public`], and [`Local`]
pub trait KeyType: Send + Sync + Sealed + Sized + 'static {
    /// ".local." or ".public." or ".secret."
    const HEADER: &'static str;
    /// ".lid." or ".pid." or ".sid."
    const ID_HEADER: &'static str;
}

/// A marker for [`Secret`] and [`Local`] keys, used for signing and encrypting tokens.
pub trait SealingKey: KeyType {
    const PIE_WRAP_HEADER: &'static str;
    const PW_WRAP_HEADER: &'static str;
}

impl KeyType for Secret {
    const HEADER: &'static str = ".secret.";
    const ID_HEADER: &'static str = ".sid.";
}

impl SealingKey for Secret {
    const PIE_WRAP_HEADER: &'static str = ".secret-wrap.pie.";
    const PW_WRAP_HEADER: &'static str = ".secret-pw.";
}

impl KeyType for Public {
    const HEADER: &'static str = ".public.";
    const ID_HEADER: &'static str = ".pid.";
}

impl KeyType for Local {
    const HEADER: &'static str = ".local.";
    const ID_HEADER: &'static str = ".lid.";
}

impl SealingKey for Local {
    const PIE_WRAP_HEADER: &'static str = ".local-wrap.pie.";
    const PW_WRAP_HEADER: &'static str = ".local-pw.";
}

impl KeyType for PkeSecret {
    const HEADER: &'static str = ".secret.";
    const ID_HEADER: &'static str = ".sid.";
}

impl KeyType for PkePublic {
    const HEADER: &'static str = ".public.";
    const ID_HEADER: &'static str = ".pid.";
}
