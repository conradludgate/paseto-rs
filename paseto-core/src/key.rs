use alloc::boxed::Box;
use core::convert::Infallible;
use core::fmt;
use core::marker::PhantomData;

use crate::PasetoError;
use crate::paserk::{IdVersion, KeyId, KeyText};
use crate::version::{Local, Marker, Public, SealingVersion, Secret, Version};

/// Defines a PASERK key type
pub trait KeyKind: Sized {
    type Version: Version;
    type KeyType: Marker;

    fn encode(&self) -> Box<[u8]>;
    fn decode(bytes: &[u8]) -> Result<Self, PasetoError>;
}

pub struct Unimplemented<V: Version, K: Marker>(Infallible, PhantomData<(V, K)>);

impl<V: Version, K: Marker> KeyKind for Unimplemented<V, K> {
    type Version = V;
    type KeyType = K;

    fn encode(&self) -> Box<[u8]> {
        match self.0 {}
    }

    fn decode(_: &[u8]) -> Result<Self, PasetoError> {
        unimplemented!("Key type {}{} is not supported", V::HEADER, K::HEADER)
    }
}

/// Generic key type.
pub struct Key<V: Version, K: Marker>(pub(crate) K::Key<V>);

impl<V: Version, K: Marker> Clone for Key<V, K>
where
    K::Key<V>: Clone,
{
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

/// Private key used for [`encryption`](crate::DecryptedToken::encrypt) and [`decryptiom`](crate::EncryptedToken::decrypt)
pub type LocalKey<V> = Key<V, Local>;
/// Public key used for signature [`verification`](crate::SignedToken::verify)
pub type PublicKey<V> = Key<V, Public>;
/// Private key used for token [`signing`](crate::VerifiedToken::sign)
pub type SecretKey<V> = Key<V, Secret>;

impl<V: Version, K: Marker> Key<V, K> {
    pub fn from_raw_bytes(b: &[u8]) -> Result<Self, PasetoError> {
        KeyKind::decode(b).map(Self)
    }

    pub fn into_raw_bytes(&self) -> Box<[u8]> {
        self.0.encode()
    }

    pub fn into_inner(self) -> K::Key<V> {
        self.0
    }

    pub fn from_inner(key: K::Key<V>) -> Self {
        Self(key)
    }

    pub fn as_inner(&self) -> &K::Key<V> {
        &self.0
    }
}

impl<V: SealingVersion<Public>> SecretKey<V> {
    pub fn random() -> Result<Self, PasetoError> {
        V::random()
    }

    pub fn public_key(&self) -> PublicKey<V> {
        V::unsealing_key(self)
    }
}

impl<V: SealingVersion<Local>> LocalKey<V> {
    pub fn random() -> Result<Self, PasetoError> {
        V::random()
    }
}

impl<V: Version> fmt::Display for PublicKey<V> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.expose_key().fmt(f)
    }
}

impl<V: Version, K: Marker> core::str::FromStr for Key<V, K> {
    type Err = PasetoError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        KeyText::<V, K>::from_str(s).and_then(|k| k.decode())
    }
}

impl<V: IdVersion, K: Marker> Key<V, K> {
    pub fn id(&self) -> KeyId<V, K> {
        KeyId::from(&self.expose_key())
    }
}
