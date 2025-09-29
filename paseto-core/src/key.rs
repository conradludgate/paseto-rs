use alloc::boxed::Box;
use alloc::vec::Vec;
use core::fmt;

use crate::PasetoError;
use crate::paserk::{KeyId, KeyText, PaserkVersion};
use crate::version::{Local, Marker, Public, Purpose, Secret, Version};

/// Defines a PASERK key type
pub trait KeyKind: Sized {
    type Version: Version;
    type KeyType: Marker;

    fn encode(&self) -> Box<[u8]>;
    fn decode(bytes: &[u8]) -> Result<Self, PasetoError>;
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
}

impl<V: Version> SecretKey<V> {
    pub fn random() -> Result<Self, PasetoError> {
        SealingKey::random().map(Self)
    }

    pub fn public_key(&self) -> PublicKey<V> {
        Key(self.0.unsealing_key())
    }
}

impl<V: Version> LocalKey<V> {
    pub fn random() -> Result<Self, PasetoError> {
        SealingKey::random().map(Self)
    }
}

impl<V: PaserkVersion> fmt::Display for PublicKey<V> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.expose_key().fmt(f)
    }
}

impl<V: PaserkVersion, K: Marker> core::str::FromStr for Key<V, K> {
    type Err = PasetoError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        KeyText::<V, K>::from_str(s).and_then(|k| k.decode())
    }
}

impl<V: PaserkVersion, K: Marker> Key<V, K> {
    pub fn id(&self) -> KeyId<V, K> {
        KeyId::from(&self.expose_key())
    }
}

/// Defines a secret PASETO key that can be used to create PASETO tokens.
///
/// We define "sealing" as encrypting or deriving a new signature.
pub trait SealingKey<P: Purpose>: KeyKind {
    /// Generate the key that can unseal the tokens this key will seal.
    fn unsealing_key(&self) -> <P::UnsealingMarker as Marker>::Key<Self::Version>;

    /// Generate a random key
    fn random() -> Result<Self, PasetoError>;

    /// Do not call this method directly.
    fn nonce() -> Result<Vec<u8>, PasetoError>;

    /// Do not call this method directly. Use [`UnsealedToken::seal`](crate::tokens::UnsealedToken::seal) instead.
    fn dangerous_seal_with_nonce(
        &self,
        encoding: &'static str,
        nonce: Vec<u8>,
        footer: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, PasetoError>;
}

/// Defines a PASETO key that can be used to validate and read PASETO tokens.
///
/// We define "unsealing" as decrypting or validating a signature.
pub trait UnsealingKey<Purpose>: KeyKind {
    fn unseal<'a>(
        &self,
        encoding: &'static str,
        payload: &'a mut [u8],
        footer: &[u8],
        aad: &[u8],
    ) -> Result<&'a [u8], PasetoError>;
}
