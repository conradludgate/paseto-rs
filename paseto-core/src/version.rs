use core::fmt;

use crate::PasetoError;
use crate::key::{Key, SealingKey, UnsealingKey};
use crate::sealed::Sealed;

/// An implementation of the PASETO cryptographic schemes.
pub trait Version: 'static {
    /// Header for PASETO
    const HEADER: &'static str;

    /// A symmetric key used to encrypt and decrypt tokens.
    type LocalKey: SealingKey<Local> + UnsealingKey<Local> + Key<Version = Self, KeyType = Local>;
    /// An asymmetric key used to validate token signatures.
    type PublicKey: UnsealingKey<Public> + Key<Version = Self, KeyType = Public> + fmt::Display;
    /// An asymmetric key used to create token signatures.
    type SecretKey: SealingKey<Public> + Key<Version = Self, KeyType = Secret>;
}

/// An implementation of the PASERK cryptographic schemes.
pub trait PaserkVersion: Version {
    /// Header for PASERK
    const PASERK_HEADER: &'static str;

    /// How to hash some keydata for creating [`KeyId`](crate::key::KeyId)
    fn hash_key(key_header: &'static str, key_data: &[u8]) -> [u8; 33];

    fn seal_key(
        sealing_key: &Self::PublicKey,
        key: Self::LocalKey,
    ) -> Result<Box<[u8]>, PasetoError>;

    fn unseal_key(
        sealing_key: &Self::SecretKey,
        key_data: Box<[u8]>,
    ) -> Result<Self::LocalKey, PasetoError>;
}

/// Marks a key as secret
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct Secret;
/// Marks a key as public and tokens as signed
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct Public;
/// Marks a key as symmetric and tokens as encrypted
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct Local;

impl Sealed for Secret {}
impl Sealed for Public {}
impl Sealed for Local {}

/// A marker for [`Secret`], [`Public`], and [`Local`]
pub trait Marker: Sealed + Sized {
    /// ".local." or ".public." or ".secret."
    const HEADER: &'static str;
    /// ".lid." or ".pid." or ".sid."
    const ID_HEADER: &'static str;
}

impl Marker for Secret {
    const HEADER: &'static str = ".secret.";
    const ID_HEADER: &'static str = ".sid.";
}

impl Marker for Public {
    const HEADER: &'static str = ".public.";
    const ID_HEADER: &'static str = ".pid.";
}

impl Marker for Local {
    const HEADER: &'static str = ".local.";
    const ID_HEADER: &'static str = ".lid.";
}

/// A marker for [`Public`] and [`Local`], used for token encodings.
pub trait Purpose: Marker {
    /// The key used to sign/encrypt tokens.
    type SealingKey<V: Version>: SealingKey<Self>;
    /// The key used to validate/decrypt tokens.
    type UnsealingKey<V: Version>: UnsealingKey<Self>;
}

impl Purpose for Public {
    type SealingKey<V: Version> = V::SecretKey;
    type UnsealingKey<V: Version> = V::PublicKey;
}

impl Purpose for Local {
    type SealingKey<V: Version> = V::LocalKey;
    type UnsealingKey<V: Version> = V::LocalKey;
}
