use crate::PasetoError;
use crate::key::{KeyKind, SealingKey, UnsealingKey};
use crate::sealed::Sealed;

/// An implementation of the PASETO cryptographic schemes.
pub trait Version: 'static {
    /// Header for PASETO
    const HEADER: &'static str;

    /// A symmetric key used to encrypt and decrypt tokens.
    type LocalKey: SealingKey<Local>
        + UnsealingKey<Local>
        + KeyKind<Version = Self, KeyType = Local>;
    /// An asymmetric key used to validate token signatures.
    type PublicKey: UnsealingKey<Public> + KeyKind<Version = Self, KeyType = Public>;
    /// An asymmetric key used to create token signatures.
    type SecretKey: SealingKey<Public> + KeyKind<Version = Self, KeyType = Secret>;
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
pub trait Marker: Sealed + Sized + 'static {
    /// ".local." or ".public." or ".secret."
    const HEADER: &'static str;
    /// ".lid." or ".pid." or ".sid."
    const ID_HEADER: &'static str;

    type Key<V: Version>: KeyKind<Version = V, KeyType = Self>;
}

pub trait SealingMarker: Marker {
    type Purpose: Purpose;
    type SealingKey<V: Version>: KeyKind<Version = V, KeyType = Self>
        + SealingKey<Self::Purpose, Version = V, KeyType = Self>;

    fn coerce_types<V: Version>(inner: &Self::Key<V>) -> &Self::SealingKey<V>;
}

pub trait UnsealingMarker: Marker {
    type Purpose: Purpose;
    type UnsealingKey<V: Version>: KeyKind<Version = V, KeyType = Self>
        + UnsealingKey<Self::Purpose, Version = V, KeyType = Self>;

    fn coerce_types<V: Version>(inner: &Self::Key<V>) -> &Self::UnsealingKey<V>;
}

impl Marker for Secret {
    const HEADER: &'static str = ".secret.";
    const ID_HEADER: &'static str = ".sid.";

    type Key<V: Version> = V::SecretKey;
}

impl SealingMarker for Secret {
    type Purpose = Public;

    type SealingKey<V: Version> = V::SecretKey;

    fn coerce_types<V: Version>(inner: &Self::Key<V>) -> &Self::SealingKey<V> {
        inner
    }
}

impl Marker for Public {
    const HEADER: &'static str = ".public.";
    const ID_HEADER: &'static str = ".pid.";

    type Key<V: Version> = V::PublicKey;
}

impl UnsealingMarker for Public {
    type Purpose = Public;

    type UnsealingKey<V: Version> = V::PublicKey;

    fn coerce_types<V: Version>(inner: &Self::Key<V>) -> &Self::UnsealingKey<V> {
        inner
    }
}

impl Marker for Local {
    const HEADER: &'static str = ".local.";
    const ID_HEADER: &'static str = ".lid.";

    type Key<V: Version> = V::LocalKey;
}

impl SealingMarker for Local {
    type Purpose = Local;

    type SealingKey<V: Version> = V::LocalKey;

    fn coerce_types<V: Version>(inner: &Self::Key<V>) -> &Self::SealingKey<V> {
        inner
    }
}

impl UnsealingMarker for Local {
    type Purpose = Local;

    type UnsealingKey<V: Version> = V::LocalKey;

    fn coerce_types<V: Version>(inner: &Self::Key<V>) -> &Self::UnsealingKey<V> {
        inner
    }
}

/// A marker for [`Public`] and [`Local`], used for token encodings.
pub trait Purpose: Marker {
    /// The key used to sign/encrypt tokens.
    type SealingMarker: SealingMarker<Purpose = Self>;
    /// The key used to validate/decrypt tokens.
    type UnsealingMarker: UnsealingMarker<Purpose = Self>;

    // /// The key used to sign/encrypt tokens.
    // type SealingKey<V: Version>: SealingKey<Self, KeyType = Self::SealingMarker>;
    // /// The key used to validate/decrypt tokens.
    // type UnsealingKey<V: Version>: UnsealingKey<Self, KeyType = Self::UnsealingMarker>;
}

impl Purpose for Public {
    type SealingMarker = Secret;
    type UnsealingMarker = Public;

    // type SealingKey<V: Version> = V::SecretKey;
    // type UnsealingKey<V: Version> = V::PublicKey;
}

impl Purpose for Local {
    type SealingMarker = Local;
    type UnsealingMarker = Local;

    // type SealingKey<V: Version> = V::LocalKey;
    // type UnsealingKey<V: Version> = V::LocalKey;
}
