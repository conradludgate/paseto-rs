use alloc::vec::Vec;

use crate::PasetoError;
use crate::key::{Key, KeyKind};
use crate::sealed::Sealed;

/// An implementation of the PASETO cryptographic schemes.
pub trait Version: Sized + 'static {
    /// Header for PASETO
    const HEADER: &'static str;

    /// A symmetric key used to encrypt and decrypt tokens.
    type LocalKey: KeyKind<Version = Self, KeyType = Local>;
    /// An asymmetric key used to validate token signatures.
    type PublicKey: KeyKind<Version = Self, KeyType = Public>;
    /// An asymmetric key used to create token signatures.
    type SecretKey: KeyKind<Version = Self, KeyType = Secret>;
}

pub trait UnsealingVersion<P: Purpose>: Version {
    /// Do not call this method directly. Use [`SealedToken::unseal`](crate::tokens::SealedToken::unseal) instead.
    fn unseal<'a>(
        key: &Key<Self, P::UnsealingMarker>,
        encoding: &'static str,
        payload: &'a mut [u8],
        footer: &[u8],
        aad: &[u8],
    ) -> Result<&'a [u8], PasetoError>;
}

pub trait SealingVersion<P: Purpose>: UnsealingVersion<P> {
    /// Generate the key that can unseal the tokens this key will seal.
    fn unsealing_key(key: &Key<Self, P::SealingMarker>) -> Key<Self, P::UnsealingMarker>;

    /// Generate a random key
    fn random() -> Result<Key<Self, P::SealingMarker>, PasetoError>;

    /// Do not call this method directly.
    fn nonce() -> Result<Vec<u8>, PasetoError>;

    /// Do not call this method directly. Use [`UnsealedToken::seal`](crate::tokens::UnsealedToken::seal) instead.
    fn dangerous_seal_with_nonce(
        key: &Key<Self, P::SealingMarker>,
        encoding: &'static str,
        payload: Vec<u8>,
        footer: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, PasetoError>;
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

    const PIE_WRAP_HEADER: &'static str;
    const PW_WRAP_HEADER: &'static str;
}

pub trait UnsealingMarker: Marker {
    type Purpose: Purpose;
}

impl Marker for Secret {
    const HEADER: &'static str = ".secret.";
    const ID_HEADER: &'static str = ".sid.";

    type Key<V: Version> = V::SecretKey;
}

impl SealingMarker for Secret {
    type Purpose = Public;

    const PIE_WRAP_HEADER: &'static str = ".secret-wrap.pie.";
    const PW_WRAP_HEADER: &'static str = ".secret-pw.";
}

impl Marker for Public {
    const HEADER: &'static str = ".public.";
    const ID_HEADER: &'static str = ".pid.";

    type Key<V: Version> = V::PublicKey;
}

impl UnsealingMarker for Public {
    type Purpose = Public;
}

impl Marker for Local {
    const HEADER: &'static str = ".local.";
    const ID_HEADER: &'static str = ".lid.";

    type Key<V: Version> = V::LocalKey;
}

impl SealingMarker for Local {
    type Purpose = Local;

    const PIE_WRAP_HEADER: &'static str = ".local-wrap.pie.";
    const PW_WRAP_HEADER: &'static str = ".local-pw.";
}

impl UnsealingMarker for Local {
    type Purpose = Local;
}

/// A marker for [`Public`] and [`Local`], used for token encodings.
pub trait Purpose: Marker {
    /// The key used to sign/encrypt tokens.
    type SealingMarker: SealingMarker<Purpose = Self>;
    /// The key used to validate/decrypt tokens.
    type UnsealingMarker: UnsealingMarker<Purpose = Self>;
}

impl Purpose for Public {
    type SealingMarker = Secret;
    type UnsealingMarker = Public;
}

impl Purpose for Local {
    type SealingMarker = Local;
    type UnsealingMarker = Local;
}
