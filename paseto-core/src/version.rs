//! Various helper traits

use alloc::vec::Vec;

use crate::PasetoError;
use crate::key::{KeyEncoding, KeyInner, KeyType, SealingKey};
use crate::sealed::Sealed;

/// An implementation of the PASETO cryptographic schemes.
pub trait Version: Send + Sync + Sized + 'static {
    /// Header for PASETO
    const HEADER: &'static str;
    /// Header for PASERK
    const PASERK_HEADER: &'static str = "k3";

    /// A symmetric key used to encrypt and decrypt tokens.
    type LocalKey: KeyEncoding<Version = Self, KeyType = Local>;
    /// An asymmetric key used to validate token signatures.
    type PublicKey: KeyEncoding<Version = Self, KeyType = Public>;
    /// An asymmetric key used to create token signatures.
    type SecretKey: KeyEncoding<Version = Self, KeyType = Secret>;
}

type SealingKeyInner<V, P> = KeyInner<V, <P as Purpose>::SealingKey>;

/// This PASETO implementation can decrypt/verify tokens.
pub trait UnsealingVersion<P: Purpose>: Version {
    /// Do not call this method directly. Use [`SealedToken::unseal`](crate::tokens::SealedToken::unseal) instead.
    fn unseal<'a>(
        key: &KeyInner<Self, P>,
        encoding: &'static str,
        payload: &'a mut [u8],
        footer: &[u8],
        aad: &[u8],
    ) -> Result<&'a [u8], PasetoError>;
}

/// This PASETO implementation can sign/encrypt tokens.
pub trait SealingVersion<P: Purpose>: UnsealingVersion<P> {
    /// Generate the key that can unseal the tokens this key will seal.
    fn unsealing_key(key: &SealingKeyInner<Self, P>) -> KeyInner<Self, P>;

    /// Generate a random key
    fn random() -> Result<SealingKeyInner<Self, P>, PasetoError>;

    /// Do not call this method directly.
    fn nonce() -> Result<Vec<u8>, PasetoError>;

    /// Do not call this method directly. Use [`UnsealedToken::seal`](crate::tokens::UnsealedToken::seal) instead.
    fn dangerous_seal_with_nonce(
        key: &SealingKeyInner<Self, P>,
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

/// A marker for [`Public`] and [`Local`], used for token encodings.
pub trait Purpose: KeyType {
    /// The key used to sign/encrypt tokens.
    type SealingKey: SealingKey;
}

impl Purpose for Public {
    type SealingKey = Secret;
}

impl Purpose for Local {
    type SealingKey = Local;
}
