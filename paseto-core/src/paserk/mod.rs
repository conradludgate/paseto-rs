//! PASERK: **P**latform-**A**gnostic **Ser**ialized **K**eys
//!
//! Core traits and types for working with the various PASERK serializations.

mod id;
mod pie_wrap;
mod pke;
mod plaintext;
mod pw_wrap;

use alloc::boxed::Box;
use alloc::vec::Vec;

pub use id::KeyId;
pub use pie_wrap::PieWrappedKey;
pub use pke::SealedKey;
pub use plaintext::KeyText;
pub use pw_wrap::PasswordWrappedKey;

use crate::PasetoError;
use crate::version::Version;

/// This PASETO implementation allows extracting key ids
pub trait IdVersion: Version {
    /// How to hash some keydata for creating [`KeyId`]
    fn hash_key(key_header: &'static str, key_data: &[u8]) -> [u8; 33];
}

/// This PASETO implementation allows encrypting keys using a [`LocalKey`](crate::LocalKey)
pub trait PieWrapVersion: Version {
    /// Wrap the key
    fn pie_wrap_key(
        header: &'static str,
        wrapping_key: &Self::LocalKey,
        key_data: Vec<u8>,
    ) -> Result<Vec<u8>, PasetoError>;

    /// Unwrap the key
    fn pie_unwrap_key<'key>(
        header: &'static str,
        wrapping_key: &Self::LocalKey,
        key_data: &'key mut [u8],
    ) -> Result<&'key [u8], PasetoError>;
}

/// This PASETO implementation allows encrypting keys using a password
pub trait PwWrapVersion: Version {
    type Params: Default;

    /// Wrap the key using a password
    fn pw_wrap_key(
        header: &'static str,
        pass: &[u8],
        params: &Self::Params,
        key_data: Vec<u8>,
    ) -> Result<Vec<u8>, PasetoError>;

    /// Extract the params from the
    fn get_params(key_data: &[u8]) -> Result<Self::Params, PasetoError>;

    /// Unwrap the key using a password
    fn pw_unwrap_key<'key>(
        header: &'static str,
        pass: &[u8],
        key_data: &'key mut [u8],
    ) -> Result<&'key [u8], PasetoError>;
}

/// This PASETO implementation allows encrypting keys using a [`PublicKey`](crate::PublicKey)
pub trait PkeVersion: Version {
    /// Seal the key using the public key
    fn seal_key(
        sealing_key: &Self::PublicKey,
        key: Self::LocalKey,
    ) -> Result<Box<[u8]>, PasetoError>;

    /// Unseal the key using the secret key
    fn unseal_key(
        sealing_key: &Self::SecretKey,
        key_data: Box<[u8]>,
    ) -> Result<Self::LocalKey, PasetoError>;
}
