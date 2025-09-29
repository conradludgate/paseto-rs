mod id;
mod keyset;
mod pie_wrap;
mod pke;
mod plaintext;
mod pw_wrap;

use alloc::boxed::Box;
use alloc::vec::Vec;

pub use id::KeyId;
pub use keyset::KeySet;
pub use pie_wrap::PieWrappedKey;
pub use pke::SealedKey;
pub use plaintext::KeyText;
pub use pw_wrap::PasswordWrappedKey;

use crate::PasetoError;
use crate::version::Version;

pub trait IdVersion: Version {
    /// How to hash some keydata for creating [`KeyId`]
    fn hash_key(key_header: &'static str, key_data: &[u8]) -> [u8; 33];
}

pub trait PieWrapVersion: Version {
    fn pie_wrap_key(
        header: &'static str,
        wrapping_key: &Self::LocalKey,
        key_data: Vec<u8>,
    ) -> Result<Vec<u8>, PasetoError>;

    fn pie_unwrap_key<'key>(
        header: &'static str,
        wrapping_key: &Self::LocalKey,
        key_data: &'key mut [u8],
    ) -> Result<&'key [u8], PasetoError>;
}

pub trait PwWrapVersion: Version {
    type Params: Default;

    fn pw_wrap_key(
        header: &'static str,
        pass: &[u8],
        params: &Self::Params,
        key_data: Vec<u8>,
    ) -> Result<Vec<u8>, PasetoError>;

    fn get_params(key_data: &[u8]) -> Result<Self::Params, PasetoError>;

    fn pw_unwrap_key<'key>(
        header: &'static str,
        pass: &[u8],
        key_data: &'key mut [u8],
    ) -> Result<&'key [u8], PasetoError>;
}

pub trait PkeVersion: Version {
    fn seal_key(
        sealing_key: &Self::PublicKey,
        key: Self::LocalKey,
    ) -> Result<Box<[u8]>, PasetoError>;

    fn unseal_key(
        sealing_key: &Self::SecretKey,
        key_data: Box<[u8]>,
    ) -> Result<Self::LocalKey, PasetoError>;
}
