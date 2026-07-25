//! PASETO v6 (RustCrypto) — DRAFT, post-quantum.
//!
//! **WARNING**: PASETO v6 is an unstable draft (paseto-standard/paseto-spec#36).
//! No reference implementation or test vectors exist yet. The on-wire format
//! may change without notice. This crate is marked `publish = false` and is
//! published only for experimentation.
//!
//! v6.local is identical to v4.local (BLAKE2b / XChaCha20).
//! v6.public uses SLH-DSA-SHA2-128s (FIPS-205) instead of Ed25519.
//! v6 PKE uses X-Wing (X25519 + ML-KEM-768) instead of plain X25519.
#![forbid(unsafe_code)]
#![no_std]

extern crate alloc;

#[cfg(feature = "zeroize")]
macro_rules! secret {
    ($value:expr) => {
        zeroize::Zeroizing::new($value)
    };
}
#[cfg(not(feature = "zeroize"))]
macro_rules! secret {
    ($value:expr) => {
        $value
    };
}

/// Low level implementation primitives.
pub mod core;

pub use paseto_core::PasetoError;

/// A token with publically readable data, but not yet verified
#[cfg(feature = "verifying")]
pub type SignedToken<M, F = ()> = paseto_core::SignedToken<core::V6, M, F>;
/// A token with secret data
#[cfg(feature = "decrypting")]
pub type EncryptedToken<M, F = ()> = paseto_core::EncryptedToken<core::V6, M, F>;
/// A [`SignedToken`] that has been verified
#[cfg(feature = "verifying")]
pub type UnsignedToken<M, F = ()> = paseto_core::UnsignedToken<core::V6, M, F>;
/// An [`EncryptedToken`] that has been decrypted
#[cfg(feature = "decrypting")]
pub type UnencryptedToken<M, F = ()> = paseto_core::UnencryptedToken<core::V6, M, F>;

/// Private key used for [`encryption`](UnencryptedToken::encrypt) and [`decryption`](EncryptedToken::decrypt)
#[cfg(feature = "decrypting")]
pub type LocalKey = paseto_core::LocalKey<core::V6>;
/// Public key used for signature [`verification`](SignedToken::verify)
#[cfg(feature = "verifying")]
pub type PublicKey = paseto_core::PublicKey<core::V6>;
/// Private key used for token [`signing`](UnsignedToken::sign)
#[cfg(feature = "signing")]
pub type SecretKey = paseto_core::SecretKey<core::V6>;

/// Public key used for [`sealing`](LocalKey::seal) a [`LocalKey`] for a recipient.
#[cfg(feature = "pke")]
pub type PkePublicKey = paseto_core::PkePublicKey<core::V6>;
/// Private key used for [`unsealing`](SealedKey::unseal) a sealed [`LocalKey`].
#[cfg(feature = "pke")]
pub type PkeSecretKey = paseto_core::PkeSecretKey<core::V6>;

/// A short ID for a key.
#[cfg(feature = "id")]
pub type KeyId<K> = paseto_core::paserk::KeyId<core::V6, K>;
/// A plaintext encoding of a key.
pub type KeyText<K> = paseto_core::paserk::KeyText<core::V6, K>;
/// An asymmetrically encrypted [`LocalKey`].
#[cfg(feature = "pke")]
pub type SealedKey = paseto_core::paserk::SealedKey<core::V6>;

/// An password encrypted [`LocalKey`].
#[cfg(feature = "pbkw")]
pub type PasswordWrappedLocalKey =
    paseto_core::paserk::PasswordWrappedKey<core::V6, paseto_core::version::Local>;

/// An password encrypted [`SecretKey`].
#[cfg(all(feature = "pbkw", feature = "signing"))]
pub type PasswordWrappedSecretKey =
    paseto_core::paserk::PasswordWrappedKey<core::V6, paseto_core::version::Secret>;

/// A symmetrically wrapped [`LocalKey`].
#[cfg(feature = "pie-wrap")]
pub type PieWrappedLocalKey =
    paseto_core::paserk::PieWrappedKey<core::V6, paseto_core::version::Local>;

/// A symmetrically wrapped [`SecretKey`].
#[cfg(all(feature = "pie-wrap", feature = "signing"))]
pub type PieWrappedSecretKey =
    paseto_core::paserk::PieWrappedKey<core::V6, paseto_core::version::Secret>;
