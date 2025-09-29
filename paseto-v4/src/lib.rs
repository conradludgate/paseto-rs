//! PASETO v4 (RustCrypto)
//!
//! ```
//! use paseto_v4::{SignedToken, UnsignedToken, SecretKey, PublicKey};
//! use paseto_json::{RegisteredClaims, Time, HasExpiry, FromIssuer, ForSubject, Validate};
//! use std::time::Duration;
//!
//! // create a new keypair
//! let secret_key = SecretKey::random().unwrap();
//! let public_key = secret_key.public_key();
//!
//! // create a set of token claims
//! let claims = RegisteredClaims::now(Duration::from_secs(3600))
//!     .from_issuer("https://paseto.conrad.cafe/".to_string())
//!     .for_subject("conradludgate".to_string());
//!
//! // create and sign a new token
//! let signed_token = UnsignedToken::new(claims).sign(&secret_key).unwrap();
//!
//! // serialize the token.
//! let token = signed_token.to_string();
//! // "v4.public.eyJpc3MiOiJodHRwczovL3Bhc2V0by5jb25yYWQuY2FmZS8iLCJzdWIiOiJjb25yYWRsdWRnYXRlIiwiYXVkIjpudWxsLCJleHAiOiIyMDI1LTA5LTIwVDEyOjAxOjEzLjcyMjQ3OVoiLCJuYmYiOiIyMDI1LTA5LTIwVDExOjAxOjEzLjcyMjQ3OVoiLCJpYXQiOiIyMDI1LTA5LTIwVDExOjAxOjEzLjcyMjQ3OVoiLCJqdGkiOm51bGx9N7O1CAXQpQ3rpxhq6xFZt32z27VSL8suiek38-5W4LRGr1tDmKcP0_xrlp5-kdE6o7B_K8KU-6Fwmu0hzrkiDQ"
//!
//! // serialize the public key.
//! let key = public_key.to_string();
//! // "k4.public.xRPdFzRvXY-H-6L3S2I3_TmdMKu6XwLKLSR10lZ-yfk"
//!
//! // ...
//!
//! // parse the token
//! let signed_token: SignedToken<RegisteredClaims> = token.parse().unwrap();
//!
//! // parse the key
//! let public_key: PublicKey = key.parse().unwrap();
//!
//! // verify the token signature and validate the claims.
//! let validation = Time::valid_now()
//!     .and_then(HasExpiry)
//!     .and_then(FromIssuer("https://paseto.conrad.cafe/"))
//!     .and_then(ForSubject("conradludgate"));
//! let verified_token = signed_token.verify(&public_key, &validation).unwrap();
//! ```
#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

/// Low level implementation primitives.
pub mod core;

pub use paseto_core::PasetoError;

/// A token with publically readable data, but not yet verified
#[cfg(feature = "verifying")]
pub type SignedToken<M, F = ()> = paseto_core::SignedToken<core::V4, M, F>;

/// A token with secret data
#[cfg(feature = "decrypting")]
pub type EncryptedToken<M, F = ()> = paseto_core::EncryptedToken<core::V4, M, F>;

/// A [`SignedToken`] that has been verified
#[cfg(feature = "verifying")]
pub type UnsignedToken<M, F = ()> = paseto_core::UnsignedToken<core::V4, M, F>;

/// An [`EncryptedToken`] that has been decrypted
#[cfg(feature = "decrypting")]
pub type UnencryptedToken<M, F = ()> = paseto_core::UnencryptedToken<core::V4, M, F>;

/// Private key used for [`encryption`](UnencryptedToken::encrypt) and [`decryptiom`](EncryptedToken::decrypt)
#[cfg(feature = "decrypting")]
pub type LocalKey = paseto_core::LocalKey<core::V4>;

/// Public key used for signature [`verification`](SignedToken::verify)
#[cfg(feature = "verifying")]
pub type PublicKey = paseto_core::PublicKey<core::V4>;

/// Private key used for token [`signing`](UnsignedToken::sign)
#[cfg(feature = "signing")]
pub type SecretKey = paseto_core::SecretKey<core::V4>;

/// A plaintext encoding of a key.
pub type KeyText<K> = paseto_core::paserk::KeyText<core::V4, K>;

/// A short ID for a key.
#[cfg(feature = "id")]
pub type KeyId<K> = paseto_core::paserk::KeyId<core::V4, K>;

/// An asymmetrically encrypted [`LocalKey`].
#[cfg(feature = "pke")]
pub type SealedKey = paseto_core::paserk::SealedKey<core::V4>;

/// An password encrypted [`LocalKey`].
#[cfg(feature = "pbkw")]
pub type PasswordWrappedLocalKey =
    paseto_core::paserk::PasswordWrappedKey<core::V4, paseto_core::version::Local>;

/// An password encrypted [`SecretKey`].
#[cfg(all(feature = "pbkw", feature = "signing"))]
pub type PasswordWrappedSecretKey =
    paseto_core::paserk::PasswordWrappedKey<core::V4, paseto_core::version::Secret>;

/// An password encrypted [`LocalKey`].
#[cfg(feature = "pie-wrap")]
pub type PieWrappedLocalKey =
    paseto_core::paserk::PieWrappedKey<core::V4, paseto_core::version::Local>;

/// An password encrypted [`SecretKey`].
#[cfg(all(feature = "pie-wrap", feature = "signing"))]
pub type PieWrappedSecretKey =
    paseto_core::paserk::PieWrappedKey<core::V4, paseto_core::version::Secret>;
