//! PASETO v1 (RustCrypto)
//!
//! ```
//! use paseto_v1::{SignedToken, UnsignedToken, SecretKey, PublicKey};
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
//! // "v1.public..."
//!
//! // serialize the public key.
//! let key = public_key.to_string();
//! // "k1.public..."
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
#![forbid(unsafe_code)]

extern crate alloc;

/// Low level implementation primitives.
pub mod core;

pub use paseto_core::PasetoError;

/// A token with publically readable data, but not yet verified
pub type SignedToken<M, F = ()> = paseto_core::SignedToken<core::V1, M, F>;
/// A token with secret data
pub type EncryptedToken<M, F = ()> = paseto_core::EncryptedToken<core::V1, M, F>;
/// A [`SignedToken`] that has been verified
pub type UnsignedToken<M, F = ()> = paseto_core::UnsignedToken<core::V1, M, F>;
/// An [`EncryptedToken`] that has been decrypted
pub type UnencryptedToken<M, F = ()> = paseto_core::UnencryptedToken<core::V1, M, F>;

/// Private key used for [`encryption`](UnencryptedToken::encrypt) and [`decryptiom`](EncryptedToken::decrypt)
pub type LocalKey = paseto_core::LocalKey<core::V1>;
/// Public key used for signature [`verification`](SignedToken::verify)
pub type PublicKey = paseto_core::PublicKey<core::V1>;
/// Private key used for token [`signing`](UnsignedToken::sign)
pub type SecretKey = paseto_core::SecretKey<core::V1>;

/// A short ID for a key.
pub type KeyId<K> = paseto_core::paserk::KeyId<core::V1, K>;
/// A plaintext encoding of a key.
pub type KeyText<K> = paseto_core::paserk::KeyText<core::V1, K>;
/// An asymmetrically encrypted [`LocalKey`].
pub type SealedKey = paseto_core::paserk::SealedKey<core::V1>;
