pub mod encodings;
pub mod key;
pub mod pae;
pub mod tokens;
pub mod version;

mod sealed {
    pub trait Sealed {}
}

#[derive(Debug)]
#[non_exhaustive]
/// Error returned for all PASETO and PASERK operations that can fail
pub enum PasetoError {
    /// The token was not Base64 URL encoded correctly.
    Base64DecodeError,
    /// Could not decode the provided key string
    InvalidKey,
    /// The PASETO or PASERK was not of a valid form
    InvalidToken,
    /// Could not verify/decrypt the PASETO/PASERK.
    CryptoError,
    /// PASETO claims failed validation.
    ClaimsError,
    /// There was an error with payload processing
    PayloadError(std::io::Error),
}

impl std::error::Error for PasetoError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            PasetoError::PayloadError(x) => Some(x),
            _ => None,
        }
    }
}

impl std::fmt::Display for PasetoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PasetoError::Base64DecodeError => f.write_str("The token could not be base64 decoded"),
            PasetoError::InvalidKey => f.write_str("Could not parse the key"),
            PasetoError::InvalidToken => f.write_str("Could not parse the token"),
            PasetoError::CryptoError => f.write_str("Token signature could not be validated"),
            PasetoError::ClaimsError => f.write_str("Token claims could not be validated"),
            PasetoError::PayloadError(x) => {
                write!(f, "there was an error with the payload encoding: {x}")
            }
        }
    }
}
