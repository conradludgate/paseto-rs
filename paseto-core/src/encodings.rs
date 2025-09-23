//! PASETO Message encodings.

use core::fmt;
use std::io::{self, Write};
use std::marker::PhantomData;

use crate::tokens::SealedToken;
use crate::{PasetoError, version};

/// A PASETO payload object.
pub trait Payload: Sized {
    /// Suffix for this encoding type.
    ///
    /// Currently the standard only supports JSON, which has no suffix.
    const SUFFIX: &'static str;

    /// Encode the message
    fn encode(self, writer: impl Write) -> Result<(), io::Error>;

    /// Decode the message
    fn decode(payload: &[u8]) -> Result<Self, Box<dyn std::error::Error + Send + Sync>>;
}

/// Encoding scheme for PASETO footers.
///
/// Footers are allowed to be any encoding, but JSON is the standard.
///
/// Footers are also optional, so the `()` empty type is considered as a missing footer.
pub trait Footer: Sized {
    /// Encode the footer to bytes
    fn encode(&self, writer: impl Write) -> Result<(), io::Error>;

    /// Decode the footer from bytes
    fn decode(footer: &[u8]) -> Result<Self, Box<dyn std::error::Error + Send + Sync>>;
}

impl Footer for Vec<u8> {
    fn encode(&self, mut writer: impl Write) -> Result<(), io::Error> {
        writer.write_all(self)
    }

    fn decode(footer: &[u8]) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        Ok(footer.to_owned())
    }
}

impl Footer for () {
    fn encode(&self, _: impl Write) -> Result<(), io::Error> {
        Ok(())
    }

    fn decode(footer: &[u8]) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        match footer {
            [] => Ok(()),
            x => Err(format!("unexpected footer {x:?}").into()),
        }
    }
}

impl<V: version::Version, P: version::Purpose, M: Payload, F> fmt::Display
    for SealedToken<V, P, M, F>
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(V::HEADER)?;
        f.write_str(M::SUFFIX)?;
        f.write_str(P::HEADER)?;
        crate::base64::write_to_fmt(&self.payload, f)?;

        if !self.encoded_footer.is_empty() {
            f.write_str(".")?;
            crate::base64::write_to_fmt(&self.encoded_footer, f)?;
        }

        Ok(())
    }
}

impl<V: version::Version, P: version::Purpose, M: Payload, F: Footer> std::str::FromStr
    for SealedToken<V, P, M, F>
{
    type Err = PasetoError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s.strip_prefix(V::HEADER).ok_or(PasetoError::InvalidToken)?;
        let s = s.strip_prefix(M::SUFFIX).ok_or(PasetoError::InvalidToken)?;
        let s = s.strip_prefix(P::HEADER).ok_or(PasetoError::InvalidToken)?;

        let (payload, footer) = match s.split_once('.') {
            Some((payload, footer)) => (payload, Some(footer)),
            None => (s, None),
        };

        let payload = crate::base64::decode_vec(payload)?.into_boxed_slice();
        let encoded_footer = footer
            .map(crate::base64::decode_vec)
            .transpose()?
            .unwrap_or_default()
            .into_boxed_slice();
        let footer = F::decode(&encoded_footer)
            .map_err(std::io::Error::other)
            .map_err(PasetoError::PayloadError)?;

        Ok(Self {
            payload,
            encoded_footer,
            footer,
            _message: PhantomData,
            _version: PhantomData,
            _purpose: PhantomData,
        })
    }
}

#[cfg(feature = "serde")]
impl<V: version::Version, P: version::Purpose, M: Payload, F> serde_core::Serialize
    for SealedToken<V, P, M, F>
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde_core::Serializer,
    {
        serializer.collect_str(self)
    }
}

#[cfg(feature = "serde")]
impl<'de, V: version::Version, P: version::Purpose, M: Payload, F: Footer>
    serde_core::Deserialize<'de> for SealedToken<V, P, M, F>
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde_core::Deserializer<'de>,
    {
        struct FromStrVisitor<V, T, F, E>(std::marker::PhantomData<(V, T, F, E)>);
        impl<'de, V: version::Version, P: version::Purpose, M: Payload, F: Footer>
            serde_core::de::Visitor<'de> for FromStrVisitor<V, P, M, F>
        {
            type Value = SealedToken<V, P, M, F>;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                write!(formatter, "a \"{}{}\" paseto", V::HEADER, P::HEADER,)
            }
            fn visit_str<Err>(self, v: &str) -> Result<Self::Value, Err>
            where
                Err: serde_core::de::Error,
            {
                v.parse().map_err(Err::custom)
            }
        }
        deserializer.deserialize_str(FromStrVisitor(std::marker::PhantomData))
    }
}
