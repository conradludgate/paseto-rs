//! PASETO Message encodings.

use alloc::borrow::ToOwned;
use alloc::boxed::Box;
use alloc::vec::Vec;
use core::error::Error;
use core::fmt;
use core::marker::PhantomData;

use crate::tokens::SealedToken;
use crate::{PasetoError, version};

pub trait WriteBytes {
    fn write(&mut self, slice: &[u8]);
}

impl<W: WriteBytes> WriteBytes for &mut W {
    fn write(&mut self, slice: &[u8]) {
        W::write(self, slice);
    }
}

impl WriteBytes for Vec<u8> {
    fn write(&mut self, slice: &[u8]) {
        self.extend_from_slice(slice)
    }
}

/// A PASETO payload object.
pub trait Payload: Sized {
    /// Suffix for this encoding type.
    ///
    /// Currently the standard only supports JSON, which has no suffix.
    const SUFFIX: &'static str;

    /// Encode the message
    fn encode(self, writer: impl WriteBytes) -> Result<(), Box<dyn Error + Send + Sync>>;

    /// Decode the message
    fn decode(payload: &[u8]) -> Result<Self, Box<dyn Error + Send + Sync>>;
}

/// Encoding scheme for PASETO footers.
///
/// Footers are allowed to be any encoding, but JSON is the standard.
///
/// Footers are also optional, so the `()` empty type is considered as a missing footer.
pub trait Footer: Sized {
    /// Encode the footer to bytes
    fn encode(&self, writer: impl WriteBytes) -> Result<(), Box<dyn Error + Send + Sync>>;

    /// Decode the footer from bytes
    fn decode(footer: &[u8]) -> Result<Self, Box<dyn Error + Send + Sync>>;
}

impl Footer for Vec<u8> {
    fn encode(&self, mut writer: impl WriteBytes) -> Result<(), Box<dyn Error + Send + Sync>> {
        writer.write(self);
        Ok(())
    }

    fn decode(footer: &[u8]) -> Result<Self, Box<dyn Error + Send + Sync>> {
        Ok(footer.to_owned())
    }
}

impl Footer for () {
    fn encode(&self, _: impl WriteBytes) -> Result<(), Box<dyn Error + Send + Sync>> {
        Ok(())
    }

    fn decode(footer: &[u8]) -> Result<Self, Box<dyn Error + Send + Sync>> {
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

impl<V: version::Version, P: version::Purpose, M: Payload, F: Footer> core::str::FromStr
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
        let footer = F::decode(&encoded_footer).map_err(PasetoError::PayloadError)?;

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

macro_rules! serde_str {
    (
        impl<$($ident:ident),*> $ty:ty
        $(where
            $($path:path: $bound:path,)*
        )?
        {
            fn expecting() { $expecting:expr }
        }
    ) => {
        #[cfg(feature = "serde")]
        impl<$($ident),*> serde_core::Serialize for $ty
        $(where
            $($path: $bound,)*
        )?
        {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: serde_core::Serializer,
            {
                serializer.collect_str(self)
            }
        }

        #[cfg(feature = "serde")]
        impl<'de, $($ident),*> serde_core::Deserialize<'de> for $ty
        $(where
            $($path: $bound,)*
        )?
        {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: serde_core::Deserializer<'de>,
            {
                struct Visitor<$($ident),*>(core::marker::PhantomData<($($ident,)*)>);
                impl<'de, $($ident),*> serde_core::de::Visitor<'de> for Visitor<$($ident),*>
                $(where
                    $($path: $bound,)*
                )?
                {
                    type Value = $ty;

                    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                        formatter.write_fmt($expecting)
                    }

                    fn visit_str<Err>(self, v: &str) -> Result<Self::Value, Err>
                    where
                        Err: serde_core::de::Error,
                    {
                        v.parse().map_err(Err::custom)
                    }
                }
                deserializer.deserialize_str(Visitor(core::marker::PhantomData))
            }
        }
    };
}

serde_str!(
    impl<V, P, M, F> SealedToken<V, P, M, F>
    where
        V: version::Version,
        P: version::Purpose,
        M: Payload,
        F: Footer,
    {
        fn expecting() {
            format_args!("a \"{}{}\" paseto", V::HEADER, P::HEADER)
        }
    }
);
