#![forbid(unsafe_code)]

use std::error::Error;
use std::io;

#[cfg(feature = "claims")]
pub use jiff;

use paseto_core::encodings::{Footer, Payload, WriteBytes};
pub use paseto_core::validation::Validate;
use serde_core::Serialize;
use serde_core::de::DeserializeOwned;

/// `Json` is a type wrapper to implement `Footer` for all types that implement
/// [`serde_core::Serialize`] and [`serde_core::Deserialize`]
///
/// When using a JSON footer, you should be aware of the risks of parsing user provided JSON.
/// <https://github.com/paseto-standard/paseto-spec/blob/master/docs/02-Implementation-Guide/01-Payload-Processing.md#storing-json-in-the-footer>.
///
/// Currently, this uses [`serde_json`] internally, which by default offers a stack-overflow protection limit on parsing JSON.
/// You should also parse into a known struct layout, and avoid arbitrary key-value mappings.
///
/// If you need stricter checks, you can make your own [`Footer`] encodings that give access to the bytes before
/// the footer is decoded.
#[derive(Default)]
pub struct Json<T>(pub T);

struct Writer<W: WriteBytes>(W);
impl<W: WriteBytes> io::Write for Writer<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.write(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl<T: Serialize + DeserializeOwned> Footer for Json<T> {
    fn encode(&self, writer: impl WriteBytes) -> Result<(), Box<dyn Error + Send + Sync>> {
        serde_json::to_writer(Writer(writer), &self.0).map_err(|err| Box::new(err) as _)
    }

    fn decode(footer: &[u8]) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        match footer {
            [] => Err("missing footer".into()),
            x => serde_json::from_slice(x).map(Self).map_err(|e| e.into()),
        }
    }
}

impl<M: Serialize + DeserializeOwned> Payload for Json<M> {
    /// JSON is the standard payload and requires no version suffix
    const SUFFIX: &'static str = "";

    fn encode(self, writer: impl WriteBytes) -> Result<(), Box<dyn Error + Send + Sync>> {
        serde_json::to_writer(Writer(writer), &self.0).map_err(|err| Box::new(err) as _)
    }

    fn decode(payload: &[u8]) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        serde_json::from_slice(payload)
            .map_err(From::from)
            .map(Self)
    }
}

#[cfg(feature = "claims")]
#[derive(Default, Clone, Debug)]
pub struct RegisteredClaims {
    pub iss: Option<String>,
    pub sub: Option<String>,
    pub aud: Option<String>,
    pub exp: Option<jiff::Timestamp>,
    pub nbf: Option<jiff::Timestamp>,
    pub iat: Option<jiff::Timestamp>,
    pub jti: Option<String>,
}

#[cfg(feature = "claims")]
pub use claims_impls::{ForAudience, ForSubject, FromIssuer, HasExpiry, Time, TimeWithLeeway};

#[cfg(feature = "claims")]
mod claims_impls {
    use core::fmt;
    use std::error::Error;
    use std::time::Duration;

    use paseto_core::{PasetoError, validation::Validate};
    use paseto_core::{encodings::Payload, pae::WriteBytes};
    use serde_core::{
        Deserialize, Deserializer, Serializer,
        de::{MapAccess, Visitor},
        ser::SerializeStruct,
    };

    use crate::RegisteredClaims;
    use crate::Writer;

    pub struct Time {
        now: jiff::Timestamp,
    }

    impl Time {
        pub fn valid_now() -> Self {
            Self {
                now: jiff::Timestamp::now(),
            }
        }

        pub fn valid_at(now: jiff::Timestamp) -> Self {
            Self { now }
        }

        pub fn with_leeway(self, leeway: Duration) -> TimeWithLeeway {
            TimeWithLeeway {
                now: self.now,
                leeway,
            }
        }
    }

    impl Validate for Time {
        type Claims = RegisteredClaims;

        fn validate(&self, claims: &Self::Claims) -> Result<(), PasetoError> {
            if let Some(exp) = claims.exp
                && exp < self.now
            {
                return Err(PasetoError::ClaimsError);
            }

            if let Some(nbf) = claims.nbf
                && self.now < nbf
            {
                return Err(PasetoError::ClaimsError);
            }

            Ok(())
        }
    }

    pub struct TimeWithLeeway {
        now: jiff::Timestamp,
        leeway: std::time::Duration,
    }

    impl Validate for TimeWithLeeway {
        type Claims = RegisteredClaims;

        fn validate(&self, claims: &Self::Claims) -> Result<(), PasetoError> {
            if let Some(exp) = claims.exp
                && exp < self.now - self.leeway
            {
                return Err(PasetoError::ClaimsError);
            }

            if let Some(nbf) = claims.nbf
                && self.now + self.leeway < nbf
            {
                return Err(PasetoError::ClaimsError);
            }

            Ok(())
        }
    }

    pub struct ForSubject<T: AsRef<str>>(pub T);

    impl<T: AsRef<str>> Validate for ForSubject<T> {
        type Claims = RegisteredClaims;

        fn validate(&self, claims: &Self::Claims) -> Result<(), PasetoError> {
            if claims.sub.as_deref() != Some(self.0.as_ref()) {
                return Err(PasetoError::ClaimsError);
            }

            Ok(())
        }
    }

    pub struct FromIssuer<T: AsRef<str>>(pub T);

    impl<T: AsRef<str>> Validate for FromIssuer<T> {
        type Claims = RegisteredClaims;

        fn validate(&self, claims: &Self::Claims) -> Result<(), PasetoError> {
            if claims.iss.as_deref() != Some(self.0.as_ref()) {
                return Err(PasetoError::ClaimsError);
            }

            Ok(())
        }
    }

    pub struct ForAudience<T: AsRef<str>>(pub T);

    impl<T: AsRef<str>> Validate for ForAudience<T> {
        type Claims = RegisteredClaims;

        fn validate(&self, claims: &Self::Claims) -> Result<(), PasetoError> {
            if claims.aud.as_deref() != Some(self.0.as_ref()) {
                return Err(PasetoError::ClaimsError);
            }

            Ok(())
        }
    }

    pub struct HasExpiry;

    impl Validate for HasExpiry {
        type Claims = RegisteredClaims;
        fn validate(&self, claims: &Self::Claims) -> Result<(), PasetoError> {
            if claims.exp.is_none() {
                return Err(PasetoError::ClaimsError);
            }
            Ok(())
        }
    }

    impl RegisteredClaims {
        pub fn new(now: jiff::Timestamp, exp: Duration) -> Self {
            Self {
                iss: None,
                sub: None,
                aud: None,
                exp: Some(now + exp),
                nbf: Some(now),
                iat: Some(now),
                jti: None,
            }
        }

        pub fn now(exp: Duration) -> Self {
            Self::new(jiff::Timestamp::now(), exp)
        }

        pub fn from_issuer(mut self, iss: String) -> Self {
            self.iss = Some(iss);
            self
        }

        pub fn for_audience(mut self, aud: String) -> Self {
            self.aud = Some(aud);
            self
        }

        pub fn for_subject(mut self, sub: String) -> Self {
            self.sub = Some(sub);
            self
        }

        pub fn with_token_id(mut self, jti: String) -> Self {
            self.jti = Some(jti);
            self
        }
    }

    impl Payload for RegisteredClaims {
        /// JSON is the standard payload and requires no version suffix
        const SUFFIX: &'static str = "";

        fn encode(self, writer: impl WriteBytes) -> Result<(), Box<dyn Error + Send + Sync>> {
            serde_json::to_writer(Writer(writer), &self).map_err(|err| Box::new(err) as _)
        }

        fn decode(payload: &[u8]) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
            serde_json::from_slice(payload).map_err(From::from)
        }
    }

    impl serde_core::Serialize for RegisteredClaims {
        fn serialize<S>(&self, s: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            let mut state = s.serialize_struct("RegisteredClaims", 7)?;
            if let Some(x) = &self.iss {
                state.serialize_field("iss", &x)?;
            }
            if let Some(x) = &self.sub {
                state.serialize_field("sub", &x)?;
            }
            if let Some(x) = &self.aud {
                state.serialize_field("aud", &x)?;
            }
            if let Some(x) = &self.exp {
                state.serialize_field("exp", &x)?;
            }
            if let Some(x) = &self.nbf {
                state.serialize_field("nbf", &x)?;
            }
            if let Some(x) = &self.iat {
                state.serialize_field("iat", &x)?;
            }
            if let Some(x) = &self.jti {
                state.serialize_field("jti", &x)?;
            }
            state.end()
        }
    }

    enum RegisteredClaimField {
        Issuer,
        Subject,
        Audience,
        Expiration,
        NotBefore,
        IssuedAt,
        TokenIdentifier,
        Ignored,
    }

    struct RegisteredClaimFieldVisitor;

    impl<'de> Visitor<'de> for RegisteredClaimFieldVisitor {
        type Value = RegisteredClaimField;
        fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
            f.write_str("field identifier")
        }

        fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
        where
            E: serde_core::de::Error,
        {
            self.visit_bytes(v.as_bytes())
        }

        fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
        where
            E: serde_core::de::Error,
        {
            match v {
                b"iss" => Ok(RegisteredClaimField::Issuer),
                b"sub" => Ok(RegisteredClaimField::Subject),
                b"aud" => Ok(RegisteredClaimField::Audience),
                b"exp" => Ok(RegisteredClaimField::Expiration),
                b"nbf" => Ok(RegisteredClaimField::NotBefore),
                b"iat" => Ok(RegisteredClaimField::IssuedAt),
                b"jti" => Ok(RegisteredClaimField::TokenIdentifier),
                _ => Ok(RegisteredClaimField::Ignored),
            }
        }
    }

    impl<'de> Deserialize<'de> for RegisteredClaimField {
        #[inline]
        fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
            d.deserialize_identifier(RegisteredClaimFieldVisitor)
        }
    }

    struct RegisteredClaimsVisitor;

    impl<'de> Visitor<'de> for RegisteredClaimsVisitor {
        type Value = RegisteredClaims;
        fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
            f.write_str("struct RegisteredClaims")
        }

        #[inline]
        fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
            let mut issuer: Option<String> = None;
            let mut subject: Option<String> = None;
            let mut audience: Option<String> = None;
            let mut expiration: Option<jiff::Timestamp> = None;
            let mut not_before: Option<jiff::Timestamp> = None;
            let mut issued_at: Option<jiff::Timestamp> = None;
            let mut token_identifier: Option<String> = None;
            while let Some(key) = map.next_key()? {
                match key {
                    RegisteredClaimField::Issuer => {
                        if issuer.is_some() {
                            return Err(serde_core::de::Error::duplicate_field("iss"));
                        }
                        issuer = map.next_value()?;
                    }
                    RegisteredClaimField::Subject => {
                        if subject.is_some() {
                            return Err(serde_core::de::Error::duplicate_field("sub"));
                        }
                        subject = map.next_value()?;
                    }
                    RegisteredClaimField::Audience => {
                        if audience.is_some() {
                            return Err(serde_core::de::Error::duplicate_field("aud"));
                        }
                        audience = map.next_value()?;
                    }
                    RegisteredClaimField::Expiration => {
                        if expiration.is_some() {
                            return Err(serde_core::de::Error::duplicate_field("exp"));
                        }
                        expiration = map.next_value()?;
                    }
                    RegisteredClaimField::NotBefore => {
                        if not_before.is_some() {
                            return Err(serde_core::de::Error::duplicate_field("nbf"));
                        }
                        not_before = map.next_value()?;
                    }
                    RegisteredClaimField::IssuedAt => {
                        if issued_at.is_some() {
                            return Err(serde_core::de::Error::duplicate_field("iat"));
                        }
                        issued_at = map.next_value()?;
                    }
                    RegisteredClaimField::TokenIdentifier => {
                        if token_identifier.is_some() {
                            return Err(serde_core::de::Error::duplicate_field("jti"));
                        }
                        token_identifier = map.next_value()?;
                    }
                    _ => {
                        map.next_value::<serde_core::de::IgnoredAny>()?;
                    }
                }
            }
            Ok(RegisteredClaims {
                iss: issuer,
                sub: subject,
                aud: audience,
                exp: expiration,
                nbf: not_before,
                iat: issued_at,
                jti: token_identifier,
            })
        }
    }

    impl<'de> Deserialize<'de> for RegisteredClaims {
        fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
            const FIELDS: &[&str] = &["iss", "sub", "aud", "exp", "nbf", "iat", "jti"];
            d.deserialize_struct("RegisteredClaims", FIELDS, RegisteredClaimsVisitor)
        }
    }
}
