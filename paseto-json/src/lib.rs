use core::fmt;

use paseto_core::encodings::{Footer, Payload};
use serde_core::{
    Deserialize, Deserializer, Serialize, Serializer,
    de::{DeserializeOwned, MapAccess, Visitor},
    ser::SerializeStruct,
};

/// `Json` is a type wrapper to implement `Footer` for all types that implement
/// [`serde::Serialize`] and [`serde::Deserialize`]
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

impl<T: Serialize + DeserializeOwned> Footer for Json<T> {
    fn encode(&self, writer: impl std::io::Write) -> Result<(), std::io::Error> {
        serde_json::to_writer(writer, &self.0).map_err(std::io::Error::from)
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
    const SUFFIX: &'static str = ".";

    fn encode(self, writer: impl std::io::Write) -> Result<(), std::io::Error> {
        serde_json::to_writer(writer, &self.0).map_err(std::io::Error::from)
    }

    fn decode(payload: &[u8]) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        serde_json::from_slice(payload)
            .map_err(From::from)
            .map(Json)
    }
}

pub struct RegisteredClaims {
    pub iss: Option<String>,
    pub sub: Option<String>,
    pub aud: Option<String>,
    pub exp: Option<jiff::Timestamp>,
    pub nbf: Option<jiff::Timestamp>,
    pub iat: Option<jiff::Timestamp>,
    pub jti: Option<String>,
}

impl serde_core::Serialize for RegisteredClaims {
    fn serialize<S>(&self, s: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = s.serialize_struct("RegisteredClaims", 7)?;
        state.serialize_field("iss", &self.iss)?;
        state.serialize_field("sub", &self.sub)?;
        state.serialize_field("aud", &self.aud)?;
        state.serialize_field("exp", &self.exp)?;
        state.serialize_field("nbf", &self.nbf)?;
        state.serialize_field("iat", &self.iat)?;
        state.serialize_field("jti", &self.jti)?;
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
