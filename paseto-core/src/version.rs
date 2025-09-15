use rand_core::TryCryptoRng;

use crate::{PasetoError, sealed::Sealed};

pub trait Version {
    /// Header for PASETO
    const PASETO_HEADER: &'static str;
    /// Header for PASERK
    const PASERK_HEADER: &'static str;

    type LocalKey: SealingKey<Local> + UnsealingKey<Local>;
    type PublicKey: UnsealingKey<Public>;
    type SecretKey: SealingKey<Public>;
}

pub trait Purpose: Sealed + Sized {
    /// "local." or "public."
    const HEADER: &'static str;

    type SealingKey<V: Version>: SealingKey<Self>;
    type UnsealingKey<V: Version>: UnsealingKey<Self>;
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct Public;
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct Local;

impl Sealed for Public {}

impl Purpose for Public {
    const HEADER: &'static str = "public.";

    type SealingKey<V: Version> = V::SecretKey;
    type UnsealingKey<V: Version> = V::PublicKey;
}

impl Sealed for Local {}

impl Purpose for Local {
    const HEADER: &'static str = "local.";

    type SealingKey<V: Version> = V::LocalKey;
    type UnsealingKey<V: Version> = V::LocalKey;
}

pub trait SealingKey<Purpose> {
    fn nonce(rng: impl TryCryptoRng) -> Result<Vec<u8>, PasetoError>;

    fn seal(
        &self,
        encoding: &'static str,
        payload: Vec<u8>,
        footer: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, PasetoError>;
}

pub trait UnsealingKey<Purpose> {
    fn unseal<'a>(
        &self,
        encoding: &'static str,
        payload: &'a mut [u8],
        footer: &[u8],
        aad: &[u8],
    ) -> Result<&'a [u8], PasetoError>;
}
