//! Generic Tokens

use std::marker::PhantomData;

use rand_core::TryCryptoRng;

use crate::{
    PasetoError,
    encodings::{Footer, Payload},
    key::{SealingKey, UnsealingKey},
    version,
};

pub type SignedToken<V, M, F = ()> = SealedToken<V, version::Public, M, F>;
pub type EncryptedToken<V, M, F = ()> = SealedToken<V, version::Local, M, F>;
pub type VerifiedToken<V, M, F = ()> = UnsealedToken<V, version::Public, M, F>;
pub type DecryptedToken<V, M, F = ()> = UnsealedToken<V, version::Local, M, F>;

/// An unsealed token.
///
/// This represents a PASETO which has had signatures or encryption validated.
/// Using one of the following aliases is suggested
/// * [`VerifiedToken`] - A [`public`](version::Public) PASETO which has had signature validated.
/// * [`DecryptedToken`] - A [`local`](version::Local) PASETO which has successfully been decrypted.
///
/// This type is un-serializable as it isn't sealed. For that you will want [`SealedToken`].
pub struct UnsealedToken<V, P, M, F = ()> {
    /// The message that was contained in the token
    pub message: M,
    /// The footer that was sent with the token
    pub footer: F,
    pub(crate) _version: PhantomData<V>,
    pub(crate) _purpose: PhantomData<P>,
}

impl<V: crate::version::Version, T: crate::version::Purpose, M> UnsealedToken<V, T, M> {
    /// Create a new [`UnsealedToken`] builder with the given message payload
    pub fn new(message: M) -> Self {
        UnsealedToken {
            message,
            footer: (),
            _version: PhantomData,
            _purpose: PhantomData,
        }
    }
}

impl<V, T, M> UnsealedToken<V, T, M, ()> {
    /// Set the footer for this token.
    ///
    /// Footers are embedded into the token as base64 only. They are authenticated but not encrypted.
    pub fn with_footer<F>(self, footer: F) -> UnsealedToken<V, T, M, F> {
        UnsealedToken {
            message: self.message,
            footer,
            _version: self._version,
            _purpose: self._purpose,
        }
    }
}

/// A secured token.
///
/// This represents a PASETO that is signed or encrypted.
/// Using one of the following aliases is suggested
/// * [`SignedToken`] - A [`public`](version::Public) PASETO that is signed.
/// * [`EncryptedToken`] - A [`local`](version::Local) PASETO that is encryption.
///
/// This type has a payload that is currently inaccessible. To access it, you will need to
/// decrypt/verify the contents. For that you will want [`UnsealedToken`].
///
/// To convert to an [`UnsealedToken`], you will need to use either
/// * [`SignedToken::verify`]
/// * [`EncryptedToken::decrypt`]
pub struct SealedToken<V, P, M, F = ()> {
    pub(crate) payload: Vec<u8>,
    pub(crate) encoded_footer: Vec<u8>,
    pub(crate) footer: F,
    pub(crate) _version: PhantomData<V>,
    pub(crate) _purpose: PhantomData<P>,
    pub(crate) _message: PhantomData<M>,
}

impl<V, T, M, F> SealedToken<V, T, M, F> {
    /// View the **unverified** footer for this token
    pub fn unverified_footer(&self) -> &F {
        &self.footer
    }
}

impl<V: version::Version, P: version::Purpose, M: Payload, F: Footer> SealedToken<V, P, M, F> {
    #[doc(alias = "decrypt")]
    #[doc(alias = "verify")]
    pub fn unseal(
        mut self,
        key: &P::UnsealingKey<V>,
        aad: &[u8],
    ) -> Result<UnsealedToken<V, P, M, F>, PasetoError> {
        let cleartext = key.unseal(M::SUFFIX, &mut self.payload, &self.encoded_footer, aad)?;

        let message = M::decode(cleartext)
            .map_err(std::io::Error::other)
            .map_err(PasetoError::PayloadError)?;

        Ok(UnsealedToken {
            message,
            footer: self.footer,
            _version: PhantomData,
            _purpose: PhantomData,
        })
    }
}

impl<V: version::Version, P: version::Purpose, M: Payload, F: Footer> UnsealedToken<V, P, M, F> {
    #[doc(alias = "encrypt")]
    #[doc(alias = "sign")]
    pub fn seal(
        self,
        key: &P::SealingKey<V>,
        aad: &[u8],
        rng: impl TryCryptoRng,
    ) -> Result<SealedToken<V, P, M, F>, PasetoError> {
        let mut footer = Vec::new();
        self.footer
            .encode(&mut footer)
            .map_err(PasetoError::PayloadError)?;

        let mut payload = <P::SealingKey<V>>::nonce(rng)?;
        self.message
            .encode(&mut payload)
            .map_err(PasetoError::PayloadError)?;

        let payload = key.seal(M::SUFFIX, payload, &footer, aad)?;

        Ok(SealedToken {
            payload,
            encoded_footer: footer,
            footer: self.footer,
            _version: PhantomData,
            _purpose: PhantomData,
            _message: PhantomData,
        })
    }
}

impl<V: version::Version, M: Payload, F: Footer> EncryptedToken<V, M, F> {
    #[inline(always)]
    pub fn decrypt(
        self,
        key: &V::LocalKey,
        aad: &[u8],
    ) -> Result<DecryptedToken<V, M, F>, PasetoError> {
        self.unseal(key, aad)
    }
}

impl<V: version::Version, M: Payload, F: Footer> DecryptedToken<V, M, F> {
    #[inline(always)]
    pub fn encrypt(
        self,
        key: &V::LocalKey,
        aad: &[u8],
        rng: impl TryCryptoRng,
    ) -> Result<EncryptedToken<V, M, F>, PasetoError> {
        self.seal(key, aad, rng)
    }
}

impl<V: version::Version, M: Payload, F: Footer> SignedToken<V, M, F> {
    #[inline(always)]
    pub fn verify(
        self,
        key: &V::PublicKey,
        aad: &[u8],
    ) -> Result<VerifiedToken<V, M, F>, PasetoError> {
        self.unseal(key, aad)
    }
}

impl<V: version::Version, M: Payload, F: Footer> VerifiedToken<V, M, F> {
    #[inline(always)]
    pub fn sign(
        self,
        key: &V::SecretKey,
        aad: &[u8],
        rng: impl TryCryptoRng,
    ) -> Result<SignedToken<V, M, F>, PasetoError> {
        self.seal(key, aad, rng)
    }
}
