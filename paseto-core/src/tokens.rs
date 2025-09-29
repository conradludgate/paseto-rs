//! Generic Tokens

use alloc::boxed::Box;
use alloc::vec::Vec;
use core::marker::PhantomData;

use crate::encodings::{Footer, Payload};
use crate::key::Key;
use crate::validation::Validate;
use crate::version::{Local, Public};
use crate::{
    EncryptedToken, LocalKey, PasetoError, PublicKey, SecretKey, SignedToken, UnencryptedToken,
    UnsignedToken, version,
};

/// An unsealed token.
///
/// This represents a PASETO which has had signatures or encryption validated.
/// Using one of the following aliases is suggested
/// * [`UnsignedToken`] - A [`public`](version::Public) PASETO which has had signature validated.
/// * [`UnencryptedToken`] - A [`local`](version::Local) PASETO which has successfully been decrypted.
///
/// This type is un-serializable as it isn't sealed. For that you will want [`SealedToken`].
pub struct UnsealedToken<V, P, M, F = ()> {
    /// The message that was contained in the token
    pub claims: M,
    /// The footer that was sent with the token
    pub footer: F,
    pub(crate) _version: PhantomData<V>,
    pub(crate) _purpose: PhantomData<P>,
}

impl<V: crate::version::Version, T: crate::version::Purpose, M> UnsealedToken<V, T, M> {
    /// Create a new [`UnsealedToken`] builder with the given message payload
    pub fn new(claims: M) -> Self {
        UnsealedToken {
            claims,
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
            claims: self.claims,
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
    pub(crate) payload: Box<[u8]>,
    pub(crate) encoded_footer: Box<[u8]>,
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

impl<V, P, M, F> SealedToken<V, P, M, F>
where
    V: version::UnsealingVersion<P>,
    P: version::Purpose,
    M: Payload,
    F: Footer,
{
    /// Unseal a token and validate the claims inside.
    #[doc(alias = "decrypt")]
    #[doc(alias = "verify")]
    pub fn unseal(
        mut self,
        key: &Key<V, P>,
        aad: &[u8],
        v: &impl Validate<Claims = M>,
    ) -> Result<UnsealedToken<V, P, M, F>, PasetoError> {
        let cleartext = V::unseal(
            &key.0,
            M::SUFFIX,
            &mut self.payload,
            &self.encoded_footer,
            aad,
        )?;

        let message = M::decode(cleartext).map_err(PasetoError::PayloadError)?;

        v.validate(&message)?;

        Ok(UnsealedToken {
            claims: message,
            footer: self.footer,
            _version: PhantomData,
            _purpose: PhantomData,
        })
    }
}

impl<V, P, M, F> UnsealedToken<V, P, M, F>
where
    V: version::SealingVersion<P>,
    P: version::Purpose,
    M: Payload,
    F: Footer,
{
    /// Seal a token and authenticate the claims
    #[doc(alias = "encrypt")]
    #[doc(alias = "sign")]
    #[inline(always)]
    pub fn seal(
        self,
        key: &Key<V, P::SealingKey>,
        aad: &[u8],
    ) -> Result<SealedToken<V, P, M, F>, PasetoError> {
        self.dangerous_seal_with_nonce(key, aad, V::nonce()?)
    }

    /// Use [`UnsealedToken::seal`](crate::tokens::UnsealedToken::seal) instead.
    ///
    /// This is provided for testing purposes only.
    /// Do not use this method directly.
    pub fn dangerous_seal_with_nonce(
        self,
        key: &Key<V, P::SealingKey>,
        aad: &[u8],
        nonce: Vec<u8>,
    ) -> Result<SealedToken<V, P, M, F>, PasetoError> {
        let mut footer = Vec::new();
        self.footer
            .encode(&mut footer)
            .map_err(PasetoError::PayloadError)?;
        let footer = footer.into_boxed_slice();

        let mut payload = nonce;
        self.claims
            .encode(&mut payload)
            .map_err(PasetoError::PayloadError)?;

        let payload = V::dangerous_seal_with_nonce(&key.0, M::SUFFIX, payload, &footer, aad)?
            .into_boxed_slice();

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

impl<V, M, F> EncryptedToken<V, M, F>
where
    V: version::UnsealingVersion<Local>,
    M: Payload,
    F: Footer,
{
    /// Try to decrypt the token
    #[inline(always)]
    pub fn decrypt(
        self,
        key: &LocalKey<V>,
        v: &impl Validate<Claims = M>,
    ) -> Result<UnencryptedToken<V, M, F>, PasetoError> {
        self.decrypt_with_aad(key, &[], v)
    }

    /// Try to decrypt the token and authenticate the implicit assertion
    #[inline(always)]
    pub fn decrypt_with_aad(
        self,
        key: &LocalKey<V>,
        aad: &[u8],
        v: &impl Validate<Claims = M>,
    ) -> Result<UnencryptedToken<V, M, F>, PasetoError> {
        self.unseal(key, aad, v)
    }
}

impl<V, M, F> UnencryptedToken<V, M, F>
where
    V: version::SealingVersion<Local>,
    M: Payload,
    F: Footer,
{
    /// Encrypt the token
    #[inline(always)]
    pub fn encrypt(self, key: &LocalKey<V>) -> Result<EncryptedToken<V, M, F>, PasetoError> {
        self.encrypt_with_aad(key, &[])
    }

    /// Encrypt the token, additionally authenticating the implicit assertions.
    #[inline(always)]
    pub fn encrypt_with_aad(
        self,
        key: &LocalKey<V>,
        aad: &[u8],
    ) -> Result<EncryptedToken<V, M, F>, PasetoError> {
        self.seal(key, aad)
    }
}

impl<V, M, F> SignedToken<V, M, F>
where
    V: version::UnsealingVersion<Public>,
    M: Payload,
    F: Footer,
{
    /// Try to verify the token signature
    #[inline(always)]
    pub fn verify(
        self,
        key: &PublicKey<V>,
        v: &impl Validate<Claims = M>,
    ) -> Result<UnsignedToken<V, M, F>, PasetoError> {
        self.verify_with_aad(key, &[], v)
    }

    /// Try to verify the token signature and authenticate the implicit assertion
    #[inline(always)]
    pub fn verify_with_aad(
        self,
        key: &PublicKey<V>,
        aad: &[u8],
        v: &impl Validate<Claims = M>,
    ) -> Result<UnsignedToken<V, M, F>, PasetoError> {
        self.unseal(key, aad, v)
    }
}

impl<V, M, F> UnsignedToken<V, M, F>
where
    V: version::SealingVersion<Public>,
    M: Payload,
    F: Footer,
{
    /// Sign the token
    #[inline(always)]
    pub fn sign(self, key: &SecretKey<V>) -> Result<SignedToken<V, M, F>, PasetoError> {
        self.sign_with_aad(key, &[])
    }

    /// Sign the token, additionally authenticating the implicit assertions.
    #[inline(always)]
    pub fn sign_with_aad(
        self,
        key: &SecretKey<V>,
        aad: &[u8],
    ) -> Result<SignedToken<V, M, F>, PasetoError> {
        self.seal(key, aad)
    }
}
