use libsodium_rs::crypto_stream::{self, xchacha20};
use libsodium_rs::utils::compare;
use libsodium_rs::{crypto_generichash, crypto_sign};
use paseto_core::PasetoError;
use paseto_core::key::HasKey;
use paseto_core::paserk::{PkeSealingVersion, PkeUnsealingVersion};
use paseto_core::version::{PkePublic, PkeSecret, Public, Secret};

use super::{LocalKey, PublicKey, SecretKey, V4};

impl HasKey<PkePublic> for V4 {
    type Key = PublicKey;
    fn decode(bytes: &[u8]) -> Result<PublicKey, PasetoError> {
        <V4 as HasKey<Public>>::decode(bytes)
    }
    fn encode(key: &PublicKey) -> Box<[u8]> {
        <V4 as HasKey<Public>>::encode(key)
    }
}

impl HasKey<PkeSecret> for V4 {
    type Key = SecretKey;
    fn decode(bytes: &[u8]) -> Result<SecretKey, PasetoError> {
        <V4 as HasKey<Secret>>::decode(bytes)
    }
    fn encode(key: &SecretKey) -> Box<[u8]> {
        <V4 as HasKey<Secret>>::encode(key)
    }
}

impl PkeSealingVersion for V4 {
    fn seal_key(sealing_key: &PublicKey, key: LocalKey) -> Result<Box<[u8]>, PasetoError> {
        use libsodium_rs::crypto_box;
        use libsodium_rs::crypto_scalarmult::curve25519;

        // Given a plaintext data key (pdk), and an Ed25519 public key (pk).
        let xpk = crypto_sign::ed25519_pk_to_curve25519(&sealing_key.0)
            .map_err(|_| PasetoError::CryptoError)?;

        let (epk, esk) = crypto_box::KeyPair::generate().into_tuple();

        // diffie hellman exchange
        let xk =
            curve25519::scalarmult(esk.as_bytes(), &xpk).map_err(|_| PasetoError::CryptoError)?;

        let mut ek = crypto_generichash::State::new(None, 32).unwrap();
        ek.update(b"\x01k4.seal.");
        ek.update(&xk);
        ek.update(epk.as_bytes());
        ek.update(&xpk);
        let ek =
            crypto_stream::Key::from_slice(&ek.finalize()).map_err(|_| PasetoError::CryptoError)?;

        let mut n = crypto_generichash::State::new(None, 24).unwrap();
        n.update(epk.as_bytes());
        n.update(&xpk);
        let n = xchacha20::Nonce::try_from_slice(&n.finalize())
            .map_err(|_| PasetoError::CryptoError)?;

        let edk = xchacha20::stream_xor(&key.0, &n, &ek).map_err(|_| PasetoError::CryptoError)?;

        let mut ak = crypto_generichash::State::new(None, 32).unwrap();
        ak.update(b"\x02k4.seal.");
        ak.update(&xk);
        ak.update(epk.as_bytes());
        ak.update(&xpk);
        let ak = ak.finalize();

        let mut tag = crypto_generichash::State::new(Some(&ak), 32).unwrap();
        tag.update(b"k4.seal.");
        tag.update(epk.as_bytes());
        tag.update(&edk);
        let tag = tag.finalize();

        let mut output = Vec::with_capacity(96);
        output.extend_from_slice(&tag);
        output.extend_from_slice(epk.as_bytes());
        output.extend_from_slice(&edk);

        Ok(output.into_boxed_slice())
    }
}

impl PkeUnsealingVersion for V4 {
    fn unseal_key(unsealing_key: &SecretKey, key_data: Box<[u8]>) -> Result<LocalKey, PasetoError> {
        use libsodium_rs::crypto_scalarmult::curve25519;

        let (tag, key_data) = key_data
            .split_first_chunk::<32>()
            .ok_or(PasetoError::InvalidKey)?;
        let (epk, edk) = key_data
            .split_first_chunk::<32>()
            .ok_or(PasetoError::InvalidKey)?;
        let edk: &[u8; 32] = edk.try_into().map_err(|_| PasetoError::InvalidKey)?;

        let xpk = crypto_sign::ed25519_pk_to_curve25519(&unsealing_key.unsealing_key().0)
            .map_err(|_| PasetoError::CryptoError)?;
        let xsk = crypto_sign::ed25519_sk_to_curve25519(&unsealing_key.0)
            .map_err(|_| PasetoError::CryptoError)?;

        // diffie hellman exchange
        let xk = curve25519::scalarmult(&xsk, epk).map_err(|_| PasetoError::CryptoError)?;

        let mut ak = crypto_generichash::State::new(None, 32).unwrap();
        ak.update(b"\x02k4.seal.");
        ak.update(&xk);
        ak.update(epk);
        ak.update(&xpk);
        let ak = ak.finalize();

        let mut t2 = crypto_generichash::State::new(Some(&ak), 32).unwrap();
        t2.update(b"k4.seal.");
        t2.update(epk);
        t2.update(edk);

        // step 6: Compare t2 with t, using a constant-time compare function. If it does not match, abort.
        if compare(&t2.finalize(), tag) != 0 {
            return Err(PasetoError::CryptoError);
        }

        let mut ek = crypto_generichash::State::new(None, 32).unwrap();
        ek.update(b"\x01k4.seal.");
        ek.update(&xk);
        ek.update(epk);
        ek.update(&xpk);
        let ek =
            crypto_stream::Key::from_slice(&ek.finalize()).map_err(|_| PasetoError::CryptoError)?;

        let mut n = crypto_generichash::State::new(None, 24).unwrap();
        n.update(epk);
        n.update(&xpk);
        let n = xchacha20::Nonce::try_from_slice(&n.finalize())
            .map_err(|_| PasetoError::CryptoError)?;

        let edk = xchacha20::stream_xor(edk, &n, &ek).map_err(|_| PasetoError::CryptoError)?;
        edk.try_into()
            .map_err(|_| PasetoError::CryptoError)
            .map(LocalKey)
    }
}
