//! PASERK v6 `k6.seal.` — X-Wing KEM (X25519 + ML-KEM-768) + BLAKE2b + XChaCha20.

use alloc::boxed::Box;
use alloc::vec::Vec;

use cipher::StreamCipher;
use digest::Mac;
use hybrid_array::sizes::U32;
use paseto_core::PasetoError;
use paseto_core::key::HasKey;
use paseto_core::paserk::{PkeSealingVersion, PkeUnsealingVersion};
use paseto_core::version::{PkePublic, PkeSecret};
use x_wing::{Decapsulate, Decapsulator, Encapsulate, Generate, KeyExport};

use super::{LocalKey, PkePublicKey, PkeSecretKey, V6};

const X_WING_EK_SIZE: usize = x_wing::ENCAPSULATION_KEY_SIZE;
const X_WING_CT_SIZE: usize = x_wing::CIPHERTEXT_SIZE;
const X_WING_SEED_SIZE: usize = x_wing::DECAPSULATION_KEY_SIZE;
const TAG_SIZE: usize = 32;

impl HasKey<PkePublic> for V6 {
    type Key = PkePublicKey;

    fn decode(bytes: &[u8]) -> Result<PkePublicKey, PasetoError> {
        if bytes.len() != X_WING_EK_SIZE {
            return Err(PasetoError::InvalidKey);
        }
        x_wing::EncapsulationKey::try_from(bytes)
            .map(PkePublicKey)
            .map_err(|_| PasetoError::InvalidKey)
    }

    fn encode(key: &PkePublicKey) -> Box<[u8]> {
        key.0.to_bytes().as_slice().to_vec().into_boxed_slice()
    }
}

impl HasKey<PkeSecret> for V6 {
    type Key = PkeSecretKey;

    fn decode(bytes: &[u8]) -> Result<PkeSecretKey, PasetoError> {
        let seed: [u8; X_WING_SEED_SIZE] = bytes.try_into().map_err(|_| PasetoError::InvalidKey)?;
        Ok(PkeSecretKey(x_wing::DecapsulationKey::from(seed)))
    }

    fn encode(key: &PkeSecretKey) -> Box<[u8]> {
        key.0.as_bytes().to_vec().into_boxed_slice()
    }
}

impl PkeSealingVersion for V6 {
    fn seal_key(sealing_key: &PkePublicKey, key: &mut LocalKey) -> Result<Box<[u8]>, PasetoError> {
        use cipher::KeyIvInit;
        use digest::{Digest, KeyInit};

        let pk_bytes = sealing_key.0.to_bytes();

        let (xc, xk) = sealing_key.0.encapsulate();

        let mut ek = blake2::Blake2b::new();
        ek.update(b"\x03k6.seal.");
        ek.update(xk);
        ek.update(xc);
        ek.update(pk_bytes);
        let ek = ek.finalize();

        let mut n = blake2::Blake2b::new();
        n.update(b"\xff");
        n.update(xc);
        n.update(pk_bytes);
        let n = n.finalize();

        chacha20::XChaCha20::new(&ek, &n).apply_keystream(&mut key.0);

        let mut ak = blake2::Blake2b::<U32>::new();
        ak.update(b"\x04k6.seal.");
        ak.update(xk);
        ak.update(xc);
        ak.update(pk_bytes);
        let ak = ak.finalize();

        let mut tag =
            blake2::Blake2bMac::<U32>::new_from_slice(&ak).expect("BLAKE2b accepts any key length");
        tag.update(b"k6.seal.");
        tag.update(&xc);
        tag.update(&key.0);
        let tag = tag.finalize().into_bytes();

        let mut output = Vec::with_capacity(TAG_SIZE + X_WING_CT_SIZE + 32);
        output.extend_from_slice(&tag);
        output.extend_from_slice(&xc);
        output.extend_from_slice(&key.0);

        Ok(output.into_boxed_slice())
    }
}

impl PkeUnsealingVersion for V6 {
    fn random_pke_secret_key() -> Result<PkeSecretKey, PasetoError> {
        x_wing::DecapsulationKey::try_generate()
            .map(PkeSecretKey)
            .map_err(|_| PasetoError::CryptoError)
    }

    fn pke_public_key_from_secret(sk: &PkeSecretKey) -> PkePublicKey {
        PkePublicKey(sk.0.encapsulation_key().clone())
    }

    fn unseal_key(
        unsealing_key: &PkeSecretKey,
        mut key_data: Box<[u8]>,
    ) -> Result<LocalKey, PasetoError> {
        use cipher::KeyIvInit;
        use digest::{Digest, KeyInit};

        let (tag, key_data) = key_data
            .split_first_chunk_mut::<TAG_SIZE>()
            .ok_or(PasetoError::InvalidKey)?;
        let (xc, edk) = key_data
            .split_first_chunk_mut::<X_WING_CT_SIZE>()
            .ok_or(PasetoError::InvalidKey)?;
        let xc: &[u8; X_WING_CT_SIZE] = &*xc;
        let edk: &mut [u8; 32] = edk.try_into().map_err(|_| PasetoError::InvalidKey)?;

        let pk_bytes = unsealing_key.0.encapsulation_key().to_bytes();

        let xc_obj = x_wing::Ciphertext::try_from(&xc[..]).map_err(|_| PasetoError::CryptoError)?;
        let xk = unsealing_key.0.decapsulate(&xc_obj);

        let mut ak = blake2::Blake2b::<U32>::new();
        ak.update(b"\x04k6.seal.");
        ak.update(xk);
        ak.update(xc);
        ak.update(pk_bytes);
        let ak = ak.finalize();

        let mut t2 =
            blake2::Blake2bMac::<U32>::new_from_slice(&ak).expect("BLAKE2b accepts any key length");
        t2.update(b"k6.seal.");
        t2.update(xc);
        t2.update(edk);

        t2.verify((&*tag).into())
            .map_err(|_| PasetoError::CryptoError)?;

        let mut ek = blake2::Blake2b::new();
        ek.update(b"\x03k6.seal.");
        ek.update(xk);
        ek.update(xc);
        ek.update(pk_bytes);
        let ek = ek.finalize();

        let mut n = blake2::Blake2b::new();
        n.update(b"\xff");
        n.update(xc);
        n.update(pk_bytes);
        let n = n.finalize();

        chacha20::XChaCha20::new(&ek, &n).apply_keystream(edk);

        let key = LocalKey(*edk);
        #[cfg(feature = "zeroize")]
        zeroize::Zeroize::zeroize(edk);
        Ok(key)
    }
}
