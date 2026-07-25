//! PASERK v5 `k5.seal.` — ML-KEM-1024 + SHA-384 + AES-256-CTR + HMAC-SHA384.

use alloc::boxed::Box;
use alloc::vec::Vec;

use cipher::StreamCipher;
use hmac::Mac;
use hybrid_array::sizes::U32;
use ml_kem::{Decapsulate, Encapsulate, Generate, KeyExport, TryKeyInit};
use paseto_core::PasetoError;
use paseto_core::key::HasKey;
use paseto_core::paserk::{PkeSealingVersion, PkeUnsealingVersion};
use paseto_core::version::{PkePublic, PkeSecret};
use sha2::Digest;

use super::{LocalKey, PkePublicKey, PkeSecretKey, V5};

const ML_KEM_1024_EK_SIZE: usize = 1568;
const ML_KEM_1024_CT_SIZE: usize = 1568;
const ML_KEM_1024_SEED_SIZE: usize = 64;
const TAG_SIZE: usize = 48;

impl HasKey<PkePublic> for V5 {
    type Key = PkePublicKey;

    fn decode(bytes: &[u8]) -> Result<PkePublicKey, PasetoError> {
        if bytes.len() != ML_KEM_1024_EK_SIZE {
            return Err(PasetoError::InvalidKey);
        }
        let ek = ml_kem::EncapsulationKey1024::new_from_slice(bytes)
            .map_err(|_| PasetoError::InvalidKey)?;
        Ok(PkePublicKey(ek))
    }

    fn encode(key: &PkePublicKey) -> Box<[u8]> {
        key.0.to_bytes().as_slice().to_vec().into_boxed_slice()
    }
}

impl HasKey<PkeSecret> for V5 {
    type Key = PkeSecretKey;

    fn decode(bytes: &[u8]) -> Result<PkeSecretKey, PasetoError> {
        if bytes.len() != ML_KEM_1024_SEED_SIZE {
            return Err(PasetoError::InvalidKey);
        }
        let seed = ml_kem::Seed::try_from(bytes).map_err(|_| PasetoError::InvalidKey)?;
        Ok(PkeSecretKey(ml_kem::DecapsulationKey1024::from_seed(seed)))
    }

    fn encode(key: &PkeSecretKey) -> Box<[u8]> {
        let seed = key
            .0
            .to_seed()
            .expect("decapsulation key was constructed from a seed");
        seed.as_slice().to_vec().into_boxed_slice()
    }
}

impl PkeSealingVersion for V5 {
    fn seal_key(sealing_key: &PkePublicKey, key: &mut LocalKey) -> Result<Box<[u8]>, PasetoError> {
        use cipher::KeyIvInit;

        let pk_bytes = sealing_key.0.to_bytes();

        // KEM: produce (xc, xk) — ciphertext + shared secret
        let (xc, xk) = sealing_key.0.encapsulate();

        // Ek || n = SHA-384(0x01 || h || xk || xc || pk)
        let mut ek = sha2::Sha384::new();
        ek.update(b"\x01k5.seal.");
        ek.update(xk);
        ek.update(xc);
        ek.update(pk_bytes);
        let (ek, n) = ek.finalize().split::<U32>();

        // Ak = SHA-384(0x02 || h || xk || xc || pk)
        let mut ak = sha2::Sha384::new();
        ak.update(b"\x02k5.seal.");
        ak.update(xk);
        ak.update(xc);
        ak.update(pk_bytes);
        let ak = ak.finalize();

        ctr::Ctr64BE::<aes::Aes256>::new(&ek, &n).apply_keystream(&mut key.0);

        // t = HMAC-SHA384(h || xc || edk, Ak)
        let mut tag = <hmac::Hmac<sha2::Sha384> as digest::KeyInit>::new_from_slice(&ak)
            .expect("HMAC accepts any key length");
        tag.update(b"k5.seal.");
        tag.update(&xc);
        tag.update(&key.0);
        let tag = tag.finalize().into_bytes();

        let mut output = Vec::with_capacity(TAG_SIZE + ML_KEM_1024_CT_SIZE + 32);
        output.extend_from_slice(&tag);
        output.extend_from_slice(&xc);
        output.extend_from_slice(&key.0);

        Ok(output.into_boxed_slice())
    }
}

impl PkeUnsealingVersion for V5 {
    fn random_pke_secret_key() -> Result<PkeSecretKey, PasetoError> {
        ml_kem::DecapsulationKey1024::try_generate()
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

        let (tag, key_data) = key_data
            .split_first_chunk_mut::<TAG_SIZE>()
            .ok_or(PasetoError::InvalidKey)?;
        let (xc, edk) = key_data
            .split_first_chunk_mut::<ML_KEM_1024_CT_SIZE>()
            .ok_or(PasetoError::InvalidKey)?;

        let xc: &[u8; ML_KEM_1024_CT_SIZE] = &*xc;
        let edk: &mut [u8; 32] = edk.try_into().map_err(|_| PasetoError::InvalidKey)?;

        let pk_bytes = unsealing_key.0.encapsulation_key().to_bytes();

        let xc_arr = ml_kem::Ciphertext::<ml_kem::ml_kem_1024::MlKem1024>::try_from(&xc[..])
            .map_err(|_| PasetoError::CryptoError)?;
        let xk = unsealing_key.0.decapsulate(&xc_arr);

        let mut ak = sha2::Sha384::new();
        ak.update(b"\x02k5.seal.");
        ak.update(xk);
        ak.update(xc);
        ak.update(pk_bytes);
        let ak = ak.finalize();

        let mut t2 = <hmac::Hmac<sha2::Sha384> as digest::KeyInit>::new_from_slice(&ak)
            .expect("HMAC accepts any key length");
        t2.update(b"k5.seal.");
        t2.update(xc);
        t2.update(edk);

        t2.verify((&*tag).into())
            .map_err(|_| PasetoError::CryptoError)?;

        let mut ek = sha2::Sha384::new();
        ek.update(b"\x01k5.seal.");
        ek.update(xk);
        ek.update(xc);
        ek.update(pk_bytes);
        let (ek, n) = ek.finalize().split::<U32>();

        ctr::Ctr64BE::<aes::Aes256>::new(&ek, &n).apply_keystream(edk);

        let key = LocalKey(*edk);
        #[cfg(feature = "zeroize")]
        zeroize::Zeroize::zeroize(edk);
        Ok(key)
    }
}
