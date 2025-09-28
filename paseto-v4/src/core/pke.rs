use alloc::boxed::Box;
use alloc::vec::Vec;

use cipher::StreamCipher;
use curve25519_dalek::EdwardsPoint;
use digest::Mac;
use generic_array::typenum::U32;
use paseto_core::PasetoError;
use paseto_core::version::PkeVersion;

use super::{LocalKey, PublicKey, SecretKey, V4};

impl PkeVersion for V4 {
    fn seal_key(sealing_key: &PublicKey, key: LocalKey) -> Result<Box<[u8]>, PasetoError> {
        use cipher::KeyIvInit;
        use curve25519_dalek::edwards::CompressedEdwardsY;
        use curve25519_dalek::scalar::{Scalar, clamp_integer};
        use digest::Digest;

        // Given a plaintext data key (pdk), and an Ed25519 public key (pk).
        let pk = CompressedEdwardsY(*sealing_key.0.as_bytes());

        // step 1: Calculate the birationally-equivalent X25519 public key (xpk) from pk.
        let xpk = pk.decompress().unwrap().to_montgomery();

        let esk = Scalar::from_bytes_mod_order(clamp_integer({
            let mut esk = [0; 32];
            getrandom::fill(&mut esk).map_err(|_| PasetoError::CryptoError)?;
            esk
        }));
        let epk = EdwardsPoint::mul_base(&esk).to_montgomery();

        // diffie hellman exchange
        let xk = esk * xpk;

        let mut ek = blake2::Blake2b::new();
        ek.update(b"\x01k4.seal.");
        ek.update(xk.as_bytes());
        ek.update(epk.as_bytes());
        ek.update(xpk.as_bytes());
        let ek = ek.finalize();

        let mut n = blake2::Blake2b::new();
        n.update(epk.as_bytes());
        n.update(xpk.as_bytes());
        let n = n.finalize();

        let mut edk = key.0;
        chacha20::XChaCha20::new(&ek, &n).apply_keystream(&mut edk);

        let mut ak = blake2::Blake2b::<U32>::new();
        ak.update(b"\x02k4.seal.");
        ak.update(xk.as_bytes());
        ak.update(epk.as_bytes());
        ak.update(xpk.as_bytes());
        let ak = ak.finalize();

        let mut tag = blake2::Blake2bMac::<U32>::new_from_slice(&ak).unwrap();
        tag.update(b"k4.seal.");
        tag.update(epk.as_bytes());
        tag.update(&edk);
        let tag = tag.finalize().into_bytes();

        let mut output = Vec::with_capacity(96);
        output.extend_from_slice(&tag);
        output.extend_from_slice(epk.as_bytes());
        output.extend_from_slice(&edk);

        Ok(output.into_boxed_slice())
    }

    fn unseal_key(
        unsealing_key: &SecretKey,
        mut key_data: Box<[u8]>,
    ) -> Result<LocalKey, PasetoError> {
        use cipher::KeyIvInit;
        use digest::Digest;

        let (tag, key_data) = key_data
            .split_first_chunk_mut::<32>()
            .ok_or(PasetoError::InvalidKey)?;
        let (epk, edk) = key_data
            .split_first_chunk_mut::<32>()
            .ok_or(PasetoError::InvalidKey)?;
        let edk: &mut [u8; 32] = edk.try_into().map_err(|_| PasetoError::InvalidKey)?;

        let epk = curve25519_dalek::MontgomeryPoint(*epk);

        // expand pk/sk pair from ed25519 to x25519
        let xpk = EdwardsPoint::mul_base(&unsealing_key.1.scalar).to_montgomery();

        // diffie hellman exchange
        let xk = unsealing_key.1.scalar * epk;

        let mut ak = blake2::Blake2b::<U32>::new();
        ak.update(b"\x02k4.seal.");
        ak.update(xk.as_bytes());
        ak.update(epk.as_bytes());
        ak.update(xpk.as_bytes());
        let ak = ak.finalize();

        let mut t2 = blake2::Blake2bMac::<U32>::new_from_slice(&ak).unwrap();
        t2.update(b"k4.seal.");
        t2.update(epk.as_bytes());
        t2.update(edk);

        // step 6: Compare t2 with t, using a constant-time compare function. If it does not match, abort.
        t2.verify((&*tag).into())
            .map_err(|_| PasetoError::CryptoError)?;

        let mut ek = blake2::Blake2b::new();
        ek.update(b"\x01k4.seal.");
        ek.update(xk.as_bytes());
        ek.update(epk.as_bytes());
        ek.update(xpk.as_bytes());
        let ek = ek.finalize();

        let mut n = blake2::Blake2b::new();
        n.update(epk.as_bytes());
        n.update(xpk.as_bytes());
        let n = n.finalize();

        chacha20::XChaCha20::new(&ek, &n).apply_keystream(edk);

        Ok(LocalKey((*edk).into()))
    }
}
