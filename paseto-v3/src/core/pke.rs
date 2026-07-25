use alloc::boxed::Box;
use alloc::vec::Vec;

use cipher::StreamCipher;
use hmac::Mac;
use hybrid_array::sizes::U32;
use paseto_core::PasetoError;
use paseto_core::key::HasKey;
use paseto_core::paserk::{PkeSealingVersion, PkeUnsealingVersion};
use paseto_core::version::{PkePublic, PkeSecret, Public, Secret};
use sha2::Digest;

use super::{LocalKey, PublicKey, SecretKey, V3};

impl HasKey<PkePublic> for V3 {
    type Key = PublicKey;
    fn decode(bytes: &[u8]) -> Result<PublicKey, PasetoError> {
        <V3 as HasKey<Public>>::decode(bytes)
    }
    fn encode(key: &PublicKey) -> Box<[u8]> {
        <V3 as HasKey<Public>>::encode(key)
    }
}

impl HasKey<PkeSecret> for V3 {
    type Key = SecretKey;
    fn decode(bytes: &[u8]) -> Result<SecretKey, PasetoError> {
        <V3 as HasKey<Secret>>::decode(bytes)
    }
    fn encode(key: &SecretKey) -> Box<[u8]> {
        <V3 as HasKey<Secret>>::encode(key)
    }
}

impl PkeSealingVersion for V3 {
    fn seal_key(sealing_key: &PublicKey, key: &mut LocalKey) -> Result<Box<[u8]>, PasetoError> {
        use cipher::KeyIvInit;
        use p384::Sec1Point;
        use p384::ecdh::diffie_hellman;
        use p384::elliptic_curve::sec1::ToSec1Point;

        let pk = sealing_key.0.to_sec1_point(true);

        let esk = p384::SecretKey::from(SecretKey::random()?.0);
        let epk: Sec1Point = esk.public_key().to_sec1_point(true);

        let xk = diffie_hellman(esk.to_nonzero_scalar(), sealing_key.0.as_affine());

        let mut ek = sha2::Sha384::new();
        ek.update(b"\x01k3.seal.");
        ek.update(xk.raw_secret_bytes());
        ek.update(epk);
        ek.update(pk.as_bytes());
        let (ek, n) = ek.finalize().split::<U32>();

        let mut ak = sha2::Sha384::new();
        ak.update(b"\x02k3.seal.");
        ak.update(xk.raw_secret_bytes());
        ak.update(epk);
        ak.update(pk.as_bytes());
        let ak = ak.finalize();

        ctr::Ctr64BE::<aes::Aes256>::new(&ek, &n).apply_keystream(&mut key.0);

        let mut tag = <hmac::Hmac<sha2::Sha384> as digest::KeyInit>::new_from_slice(&ak).unwrap();
        tag.update(b"k3.seal.");
        tag.update(epk.as_bytes());
        tag.update(&key.0);
        let tag = tag.finalize().into_bytes();

        let mut output = Vec::with_capacity(48 + 49 + 32);
        output.extend_from_slice(&tag);
        output.extend_from_slice(epk.as_bytes());
        output.extend_from_slice(&key.0);

        Ok(output.into_boxed_slice())
    }
}

impl PkeUnsealingVersion for V3 {
    fn random_pke_secret_key() -> Result<SecretKey, PasetoError> {
        use paseto_core::version::SealingVersion;
        <V3 as SealingVersion<Public>>::random()
    }

    fn pke_public_key_from_secret(sk: &SecretKey) -> PublicKey {
        use paseto_core::version::SealingVersion;
        <V3 as SealingVersion<Public>>::unsealing_key(sk)
    }

    fn unseal_key(
        unsealing_key: &SecretKey,
        mut key_data: Box<[u8]>,
    ) -> Result<LocalKey, PasetoError> {
        use cipher::KeyIvInit;
        use p384::ecdh::diffie_hellman;
        use p384::{AffinePoint, Sec1Point};

        let (tag, key_data) = key_data
            .split_first_chunk_mut::<48>()
            .ok_or(PasetoError::InvalidKey)?;
        let (epk, edk) = key_data
            .split_first_chunk_mut::<49>()
            .ok_or(PasetoError::InvalidKey)?;

        let epk: &[u8; 49] = &*epk;
        let edk: &mut [u8; 32] = edk.try_into().map_err(|_| PasetoError::InvalidKey)?;

        let sk = p384::SecretKey::from(&unsealing_key.0);

        use p384::elliptic_curve::sec1::ToSec1Point;
        let pk = sk.public_key().to_sec1_point(true);

        let epk_point = Sec1Point::from_bytes(epk).map_err(|_| PasetoError::CryptoError)?;
        let epk_point = AffinePoint::try_from(&epk_point).map_err(|_| PasetoError::CryptoError)?;

        let xk = diffie_hellman(sk.to_nonzero_scalar(), epk_point);

        let mut ak = sha2::Sha384::new();
        ak.update(b"\x02k3.seal.");
        ak.update(xk.raw_secret_bytes());
        ak.update(epk);
        ak.update(pk.as_bytes());
        let ak = ak.finalize();

        let mut t2 = <hmac::Hmac<sha2::Sha384> as digest::KeyInit>::new_from_slice(&ak).unwrap();
        t2.update(b"k3.seal.");
        t2.update(epk);
        t2.update(edk);

        // step 6: Compare t2 with t, using a constant-time compare function. If it does not match, abort.
        t2.verify((&*tag).into())
            .map_err(|_| PasetoError::CryptoError)?;

        let mut ek = sha2::Sha384::new();
        ek.update(b"\x01k3.seal.");
        ek.update(xk.raw_secret_bytes());
        ek.update(epk);
        ek.update(pk.as_bytes());
        let (ek, n) = ek.finalize().split::<U32>();

        ctr::Ctr64BE::<aes::Aes256>::new(&ek, &n).apply_keystream(edk);

        let key = LocalKey(*edk);
        #[cfg(feature = "zeroize")]
        zeroize::Zeroize::zeroize(edk);
        Ok(key)
    }
}
