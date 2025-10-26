use alloc::boxed::Box;
use alloc::vec::Vec;

use cipher::StreamCipher;
use generic_array::sequence::Split;
use hmac::Mac;
use paseto_core::PasetoError;
use paseto_core::key::HasKey;
use paseto_core::paserk::{PkeSealingVersion, PkeUnsealingVersion};
use paseto_core::version::{PkePublic, PkeSecret};
use rsa::BigUint;
use rsa::hazmat::{rsa_decrypt_and_check, rsa_encrypt};
use rsa::traits::PublicKeyParts;
use sha2::Digest;
use zerocopy::IntoBytes;

use super::{LocalKey, V1};

#[derive(Clone)]
pub struct PkeSecretKey(rsa::RsaPrivateKey);

#[derive(Clone)]
pub struct PkePublicKey(rsa::RsaPublicKey);

impl HasKey<PkePublic> for V1 {
    type Key = PkePublicKey;
    fn decode(bytes: &[u8]) -> Result<PkePublicKey, PasetoError> {
        use rsa::pkcs8::spki::DecodePublicKey;

        let key = if let Ok(key) = rsa::RsaPublicKey::from_public_key_der(bytes) {
            key
        } else {
            let s = str::from_utf8(bytes).map_err(|_| PasetoError::InvalidKey)?;
            rsa::RsaPublicKey::from_public_key_pem(s).map_err(|_| PasetoError::InvalidKey)?
        };

        if key.n().bits() != 4096 {
            return Err(PasetoError::InvalidKey);
        }

        Ok(PkePublicKey(key))
    }
    fn encode(key: &PkePublicKey) -> Box<[u8]> {
        use rsa::pkcs8::spki::EncodePublicKey;

        key.0
            .to_public_key_der()
            .expect("encoding to spki der should succeed")
            .into_vec()
            .into_boxed_slice()
    }
}

impl HasKey<PkeSecret> for V1 {
    type Key = PkeSecretKey;
    fn decode(bytes: &[u8]) -> Result<PkeSecretKey, PasetoError> {
        use rsa::pkcs1::DecodeRsaPrivateKey;

        let key = if let Ok(key) = rsa::RsaPrivateKey::from_pkcs1_der(bytes) {
            key
        } else {
            let s = str::from_utf8(bytes).map_err(|_| PasetoError::InvalidKey)?;
            rsa::RsaPrivateKey::from_pkcs1_pem(s).map_err(|_| PasetoError::InvalidKey)?
        };

        if key.n().bits() != 4096 {
            return Err(PasetoError::InvalidKey);
        }

        Ok(PkeSecretKey(key))
    }
    fn encode(key: &PkeSecretKey) -> Box<[u8]> {
        use rsa::pkcs1::EncodeRsaPrivateKey;

        key.0
            .to_pkcs1_der()
            .expect("encoding to pkcs1 der should succeed")
            .to_bytes()
            .to_vec()
            .into_boxed_slice()
    }
}

impl PkeSealingVersion for V1 {
    fn seal_key(sealing_key: &PkePublicKey, key: LocalKey) -> Result<Box<[u8]>, PasetoError> {
        use cipher::KeyIvInit;

        let mut r = vec![0u8; 512];
        getrandom::fill(&mut r).map_err(|_| PasetoError::CryptoError)?;
        r[0] &= 0x7f;
        r[0] |= 0x40;
        let c = rsa_encrypt(&sealing_key.0, &BigUint::from_bytes_be(&r))
            .map_err(|_| PasetoError::CryptoError)?
            .to_bytes_be();

        let k = sha2::Sha384::digest(&c);

        let mut mac =
            hmac::Hmac::<sha2::Sha384>::new_from_slice(&k[..]).expect("hmac accepts all key sizes");
        mac.update(b"\x01k1.seal.");
        mac.update(r.as_bytes());
        let (ek, n) = mac.finalize_reset().into_bytes().split();

        mac.update(b"\x02k1.seal.");
        mac.update(r.as_bytes());
        let ak = mac.finalize().into_bytes();

        let mut edk = key.0;
        ctr::Ctr64BE::<aes::Aes256>::new(&ek, &n).apply_keystream(&mut edk);

        let mut tag = hmac::Hmac::<sha2::Sha384>::new_from_slice(&ak).unwrap();
        tag.update(b"k1.seal.");
        tag.update(c.as_bytes());
        tag.update(&edk);
        let tag = tag.finalize().into_bytes();

        let mut output = Vec::with_capacity(48 + 32 + 512);
        output.extend_from_slice(&tag);
        output.extend_from_slice(&edk);
        output.extend_from_slice(c.as_bytes());

        Ok(output.into_boxed_slice())
    }
}

impl PkeUnsealingVersion for V1 {
    fn unseal_key(
        unsealing_key: &PkeSecretKey,
        mut key_data: Box<[u8]>,
    ) -> Result<LocalKey, PasetoError> {
        use cipher::KeyIvInit;

        let (tag, key_data) = key_data
            .split_first_chunk_mut::<48>()
            .ok_or(PasetoError::InvalidKey)?;
        let (edk, c) = key_data
            .split_last_chunk_mut::<512>()
            .ok_or(PasetoError::InvalidKey)?;

        let c: &[u8] = &*c;
        let edk: &mut [u8; 32] = edk.try_into().map_err(|_| PasetoError::InvalidKey)?;

        let r = rsa_decrypt_and_check::<rsa::rand_core::OsRng>(
            &unsealing_key.0,
            None,
            &BigUint::from_bytes_be(c),
        )
        .map_err(|_| PasetoError::CryptoError)?
        .to_bytes_be();

        let k = sha2::Sha384::digest(c);

        let mut mac =
            hmac::Hmac::<sha2::Sha384>::new_from_slice(&k[..]).expect("hmac accepts all key sizes");

        mac.update(b"\x02k1.seal.");
        mac.update(r.as_bytes());
        let ak = mac.finalize_reset().into_bytes();

        let mut t2 = hmac::Hmac::<sha2::Sha384>::new_from_slice(&ak).unwrap();
        t2.update(b"k1.seal.");
        t2.update(c);
        t2.update(edk);

        // step 6: Compare t2 with t, using a constant-time compare function. If it does not match, abort.
        t2.verify((&*tag).into())
            .map_err(|_| PasetoError::CryptoError)?;

        mac.update(b"\x01k1.seal.");
        mac.update(r.as_bytes());
        let (ek, n) = mac.finalize().into_bytes().split();

        ctr::Ctr64BE::<aes::Aes256>::new(&ek, &n).apply_keystream(edk);

        Ok(LocalKey(*edk))
    }
}
