use aws_lc_rs::cipher::{AES_256, UnboundCipherKey};
use aws_lc_rs::constant_time;
use aws_lc_rs::digest::{self, SHA384};
use aws_lc_rs::hmac::{self, HMAC_SHA384};
use aws_lc_rs::iv::FixedLength;
use paseto_core::PasetoError;
use paseto_core::key::SealingKey;
use paseto_core::paserk::PkeVersion;

use super::{Cipher, LocalKey, PublicKey, SecretKey, V3};
use crate::lc::VerifyingKey;

fn seal_keys(
    xk: &[u8; 48],
    epk: &[u8; 49],
    pk: &[u8; 49],
) -> Result<(Cipher, hmac::Key), PasetoError> {
    let mut ek = digest::Context::new(&SHA384);
    ek.update(b"\x01k3.seal.");
    ek.update(xk);
    ek.update(epk);
    ek.update(pk);
    let ek = ek.finish();
    let (ek, n) = ek
        .as_ref()
        .split_last_chunk::<16>()
        .ok_or(PasetoError::CryptoError)?;

    let mut ak = digest::Context::new(&SHA384);
    ak.update(b"\x02k3.seal.");
    ak.update(xk);
    ak.update(epk);
    ak.update(pk);
    let ak = ak.finish();

    let key = UnboundCipherKey::new(&AES_256, ek).map_err(|_| PasetoError::CryptoError)?;
    let iv = FixedLength::from(n);
    let mac = hmac::Key::new(HMAC_SHA384, ak.as_ref());

    Ok((Cipher(key, iv), mac))
}

impl PkeVersion for V3 {
    fn seal_key(sealing_key: &PublicKey, key: LocalKey) -> Result<Box<[u8]>, PasetoError> {
        let pk = sealing_key.0.compressed_pub_key();

        let esk = SecretKey::random()?.0;
        let epk = esk.verifying_key().compressed_pub_key();

        let xk = esk.diffie_hellman(&sealing_key.0)?;

        let (cipher, mac) = seal_keys(&xk, &epk, &pk)?;

        let mut edk = key.0;
        cipher.apply_keystream(&mut edk)?;

        let mut tag = hmac::Context::with_key(&mac);
        tag.update(b"k3.seal.");
        tag.update(&epk);
        tag.update(&edk);
        let tag = tag.sign();

        let mut output = Vec::with_capacity(48 + 49 + 32);
        output.extend_from_slice(tag.as_ref());
        output.extend_from_slice(&epk);
        output.extend_from_slice(&edk);

        Ok(output.into_boxed_slice())
    }

    fn unseal_key(
        unsealing_key: &SecretKey,
        mut key_data: Box<[u8]>,
    ) -> Result<LocalKey, PasetoError> {
        let (tag, key_data) = key_data
            .split_first_chunk_mut::<48>()
            .ok_or(PasetoError::InvalidKey)?;
        let (epk, edk) = key_data
            .split_first_chunk_mut::<49>()
            .ok_or(PasetoError::InvalidKey)?;

        let epk: &[u8; 49] = &*epk;
        let edk: &mut [u8; 32] = edk.try_into().map_err(|_| PasetoError::InvalidKey)?;

        let epk_point = VerifyingKey::from_sec1_bytes(epk)?;
        let xk = unsealing_key.0.diffie_hellman(&epk_point)?;

        let pk = unsealing_key.0.compressed_pub_key();
        let (cipher, mac) = seal_keys(&xk, epk, &pk)?;

        let mut t2 = hmac::Context::with_key(&mac);
        t2.update(b"k3.seal.");
        t2.update(epk);
        t2.update(edk);
        let t2 = t2.sign();

        // step 6: Compare t2 with t, using a constant-time compare function. If it does not match, abort.
        constant_time::verify_slices_are_equal(t2.as_ref(), tag)
            .map_err(|_| PasetoError::CryptoError)?;

        cipher.apply_keystream(edk)?;
        Ok(LocalKey(*edk))
    }
}
