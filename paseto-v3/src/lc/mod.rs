mod ptr;

use std::ptr::{null, null_mut};

use aws_lc_sys::{
    BN_bin2bn, BN_bn2bin, BN_num_bytes, EC_GROUP, EC_KEY, EC_KEY_get0_private_key,
    EC_KEY_get0_public_key, EC_KEY_new, EC_KEY_set_group, EC_KEY_set_private_key,
    EC_KEY_set_public_key, EC_POINT, EC_POINT_mul, EC_POINT_new, EC_POINT_oct2point,
    EC_POINT_point2oct, EC_group_p384, ECDSA_SIG, ECDSA_SIG_from_bytes, ECDSA_SIG_get0,
    ECDSA_SIG_new, ECDSA_SIG_set0, ECDSA_SIG_to_bytes, ECDSA_sign, ECDSA_size, ECDSA_verify,
};
use paseto_core::PasetoError;

use crate::lc::ptr::{ConstPointer, DetachableLcPtr, LcPtr};

#[cfg(feature = "fips")]
extern crate aws_lc_fips_sys as aws_lc;
#[cfg(not(feature = "fips"))]
extern crate aws_lc_sys as aws_lc;

pub struct SigningKey {
    key: LcPtr<EC_KEY>,
}

impl Clone for SigningKey {
    fn clone(&self) -> Self {
        let g = unsafe { ConstPointer::new_static(EC_group_p384()).unwrap() };

        let key = self.key.as_const();
        let pk = key
            .project(|k| unsafe { EC_KEY_get0_public_key(**k) })
            .unwrap();
        let bn = key
            .project(|k| unsafe { EC_KEY_get0_private_key(**k) })
            .unwrap();

        let mut key = LcPtr::new(unsafe { EC_KEY_new() }).unwrap();

        if unsafe { EC_KEY_set_group(*key.as_mut(), *g) } != 1 {
            panic!("unable to clone signing key");
        }
        if unsafe { EC_KEY_set_private_key(*key.as_mut(), *bn) } != 1 {
            panic!("unable to clone signing key");
        }
        if unsafe { EC_KEY_set_public_key(*key.as_mut(), *pk) } != 1 {
            panic!("unable to clone signing key");
        }

        Self { key }
    }
}

unsafe impl Send for SigningKey {}
unsafe impl Sync for SigningKey {}

impl SigningKey {
    #[inline]
    pub fn from_sec1_bytes(bytes: &[u8]) -> Result<Self, PasetoError> {
        let g = unsafe { ConstPointer::new_static(EC_group_p384())? };

        let bn = LcPtr::new(unsafe { BN_bin2bn(bytes.as_ptr(), bytes.len(), null_mut()) })
            .map_err(|_| PasetoError::InvalidKey)?;

        let mut pk = LcPtr::new(unsafe { EC_POINT_new(*g) })?;
        if unsafe { EC_POINT_mul(*g, *pk.as_mut(), *bn.as_const(), null(), null(), null_mut()) }
            != 1
        {
            return Err(PasetoError::CryptoError);
        }

        let mut key = LcPtr::new(unsafe { EC_KEY_new() })?;

        if unsafe { EC_KEY_set_group(*key.as_mut(), *g) } != 1 {
            return Err(PasetoError::CryptoError);
        }
        if unsafe { EC_KEY_set_private_key(*key.as_mut(), *bn.as_const()) } != 1 {
            return Err(PasetoError::CryptoError);
        }
        if unsafe { EC_KEY_set_public_key(*key.as_mut(), *pk.as_const()) } != 1 {
            return Err(PasetoError::CryptoError);
        }

        Ok(Self { key })
    }

    pub fn encode(&self) -> [u8; 48] {
        let key = self.key.as_const();
        let key = key
            .project(|k| unsafe { EC_KEY_get0_private_key(**k) })
            .unwrap();

        let key_len = unsafe { BN_num_bytes(*key) } as usize;
        if key_len > 48 {
            panic!("invalid key_len");
        }

        let mut key_bytes = [0; 48];
        if unsafe { BN_bn2bin(*key, key_bytes[48 - key_len..].as_mut_ptr()) } != key_len {
            panic!("invalid key_len");
        }

        key_bytes
    }

    pub fn compressed_pub_key(&self) -> [u8; 49] {
        let key = self.key.as_const();
        let key = key
            .project(|k| unsafe { EC_KEY_get0_public_key(**k) })
            .unwrap();

        compressed_pub_key(key)
    }

    pub fn verifying_key(&self) -> VerifyingKey {
        let key = self.key.as_const();
        let p = key
            .project(|k| unsafe { EC_KEY_get0_public_key(**k) })
            .unwrap();

        let g =
            unsafe { ConstPointer::new_static(EC_group_p384()).expect("group should be valid") };

        VerifyingKey::from_point(g, p).expect("pub_key point should be valid")
    }

    #[inline]
    pub fn sign(&self, digest: &[u8]) -> Result<Signature, PasetoError> {
        let key = self.key.as_const();

        if unsafe { ECDSA_size(*key) } != 104 {
            return Err(PasetoError::CryptoError);
        }

        let mut sig_len = 0;
        let mut sig = [0; 104];
        let res = unsafe {
            ECDSA_sign(
                0,
                digest.as_ptr(),
                digest.len(),
                sig.as_mut_ptr(),
                &mut sig_len,
                *key,
            )
        };
        if res != 1 {
            return Err(PasetoError::CryptoError);
        }

        let sig = LcPtr::new(unsafe { ECDSA_SIG_from_bytes(sig.as_ptr(), sig_len as usize) })?;
        Ok(Signature { sig })
    }
}

pub struct Signature {
    sig: LcPtr<ECDSA_SIG>,
}

impl Signature {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, PasetoError> {
        if bytes.len() != 96 {
            return Err(PasetoError::CryptoError);
        }
        let r = &bytes[0..48];
        let s = &bytes[48..96];

        let r = DetachableLcPtr::new(unsafe { BN_bin2bn(r.as_ptr(), r.len(), null_mut()) })?;
        let s = DetachableLcPtr::new(unsafe { BN_bin2bn(s.as_ptr(), s.len(), null_mut()) })?;

        let mut sig = LcPtr::new(unsafe { ECDSA_SIG_new() })?;
        if unsafe { ECDSA_SIG_set0(*sig.as_mut(), *r, *s) } != 1 {
            return Err(PasetoError::CryptoError);
        }
        r.detach();
        s.detach();

        Ok(Signature { sig })
    }

    pub fn append_to_vec(&self, out: &mut Vec<u8>) -> Result<(), PasetoError> {
        let sig = &self.sig;

        let mut r = null();
        let mut s = null();
        unsafe { ECDSA_SIG_get0(*sig.as_const(), &mut r, &mut s) };

        if unsafe { BN_num_bytes(r) } != 48 || unsafe { BN_num_bytes(s) } != 48 {
            return Err(PasetoError::CryptoError);
        }

        out.reserve(48 + 48);
        let len = out.len();
        let ptr = out.spare_capacity_mut().as_mut_ptr().cast();
        if unsafe { BN_bn2bin(r, ptr) } != 48 {
            return Err(PasetoError::CryptoError);
        }
        if unsafe { BN_bn2bin(s, ptr.add(48)) } != 48 {
            return Err(PasetoError::CryptoError);
        }
        unsafe { out.set_len(len + 48 + 48) };

        Ok(())
    }
}

pub struct VerifyingKey {
    key: LcPtr<EC_KEY>,
}

impl Clone for VerifyingKey {
    fn clone(&self) -> Self {
        let g = unsafe { ConstPointer::new_static(EC_group_p384()).unwrap() };

        let key = self.key.as_const();
        let p = key
            .project(|k| unsafe { EC_KEY_get0_public_key(**k) })
            .unwrap();

        Self::from_point(g, p).unwrap()
    }
}

unsafe impl Send for VerifyingKey {}
unsafe impl Sync for VerifyingKey {}

impl VerifyingKey {
    #[inline]
    pub fn from_sec1_bytes(b: &[u8]) -> Result<Self, PasetoError> {
        let g = unsafe { ConstPointer::new_static(EC_group_p384())? };

        let mut p = LcPtr::new(unsafe { EC_POINT_new(*g) })?;
        if unsafe { EC_POINT_oct2point(*g, *p.as_mut(), b.as_ptr(), b.len(), null_mut()) } != 1 {
            return Err(PasetoError::InvalidKey);
        }

        Self::from_point(g, p.as_const())
    }

    #[inline]
    fn from_point(
        g: ConstPointer<'static, EC_GROUP>,
        p: ConstPointer<'_, EC_POINT>,
    ) -> Result<Self, PasetoError> {
        let mut key = LcPtr::new(unsafe { EC_KEY_new() })?;

        if unsafe { EC_KEY_set_group(*key.as_mut(), *g) } != 1 {
            return Err(PasetoError::CryptoError);
        }
        if unsafe { EC_KEY_set_public_key(*key.as_mut(), *p) } != 1 {
            return Err(PasetoError::CryptoError);
        }

        Ok(Self { key })
    }

    pub fn compressed_pub_key(&self) -> [u8; 49] {
        let key = self.key.as_const();
        let key = key
            .project(|k| unsafe { EC_KEY_get0_public_key(**k) })
            .unwrap();

        compressed_pub_key(key)
    }

    #[inline]
    pub fn verify(&self, digest: &[u8], signature: &Signature) -> Result<(), PasetoError> {
        let mut sig_len = 0;
        let mut sig = null_mut();
        if unsafe { ECDSA_SIG_to_bytes(&mut sig, &mut sig_len, *signature.sig.as_const()) } != 1 {
            return Err(PasetoError::CryptoError);
        }
        let sig = LcPtr::new(sig)?;

        let res = unsafe {
            ECDSA_verify(
                0,
                digest.as_ptr(),
                digest.len(),
                *sig.as_const(),
                sig_len,
                *self.key.as_const(),
            )
        };

        if res != 1 {
            return Err(PasetoError::CryptoError);
        }

        Ok(())
    }
}

pub fn compressed_pub_key(p: ConstPointer<EC_POINT>) -> [u8; 49] {
    let g = unsafe { ConstPointer::new_static(EC_group_p384()).expect("group should be valid") };

    let mut out = [0; 49];
    let len = unsafe {
        EC_POINT_point2oct(
            *g,
            *p,
            aws_lc_sys::point_conversion_form_t::POINT_CONVERSION_COMPRESSED,
            out.as_mut_ptr(),
            out.len(),
            null_mut(),
        )
    };

    if len != 49 {
        panic!("compressed point should be 49 bytes");
    }

    out
}
