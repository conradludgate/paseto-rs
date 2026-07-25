use aws_lc_rs::agreement::{self, ECDH_P384};
use aws_lc_rs::digest;
use aws_lc_rs::encoding::AsBigEndian;
use aws_lc_rs::signature::{
    self, ECDSA_P384_SHA384_FIXED, ECDSA_P384_SHA384_FIXED_SIGNING, EcdsaKeyPair,
};
use paseto_core::PasetoError;

#[derive(Clone)]
#[cfg_attr(feature = "zeroize", derive(zeroize::Zeroize, zeroize::ZeroizeOnDrop))]
pub struct SigningKey {
    scalar: [u8; 48],
    compressed_pubkey: [u8; 49],
    uncompressed_pubkey: Vec<u8>,
}

impl SigningKey {
    pub fn from_sec1_bytes(bytes: &[u8]) -> Result<Self, PasetoError> {
        let ecdh_key = agreement::PrivateKey::from_private_key(&ECDH_P384, bytes)
            .map_err(|_| PasetoError::InvalidKey)?;
        let pk = ecdh_key
            .compute_public_key()
            .map_err(|_| PasetoError::CryptoError)?;
        let compressed: aws_lc_rs::encoding::EcPublicKeyCompressedBin =
            pk.as_be_bytes().map_err(|_| PasetoError::CryptoError)?;

        let mut scalar = [0u8; 48];
        scalar.copy_from_slice(bytes);

        Ok(Self {
            scalar,
            compressed_pubkey: compressed
                .as_ref()
                .try_into()
                .map_err(|_| PasetoError::CryptoError)?,
            uncompressed_pubkey: pk.as_ref().to_vec(),
        })
    }

    pub fn encode(&self) -> [u8; 48] {
        self.scalar
    }

    fn ecdsa_key_pair(&self) -> Result<EcdsaKeyPair, PasetoError> {
        EcdsaKeyPair::from_private_key_and_public_key(
            &ECDSA_P384_SHA384_FIXED_SIGNING,
            &self.scalar,
            &self.uncompressed_pubkey,
        )
        .map_err(|_| PasetoError::CryptoError)
    }

    pub fn compressed_pub_key(&self) -> [u8; 49] {
        self.compressed_pubkey
    }

    pub fn verifying_key(&self) -> VerifyingKey {
        VerifyingKey::from_sec1_bytes(&self.compressed_pubkey)
            .expect("compressed pubkey should be valid")
    }

    pub fn sign(&self, digest: &digest::Digest) -> Result<[u8; 96], PasetoError> {
        let key_pair = self.ecdsa_key_pair()?;
        let sig = key_pair
            .sign_digest(digest)
            .map_err(|_| PasetoError::CryptoError)?;
        sig.as_ref()
            .try_into()
            .map_err(|_| PasetoError::CryptoError)
    }

    pub fn diffie_hellman(&self, pubkey: &VerifyingKey) -> Result<[u8; 48], PasetoError> {
        let ecdh_key = agreement::PrivateKey::from_private_key(&ECDH_P384, &self.scalar)
            .map_err(|_| PasetoError::CryptoError)?;
        let peer_pk = agreement::UnparsedPublicKey::new(&ECDH_P384, &pubkey.compressed_pubkey);
        agreement::agree(&ecdh_key, &peer_pk, PasetoError::CryptoError, |shared| {
            shared.try_into().map_err(|_| PasetoError::CryptoError)
        })
    }
}

#[derive(Clone)]
pub struct VerifyingKey {
    key: signature::ParsedPublicKey,
    compressed_pubkey: [u8; 49],
}

impl VerifyingKey {
    pub fn from_sec1_bytes(b: &[u8]) -> Result<Self, PasetoError> {
        let key = signature::ParsedPublicKey::new(&ECDSA_P384_SHA384_FIXED, b)
            .map_err(|_| PasetoError::InvalidKey)?;

        let compressed = if b.len() == 49 {
            b.try_into().map_err(|_| PasetoError::InvalidKey)?
        } else {
            compress_p384_point(b)?
        };

        Ok(Self {
            key,
            compressed_pubkey: compressed,
        })
    }

    pub fn compressed_pub_key(&self) -> [u8; 49] {
        self.compressed_pubkey
    }

    pub fn verify(&self, digest: &digest::Digest, signature: &[u8]) -> Result<(), PasetoError> {
        self.key
            .verify_digest_sig(digest, signature)
            .map_err(|_| PasetoError::CryptoError)
    }
}

fn compress_p384_point(uncompressed: &[u8]) -> Result<[u8; 49], PasetoError> {
    if uncompressed.len() != 97 || uncompressed[0] != 0x04 {
        return Err(PasetoError::InvalidKey);
    }
    let mut out = [0u8; 49];
    let y_last_byte = uncompressed[96];
    out[0] = if y_last_byte & 1 == 0 { 0x02 } else { 0x03 };
    out[1..].copy_from_slice(&uncompressed[1..49]);
    Ok(out)
}
