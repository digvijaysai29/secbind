use base64::{engine::general_purpose::STANDARD, Engine as _};
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Key, Nonce,
};
use hkdf::Hkdf;
use pqcrypto_kyber::kyber768;
use pqcrypto_traits::kem::{Ciphertext, PublicKey, SecretKey, SharedSecret};
use rand::Rng;
use serde::{Deserialize, Serialize};
use sha3::Sha3_512;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::SecBindError;

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct SealedSecret {
    pub kem_ciphertext: String,
    pub nonce: String,
    pub ciphertext: String,
}

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SealingKeypair {
    pub kem_sk: Vec<u8>,
    pub dsa_sk: Vec<u8>,
}

pub fn seal(
    plaintext: &[u8],
    ml_kem_pk_bytes: &[u8],
    fingerprint: &[u8],
) -> Result<SealedSecret, SecBindError> {
    let pk = kyber768::PublicKey::from_bytes(ml_kem_pk_bytes)
        .map_err(|e| SecBindError::KemError(e.to_string()))?;

    let (shared_secret, kem_ct) = kyber768::encapsulate(&pk);

    let hk = Hkdf::<Sha3_512>::new(Some(fingerprint), shared_secret.as_bytes());
    let mut key_bytes = [0u8; 32];
    hk.expand(b"secbind-v1-seal", &mut key_bytes)
        .map_err(|_| SecBindError::KemError("HKDF expand failed".to_string()))?;

    let cipher = ChaCha20Poly1305::new(Key::from_slice(&key_bytes));
    let nonce_arr: [u8; 12] = rand::thread_rng().gen();
    let nonce = Nonce::from_slice(&nonce_arr);
    let ciphertext_bytes = cipher
        .encrypt(nonce, plaintext)
        .map_err(|_| SecBindError::DecryptionFailed)?;

    key_bytes.zeroize();

    Ok(SealedSecret {
        kem_ciphertext: STANDARD.encode(kem_ct.as_bytes()),
        nonce: STANDARD.encode(nonce_arr),
        ciphertext: STANDARD.encode(ciphertext_bytes),
    })
}

pub fn reveal(
    sealed: &SealedSecret,
    ml_kem_sk_bytes: &[u8],
    fingerprint: &[u8],
) -> Result<Vec<u8>, SecBindError> {
    let kem_ct_bytes = STANDARD
        .decode(&sealed.kem_ciphertext)
        .map_err(|e| SecBindError::SerializationError(e.to_string()))?;
    let nonce_bytes = STANDARD
        .decode(&sealed.nonce)
        .map_err(|e| SecBindError::SerializationError(e.to_string()))?;
    let ct_bytes = STANDARD
        .decode(&sealed.ciphertext)
        .map_err(|e| SecBindError::SerializationError(e.to_string()))?;

    if nonce_bytes.len() != 12 {
        return Err(SecBindError::SerializationError(
            "invalid nonce length".to_string(),
        ));
    }

    let sk = kyber768::SecretKey::from_bytes(ml_kem_sk_bytes)
        .map_err(|e| SecBindError::KemError(e.to_string()))?;
    let kem_ct = kyber768::Ciphertext::from_bytes(&kem_ct_bytes)
        .map_err(|e| SecBindError::KemError(e.to_string()))?;

    let shared_secret = kyber768::decapsulate(&kem_ct, &sk);

    let hk = Hkdf::<Sha3_512>::new(Some(fingerprint), shared_secret.as_bytes());
    let mut key_bytes = [0u8; 32];
    hk.expand(b"secbind-v1-seal", &mut key_bytes)
        .map_err(|_| SecBindError::KemError("HKDF expand failed".to_string()))?;

    let cipher = ChaCha20Poly1305::new(Key::from_slice(&key_bytes));
    let nonce = Nonce::from_slice(&nonce_bytes);
    let plaintext = cipher
        .decrypt(nonce, ct_bytes.as_ref())
        .map_err(|_| SecBindError::FingerprintMismatch)?;

    key_bytes.zeroize();

    Ok(plaintext)
}
