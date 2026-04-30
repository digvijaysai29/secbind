use base64::{engine::general_purpose::STANDARD, Engine as _};
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Key, Nonce,
};
use hkdf::Hkdf;
use pqcrypto_kyber::kyber768;
use pqcrypto_mlkem::mlkem768;
use pqcrypto_traits::kem::{Ciphertext, PublicKey, SecretKey, SharedSecret};
use rand::Rng;
use serde::{Deserialize, Serialize};
use sha3::Sha3_512;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::SecBindError;
use crate::version::{EnvelopeVersion, LATEST_ENVELOPE_VERSION};

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

fn hkdf_info_for_version(version: EnvelopeVersion) -> &'static [u8] {
    match version {
        EnvelopeVersion::V1 => b"secbind-v1-seal",
        EnvelopeVersion::V2 => b"secbind-v2-seal",
    }
}

fn encrypt_with_shared_secret(
    shared_secret: &[u8],
    fingerprint: &[u8],
    info: &[u8],
    plaintext: &[u8],
) -> Result<(String, String), SecBindError> {
    let hk = Hkdf::<Sha3_512>::new(Some(fingerprint), shared_secret);
    let mut key_bytes = [0u8; 32];
    hk.expand(info, &mut key_bytes)
        .map_err(|_| SecBindError::KemError("HKDF expand failed".to_string()))?;

    let cipher = ChaCha20Poly1305::new(Key::from_slice(&key_bytes));
    let nonce_arr: [u8; 12] = rand::thread_rng().gen();
    let nonce = Nonce::from_slice(&nonce_arr);
    let ciphertext_bytes = cipher
        .encrypt(nonce, plaintext)
        .map_err(|_| SecBindError::DecryptionFailed)?;

    key_bytes.zeroize();

    Ok((
        STANDARD.encode(nonce_arr),
        STANDARD.encode(ciphertext_bytes),
    ))
}

fn decrypt_with_shared_secret(
    shared_secret: &[u8],
    fingerprint: &[u8],
    info: &[u8],
    nonce_bytes: &[u8],
    ct_bytes: &[u8],
) -> Result<Vec<u8>, SecBindError> {
    let hk = Hkdf::<Sha3_512>::new(Some(fingerprint), shared_secret);
    let mut key_bytes = [0u8; 32];
    hk.expand(info, &mut key_bytes)
        .map_err(|_| SecBindError::KemError("HKDF expand failed".to_string()))?;

    let cipher = ChaCha20Poly1305::new(Key::from_slice(&key_bytes));
    let nonce = Nonce::from_slice(nonce_bytes);
    let plaintext = cipher
        .decrypt(nonce, ct_bytes)
        .map_err(|_| SecBindError::FingerprintMismatch)?;

    key_bytes.zeroize();
    Ok(plaintext)
}

pub fn seal_for_version(
    version: EnvelopeVersion,
    plaintext: &[u8],
    ml_kem_pk_bytes: &[u8],
    fingerprint: &[u8],
) -> Result<SealedSecret, SecBindError> {
    let info = hkdf_info_for_version(version);

    match version {
        EnvelopeVersion::V1 => {
            let pk = kyber768::PublicKey::from_bytes(ml_kem_pk_bytes)
                .map_err(|e| SecBindError::KemError(e.to_string()))?;
            let (shared_secret, kem_ct) = kyber768::encapsulate(&pk);
            let (nonce_b64, ciphertext_b64) =
                encrypt_with_shared_secret(shared_secret.as_bytes(), fingerprint, info, plaintext)?;

            Ok(SealedSecret {
                kem_ciphertext: STANDARD.encode(kem_ct.as_bytes()),
                nonce: nonce_b64,
                ciphertext: ciphertext_b64,
            })
        }
        EnvelopeVersion::V2 => {
            let pk = mlkem768::PublicKey::from_bytes(ml_kem_pk_bytes)
                .map_err(|e| SecBindError::KemError(e.to_string()))?;
            let (shared_secret, kem_ct) = mlkem768::encapsulate(&pk);
            let (nonce_b64, ciphertext_b64) =
                encrypt_with_shared_secret(shared_secret.as_bytes(), fingerprint, info, plaintext)?;

            Ok(SealedSecret {
                kem_ciphertext: STANDARD.encode(kem_ct.as_bytes()),
                nonce: nonce_b64,
                ciphertext: ciphertext_b64,
            })
        }
    }
}

pub fn seal(
    plaintext: &[u8],
    ml_kem_pk_bytes: &[u8],
    fingerprint: &[u8],
) -> Result<SealedSecret, SecBindError> {
    seal_for_version(
        LATEST_ENVELOPE_VERSION,
        plaintext,
        ml_kem_pk_bytes,
        fingerprint,
    )
}

pub fn reveal_for_version(
    version: EnvelopeVersion,
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

    let info = hkdf_info_for_version(version);

    match version {
        EnvelopeVersion::V1 => {
            let sk = kyber768::SecretKey::from_bytes(ml_kem_sk_bytes)
                .map_err(|e| SecBindError::KemError(e.to_string()))?;
            let kem_ct = kyber768::Ciphertext::from_bytes(&kem_ct_bytes)
                .map_err(|e| SecBindError::KemError(e.to_string()))?;
            let shared_secret = kyber768::decapsulate(&kem_ct, &sk);
            decrypt_with_shared_secret(
                shared_secret.as_bytes(),
                fingerprint,
                info,
                &nonce_bytes,
                &ct_bytes,
            )
        }
        EnvelopeVersion::V2 => {
            let sk = mlkem768::SecretKey::from_bytes(ml_kem_sk_bytes)
                .map_err(|e| SecBindError::KemError(e.to_string()))?;
            let kem_ct = mlkem768::Ciphertext::from_bytes(&kem_ct_bytes)
                .map_err(|e| SecBindError::KemError(e.to_string()))?;
            let shared_secret = mlkem768::decapsulate(&kem_ct, &sk);
            decrypt_with_shared_secret(
                shared_secret.as_bytes(),
                fingerprint,
                info,
                &nonce_bytes,
                &ct_bytes,
            )
        }
    }
}

pub fn reveal(
    sealed: &SealedSecret,
    ml_kem_sk_bytes: &[u8],
    fingerprint: &[u8],
) -> Result<Vec<u8>, SecBindError> {
    reveal_for_version(
        LATEST_ENVELOPE_VERSION,
        sealed,
        ml_kem_sk_bytes,
        fingerprint,
    )
}
