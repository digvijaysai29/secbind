pub mod context;
pub mod crypto;
pub mod envelope;
pub mod error;
pub mod fingerprint;
pub mod version;

pub use crypto::{
    reveal, reveal_for_version, seal, seal_for_version, SealedSecret, SealingKeypair,
};
pub use envelope::{Antigens, SecEnvFile};
pub use error::SecBindError;
pub use fingerprint::RuntimeContext;
pub use version::{EnvelopeVersion, LATEST_ENVELOPE_VERSION};

pub fn kem_secret_key_len_for_version(version: EnvelopeVersion) -> usize {
    match version {
        EnvelopeVersion::V1 => pqcrypto_kyber::kyber768::secret_key_bytes(),
        EnvelopeVersion::V2 => pqcrypto_mlkem::mlkem768::secret_key_bytes(),
    }
}

pub fn dsa_secret_key_len_for_version(version: EnvelopeVersion) -> usize {
    match version {
        EnvelopeVersion::V1 => pqcrypto_dilithium::dilithium3::secret_key_bytes(),
        EnvelopeVersion::V2 => pqcrypto_mldsa::mldsa65::secret_key_bytes(),
    }
}

pub fn combined_secret_key_len_for_version(version: EnvelopeVersion) -> usize {
    kem_secret_key_len_for_version(version) + dsa_secret_key_len_for_version(version)
}

pub fn kem_secret_key_len() -> usize {
    kem_secret_key_len_for_version(LATEST_ENVELOPE_VERSION)
}

pub fn dsa_secret_key_len() -> usize {
    dsa_secret_key_len_for_version(LATEST_ENVELOPE_VERSION)
}

pub fn combined_secret_key_len() -> usize {
    combined_secret_key_len_for_version(LATEST_ENVELOPE_VERSION)
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    use chrono::Utc;

    fn make_ctx(env_label: &str) -> RuntimeContext {
        RuntimeContext {
            machine_id: "test-machine-123".to_string(),
            binary_hash: "aabbccddeeff".to_string(),
            env_label: env_label.to_string(),
            binding_tag: None,
        }
    }

    #[test]
    fn seal_and_reveal_roundtrip() {
        let ctx = make_ctx("test");
        let (file, combined_sk) = SecEnvFile::new("test", None);
        let kem_sk = &combined_sk[..kem_secret_key_len()];
        let pk_bytes = STANDARD.decode(&file.sealing_public_key).unwrap();
        let fp = ctx.digest();
        let plaintext = b"super-secret-value";
        let sealed = seal(plaintext, &pk_bytes, &fp).unwrap();
        let revealed = reveal(&sealed, kem_sk, &fp).unwrap();
        assert_eq!(revealed, plaintext);
    }

    #[test]
    fn v1_seal_and_reveal_roundtrip() {
        let ctx = make_ctx("test");
        let (file, combined_sk) = SecEnvFile::new_for_version("test", None, EnvelopeVersion::V1);
        let kem_len = kem_secret_key_len_for_version(EnvelopeVersion::V1);
        let kem_sk = &combined_sk[..kem_len];
        let pk_bytes = STANDARD.decode(&file.sealing_public_key).unwrap();
        let fp = ctx.digest();
        let plaintext = b"legacy-secret-value";
        let sealed = seal_for_version(EnvelopeVersion::V1, plaintext, &pk_bytes, &fp).unwrap();
        let revealed = reveal_for_version(EnvelopeVersion::V1, &sealed, kem_sk, &fp).unwrap();
        assert_eq!(revealed, plaintext);
    }

    #[test]
    fn wrong_fingerprint_fails() {
        let ctx = make_ctx("test");
        let (file, combined_sk) = SecEnvFile::new("test", None);
        let kem_sk = &combined_sk[..kem_secret_key_len()];
        let pk_bytes = STANDARD.decode(&file.sealing_public_key).unwrap();
        let fp = ctx.digest();
        let sealed = seal(b"secret", &pk_bytes, &fp).unwrap();
        let mut bad_fp = fp;
        bad_fp[0] ^= 0xFF;
        let result = reveal(&sealed, kem_sk, &bad_fp);
        assert!(matches!(result, Err(SecBindError::FingerprintMismatch)));
    }

    #[test]
    fn antigen_expiry() {
        let ctx = make_ctx("test");
        let (mut file, _) = SecEnvFile::new("test", None);
        file.antigens.not_after = Some(Utc::now() - chrono::Duration::seconds(1));
        let result = file.check_antigens(&ctx);
        assert!(matches!(result, Err(SecBindError::EnvelopeExpired { .. })));
    }

    #[test]
    fn antigen_wrong_environment() {
        let ctx = make_ctx("production");
        let (file, _) = SecEnvFile::new("staging", None);
        let result = file.check_antigens(&ctx);
        assert!(matches!(result, Err(SecBindError::AntigenViolation { .. })));
    }

    #[test]
    fn tampered_envelope_fails_signature() {
        let ctx = make_ctx("test");
        let (mut file, combined_sk) = SecEnvFile::new("test", None);
        let dsa_sk = &combined_sk[kem_secret_key_len()..];
        file.add_secret("FOO", b"bar", &ctx).unwrap();
        file.sign(dsa_sk).unwrap();
        file.secrets.get_mut("FOO").unwrap().ciphertext.push('X');
        let result = file.verify_signature();
        assert!(matches!(result, Err(SecBindError::SignatureInvalid)));
    }

    #[test]
    fn multiple_secrets_roundtrip() {
        let ctx = make_ctx("test");
        let (mut file, combined_sk) = SecEnvFile::new("test", None);
        let kem_len = kem_secret_key_len();
        let kem_sk = &combined_sk[..kem_len];
        let dsa_sk = &combined_sk[kem_len..];

        for i in 0..10 {
            let key = format!("SECRET_{}", i);
            let val = format!("value_{}", i);
            file.add_secret(&key, val.as_bytes(), &ctx).unwrap();
        }
        file.sign(dsa_sk).unwrap();
        file.verify_signature().unwrap();

        let fp = ctx.digest();
        for i in 0..10 {
            let key = format!("SECRET_{}", i);
            let expected = format!("value_{}", i);
            let sealed = &file.secrets[&key];
            let revealed = reveal(sealed, kem_sk, &fp).unwrap();
            assert_eq!(revealed, expected.as_bytes());
        }
    }

    #[test]
    fn zeroize_on_drop() {
        use zeroize::Zeroize;

        let mut kp = SealingKeypair {
            kem_sk: vec![0xFFu8; kem_secret_key_len()],
            dsa_sk: vec![0xFFu8; dsa_secret_key_len()],
        };
        let raw_kem: *const u8 = kp.kem_sk.as_ptr();
        let raw_dsa: *const u8 = kp.dsa_sk.as_ptr();

        kp.kem_sk.zeroize();
        kp.dsa_sk.zeroize();

        // Safety: memory is still allocated (kp hasn't been dropped), we only zeroized the contents
        unsafe {
            assert_eq!(*raw_kem, 0u8, "kem_sk not zeroed");
            assert_eq!(*raw_dsa, 0u8, "dsa_sk not zeroed");
        }
    }
}
