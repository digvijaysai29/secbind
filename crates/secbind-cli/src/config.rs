use std::path::PathBuf;

use secbind_core::{combined_secret_key_len, dsa_secret_key_len, kem_secret_key_len, SecBindError};

pub const KEYRING_USER: &str = "secbind-sk";

pub fn keyring_service(env_label: &str) -> String {
    format!("secbind/{}", env_label)
}

pub fn default_secenv_path(file: Option<PathBuf>) -> PathBuf {
    file.unwrap_or_else(|| PathBuf::from(".secenv"))
}

pub fn split_combined_sk(combined_sk: &[u8]) -> Result<(&[u8], &[u8]), SecBindError> {
    let kem_len = kem_secret_key_len();
    let dsa_len = dsa_secret_key_len();
    let expected_len = combined_secret_key_len();
    if combined_sk.len() != expected_len {
        return Err(SecBindError::SerializationError(format!(
            "invalid keyring payload length: expected {}, got {}",
            expected_len,
            combined_sk.len()
        )));
    }
    Ok((
        &combined_sk[..kem_len],
        &combined_sk[kem_len..(kem_len + dsa_len)],
    ))
}
