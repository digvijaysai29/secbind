use std::path::PathBuf;

use secbind_core::{
    combined_secret_key_len_for_version, dsa_secret_key_len_for_version,
    kem_secret_key_len_for_version, EnvelopeVersion, SecBindError,
};

pub const KEYRING_USER: &str = "secbind-sk";

pub fn keyring_service(env_label: &str) -> String {
    format!("secbind/{}", env_label)
}

pub fn default_secenv_path(file: Option<PathBuf>) -> PathBuf {
    file.unwrap_or_else(|| PathBuf::from(".secenv"))
}

pub fn split_combined_sk_for_version(
    combined_sk: &[u8],
    version: EnvelopeVersion,
) -> Result<(&[u8], &[u8]), SecBindError> {
    let kem_len = kem_secret_key_len_for_version(version);
    let dsa_len = dsa_secret_key_len_for_version(version);
    let expected_len = combined_secret_key_len_for_version(version);
    if combined_sk.len() != expected_len {
        return Err(SecBindError::SerializationError(format!(
            "invalid keyring payload length for v{}: expected {}, got {}",
            version.as_str(),
            expected_len,
            combined_sk.len()
        )));
    }
    Ok((
        &combined_sk[..kem_len],
        &combined_sk[kem_len..(kem_len + dsa_len)],
    ))
}
