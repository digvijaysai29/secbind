use std::path::PathBuf;

pub const KEYRING_USER: &str = "secbind-sk";
pub const KEM_SK_LEN: usize = 2400;
pub const DSA_SK_LEN: usize = 4032;
pub const COMBINED_SK_LEN: usize = KEM_SK_LEN + DSA_SK_LEN;

pub fn keyring_service(env_label: &str) -> String {
    format!("secbind/{}", env_label)
}

pub fn default_secenv_path(file: Option<PathBuf>) -> PathBuf {
    file.unwrap_or_else(|| PathBuf::from(".secenv"))
}
