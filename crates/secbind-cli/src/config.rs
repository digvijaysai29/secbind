use std::path::PathBuf;

pub const KEYRING_USER: &str = "secbind-sk";

pub fn keyring_service(env_label: &str) -> String {
    format!("secbind/{}", env_label)
}

pub fn default_secenv_path(file: Option<PathBuf>) -> PathBuf {
    file.unwrap_or_else(|| PathBuf::from(".secenv"))
}
