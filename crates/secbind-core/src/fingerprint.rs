use sha3::{Digest, Sha3_512};

use crate::error::SecBindError;

pub struct RuntimeContext {
    pub machine_id: String,
    pub binary_hash: String,
    pub env_label: String,
    pub binding_tag: Option<String>,
}

impl RuntimeContext {
    pub fn capture(env_label: &str) -> Result<Self, SecBindError> {
        let machine_id = machine_uid::get().map_err(|e| SecBindError::KemError(e.to_string()))?;

        let exe_path = std::env::current_exe()?;
        let exe_bytes = std::fs::read(&exe_path)?;
        let mut hasher = Sha3_512::new();
        hasher.update(&exe_bytes);
        let hash_bytes = hasher.finalize();
        let binary_hash: String = hash_bytes.iter().map(|b| format!("{:02x}", b)).collect();

        Ok(RuntimeContext {
            machine_id,
            binary_hash,
            env_label: env_label.to_string(),
            binding_tag: None,
        })
    }

    pub fn digest(&self) -> [u8; 64] {
        let mut hasher = Sha3_512::new();
        hasher.update(b"secbind-v1-fingerprint\x00");
        hasher.update(self.machine_id.as_bytes());
        hasher.update(b"\x00");
        hasher.update(self.binary_hash.as_bytes());
        hasher.update(b"\x00");
        hasher.update(self.env_label.as_bytes());
        hasher.update(b"\x00");
        if let Some(tag) = &self.binding_tag {
            hasher.update(tag.as_bytes());
        }
        hasher.finalize().into()
    }
}
