use base64::{engine::general_purpose::STANDARD, Engine as _};
use clap::Args;
use keyring::Entry;
use secbind_core::{reveal, RuntimeContext, SecBindError, SecEnvFile};
use std::path::PathBuf;
use zeroize::Zeroize;

use crate::config::{
    default_secenv_path, keyring_service, COMBINED_SK_LEN, KEM_SK_LEN, KEYRING_USER,
};

#[derive(Args)]
pub struct ExportArgs {
    #[arg(long, default_value = "default")]
    pub env: String,
    #[arg(long)]
    pub file: Option<PathBuf>,
}

pub fn run(args: ExportArgs) -> Result<(), Box<dyn std::error::Error>> {
    let path = default_secenv_path(args.file);
    let file = SecEnvFile::load(&path)?;

    file.verify_signature()?;

    let ctx = RuntimeContext::capture(&args.env)?;
    file.check_antigens(&ctx)?;

    let entry = Entry::new(&keyring_service(&args.env), KEYRING_USER)?;
    let sk_b64 = entry.get_password()?;
    let mut combined_sk = STANDARD.decode(&sk_b64)?;
    if combined_sk.len() != COMBINED_SK_LEN {
        return Err(SecBindError::SerializationError(format!(
            "invalid keyring payload length: expected {}, got {}",
            COMBINED_SK_LEN,
            combined_sk.len()
        ))
        .into());
    }
    let kem_sk = combined_sk[..KEM_SK_LEN].to_vec();
    combined_sk.zeroize();

    let fp = ctx.digest();

    for (key, sealed) in &file.secrets {
        let plaintext = reveal(sealed, &kem_sk, &fp)?;
        let value = String::from_utf8(plaintext)
            .map_err(|e| SecBindError::SerializationError(e.to_string()))?;
        println!("{}={}", key, value);
    }

    Ok(())
}
