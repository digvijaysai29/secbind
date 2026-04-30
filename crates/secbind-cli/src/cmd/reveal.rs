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
pub struct RevealArgs {
    #[arg(short = 'k', long)]
    pub key: String,
    #[arg(long, default_value = "default")]
    pub env: String,
    #[arg(long)]
    pub file: Option<PathBuf>,
}

pub fn run(args: RevealArgs) -> Result<(), Box<dyn std::error::Error>> {
    let path = default_secenv_path(args.file);
    let file = SecEnvFile::load(&path)?;

    file.verify_signature()?;

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

    let ctx = RuntimeContext::capture(&args.env)?;
    file.check_antigens(&ctx)?;

    let sealed = file
        .secrets
        .get(&args.key)
        .ok_or_else(|| SecBindError::EnvVarNotFound(args.key.clone()))?;

    let fp = ctx.digest();
    let plaintext = reveal(sealed, &combined_sk[..KEM_SK_LEN], &fp)?;

    combined_sk.zeroize();

    let value =
        String::from_utf8(plaintext).unwrap_or_else(|_| "<binary data>".to_string());
    println!("{}", value);
    Ok(())
}
