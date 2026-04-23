use base64::{engine::general_purpose::STANDARD, Engine as _};
use clap::Args;
use keyring::Entry;
use secbind_core::{reveal, RuntimeContext, SecBindError, SecEnvFile};
use std::collections::HashMap;
use std::path::PathBuf;
use std::process::Command;
use zeroize::Zeroize;

use crate::config::{default_secenv_path, keyring_service, KEYRING_USER};

#[derive(Args)]
pub struct RunArgs {
    #[arg(long, default_value = "default")]
    pub env: String,
    #[arg(long)]
    pub file: Option<PathBuf>,
    #[arg(last = true, required = true)]
    pub command: Vec<String>,
}

pub fn run(args: RunArgs) -> Result<(), Box<dyn std::error::Error>> {
    let path = default_secenv_path(args.file);
    let file = SecEnvFile::load(&path)?;

    file.verify_signature()?;

    let ctx = RuntimeContext::capture(&args.env)?;
    file.check_antigens(&ctx)?;

    let entry = Entry::new(&keyring_service(&args.env), KEYRING_USER)?;
    let sk_b64 = entry.get_password()?;
    let mut combined_sk = STANDARD.decode(&sk_b64)?;
    let kem_sk = combined_sk[..2400].to_vec();
    combined_sk.zeroize();

    let fp = ctx.digest();
    let mut env_map: HashMap<String, String> = HashMap::new();

    for (key, sealed) in &file.secrets {
        let plaintext = reveal(sealed, &kem_sk, &fp)?;
        let value = String::from_utf8(plaintext)
            .map_err(|e| SecBindError::SerializationError(e.to_string()))?;
        env_map.insert(key.clone(), value);
    }

    let cmd_str = &args.command[0];
    let cmd_args = &args.command[1..];

    let status = Command::new(cmd_str)
        .args(cmd_args)
        .envs(&env_map)
        .status()?;

    std::process::exit(status.code().unwrap_or(1));
}
