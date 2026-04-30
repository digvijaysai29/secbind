use base64::{engine::general_purpose::STANDARD, Engine as _};
use clap::Args;
use keyring::Entry;
use secbind_core::{kem_secret_key_len, SecEnvFile};
use std::path::PathBuf;
use zeroize::Zeroize;

use crate::config::{default_secenv_path, keyring_service, KEYRING_USER};

#[derive(Args)]
pub struct InitArgs {
    #[arg(long)]
    pub env: String,
    #[arg(long)]
    pub output: Option<PathBuf>,
    #[arg(long)]
    pub ttl_hours: Option<u64>,
}

pub fn run(args: InitArgs) -> Result<(), Box<dyn std::error::Error>> {
    let output_path = default_secenv_path(args.output);
    let (mut file, mut combined_sk) = SecEnvFile::new(&args.env, args.ttl_hours);

    let kem_len = kem_secret_key_len();
    file.sign(&combined_sk[kem_len..])?;

    let entry = Entry::new(&keyring_service(&args.env), KEYRING_USER)?;
    entry.set_password(&STANDARD.encode(&combined_sk))?;

    combined_sk.zeroize();

    file.save(&output_path)?;

    println!(
        "Initialized secbind env '{}' -> {}",
        args.env,
        output_path.display()
    );
    Ok(())
}
