use base64::{engine::general_purpose::STANDARD, Engine as _};
use clap::Args;
use keyring::Entry;
use secbind_core::{RuntimeContext, SealingKeypair, SecEnvFile};
use std::path::PathBuf;
use zeroize::Zeroize;

use crate::config::{default_secenv_path, keyring_service, split_combined_sk, KEYRING_USER};

#[derive(Args)]
pub struct SealArgs {
    #[arg(short = 'k', long)]
    pub key: String,
    #[arg(short = 'v', long)]
    pub value: String,
    #[arg(long, default_value = "default")]
    pub env: String,
    #[arg(long)]
    pub file: Option<PathBuf>,
}

pub fn run(args: SealArgs) -> Result<(), Box<dyn std::error::Error>> {
    let path = default_secenv_path(args.file);
    let mut file = SecEnvFile::load(&path)?;

    file.verify_signature()?;

    let entry = Entry::new(&keyring_service(&args.env), KEYRING_USER)?;
    let sk_b64 = entry.get_password()?;
    let mut combined_sk = STANDARD.decode(&sk_b64)?;
    let (kem_sk, dsa_sk) = split_combined_sk(&combined_sk)?;

    let ctx = RuntimeContext::capture(&args.env)?;

    file.add_secret(&args.key, args.value.as_bytes(), &ctx)?;

    let kp = SealingKeypair {
        kem_sk: kem_sk.to_vec(),
        dsa_sk: dsa_sk.to_vec(),
    };
    combined_sk.zeroize();
    file.sign(&kp.dsa_sk)?;

    file.save(&path)?;
    println!("Sealed '{}' into {}", args.key, path.display());
    Ok(())
}
