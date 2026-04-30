use base64::{engine::general_purpose::STANDARD, Engine as _};
use clap::Args;
use keyring::Entry;
use secbind_core::{RuntimeContext, SealingKeypair, SecEnvFile};
use std::path::PathBuf;
use zeroize::Zeroize;

use crate::config::{
    default_secenv_path, keyring_service, COMBINED_SK_LEN, DSA_SK_LEN, KEM_SK_LEN, KEYRING_USER,
};

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
    if combined_sk.len() != COMBINED_SK_LEN {
        return Err(secbind_core::SecBindError::SerializationError(format!(
            "invalid keyring payload length: expected {}, got {}",
            COMBINED_SK_LEN,
            combined_sk.len()
        ))
        .into());
    }

    let ctx = RuntimeContext::capture(&args.env)?;

    file.add_secret(&args.key, args.value.as_bytes(), &ctx)?;

    let kp = SealingKeypair {
        kem_sk: combined_sk[..KEM_SK_LEN].to_vec(),
        dsa_sk: combined_sk[KEM_SK_LEN..(KEM_SK_LEN + DSA_SK_LEN)].to_vec(),
    };
    combined_sk.zeroize();
    file.sign(&kp.dsa_sk)?;

    file.save(&path)?;
    println!("Sealed '{}' into {}", args.key, path.display());
    Ok(())
}
