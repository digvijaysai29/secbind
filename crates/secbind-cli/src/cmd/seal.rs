use base64::{engine::general_purpose::STANDARD, Engine as _};
use clap::Args;
use keyring::Entry;
use secbind_core::{RuntimeContext, SealingKeypair, SecEnvFile};
use std::io::Read;
use std::path::PathBuf;
use zeroize::Zeroize;

use crate::config::{default_secenv_path, keyring_service, KEYRING_USER};

#[derive(Args)]
pub struct SealArgs {
    #[arg(short = 'k', long)]
    pub key: String,
    #[arg(long, conflicts_with = "value_file")]
    pub value_stdin: bool,
    #[arg(long, value_name = "PATH", conflicts_with = "value_stdin")]
    pub value_file: Option<PathBuf>,
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

    let ctx = RuntimeContext::capture(&args.env)?;

    let mut secret_bytes = if args.value_stdin {
        let mut buf = Vec::new();
        std::io::stdin().read_to_end(&mut buf)?;
        buf
    } else if let Some(value_file) = args.value_file {
        std::fs::read(value_file)?
    } else {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "provide either --value-stdin or --value-file <PATH>",
        )
        .into());
    };

    file.add_secret(&args.key, &secret_bytes, &ctx)?;
    secret_bytes.zeroize();

    let kp = SealingKeypair {
        kem_sk: combined_sk[..2400].to_vec(),
        dsa_sk: combined_sk[2400..].to_vec(),
    };
    combined_sk.zeroize();
    file.sign(&kp.dsa_sk)?;

    file.save(&path)?;
    println!("Sealed '{}' into {}", args.key, path.display());
    Ok(())
}
