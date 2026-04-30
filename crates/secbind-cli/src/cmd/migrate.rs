use base64::{engine::general_purpose::STANDARD, Engine as _};
use clap::Args;
use keyring::Entry;
use secbind_core::{
    dsa_secret_key_len_for_version, reveal_for_version, EnvelopeVersion, RuntimeContext, SecEnvFile,
};
use std::path::PathBuf;
use zeroize::Zeroize;

use crate::config::{
    default_secenv_path, keyring_service, split_combined_sk_for_version, KEYRING_USER,
};

#[derive(Args)]
pub struct MigrateArgs {
    #[arg(long, default_value = "default")]
    pub env: String,
    #[arg(long)]
    pub file: Option<PathBuf>,
}

pub fn run(args: MigrateArgs) -> Result<(), Box<dyn std::error::Error>> {
    let path = default_secenv_path(args.file);
    let legacy_file = SecEnvFile::load(&path)?;
    let version = legacy_file.envelope_version()?;

    if version == EnvelopeVersion::V2 {
        println!(
            "No migration needed: {} is already version 2",
            path.display()
        );
        return Ok(());
    }

    legacy_file.verify_signature()?;

    let ctx = RuntimeContext::capture(&args.env)?;
    legacy_file.check_antigens(&ctx)?;

    let entry = Entry::new(&keyring_service(&args.env), KEYRING_USER)?;
    let old_sk_b64 = entry.get_password()?;
    let mut old_combined_sk = STANDARD.decode(&old_sk_b64)?;
    let (old_kem_sk, _) = split_combined_sk_for_version(&old_combined_sk, version)?;

    let fp = ctx.digest();
    let mut plaintext_secrets: Vec<(String, Vec<u8>)> =
        Vec::with_capacity(legacy_file.secrets.len());

    for (key, sealed) in &legacy_file.secrets {
        let plaintext = reveal_for_version(version, sealed, old_kem_sk, &fp)?;
        plaintext_secrets.push((key.clone(), plaintext));
    }

    let (mut migrated_file, mut new_combined_sk) =
        SecEnvFile::new_for_version(&legacy_file.env_label, None, EnvelopeVersion::V2);
    migrated_file.antigens = legacy_file.antigens.clone();

    for (key, plaintext) in &plaintext_secrets {
        migrated_file.add_secret(key, plaintext, &ctx)?;
    }

    let dsa_len = dsa_secret_key_len_for_version(EnvelopeVersion::V2);
    let dsa_offset = new_combined_sk.len() - dsa_len;
    migrated_file.sign(&new_combined_sk[dsa_offset..])?;

    let temp_path = path.with_extension("secenv.migrating");
    migrated_file.save(&temp_path)?;

    let original_content = std::fs::read_to_string(&path)?;

    std::fs::rename(&temp_path, &path)?;

    let new_sk_b64 = STANDARD.encode(&new_combined_sk);
    if let Err(e) = entry.set_password(&new_sk_b64) {
        let _ = std::fs::write(&path, original_content);
        old_combined_sk.zeroize();
        new_combined_sk.zeroize();
        for (_, plaintext) in &mut plaintext_secrets {
            plaintext.zeroize();
        }
        return Err(Box::new(e));
    }

    old_combined_sk.zeroize();
    new_combined_sk.zeroize();

    for (_, plaintext) in &mut plaintext_secrets {
        plaintext.zeroize();
    }

    println!(
        "Migrated {} to version 2 and rotated key material",
        path.display()
    );

    Ok(())
}
