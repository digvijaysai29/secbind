use clap::Args;
use secbind_core::SecEnvFile;
use std::path::PathBuf;

use crate::config::default_secenv_path;

#[derive(Args)]
pub struct AuditArgs {
    #[arg(long)]
    pub file: Option<PathBuf>,
}

pub fn run(args: AuditArgs) -> Result<(), Box<dyn std::error::Error>> {
    let path = default_secenv_path(args.file);
    let file = SecEnvFile::load(&path)?;

    println!("Version:       {}", file.version);
    println!("Environment:   {}", file.env_label);
    println!("Secrets:       {}", file.secrets.len());

    if let Some(not_after) = file.antigens.not_after {
        println!("Expires:       {}", not_after.format("%Y-%m-%dT%H:%M:%SZ"));
        if chrono::Utc::now() > not_after {
            println!("               ** EXPIRED **");
        }
    } else {
        println!("Expires:       never");
    }

    if let Some(env) = &file.antigens.environment {
        println!("Antigen/env:   {}", env);
    }
    if let Some(cidr) = &file.antigens.allowed_cidr {
        println!("Antigen/cidr:  {}", cidr);
    }

    match file.verify_signature() {
        Ok(()) => println!("Signature:     VALID"),
        Err(_) => println!("Signature:     INVALID or MISSING"),
    }

    Ok(())
}
