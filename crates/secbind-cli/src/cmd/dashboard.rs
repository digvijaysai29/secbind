use clap::{Args, ValueEnum};
use secbind_core::SecEnvFile;
use std::path::PathBuf;

use crate::config::default_secenv_path;

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub enum DashboardView {
    Overview,
    Secrets,
    Policy,
    All,
}

#[derive(Args)]
pub struct DashboardArgs {
    #[arg(long)]
    pub file: Option<PathBuf>,

    #[arg(long, value_enum, default_value_t = DashboardView::All)]
    pub view: DashboardView,

    #[arg(long, help = "Show secret keys (names only), never values")]
    pub show_keys: bool,
}

pub fn run(args: DashboardArgs) -> Result<(), Box<dyn std::error::Error>> {
    let path = default_secenv_path(args.file);
    let file = SecEnvFile::load(&path)?;

    match args.view {
        DashboardView::Overview => print_overview(&file),
        DashboardView::Secrets => print_secrets(&file, args.show_keys),
        DashboardView::Policy => print_policy(&file),
        DashboardView::All => {
            print_overview(&file);
            println!();
            print_secrets(&file, args.show_keys);
            println!();
            print_policy(&file);
        }
    }

    Ok(())
}

fn print_overview(file: &SecEnvFile) {
    println!("== SecBind Dashboard / Overview ==");
    println!("Version:              {}", file.version);
    println!("Environment:          {}", file.env_label);
    println!("Secret count:         {}", file.secrets.len());
    println!(
        "Signature status:     {}",
        if file.verify_signature().is_ok() {
            "VALID"
        } else {
            "INVALID or MISSING"
        }
    );
}

fn print_secrets(file: &SecEnvFile, show_keys: bool) {
    println!("== SecBind Dashboard / Secrets ==");
    println!("Total sealed secrets: {}", file.secrets.len());

    if show_keys {
        if file.secrets.is_empty() {
            println!("Secret keys:          (none)");
        } else {
            let mut keys: Vec<&str> = file.secrets.keys().map(String::as_str).collect();
            keys.sort_unstable();
            println!("Secret keys:");
            for key in keys {
                println!("  - {}", key);
            }
        }
    } else {
        println!("Secret keys:          hidden (use --show-keys)");
    }
}

fn print_policy(file: &SecEnvFile) {
    println!("== SecBind Dashboard / Policy ==");

    if let Some(not_after) = file.antigens.not_after {
        println!(
            "Expiry (not_after):   {}",
            not_after.format("%Y-%m-%dT%H:%M:%SZ")
        );
        if chrono::Utc::now() > not_after {
            println!("Expiry status:        EXPIRED");
        } else {
            println!("Expiry status:        active");
        }
    } else {
        println!("Expiry (not_after):   never");
    }

    match &file.antigens.environment {
        Some(env) => println!("Environment antigen:  {}", env),
        None => println!("Environment antigen:  (none)"),
    }

    match &file.antigens.allowed_cidr {
        Some(cidr) => println!("CIDR antigen:         {}", cidr),
        None => println!("CIDR antigen:         (none)"),
    }

    if file.antigens.custom_tags.is_empty() {
        println!("Custom tags:          (none)");
    } else {
        println!("Custom tags:");
        let mut tags: Vec<(&str, &str)> = file
            .antigens
            .custom_tags
            .iter()
            .map(|(key, value)| (key.as_str(), value.as_str()))
            .collect();
        tags.sort_unstable_by(|a, b| a.0.cmp(b.0));
        for (key, value) in tags {
            println!("  - {}={}", key, value);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::DashboardView;
    use clap::ValueEnum;

    #[test]
    fn dashboard_view_allows_expected_variants() {
        let variants: Vec<String> = DashboardView::value_variants()
            .iter()
            .filter_map(|variant| {
                variant
                    .to_possible_value()
                    .map(|value| value.get_name().to_string())
            })
            .collect();

        assert_eq!(variants, vec!["overview", "secrets", "policy", "all"]);
    }
}
