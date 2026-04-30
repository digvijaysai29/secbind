use clap::{Parser, Subcommand};

mod cmd {
    pub mod audit;
    pub mod export;
    pub mod init;
    pub mod migrate;
    pub mod reveal;
    pub mod run;
    pub mod seal;
}
mod config;

#[derive(Parser)]
#[command(
    name = "secbind",
    version,
    about = "Post-quantum context-bound secrets manager"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Init(cmd::init::InitArgs),
    Seal(cmd::seal::SealArgs),
    Reveal(cmd::reveal::RevealArgs),
    Migrate(cmd::migrate::MigrateArgs),
    Run(cmd::run::RunArgs),
    Audit(cmd::audit::AuditArgs),
    Export(cmd::export::ExportArgs),
}

fn main() {
    let cli = Cli::parse();
    let result = match cli.command {
        Commands::Init(args) => cmd::init::run(args),
        Commands::Seal(args) => cmd::seal::run(args),
        Commands::Reveal(args) => cmd::reveal::run(args),
        Commands::Migrate(args) => cmd::migrate::run(args),
        Commands::Run(args) => cmd::run::run(args),
        Commands::Audit(args) => cmd::audit::run(args),
        Commands::Export(args) => cmd::export::run(args),
    };
    if let Err(e) = result {
        eprintln!("Error: {}", e);
        std::process::exit(1);
    }
}
