//! Holocron CLI.
//!
//! v0.1 stub. The `audit` subcommand is implemented in issue #12 once the
//! auditor trait (#3) and the four real auditors (#4–#7) are in place.

use anyhow::Result;
use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(name = "holocron", version, about = "Audit a Rust codebase and produce a graded report card", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Audit a Rust project and emit a graded report.
    Audit {
        /// Path to a Rust project (must contain Cargo.toml).
        path: PathBuf,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let cli = Cli::parse();
    match cli.command {
        Command::Audit { path } => {
            tracing::info!(target = %path.display(), holocron_core = %holocron_core::version(), "audit not yet implemented; landing in OneDev issue #12");
            println!(
                "Holocron {} — `audit` is a stub. Implementation lands in issues #3–#12.\nTarget: {}",
                holocron_core::version(),
                path.display()
            );
        }
    }
    Ok(())
}
