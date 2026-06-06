//! Holocron CLI — wires the four auditors, runner, grade, and report
//! renderers into the single `holocron audit <path>` command.

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use holocron_auditors::default_set;
use holocron_core::{Grade, Runner};
use holocron_report::{render_json, render_markdown, Report};
use std::path::{Path, PathBuf};
use std::time::Duration;
use tracing::info;

#[derive(Parser, Debug)]
#[command(name = "holocron", version, about = "Audit a Rust codebase and produce a graded report card", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Audit a Rust project and emit a graded report.
    Audit(AuditArgs),
}

#[derive(clap::Args, Debug)]
struct AuditArgs {
    /// Path to a Rust project (must contain Cargo.toml at the root or
    /// any parent directory).
    path: PathBuf,

    /// Override output path for the Markdown report.
    /// Default: /tmp/holocron-<project>-<unix-ts>.md
    #[arg(long)]
    output: Option<PathBuf>,

    /// Skip the JSON sidecar.
    #[arg(long)]
    no_json: bool,

    /// Install any auditor binaries that aren't on PATH (cargo-audit,
    /// cargo-machete, rust-code-analysis-cli). Default false — Holocron
    /// will report them as skipped instead.
    #[arg(long)]
    install_missing: bool,

    /// Per-auditor timeout, in seconds. Default 600 (10 minutes).
    /// Complexity scans on large projects can take several minutes.
    #[arg(long, default_value_t = 600)]
    timeout: u64,
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
        Command::Audit(args) => audit(args).await,
    }
}

async fn audit(args: AuditArgs) -> Result<()> {
    let target = resolve_target(&args.path)
        .with_context(|| format!("resolving target {}", args.path.display()))?;
    info!(target = %target.display(), "starting audit");
    println!("Holocron {} — auditing {}", holocron_core::VERSION, target.display());

    let outcome = build_runner(&target, &args).run().await.context("running auditors")?;
    let grade = Grade::new(&outcome.auditor_results).compute();
    let report = Report::new(&outcome, &grade);

    let (md_path, json_path) = write_reports(&report, &target, &args)?;
    print_summary(&grade, &md_path, json_path.as_deref());

    Ok(())
}

/// Construct the [`Runner`] with the default auditor set and CLI flags applied.
fn build_runner(target: &Path, args: &AuditArgs) -> Runner {
    let mut runner = Runner::new(target)
        .with_timeout(Duration::from_secs(args.timeout))
        .with_install_missing(args.install_missing);
    for a in default_set() {
        runner = runner.with_auditor(a);
    }
    runner
}

/// Render the Markdown report (always) and JSON sidecar (unless `--no-json`).
/// Returns the paths written. Either is rooted at `--output` if set, otherwise
/// at `/tmp/holocron-<slug>-<ts>.{md,json}`.
fn write_reports(
    report: &Report<'_>,
    target: &Path,
    args: &AuditArgs,
) -> Result<(PathBuf, Option<PathBuf>)> {
    let md_path = args.output.clone().unwrap_or_else(|| default_report_path(target, "md"));
    let md = render_markdown(report);
    std::fs::write(&md_path, &md)
        .with_context(|| format!("writing markdown report to {}", md_path.display()))?;

    let json_path = if args.no_json {
        None
    } else {
        let p = args
            .output
            .as_ref()
            .map_or_else(|| default_report_path(target, "json"), |o| o.with_extension("json"));
        let json = render_json(report).context("serializing JSON sidecar")?;
        std::fs::write(&p, json)
            .with_context(|| format!("writing JSON sidecar to {}", p.display()))?;
        Some(p)
    };

    Ok((md_path, json_path))
}

/// Print the final grade card to stdout. Matches the layout users expect from
/// every Holocron run.
fn print_summary(grade: &holocron_core::GradeReport, md_path: &Path, json_path: Option<&Path>) {
    println!();
    println!("===============================================");
    println!("  Grade: {}  ({:.2})", grade.overall_letter, grade.overall_score);
    for cs in &grade.by_category {
        println!(
            "    {:<11}  {:<3}  {:.2}  ({} findings)",
            cs.category.to_string(),
            cs.letter.to_string(),
            cs.score,
            cs.finding_count
        );
    }
    println!();
    println!("  Markdown report: {}", md_path.display());
    if let Some(jp) = json_path {
        println!("  JSON sidecar:    {}", jp.display());
    }
    println!("===============================================");
}

fn resolve_target(input: &Path) -> Result<PathBuf> {
    let abs = if input.is_absolute() {
        input.to_path_buf()
    } else {
        std::env::current_dir()?.join(input)
    };
    let canon =
        abs.canonicalize().with_context(|| format!("path {} does not exist", abs.display()))?;
    // Walk upward looking for a Cargo.toml.
    let mut cur = canon.clone();
    loop {
        if cur.join("Cargo.toml").is_file() {
            return Ok(cur);
        }
        if !cur.pop() {
            anyhow::bail!("no Cargo.toml found at or above {}", canon.display());
        }
    }
}

fn default_report_path(target: &Path, ext: &str) -> PathBuf {
    let slug = target
        .file_name()
        .map_or_else(|| "project".to_string(), |n| n.to_string_lossy().into_owned());
    let ts = chrono::Utc::now().timestamp();
    PathBuf::from(format!("/tmp/holocron-{slug}-{ts}.{ext}"))
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::missing_const_for_fn,
        clippy::useless_vec,
        clippy::needless_raw_string_hashes
    )]
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn resolve_target_walks_up_for_cargo_toml() {
        let d = TempDir::new().unwrap();
        std::fs::write(
            d.path().join("Cargo.toml"),
            "[package]\nname=\"x\"\nversion=\"0.1.0\"\nedition=\"2021\"\n",
        )
        .unwrap();
        let sub = d.path().join("src");
        std::fs::create_dir(&sub).unwrap();
        let resolved = resolve_target(&sub).unwrap();
        // Compare canonical paths to handle /var vs /private/var on macOS.
        assert_eq!(resolved, d.path().canonicalize().unwrap());
    }

    #[test]
    fn resolve_target_errors_when_no_cargo_toml() {
        let d = TempDir::new().unwrap();
        let err = resolve_target(d.path()).unwrap_err();
        assert!(err.to_string().contains("Cargo.toml") || err.to_string().contains("path"));
    }
}
