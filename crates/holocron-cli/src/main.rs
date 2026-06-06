//! Holocron CLI — wires the four auditors, runner, grade, and report
//! renderers into the single `holocron audit <path>` command.

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use holocron_auditors::default_set;
use holocron_core::{CategoryScore, Grade, GradeReport, Letter, Runner};
use holocron_report::{render_json, render_markdown, Report};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
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
    /// Generate a starter `.holocronrc.toml` in the target directory.
    ///
    /// The file contains commented-out defaults you can opt into to tune
    /// the audit (per-auditor severity overrides, per-finding allowlists,
    /// complexity thresholds, the `--fail-below` gate threshold). Holocron
    /// runs fine with no config file — this is purely for projects that
    /// want to commit their tuning into the repo.
    Init(InitArgs),
    /// Look up a finding by fingerprint and emit an LLM-friendly
    /// explanation block ready to paste into a coding agent.
    ///
    /// The output is a Markdown block containing the finding's full
    /// context (auditor, severity, location, rendered diagnostic) plus
    /// a pre-formatted "ask the LLM to fix this" prompt template.
    Explain(ExplainArgs),
}

#[derive(clap::Args, Debug)]
struct ExplainArgs {
    /// The finding fingerprint (16-char hex string). Look this up in
    /// the JSON sidecar's `findings[*].fingerprint` field.
    fingerprint: String,

    /// JSON sidecar from a prior `holocron audit` run. Defaults to the
    /// most recent `/tmp/holocron-*-*.json` (lexicographic).
    #[arg(long)]
    from: Option<PathBuf>,
}

#[derive(clap::Args, Debug)]
struct InitArgs {
    /// Directory to write `.holocronrc.toml` into. Defaults to the
    /// current directory.
    #[arg(default_value = ".")]
    path: PathBuf,

    /// Overwrite an existing `.holocronrc.toml` without prompting.
    /// Without this flag, `holocron init` refuses to clobber.
    #[arg(long)]
    force: bool,
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

    /// CI gate: exit with code 1 if the overall grade is below this
    /// letter. Accepts A+, A, A-, B+, B, B-, C+, C, C-, D+, D, D-, F.
    /// Unicode minus (`A−`) and ASCII dash (`A-`) both work.
    ///
    /// Example: `holocron audit . --fail-below A-` fails on anything
    /// worse than A−. When omitted, holocron always exits 0 regardless
    /// of grade (advisory mode).
    #[arg(long, value_name = "GRADE")]
    fail_below: Option<Letter>,
}

#[tokio::main]
async fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let cli = Cli::parse();
    match cli.command {
        Command::Audit(args) => match audit(args).await {
            Ok(exit) => exit,
            Err(e) => {
                eprintln!("error: {e:#}");
                ExitCode::from(2)
            }
        },
        Command::Init(args) => match init(&args) {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("error: {e:#}");
                ExitCode::from(2)
            }
        },
        Command::Explain(args) => match explain(&args) {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("error: {e:#}");
                ExitCode::from(2)
            }
        },
    }
}

/// Default `.holocronrc.toml` shipped by `holocron init`. Heavily
/// commented so users learn what's configurable without reading the
/// source. Holocron's runtime currently ignores most of these — they
/// describe the *intended* config surface so users can pre-stage their
/// preferences. Wire-in happens in follow-up issues.
const DEFAULT_HOLOCRONRC: &str = include_str!("../templates/holocronrc-default.toml");

fn init(args: &InitArgs) -> Result<()> {
    let dir = if args.path.is_absolute() {
        args.path.clone()
    } else {
        std::env::current_dir()?.join(&args.path)
    };
    anyhow::ensure!(dir.is_dir(), "{} is not a directory", dir.display());

    let dest = dir.join(".holocronrc.toml");
    if dest.exists() && !args.force {
        anyhow::bail!("{} already exists — pass --force to overwrite", dest.display());
    }
    std::fs::write(&dest, DEFAULT_HOLOCRONRC)
        .with_context(|| format!("writing {}", dest.display()))?;
    println!("Wrote {}", dest.display());
    println!();
    println!("This file is currently advisory — Holocron's runtime doesn't read");
    println!("it yet. The schema is committed so you can pre-stage your tuning");
    println!("now and it'll take effect when later issues land.");
    Ok(())
}

fn explain(args: &ExplainArgs) -> Result<()> {
    let path = match &args.from {
        Some(p) => p.clone(),
        None => latest_audit_json()?,
    };
    let body = std::fs::read_to_string(&path)
        .with_context(|| format!("reading sidecar {}", path.display()))?;
    let sidecar: serde_json::Value =
        serde_json::from_str(&body).with_context(|| format!("parsing {}", path.display()))?;

    let findings = sidecar["findings"]
        .as_array()
        .ok_or_else(|| anyhow::anyhow!("sidecar has no `findings` array: {}", path.display()))?;

    let needle = args.fingerprint.trim();
    let matched = findings.iter().find(|f| f["fingerprint"].as_str() == Some(needle));
    let Some(finding) = matched else {
        eprintln!(
            "fingerprint {needle} not found in {}\n\
             (search the sidecar's findings[*].fingerprint field; first 8 chars also accepted)",
            path.display()
        );
        // Try a prefix match for ergonomics
        let prefix_hit = findings
            .iter()
            .find(|f| f["fingerprint"].as_str().is_some_and(|s| s.starts_with(needle)));
        if let Some(p) = prefix_hit {
            eprintln!(
                "\nDid you mean fingerprint {} ({})?",
                p["fingerprint"].as_str().unwrap_or(""),
                p["message"].as_str().unwrap_or("")
            );
        }
        anyhow::bail!("no finding matched {needle}");
    };

    print_explanation_markdown(finding, &path);
    Ok(())
}

/// Find the most recent `/tmp/holocron-*.json` by filename
/// (lexicographic — the timestamps in the filename sort naturally).
fn latest_audit_json() -> Result<PathBuf> {
    let mut candidates: Vec<PathBuf> = std::fs::read_dir("/tmp")
        .context("reading /tmp")?
        .filter_map(Result::ok)
        .map(|e| e.path())
        .filter(|p| {
            let Some(name) = p.file_name().and_then(|n| n.to_str()) else {
                return false;
            };
            name.starts_with("holocron-")
                && std::path::Path::new(name)
                    .extension()
                    .is_some_and(|ext| ext.eq_ignore_ascii_case("json"))
        })
        .collect();
    candidates.sort();
    candidates.pop().ok_or_else(|| {
        anyhow::anyhow!(
            "no /tmp/holocron-*.json sidecar found — run `holocron audit <path>` first, \
             or pass --from <path>"
        )
    })
}

/// Render an LLM-friendly explanation of a single finding to stdout.
///
/// The output is a Markdown block sized for direct paste into a coding
/// agent (Cortana, Codex, Claude Code). It has three sections:
///   1. The finding itself — auditor, severity, message, location.
///   2. The renderer's detail string if present (full diagnostic).
///   3. A prompt template the user can hand to an LLM.
fn print_explanation_markdown(finding: &serde_json::Value, sidecar_path: &Path) {
    let auditor = finding["auditor"].as_str().unwrap_or("?");
    let severity = finding["severity"].as_str().unwrap_or("?");
    let category = finding["category"].as_str().unwrap_or("?");
    let code = finding["code"].as_str().unwrap_or("(no code)");
    let message = finding["message"].as_str().unwrap_or("(no message)");
    let fingerprint = finding["fingerprint"].as_str().unwrap_or("?");
    let location_str = render_location(&finding["location"]);
    let detail = finding["detail"].as_str().unwrap_or("").trim();

    println!("# Holocron finding {fingerprint}");
    println!();
    println!("**Auditor:** `{auditor}` • **Category:** {category} • **Severity:** {severity}");
    println!("**Code:** `{code}`");
    println!("**Location:** {location_str}");
    println!("**Source sidecar:** `{}`", sidecar_path.display());
    println!();
    println!("## What it says");
    println!();
    println!("{message}");
    if !detail.is_empty() {
        println!();
        println!("## Full diagnostic");
        println!();
        println!("```");
        for line in detail.lines() {
            println!("{line}");
        }
        println!("```");
    }
    println!();
    println!("## Ask an LLM to fix it");
    println!();
    println!("Paste this into Cortana, Codex, Claude Code, etc:");
    println!();
    println!("---");
    println!();
    println!(
        "I have a Rust code-quality finding from `holocron audit` (auditor: \
              `{auditor}`, severity {severity}) that I want to address:"
    );
    println!();
    println!("- **Location:** {location_str}");
    println!("- **Code:** `{code}`");
    println!("- **Message:** {message}");
    if !detail.is_empty() {
        println!("- **Detail:**");
        println!();
        println!("  ```");
        for line in detail.lines().take(20) {
            println!("  {line}");
        }
        println!("  ```");
    }
    println!();
    println!("Please:");
    println!("1. Read the file at the location above and the surrounding context (~20 lines either side).");
    println!("2. Explain what this finding means in one short paragraph.");
    println!("3. Propose the minimal fix that satisfies the lint without changing behavior.");
    println!("4. Show me the unified diff.");
    println!("5. Call out any trade-offs (e.g. a clippy lint that's wrong for this codebase).");
    println!();
    println!("Do NOT make the change yet — just show me the diff and your reasoning.");
}

fn render_location(loc: &serde_json::Value) -> String {
    if loc.is_null() {
        return "(no location)".to_string();
    }
    let file = loc["file"].as_str().unwrap_or("?");
    let line = loc["line"].as_u64();
    let col = loc["column"].as_u64();
    match (line, col) {
        (Some(l), Some(c)) => format!("`{file}:{l}:{c}`"),
        (Some(l), None) => format!("`{file}:{l}`"),
        _ => format!("`{file}`"),
    }
}

async fn audit(args: AuditArgs) -> Result<ExitCode> {
    let target = resolve_target(&args.path)
        .with_context(|| format!("resolving target {}", args.path.display()))?;
    info!(target = %target.display(), "starting audit");
    println!("Holocron {} — auditing {}", holocron_core::VERSION, target.display());

    let outcome = build_runner(&target, &args).run().await.context("running auditors")?;
    let grade = Grade::new(&outcome.auditor_results).compute();
    let report = Report::new(&outcome, &grade);

    let (md_path, json_path) = write_reports(&report, &target, &args)?;
    print_summary(&grade, &md_path, json_path.as_deref());

    // Decide exit code + emit the right user-facing banner.
    //
    // Precedence:
    //   1 = gate failed (--fail-below; quality regression)
    //   3 = auditor outage (one or more categories couldn't be measured)
    //   0 = clean / gate passed
    // Gate failure wins over outage so a regression isn't masked when
    // BOTH happened.
    let exit_kind = decide_exit(&grade, args.fail_below);
    match exit_kind {
        ExitKind::GateFailed(threshold) => eprintln!(
            "\nGATE FAILED: grade {} is below threshold {}",
            grade.overall_letter, threshold
        ),
        ExitKind::AuditorOutage => {
            let skipped: Vec<String> = grade
                .by_category
                .iter()
                .filter_map(|cs| match cs {
                    CategoryScore::Skipped { category, reason } => {
                        Some(format!("  {category}: {reason}"))
                    }
                    CategoryScore::Graded { .. } => None,
                })
                .collect();
            eprintln!(
                "\nAUDITOR OUTAGE: {} categor{} skipped — overall grade is advisory.\n{}",
                skipped.len(),
                if skipped.len() == 1 { "y was" } else { "ies were" },
                skipped.join("\n"),
            );
        }
        ExitKind::Clean => {
            if let Some(threshold) = args.fail_below {
                println!("Gate passed: {} ≥ {}", grade.overall_letter, threshold);
            }
        }
    }
    Ok(exit_kind.into())
}

/// Distinct exit signals from `holocron audit`.
///
/// Modeled as an enum (not bare `u8`/`ExitCode`) so the decision logic
/// is testable and the banner-printing match can be exhaustive.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ExitKind {
    Clean,
    GateFailed(Letter),
    AuditorOutage,
}

impl From<ExitKind> for ExitCode {
    fn from(k: ExitKind) -> Self {
        match k {
            ExitKind::Clean => Self::SUCCESS,
            ExitKind::GateFailed(_) => Self::from(1),
            ExitKind::AuditorOutage => Self::from(3),
        }
    }
}

/// Decide the process exit based on grade + gate threshold + skip count.
/// Precedence: gate failure > auditor outage > clean.
fn decide_exit(grade: &GradeReport, threshold: Option<Letter>) -> ExitKind {
    if let Some(t) = threshold {
        if grade.overall_letter < t {
            return ExitKind::GateFailed(t);
        }
    }
    if grade.any_skipped() {
        return ExitKind::AuditorOutage;
    }
    ExitKind::Clean
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
        match cs {
            CategoryScore::Graded { category, score, letter, finding_count } => {
                println!(
                    "    {:<11}  {:<3}  {:.2}  ({} findings)",
                    category.to_string(),
                    letter.to_string(),
                    score,
                    finding_count
                );
            }
            CategoryScore::Skipped { category, reason } => {
                // Trim the reason for the one-line summary; full text is
                // in the report file.
                let short = reason.lines().next().unwrap_or("");
                let short = if short.len() > 50 { &short[..50] } else { short };
                println!("    {:<11}  —    —     (skipped: {short})", category.to_string());
            }
        }
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

    // --- Exit code decision tree (#24) ---

    use holocron_core::CategoryScore as CS;

    fn graded_report(letter: Letter, score: f64) -> GradeReport {
        GradeReport {
            overall_letter: letter,
            overall_score: score,
            by_category: vec![CS::Graded {
                category: holocron_core::Category::Lints,
                score,
                letter,
                finding_count: 0,
            }],
        }
    }

    fn graded_with_one_skipped(letter: Letter, score: f64) -> GradeReport {
        GradeReport {
            overall_letter: letter,
            overall_score: score,
            by_category: vec![
                CS::Graded {
                    category: holocron_core::Category::Lints,
                    score,
                    letter,
                    finding_count: 0,
                },
                CS::Skipped {
                    category: holocron_core::Category::Security,
                    reason: "cargo-audit failed".to_string(),
                },
            ],
        }
    }

    #[test]
    fn decide_exit_clean_when_no_threshold_and_no_skipped() {
        let r = graded_report(Letter::APlus, 1.0);
        assert_eq!(decide_exit(&r, None), ExitKind::Clean);
    }

    #[test]
    fn decide_exit_gate_failed_when_below_threshold() {
        let r = graded_report(Letter::C, 0.74);
        match decide_exit(&r, Some(Letter::AMinus)) {
            ExitKind::GateFailed(t) => assert_eq!(t, Letter::AMinus),
            other => panic!("expected GateFailed, got {other:?}"),
        }
    }

    #[test]
    fn decide_exit_clean_when_at_or_above_threshold() {
        let r = graded_report(Letter::AMinus, 0.90);
        assert_eq!(decide_exit(&r, Some(Letter::AMinus)), ExitKind::Clean);
        let r = graded_report(Letter::APlus, 1.0);
        assert_eq!(decide_exit(&r, Some(Letter::AMinus)), ExitKind::Clean);
    }

    #[test]
    fn decide_exit_auditor_outage_takes_precedence_over_clean() {
        // Grade passes the gate, but Security was skipped → exit 3.
        let r = graded_with_one_skipped(Letter::A, 0.95);
        assert_eq!(decide_exit(&r, Some(Letter::AMinus)), ExitKind::AuditorOutage);
        // Same without threshold: any skipped → outage.
        assert_eq!(decide_exit(&r, None), ExitKind::AuditorOutage);
    }

    #[test]
    fn decide_exit_gate_failed_takes_precedence_over_outage() {
        // Both regressed AND skipped → user's primary signal is the
        // regression, not the outage. Gate wins.
        let r = graded_with_one_skipped(Letter::C, 0.74);
        match decide_exit(&r, Some(Letter::AMinus)) {
            ExitKind::GateFailed(_) => {} // ok
            other => panic!("gate failure must win over outage, got {other:?}"),
        }
    }

    #[test]
    fn exit_kind_maps_to_distinct_exit_codes() {
        // Smoke test the ExitKind → ExitCode conversion. We can't read
        // the inner u8 of ExitCode, but we can debug-format it.
        let clean = format!("{:?}", ExitCode::from(ExitKind::Clean));
        let gate = format!("{:?}", ExitCode::from(ExitKind::GateFailed(Letter::AMinus)));
        let outage = format!("{:?}", ExitCode::from(ExitKind::AuditorOutage));
        // Debug repr is "ExitCode(unix_exit_status(0))" on Linux/macOS — just
        // assert the three are different and the integers appear.
        assert!(clean.contains('0'));
        assert!(gate.contains('1'));
        assert!(outage.contains('3'));
    }

    // --- holocron init (#15) ---

    #[test]
    fn init_writes_starter_holocronrc_into_empty_dir() {
        let d = TempDir::new().unwrap();
        let args = InitArgs { path: d.path().to_path_buf(), force: false };
        init(&args).unwrap();
        let path = d.path().join(".holocronrc.toml");
        assert!(path.is_file());
        let body = std::fs::read_to_string(&path).unwrap();
        assert!(body.contains("# .holocronrc.toml"));
        assert!(body.contains("[gate]"));
        assert!(body.contains("fail_below"));
    }

    #[test]
    fn init_refuses_to_clobber_without_force() {
        let d = TempDir::new().unwrap();
        let path = d.path().join(".holocronrc.toml");
        std::fs::write(&path, "# existing user config\n").unwrap();
        let args = InitArgs { path: d.path().to_path_buf(), force: false };
        let err = init(&args).unwrap_err();
        assert!(err.to_string().contains("already exists"), "got: {err}");
        // Body unchanged.
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "# existing user config\n");
    }

    #[test]
    fn init_force_overwrites_existing_file() {
        let d = TempDir::new().unwrap();
        let path = d.path().join(".holocronrc.toml");
        std::fs::write(&path, "# stale\n").unwrap();
        let args = InitArgs { path: d.path().to_path_buf(), force: true };
        init(&args).unwrap();
        let body = std::fs::read_to_string(&path).unwrap();
        assert!(body.contains("[gate]"), "expected fresh template, got: {body}");
    }

    #[test]
    fn init_errors_on_nonexistent_dir() {
        let args = InitArgs {
            path: PathBuf::from("/this/path/does/not/exist/and/should/not/be/created"),
            force: false,
        };
        let err = init(&args).unwrap_err();
        assert!(err.to_string().contains("not a directory"), "got: {err}");
    }

    #[test]
    fn shipped_template_is_valid_toml() {
        // The included template ships in every binary. If the TOML
        // doesn't parse, every `holocron init` produces a broken file.
        let _: toml::Value =
            toml::from_str(DEFAULT_HOLOCRONRC).expect("DEFAULT_HOLOCRONRC must be valid TOML");
    }

    // --- holocron explain (#16) ---

    fn sample_sidecar() -> String {
        // Mirror the real shape produced by holocron-report::render_json
        r#"{
          "schema_version": 2,
          "findings": [
            {
              "fingerprint": "a1b2c3d4e5f60718",
              "auditor": "clippy",
              "category": "Lints",
              "severity": "Medium",
              "code": "clippy::manual_let_else",
              "message": "this could be rewritten as `let...else`",
              "location": {"file": "src/foo.rs", "line": 42, "column": 5},
              "detail": "warning: this could be rewritten...\n  --> src/foo.rs:42:5"
            },
            {
              "fingerprint": "ffffeeeebbbb0000",
              "auditor": "cargo-audit",
              "category": "Security",
              "severity": "Critical",
              "code": "RUSTSEC-2024-0001",
              "message": "RUSTSEC-2024-0001: bad thing happens",
              "location": null,
              "detail": ""
            }
          ]
        }"#
        .to_string()
    }

    fn write_sidecar(d: &TempDir) -> PathBuf {
        let path = d.path().join("holocron-test.json");
        std::fs::write(&path, sample_sidecar()).unwrap();
        path
    }

    #[test]
    fn explain_resolves_fingerprint_via_explicit_from() {
        let d = TempDir::new().unwrap();
        let path = write_sidecar(&d);
        let args = ExplainArgs { fingerprint: "a1b2c3d4e5f60718".to_string(), from: Some(path) };
        // Should not error.
        explain(&args).unwrap();
    }

    #[test]
    fn explain_errors_on_unknown_fingerprint() {
        let d = TempDir::new().unwrap();
        let path = write_sidecar(&d);
        let args = ExplainArgs { fingerprint: "0000000000000000".to_string(), from: Some(path) };
        let err = explain(&args).unwrap_err();
        assert!(err.to_string().contains("no finding matched"), "got: {err}");
    }

    #[test]
    fn explain_errors_on_missing_sidecar() {
        let args = ExplainArgs {
            fingerprint: "deadbeef".to_string(),
            from: Some(PathBuf::from("/tmp/this-sidecar-does-not-exist-12345.json")),
        };
        let err = explain(&args).unwrap_err();
        assert!(
            err.to_string().contains("reading sidecar") || err.to_string().contains("No such"),
            "got: {err}"
        );
    }

    #[test]
    fn render_location_handles_null_partial_and_full() {
        let null = render_location(&serde_json::Value::Null);
        assert!(null.contains("no location"));
        let line_only =
            render_location(&serde_json::json!({"file": "src/a.rs", "line": 7, "column": null}));
        assert_eq!(line_only, "`src/a.rs:7`");
        let full =
            render_location(&serde_json::json!({"file": "src/a.rs", "line": 7, "column": 12}));
        assert_eq!(full, "`src/a.rs:7:12`");
    }
}
