//! Holocron CLI — wires the four auditors, runner, grade, and report
//! renderers into the single `holocron audit <path>` command.

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use holocron_auditors::{default_set_partitioned, ComplexityThresholds};
use holocron_core::{Category, CategoryScore, Grade, GradeReport, Letter, Runner};
use holocron_report::{render_json, render_markdown, render_sarif, Report};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;
use tracing::info;

mod progress;
use progress::ProgressMode;

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

    /// Also emit a SARIF v2.1.0 sidecar alongside the Markdown + JSON.
    /// Default off — SARIF is for downstream code-scanning consumers
    /// (GitHub Code Scanning, Azure DevOps), and most users don't need
    /// it. Output path: same stem as --output but with `.sarif`.
    #[arg(long)]
    sarif: bool,

    /// Install any auditor binaries that aren't on PATH (cargo-audit,
    /// cargo-machete, rust-code-analysis-cli). Without this flag we
    /// will report them as skipped instead.
    #[arg(long)]
    install_missing: bool,

    /// Live progress display while auditors run (#36).
    ///   auto (default): TTY block if stderr is a terminal, log otherwise.
    ///   tty: force in-place spinner block.
    ///   log: force timestamped one-line-per-event log.
    ///   off: no progress output.
    #[arg(long, value_enum, default_value_t = ProgressMode::Auto)]
    progress: ProgressMode,

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

/// Load and merge rc-driven settings. Returns the rc itself, the
/// effective `--fail-below` (flag wins over rc), and the
/// `ComplexityThresholds` to use for the audit. Extracted from
/// `audit()` to keep its cyclomatic complexity below threshold.
fn load_rc_and_merge(target: &Path, flag_fail_below: Option<Letter>) -> Result<RcResolution> {
    let (rc, rc_path) =
        holocron_core::HolocronConfig::load_from(target).context("loading .holocronrc.toml")?;
    let effective_fail_below = match flag_fail_below {
        Some(letter) => Some(letter),
        None => rc.gate.fail_below_letter().ok().flatten(),
    };
    let thresholds = merge_complexity_thresholds(&rc.complexity);
    Ok(RcResolution { rc, rc_path, effective_fail_below, thresholds })
}

struct RcResolution {
    rc: holocron_core::HolocronConfig,
    rc_path: Option<PathBuf>,
    effective_fail_below: Option<Letter>,
    thresholds: ComplexityThresholds,
}

async fn audit(args: AuditArgs) -> Result<ExitCode> {
    let target = resolve_target(&args.path)
        .with_context(|| format!("resolving target {}", args.path.display()))?;
    info!(target = %target.display(), "starting audit");
    println!("Holocron {} — auditing {}", holocron_core::VERSION, target.display());

    let RcResolution { rc, rc_path, effective_fail_below, thresholds } =
        load_rc_and_merge(&target, args.fail_below)?;
    if let Some(p) = &rc_path {
        println!("Config: {}", p.display());
    }

    // Partition the default set against [auditors] rc. Disabled
    // auditors produce synthetic Skipped results that we splice into
    // the outcome after the runner finishes — the grader treats those
    // categories as Skipped, distinct from missing-binary or runtime
    // failures (#28).
    let (enabled, disabled_results) = default_set_partitioned(thresholds, &rc.auditors);

    // Set up the progress display (#36). For Off mode we skip the sink
    // entirely so we don't pay for an unused channel/task. Both branches
    // produce a `RunOutcome` so the rest of audit() is mode-agnostic.
    let mut outcome = if let Some(mode) = progress::resolve_mode(args.progress) {
        let (sink, handle) = progress::spawn_display(mode, enabled.len());
        let runner = build_runner(&target, &args, enabled).with_progress(sink.clone());
        // sink moves into the runner via with_progress; drop our copy
        // so the receiver gets the close signal when the runner ends.
        drop(sink);
        let mut outcome = runner.run().await.context("running auditors")?;
        outcome.auditor_results.extend(disabled_results);
        // Wait for the display task to drain remaining events + render
        // its final frame. Bounded — events are already in flight.
        let _ = handle.await;
        outcome
    } else {
        let mut outcome =
            build_runner(&target, &args, enabled).run().await.context("running auditors")?;
        outcome.auditor_results.extend(disabled_results);
        outcome
    };

    // Merge [weights] from rc onto built-in defaults (#30). Missing keys
    // keep defaults. We warn if the sum drifts > 0.01 from 1.0 because
    // the report scale becomes non-intuitive (overall still computes
    // because `Grade::compute` renormalizes — see the with_weights doc).
    let weights = merge_weights(&rc.weights);
    warn_if_weights_skewed(&weights);

    // #29: apply [[allowlist]] rules before grading. Allowlisted
    // findings still appear in the report but are excluded from the
    // grade math. Mutate each AuditorResult.findings in place.
    let allowlisted_count: usize = outcome
        .auditor_results
        .iter_mut()
        .map(|r| holocron_core::apply_allowlist(&mut r.findings, &rc.allowlist))
        .sum();
    if allowlisted_count > 0 {
        println!(
            "Allowlist: {allowlisted_count} finding{} suppressed from grade",
            if allowlisted_count == 1 { "" } else { "s" }
        );
    }

    let grade = Grade::new(&outcome.auditor_results).with_weights(weights).compute();
    let report = Report::new(&outcome, &grade);

    let written = write_reports(&report, &target, &args)?;
    print_summary(&grade, &written);
    emit_exit_banner(&grade, effective_fail_below);

    let exit_kind = decide_exit(&grade, effective_fail_below);
    Ok(exit_kind.into())
}

/// Emit the user-facing banner that explains the exit code about to
/// be returned. Extracted from `audit()` to keep its complexity below
/// threshold. The actual exit kind decision lives in `decide_exit`.
fn emit_exit_banner(grade: &holocron_core::GradeReport, effective_fail_below: Option<Letter>) {
    let exit_kind = decide_exit(grade, effective_fail_below);
    match exit_kind {
        ExitKind::GateFailed(threshold) => eprintln!(
            "\nGATE FAILED: grade {} is below threshold {}",
            grade.overall_letter, threshold
        ),
        ExitKind::AuditorOutage => emit_outage_banner(grade),
        ExitKind::Clean => {
            if let Some(threshold) = effective_fail_below {
                println!("Gate passed: {} ≥ {}", grade.overall_letter, threshold);
            }
        }
    }
}

fn emit_outage_banner(grade: &holocron_core::GradeReport) {
    let skipped: Vec<String> = grade
        .by_category
        .iter()
        .filter_map(|cs| match cs {
            CategoryScore::Skipped { category, reason } => Some(format!("  {category}: {reason}")),
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

/// Construct the [`Runner`] with the given auditor set and CLI flags applied.
fn build_runner(
    target: &Path,
    args: &AuditArgs,
    auditors: Vec<std::sync::Arc<dyn holocron_core::Auditor>>,
) -> Runner {
    let mut runner = Runner::new(target)
        .with_timeout(Duration::from_secs(args.timeout))
        .with_install_missing(args.install_missing);
    for a in auditors {
        runner = runner.with_auditor(a);
    }
    runner
}

/// Merge rc-provided complexity thresholds onto the built-in defaults.
/// Missing rc keys keep the defaults; present rc keys override.
fn merge_complexity_thresholds(rc: &holocron_core::ComplexityConfig) -> ComplexityThresholds {
    let mut t = ComplexityThresholds::default();
    if let Some(v) = rc.cyclomatic_medium {
        t.cyclomatic_warn = v;
    }
    if let Some(v) = rc.cyclomatic_high {
        t.cyclomatic_high = v;
    }
    if let Some(v) = rc.cognitive_medium {
        t.cognitive_warn = v;
    }
    if let Some(v) = rc.cognitive_high {
        t.cognitive_high = v;
    }
    t
}

/// Merge rc-provided category weights onto the built-in defaults. Any
/// missing rc key keeps the default. Returns the 5-tuple in the same
/// canonical category order as `Grade::CATEGORY_WEIGHTS`.
fn merge_weights(rc: &holocron_core::WeightsConfig) -> [(Category, f64); 5] {
    let mut weights = Grade::CATEGORY_WEIGHTS;
    for (cat, w) in &mut weights {
        let override_val = match cat {
            Category::Security => rc.security,
            Category::Lints => rc.lints,
            Category::Complexity => rc.complexity,
            Category::DeadCode => rc.dead_code,
            Category::Maintenance => rc.maintenance,
        };
        if let Some(v) = override_val {
            *w = v;
        }
    }
    weights
}

/// Emit a one-line warning to stderr if the weights sum is far from 1.0.
/// The grader renormalizes either way (`Grade::compute` already does it
/// for Skipped categories), but a sum of e.g. 5.0 means the reported
/// overall is on a non-intuitive scale.
fn warn_if_weights_skewed(weights: &[(Category, f64); 5]) {
    let sum: f64 = weights.iter().map(|(_, w)| w).sum();
    if (sum - 1.0).abs() > 0.01 {
        eprintln!(
            "WARNING: [weights] in .holocronrc.toml sum to {sum:.3}, not 1.0. \
             Grade will be renormalized, but the reported scale may be unintuitive."
        );
    }
}

/// Render the Markdown report (always), JSON sidecar (unless `--no-json`),
/// and SARIF sidecar (if `--sarif`). Returns the paths written.
fn write_reports(report: &Report<'_>, target: &Path, args: &AuditArgs) -> Result<WrittenPaths> {
    let md = write_markdown(report, target, args)?;
    let json = write_json(report, target, args)?;
    let sarif = write_sarif_sidecar(report, target, args)?;
    Ok(WrittenPaths { md, json, sarif })
}

fn write_markdown(report: &Report<'_>, target: &Path, args: &AuditArgs) -> Result<PathBuf> {
    let path = args.output.clone().unwrap_or_else(|| default_report_path(target, "md"));
    let body = render_markdown(report);
    std::fs::write(&path, &body)
        .with_context(|| format!("writing markdown report to {}", path.display()))?;
    Ok(path)
}

fn write_json(report: &Report<'_>, target: &Path, args: &AuditArgs) -> Result<Option<PathBuf>> {
    if args.no_json {
        return Ok(None);
    }
    let path = args
        .output
        .as_ref()
        .map_or_else(|| default_report_path(target, "json"), |o| o.with_extension("json"));
    let body = render_json(report).context("serializing JSON sidecar")?;
    std::fs::write(&path, body)
        .with_context(|| format!("writing JSON sidecar to {}", path.display()))?;
    Ok(Some(path))
}

fn write_sarif_sidecar(
    report: &Report<'_>,
    target: &Path,
    args: &AuditArgs,
) -> Result<Option<PathBuf>> {
    if !args.sarif {
        return Ok(None);
    }
    let path = args
        .output
        .as_ref()
        .map_or_else(|| default_report_path(target, "sarif"), |o| o.with_extension("sarif"));
    let body = render_sarif(report).context("serializing SARIF sidecar")?;
    std::fs::write(&path, body)
        .with_context(|| format!("writing SARIF sidecar to {}", path.display()))?;
    Ok(Some(path))
}

struct WrittenPaths {
    md: PathBuf,
    json: Option<PathBuf>,
    sarif: Option<PathBuf>,
}

/// Print the final grade card to stdout. Matches the layout users expect from
/// every Holocron run.
fn print_summary(grade: &holocron_core::GradeReport, paths: &WrittenPaths) {
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
    println!("  Markdown report: {}", paths.md.display());
    if let Some(jp) = &paths.json {
        println!("  JSON sidecar:    {}", jp.display());
    }
    if let Some(sp) = &paths.sarif {
        println!("  SARIF sidecar:   {}", sp.display());
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

    // --- rc merge: #31 ---

    #[test]
    fn merge_thresholds_keeps_defaults_when_rc_empty() {
        let rc = holocron_core::ComplexityConfig::default();
        let merged = merge_complexity_thresholds(&rc);
        let defaults = ComplexityThresholds::default();
        assert_eq!(merged.cyclomatic_warn, defaults.cyclomatic_warn);
        assert_eq!(merged.cyclomatic_high, defaults.cyclomatic_high);
        assert_eq!(merged.cognitive_warn, defaults.cognitive_warn);
    }

    #[test]
    fn merge_thresholds_overrides_only_set_keys() {
        let rc = holocron_core::ComplexityConfig {
            cyclomatic_medium: Some(10),
            cyclomatic_high: None,
            cognitive_medium: Some(12),
            cognitive_high: None,
        };
        let merged = merge_complexity_thresholds(&rc);
        let defaults = ComplexityThresholds::default();
        assert_eq!(merged.cyclomatic_warn, 10, "cyclomatic_warn overridden");
        assert_eq!(
            merged.cyclomatic_high, defaults.cyclomatic_high,
            "cyclomatic_high kept default"
        );
        assert_eq!(merged.cognitive_warn, 12, "cognitive_warn overridden");
    }

    #[test]
    fn merge_thresholds_honors_cognitive_high_now() {
        // #37 closed the no-op gap: cognitive_high IS wired through.
        let rc = holocron_core::ComplexityConfig {
            cyclomatic_medium: None,
            cyclomatic_high: None,
            cognitive_medium: None,
            cognitive_high: Some(50),
        };
        let merged = merge_complexity_thresholds(&rc);
        assert_eq!(merged.cognitive_high, 50, "cognitive_high overridden by rc (#37)");
    }

    #[test]
    fn merge_weights_defaults_when_rc_empty() {
        // Empty rc -> defaults preserved (Security 0.30, Lints 0.20,
        // Complexity 0.20, DeadCode 0.15, Maintenance 0.15).
        let rc = holocron_core::WeightsConfig::default();
        let merged = merge_weights(&rc);
        assert_eq!(merged, Grade::CATEGORY_WEIGHTS);
    }

    #[test]
    fn merge_weights_overrides_specified_categories() {
        // Partial override: only Security set; others keep default.
        let rc = holocron_core::WeightsConfig {
            security: Some(0.50),
            lints: None,
            complexity: None,
            dead_code: None,
            maintenance: None,
        };
        let merged = merge_weights(&rc);
        let sec = merged.iter().find(|(c, _)| *c == Category::Security).unwrap().1;
        let lints = merged.iter().find(|(c, _)| *c == Category::Lints).unwrap().1;
        assert!((sec - 0.50).abs() < 1e-9, "Security overridden");
        assert!((lints - 0.20).abs() < 1e-9, "Lints unchanged");
    }

    #[test]
    fn merge_weights_full_override() {
        // Full override of every category; verify all 5 land.
        let rc = holocron_core::WeightsConfig {
            security: Some(0.10),
            lints: Some(0.10),
            complexity: Some(0.10),
            dead_code: Some(0.35),
            maintenance: Some(0.35),
        };
        let merged = merge_weights(&rc);
        let by_cat = |c: Category| merged.iter().find(|(x, _)| *x == c).unwrap().1;
        assert!((by_cat(Category::Security) - 0.10).abs() < 1e-9);
        assert!((by_cat(Category::Lints) - 0.10).abs() < 1e-9);
        assert!((by_cat(Category::Complexity) - 0.10).abs() < 1e-9);
        assert!((by_cat(Category::DeadCode) - 0.35).abs() < 1e-9);
        assert!((by_cat(Category::Maintenance) - 0.35).abs() < 1e-9);
        // And the result sums to 1.0.
        let sum: f64 = merged.iter().map(|(_, w)| w).sum();
        assert!((sum - 1.0).abs() < 1e-9);
    }
}
