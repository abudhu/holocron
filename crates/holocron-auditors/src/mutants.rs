//! `cargo-mutants` auditor — mutation testing for test-quality (#32).
//!
//! Mutation testing flips small parts of your code (e.g. `< → <=`,
//! `+ → -`, `true → false`) and runs your tests. A "missed" mutant
//! means a real bug-shaped change slipped past every test you wrote;
//! a "caught" mutant means at least one test failed; "unviable" means
//! the mutation didn't compile (cargo-mutants drops those).
//!
//! Holocron treats each **missed** mutant as a Medium finding (test
//! coverage gap) under the `Complexity` category — same code-health
//! umbrella as cyclomatic hotspots. The auditor is **opt-in** via
//! `--with-mutants` because cargo-mutants is slow (30min-many-hours
//! on a real workspace) and not appropriate for every audit.

use async_trait::async_trait;
use holocron_core::{Auditor, AuditorMeta, Category, Finding, Location, Severity};
use serde::Deserialize;
use std::path::Path;
use tokio::process::Command;

#[derive(Debug, Default)]
pub struct MutantsAuditor;

const META: AuditorMeta = AuditorMeta { name: "cargo-mutants", category: Category::Complexity };

#[async_trait]
impl Auditor for MutantsAuditor {
    fn meta(&self) -> AuditorMeta {
        META
    }

    async fn check_available(&self) -> anyhow::Result<()> {
        which::which("cargo-mutants").map(|_| ()).map_err(|e| anyhow::anyhow!("{e}"))
    }

    async fn install(&self) -> anyhow::Result<()> {
        let status =
            Command::new("cargo").args(["install", "cargo-mutants", "--locked"]).status().await?;
        anyhow::ensure!(status.success(), "cargo install cargo-mutants failed");
        Ok(())
    }

    async fn run(&self, target: &Path) -> anyhow::Result<Vec<Finding>> {
        // --json emits NDJSON to stdout; one object per mutant outcome.
        // --in-place keeps mutations contained to the working dir.
        // --no-shuffle so output ordering is deterministic for diffs.
        let output = Command::new("cargo")
            .current_dir(target)
            .args(["mutants", "--json", "--no-shuffle"])
            .output()
            .await?;
        // cargo-mutants exits non-zero when any mutants are MISSED
        // (treat that as "tests don't cover these mutations"). Don't
        // bail on non-zero — parse the stream regardless.
        let stdout = String::from_utf8_lossy(&output.stdout);
        Ok(parse_mutants_stream(&stdout, target))
    }
}

/// Parse cargo-mutants `--json` NDJSON output into Findings. One
/// Medium finding per MISSED mutant. CAUGHT and UNVIABLE mutants are
/// not findings (they're good outcomes / non-events respectively).
fn parse_mutants_stream(text: &str, project_root: &Path) -> Vec<Finding> {
    text.lines()
        .filter_map(parse_outcome_line)
        .filter_map(|o| missed_to_finding(&o, project_root))
        .collect()
}

fn parse_outcome_line(line: &str) -> Option<MutantOutcome> {
    let line = line.trim();
    if !line.starts_with('{') {
        return None;
    }
    serde_json::from_str(line).ok()
}

fn missed_to_finding(o: &MutantOutcome, project_root: &Path) -> Option<Finding> {
    if o.summary != "MISSED" {
        return None;
    }
    let display_path = o
        .file
        .strip_prefix(&project_root.to_string_lossy()[..])
        .unwrap_or(&o.file)
        .trim_start_matches('/')
        .to_string();
    let msg = format!(
        "test gap: mutation `{}` at {}:{} was not detected by any test",
        o.mutation, display_path, o.line
    );
    let detail = format!(
        "cargo-mutants applied the mutation `{}` and your tests still passed. \
         Add a test that fails when this mutation is in place.\n\
         File: {}\nLine: {}\nMutation: {}",
        o.mutation, display_path, o.line, o.mutation
    );
    let loc = Location::at(&display_path, o.line);
    Some(
        Finding::new("cargo-mutants", Category::Complexity, Severity::Medium, msg)
            .with_code("mutant-missed")
            .with_detail(detail)
            .with_location(loc),
    )
}

/// Trimmed view of cargo-mutants' JSON outcome envelope. Fields kept
/// to the minimum we need; serde silently ignores everything else.
#[derive(Debug, Deserialize)]
struct MutantOutcome {
    /// "MISSED", "CAUGHT", "UNVIABLE", "TIMEOUT".
    summary: String,
    /// Source file the mutation touched.
    file: String,
    /// Line the mutation was applied at.
    #[serde(default)]
    line: u32,
    /// Human-readable description of the mutation (e.g. `replace == with !=`).
    #[serde(default)]
    mutation: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn line(summary: &str, file: &str, line: u32, mutation: &str) -> String {
        format!(
            r#"{{"summary":"{summary}","file":"{file}","line":{line},"mutation":"{mutation}"}}"#
        )
    }

    #[test]
    fn parses_one_missed_mutant_into_one_finding() {
        let text = line("MISSED", "src/lib.rs", 42, "replace == with !=");
        let findings = parse_mutants_stream(&text, &PathBuf::from("/tmp/proj"));
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Medium);
        assert_eq!(findings[0].code.as_deref(), Some("mutant-missed"));
        assert!(findings[0].message.contains("src/lib.rs:42"));
        assert!(findings[0].message.contains("replace == with !="));
    }

    #[test]
    fn caught_mutants_produce_no_findings() {
        let text = line("CAUGHT", "src/lib.rs", 10, "replace + with -");
        let findings = parse_mutants_stream(&text, &PathBuf::from("/tmp/proj"));
        assert!(findings.is_empty(), "CAUGHT is a positive outcome, not a finding");
    }

    #[test]
    fn unviable_and_timeout_filtered_out() {
        let text = format!(
            "{}\n{}\n",
            line("UNVIABLE", "src/lib.rs", 5, "replace true with false"),
            line("TIMEOUT", "src/lib.rs", 12, "replace 1 with 0"),
        );
        let findings = parse_mutants_stream(&text, &PathBuf::from("/tmp/proj"));
        assert!(findings.is_empty(), "only MISSED produces findings");
    }

    #[test]
    fn mixed_stream_extracts_only_missed() {
        let text = format!(
            "{}\n{}\n{}\n{}\n",
            line("CAUGHT", "src/a.rs", 1, "mut1"),
            line("MISSED", "src/b.rs", 2, "mut2"),
            line("UNVIABLE", "src/c.rs", 3, "mut3"),
            line("MISSED", "src/d.rs", 4, "mut4"),
        );
        let findings = parse_mutants_stream(&text, &PathBuf::from("/tmp/proj"));
        assert_eq!(findings.len(), 2);
        assert!(findings.iter().any(|f| f.message.contains("src/b.rs:2")));
        assert!(findings.iter().any(|f| f.message.contains("src/d.rs:4")));
    }

    #[test]
    fn blank_and_non_json_lines_skipped() {
        let text = format!(
            "\n\n{}{}{}\n",
            "this is not json\n",
            "# some shell comment\n",
            line("MISSED", "src/lib.rs", 1, "mut"),
        );
        let findings = parse_mutants_stream(&text, &PathBuf::from("/tmp/proj"));
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn malformed_json_skipped_without_failure() {
        // Half-broken envelope (missing closing brace) should not crash.
        let text = "{\"summary\":\"MISSED\",\"file\":\"src/lib.rs\"\n";
        let findings = parse_mutants_stream(text, &PathBuf::from("/tmp/proj"));
        assert!(findings.is_empty());
    }

    #[test]
    fn category_is_complexity_for_test_gaps() {
        let text = line("MISSED", "src/lib.rs", 1, "mut");
        let findings = parse_mutants_stream(&text, &PathBuf::from("/tmp/proj"));
        assert_eq!(findings[0].category, Category::Complexity);
    }
}
