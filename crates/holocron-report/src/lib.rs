//! Report rendering for Holocron — Markdown for humans/LLMs, JSON for
//! machines (CI gates, downstream tooling, future SARIF conversion).

pub mod json;
pub mod markdown;

pub use json::render_json;
pub use markdown::render_markdown;

use holocron_core::{Finding, GradeReport, RunOutcome};
use serde::{Deserialize, Serialize};

/// Schema version for the JSON sidecar. Bump on breaking changes.
///
/// History:
/// * `1` — initial shape. `grade.by_category[*]` was a flat object with
///   `category`, `score`, `letter`, `finding_count`.
/// * `2` — `grade.by_category[*]` became a tagged union with
///   `kind: "graded" | "skipped"`. `graded` keeps the v1 fields;
///   `skipped` carries `category` + `reason`. Driven by holocron #24
///   (the silent `B 0.85` fallback for failed auditors).
pub const JSON_SCHEMA_VERSION: u32 = 2;

/// Header carried by both report formats.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportHeader {
    pub holocron_version: String,
    pub schema_version: u32,
    pub generated_at: chrono::DateTime<chrono::Utc>,
    pub target_path: String,
    pub target_commit: Option<String>,
}

impl ReportHeader {
    #[must_use]
    pub fn new(outcome: &RunOutcome) -> Self {
        Self {
            holocron_version: holocron_core::VERSION.to_string(),
            schema_version: JSON_SCHEMA_VERSION,
            generated_at: outcome.started_at,
            target_path: outcome.target.display().to_string(),
            target_commit: detect_git_commit(&outcome.target),
        }
    }
}

fn detect_git_commit(target: &std::path::Path) -> Option<String> {
    let out = std::process::Command::new("git")
        .current_dir(target)
        .args(["rev-parse", "--short", "HEAD"])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let s = String::from_utf8(out.stdout).ok()?.trim().to_string();
    if s.is_empty() {
        None
    } else {
        Some(s)
    }
}

/// Full data carried by every report: header + outcome + grade.
#[derive(Debug, Clone)]
pub struct Report<'a> {
    pub header: ReportHeader,
    pub outcome: &'a RunOutcome,
    pub grade: &'a GradeReport,
    pub findings: Vec<Finding>,
}

impl<'a> Report<'a> {
    #[must_use]
    pub fn new(outcome: &'a RunOutcome, grade: &'a GradeReport) -> Self {
        let header = ReportHeader::new(outcome);
        let findings = outcome.all_findings();
        Self { header, outcome, grade, findings }
    }
}
