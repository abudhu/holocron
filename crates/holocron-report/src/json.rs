//! JSON sidecar renderer — full findings, no truncation, stable schema.

use crate::{Report, JSON_SCHEMA_VERSION};
use holocron_core::{Finding, GradeReport, RunStatus};
use serde::Serialize;
use std::time::Duration;

#[derive(Debug, Serialize)]
pub struct JsonReport<'a> {
    pub schema_version: u32,
    pub holocron_version: &'a str,
    pub generated_at: String,
    pub target: TargetInfo<'a>,
    pub grade: &'a GradeReport,
    pub findings: &'a [Finding],
    pub auditor_results: Vec<AuditorSummary<'a>>,
    pub run: RunSummary,
}

#[derive(Debug, Serialize)]
pub struct TargetInfo<'a> {
    pub path: &'a str,
    pub commit: Option<&'a str>,
}

#[derive(Debug, Serialize)]
pub struct AuditorSummary<'a> {
    pub auditor: &'a str,
    pub category: &'a holocron_core::Category,
    pub status: &'a RunStatus,
    pub duration_ms: u128,
    pub finding_count: usize,
    pub error: Option<&'a str>,
}

#[derive(Debug, Serialize)]
pub struct RunSummary {
    pub total_duration_ms: u128,
    pub any_failures: bool,
}

/// Render the report as pretty-printed JSON.
///
/// # Errors
/// Returns an error if `serde_json` fails to serialize. In practice this
/// never happens — all types in the report tree implement `Serialize`
/// over JSON-safe primitives.
pub fn render_json(report: &Report<'_>) -> anyhow::Result<String> {
    let auditor_results: Vec<AuditorSummary<'_>> = report
        .outcome
        .auditor_results
        .iter()
        .map(|r| AuditorSummary {
            auditor: r.auditor,
            category: &r.category,
            status: &r.status,
            duration_ms: r.duration.as_millis(),
            finding_count: r.findings.len(),
            error: r.error.as_deref(),
        })
        .collect();

    let json = JsonReport {
        schema_version: JSON_SCHEMA_VERSION,
        holocron_version: &report.header.holocron_version,
        generated_at: report.header.generated_at.to_rfc3339(),
        target: TargetInfo {
            path: &report.header.target_path,
            commit: report.header.target_commit.as_deref(),
        },
        grade: report.grade,
        findings: &report.findings,
        auditor_results,
        run: RunSummary {
            total_duration_ms: report.outcome.total_duration.as_millis(),
            any_failures: report.outcome.any_failures(),
        },
    };

    Ok(serde_json::to_string_pretty(&json)?)
}

// Suppress unused-import lint when no tests are compiled.
#[allow(unused_imports)]
use Duration as _DurationMarker;

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
    use crate::Report;
    use holocron_core::{
        auditor::AuditorMeta, AuditorResult, Category, Finding, Grade, RunOutcome, Severity,
    };

    #[test]
    fn json_roundtrips_and_has_schema_version() {
        let outcome = RunOutcome {
            target: std::path::PathBuf::from("/tmp/proj"),
            started_at: chrono::Utc::now(),
            total_duration: std::time::Duration::from_millis(123),
            auditor_results: vec![AuditorResult::ok(
                AuditorMeta { name: "clippy", category: Category::Lints },
                vec![Finding::new("clippy", Category::Lints, Severity::Low, "nit")],
                std::time::Duration::from_millis(50),
            )],
        };
        let grade = Grade::new(&outcome.auditor_results).compute();
        let report = Report::new(&outcome, &grade);
        let json = render_json(&report).unwrap();
        // Parse it back as Value to ensure validity.
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(v["schema_version"], JSON_SCHEMA_VERSION);
        assert_eq!(v["findings"].as_array().unwrap().len(), 1);
        assert!(v["grade"]["overall_letter"].is_string());
        assert_eq!(v["auditor_results"][0]["auditor"], "clippy");
    }
}
