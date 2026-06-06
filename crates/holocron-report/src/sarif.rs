//! SARIF v2.1.0 renderer — produces the OASIS-standard SARIF format
//! consumed by GitHub Code Scanning, Azure DevOps, and most other code-
//! scanning dashboards.
//!
//! Spec: <https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html>
//! GitHub guide: <https://docs.github.com/en/code-security/code-scanning/integrating-with-code-scanning/sarif-support-for-code-scanning>
//!
//! We emit a SINGLE `runs[]` entry per audit, with one `results[]`
//! object per finding. Rule definitions are deduplicated and placed
//! under `tool.driver.rules[]` so consumers can group results by rule.

use crate::Report;
use holocron_core::{Finding, Severity};
use serde::Serialize;
use std::collections::BTreeMap;

const SARIF_VERSION: &str = "2.1.0";
const SARIF_SCHEMA: &str =
    "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json";

/// Render the report as SARIF v2.1.0 JSON.
///
/// # Errors
/// Returns an error if serde-json serialization fails. In practice this
/// never happens — all types here implement `Serialize` over JSON-safe
/// primitives.
pub fn render_sarif(report: &Report<'_>) -> anyhow::Result<String> {
    let driver = Driver {
        name: "Holocron",
        version: &report.header.holocron_version,
        information_uri: "https://onedev.amitbudhu.com/holocron",
        rules: collect_rules(&report.findings),
    };

    let results: Vec<SarifResult> = report.findings.iter().map(finding_to_result).collect();

    let run = Run { tool: Tool { driver }, results };

    let sarif = Sarif { version: SARIF_VERSION, schema: SARIF_SCHEMA, runs: vec![run] };
    Ok(serde_json::to_string_pretty(&sarif)?)
}

fn collect_rules(findings: &[Finding]) -> Vec<Rule> {
    // Dedupe by rule id (the SARIF concept). We use auditor:code as
    // the rule id when code is present, else auditor:<category>.
    let mut by_id: BTreeMap<String, Rule> = BTreeMap::new();
    for f in findings {
        let id = rule_id(f);
        by_id.entry(id.clone()).or_insert_with(|| Rule {
            id: id.clone(),
            name: f.code.clone().unwrap_or_else(|| f.auditor.clone()),
            short_description: TextField { text: format!("{}: {}", f.auditor, f.category) },
            full_description: TextField {
                text: format!(
                    "Rule surfaced by the {} auditor under the {} category. \
                     Severity is set per-finding (this is the rule defaulting \
                     to the first observed severity).",
                    f.auditor, f.category
                ),
            },
            help_uri: rule_help_uri(f),
            default_configuration: DefaultConfiguration { level: sarif_level(f.severity) },
        });
    }
    by_id.into_values().collect()
}

fn finding_to_result(f: &Finding) -> SarifResult {
    let rule_id = rule_id(f);
    let level = sarif_level(f.severity);

    let locations = f.location.as_ref().map_or_else(Vec::new, |loc| {
        vec![Location {
            physical_location: PhysicalLocation {
                artifact_location: ArtifactLocation { uri: loc.file.display().to_string() },
                region: loc.line.map(|line| Region { start_line: line, start_column: loc.column }),
            },
        }]
    });

    SarifResult {
        rule_id,
        level,
        message: TextField { text: f.message.clone() },
        locations,
        properties: ResultProperties {
            severity: format!("{}", f.severity),
            auditor: f.auditor.clone(),
            category: format!("{}", f.category),
            fingerprint: f.fingerprint.clone(),
        },
        partial_fingerprints: PartialFingerprints {
            holocron_fingerprint_v1: f.fingerprint.clone(),
        },
    }
}

fn rule_id(f: &Finding) -> String {
    f.code.as_ref().map_or_else(
        || format!("{}/{}", f.auditor, f.category),
        |code| format!("{}/{code}", f.auditor),
    )
}

fn rule_help_uri(f: &Finding) -> Option<String> {
    // clippy lints have a canonical docs URL.
    f.code.as_ref().and_then(|c| {
        c.strip_prefix("clippy::")
            .map(|lint| format!("https://rust-lang.github.io/rust-clippy/master/index.html#{lint}"))
    })
}

/// Map our Severity onto SARIF's three-level "level" enum.
/// SARIF only has note / warning / error — we collapse Info+Low → note,
/// Medium → warning, High+Critical → error.
const fn sarif_level(s: Severity) -> &'static str {
    match s {
        Severity::Critical | Severity::High => "error",
        Severity::Medium => "warning",
        Severity::Low | Severity::Info => "note",
    }
}

// --- SARIF v2.1.0 schema (trimmed to what we emit) ---

#[derive(Serialize)]
struct Sarif<'a> {
    version: &'static str,
    #[serde(rename = "$schema")]
    schema: &'static str,
    runs: Vec<Run<'a>>,
}

#[derive(Serialize)]
struct Run<'a> {
    tool: Tool<'a>,
    results: Vec<SarifResult>,
}

#[derive(Serialize)]
struct Tool<'a> {
    driver: Driver<'a>,
}

#[derive(Serialize)]
struct Driver<'a> {
    name: &'static str,
    version: &'a str,
    #[serde(rename = "informationUri")]
    information_uri: &'static str,
    rules: Vec<Rule>,
}

#[derive(Serialize)]
struct Rule {
    id: String,
    name: String,
    #[serde(rename = "shortDescription")]
    short_description: TextField,
    #[serde(rename = "fullDescription")]
    full_description: TextField,
    #[serde(rename = "helpUri", skip_serializing_if = "Option::is_none")]
    help_uri: Option<String>,
    #[serde(rename = "defaultConfiguration")]
    default_configuration: DefaultConfiguration,
}

#[derive(Serialize)]
struct DefaultConfiguration {
    level: &'static str,
}

#[derive(Serialize)]
struct TextField {
    text: String,
}

#[derive(Serialize)]
struct SarifResult {
    #[serde(rename = "ruleId")]
    rule_id: String,
    level: &'static str,
    message: TextField,
    locations: Vec<Location>,
    properties: ResultProperties,
    #[serde(rename = "partialFingerprints")]
    partial_fingerprints: PartialFingerprints,
}

#[derive(Serialize)]
struct Location {
    #[serde(rename = "physicalLocation")]
    physical_location: PhysicalLocation,
}

#[derive(Serialize)]
struct PhysicalLocation {
    #[serde(rename = "artifactLocation")]
    artifact_location: ArtifactLocation,
    #[serde(skip_serializing_if = "Option::is_none")]
    region: Option<Region>,
}

#[derive(Serialize)]
struct ArtifactLocation {
    uri: String,
}

#[derive(Serialize)]
struct Region {
    #[serde(rename = "startLine")]
    start_line: u32,
    #[serde(rename = "startColumn", skip_serializing_if = "Option::is_none")]
    start_column: Option<u32>,
}

#[derive(Serialize)]
struct ResultProperties {
    severity: String,
    auditor: String,
    category: String,
    fingerprint: String,
}

#[derive(Serialize)]
struct PartialFingerprints {
    /// SARIF lets tools advertise their own fingerprint schemes by
    /// arbitrary key — consumers (GitHub) use these for cross-run
    /// deduplication.
    #[serde(rename = "holocronFingerprint/v1")]
    holocron_fingerprint_v1: String,
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
    use crate::Report;
    use holocron_core::auditor::AuditorMeta;
    use holocron_core::{
        AuditorResult, Category, Finding, Grade, Location as CoreLocation, RunOutcome,
    };
    use std::time::Duration;

    fn fixture_outcome() -> RunOutcome {
        let r = AuditorResult::ok(
            AuditorMeta { name: "clippy", category: Category::Lints },
            vec![
                Finding::new("clippy", Category::Lints, Severity::Medium, "uses unwrap()")
                    .with_code("clippy::unwrap_used")
                    .with_location(CoreLocation::at("src/lib.rs", 42)),
                Finding::new(
                    "cargo-audit",
                    Category::Security,
                    Severity::Critical,
                    "RUSTSEC-2024-0001: bad thing",
                )
                .with_code("RUSTSEC-2024-0001"),
            ],
            Duration::from_millis(50),
        );
        RunOutcome {
            target: std::path::PathBuf::from("/tmp/proj"),
            started_at: chrono::Utc::now(),
            total_duration: Duration::from_secs(1),
            auditor_results: vec![r],
        }
    }

    #[test]
    fn rendered_sarif_is_valid_json_and_has_expected_top_level_fields() {
        let outcome = fixture_outcome();
        let grade = Grade::new(&outcome.auditor_results).compute();
        let report = Report::new(&outcome, &grade);
        let s = render_sarif(&report).unwrap();
        let v: serde_json::Value = serde_json::from_str(&s).unwrap();
        assert_eq!(v["version"], "2.1.0");
        assert!(v["$schema"].as_str().unwrap().contains("sarif-schema-2.1.0"));
        let runs = v["runs"].as_array().unwrap();
        assert_eq!(runs.len(), 1);
    }

    #[test]
    fn severity_collapses_to_three_sarif_levels() {
        assert_eq!(sarif_level(Severity::Critical), "error");
        assert_eq!(sarif_level(Severity::High), "error");
        assert_eq!(sarif_level(Severity::Medium), "warning");
        assert_eq!(sarif_level(Severity::Low), "note");
        assert_eq!(sarif_level(Severity::Info), "note");
    }

    #[test]
    fn each_finding_becomes_a_result_with_a_rule_id() {
        let outcome = fixture_outcome();
        let grade = Grade::new(&outcome.auditor_results).compute();
        let report = Report::new(&outcome, &grade);
        let v: serde_json::Value = serde_json::from_str(&render_sarif(&report).unwrap()).unwrap();

        let results = v["runs"][0]["results"].as_array().unwrap();
        assert_eq!(results.len(), 2);

        let clippy_result =
            results.iter().find(|r| r["ruleId"] == "clippy/clippy::unwrap_used").unwrap();
        assert_eq!(clippy_result["level"], "warning");
        assert_eq!(clippy_result["message"]["text"], "uses unwrap()");
        let region = &clippy_result["locations"][0]["physicalLocation"]["region"];
        assert_eq!(region["startLine"], 42);

        let audit_result =
            results.iter().find(|r| r["ruleId"] == "cargo-audit/RUSTSEC-2024-0001").unwrap();
        assert_eq!(audit_result["level"], "error");
    }

    #[test]
    fn rules_are_deduplicated_in_driver() {
        // Two findings with same code should produce ONE rule entry.
        let r = AuditorResult::ok(
            AuditorMeta { name: "clippy", category: Category::Lints },
            vec![
                Finding::new("clippy", Category::Lints, Severity::Medium, "first")
                    .with_code("clippy::unwrap_used"),
                Finding::new("clippy", Category::Lints, Severity::Medium, "second")
                    .with_code("clippy::unwrap_used"),
            ],
            Duration::from_millis(1),
        );
        let outcome = RunOutcome {
            target: std::path::PathBuf::from("/tmp/proj"),
            started_at: chrono::Utc::now(),
            total_duration: Duration::ZERO,
            auditor_results: vec![r],
        };
        let grade = Grade::new(&outcome.auditor_results).compute();
        let report = Report::new(&outcome, &grade);
        let v: serde_json::Value = serde_json::from_str(&render_sarif(&report).unwrap()).unwrap();
        let rules = v["runs"][0]["tool"]["driver"]["rules"].as_array().unwrap();
        assert_eq!(rules.len(), 1, "duplicate code should collapse to one rule");
        assert_eq!(rules[0]["id"], "clippy/clippy::unwrap_used");
    }

    #[test]
    fn clippy_rules_get_help_uri_to_lint_docs() {
        let r = AuditorResult::ok(
            AuditorMeta { name: "clippy", category: Category::Lints },
            vec![Finding::new("clippy", Category::Lints, Severity::Medium, "msg")
                .with_code("clippy::manual_let_else")],
            Duration::from_millis(1),
        );
        let outcome = RunOutcome {
            target: std::path::PathBuf::from("/tmp/proj"),
            started_at: chrono::Utc::now(),
            total_duration: Duration::ZERO,
            auditor_results: vec![r],
        };
        let grade = Grade::new(&outcome.auditor_results).compute();
        let report = Report::new(&outcome, &grade);
        let v: serde_json::Value = serde_json::from_str(&render_sarif(&report).unwrap()).unwrap();
        let rule = &v["runs"][0]["tool"]["driver"]["rules"][0];
        assert!(rule["helpUri"].as_str().unwrap().contains("rust-clippy"));
        assert!(rule["helpUri"].as_str().unwrap().contains("manual_let_else"));
    }

    #[test]
    fn fingerprints_propagate_for_cross_run_dedup() {
        let r = AuditorResult::ok(
            AuditorMeta { name: "clippy", category: Category::Lints },
            vec![Finding::new("clippy", Category::Lints, Severity::Low, "msg")
                .with_code("clippy::foo")],
            Duration::from_millis(1),
        );
        let outcome = RunOutcome {
            target: std::path::PathBuf::from("/tmp/proj"),
            started_at: chrono::Utc::now(),
            total_duration: Duration::ZERO,
            auditor_results: vec![r],
        };
        let grade = Grade::new(&outcome.auditor_results).compute();
        let report = Report::new(&outcome, &grade);
        let v: serde_json::Value = serde_json::from_str(&render_sarif(&report).unwrap()).unwrap();
        let result = &v["runs"][0]["results"][0];
        let fp = result["properties"]["fingerprint"].as_str().unwrap();
        let partial_fp = result["partialFingerprints"]["holocronFingerprint/v1"].as_str().unwrap();
        assert_eq!(fp, partial_fp, "fingerprint must appear in both places");
        assert_eq!(fp.len(), 16, "holocron fingerprints are 16-char hex");
    }
}
