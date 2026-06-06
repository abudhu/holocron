//! cargo-deny auditor — wraps `cargo deny --format=json check` to surface
//! licensing, banned/duplicate crates, and untrusted-source findings.
//!
//! cargo-deny needs a `deny.toml` to do anything useful. If the target
//! project doesn't have one, this auditor ships a sensible default
//! (templates/`deny-default.toml`, baked into the binary) into a temp
//! file and points cargo-deny at it via `--config`. That way Holocron's
//! supply-chain coverage works out-of-the-box on any Rust project.

use async_trait::async_trait;
use holocron_core::{Auditor, AuditorMeta, Category, Finding, Severity};
use serde::Deserialize;
use std::path::Path;
use std::process::Stdio;
use tokio::process::Command;

#[derive(Debug, Default)]
pub struct DenyAuditor;

const META: AuditorMeta = AuditorMeta { name: "cargo-deny", category: Category::Maintenance };

/// Sensible default `deny.toml` used when the target project has none.
/// Matches the policy in Holocron's own `deny.toml`.
const DEFAULT_DENY_TOML: &str = include_str!("../templates/deny-default.toml");

#[async_trait]
impl Auditor for DenyAuditor {
    fn meta(&self) -> AuditorMeta {
        META
    }

    async fn check_available(&self) -> anyhow::Result<()> {
        which::which("cargo-deny").map(|_| ()).map_err(|e| anyhow::anyhow!("{e}"))
    }

    async fn install(&self) -> anyhow::Result<()> {
        let status =
            Command::new("cargo").args(["install", "cargo-deny", "--locked"]).status().await?;
        anyhow::ensure!(status.success(), "cargo install cargo-deny failed");
        Ok(())
    }

    async fn run(&self, target: &Path) -> anyhow::Result<Vec<Finding>> {
        // Stage a config: either the project's own deny.toml, or our
        // bundled default written to a temp file.
        let project_config = target.join("deny.toml");
        let (config_path, _tmp_holder) = if project_config.is_file() {
            (project_config, None)
        } else {
            let tmp =
                tempfile::Builder::new().prefix("holocron-deny-").suffix(".toml").tempfile()?;
            std::fs::write(tmp.path(), DEFAULT_DENY_TOML)?;
            let path = tmp.path().to_path_buf();
            (path, Some(tmp))
        };

        let output = Command::new("cargo")
            .current_dir(target)
            .args(["deny", "--format=json"])
            .arg("--config")
            .arg(&config_path)
            .arg("check")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .await?;

        // cargo-deny exits non-zero on findings. Always parse output regardless.
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        // Diagnostics are written to stderr in JSON-line form; summary
        // ("advisories ok, bans FAILED, ...") goes to stderr too.
        let combined = format!("{stdout}\n{stderr}");
        Ok(parse_deny_stream(&combined))
    }
}

/// Parse cargo-deny's `--format=json` NDJSON stream. Each line is one
/// diagnostic object; we only keep the ones we know how to map.
fn parse_deny_stream(text: &str) -> Vec<Finding> {
    let mut seen_keys: std::collections::HashSet<String> = std::collections::HashSet::new();
    text.lines()
        .filter_map(parse_diag_line)
        .filter_map(|d| diag_to_finding(&d, &mut seen_keys))
        .collect()
}

/// Parse a single NDJSON line into a `Diagnostic`. Returns `None` for
/// blanks, non-JSON lines, non-diagnostic envelopes, and malformed JSON
/// — all of which cargo-deny mixes into its stream alongside the real
/// diagnostics.
fn parse_diag_line(line: &str) -> Option<Diagnostic> {
    let line = line.trim();
    if !line.starts_with('{') {
        return None;
    }
    let env: DiagnosticEnvelope = serde_json::from_str(line).ok()?;
    if env.r#type != "diagnostic" {
        return None;
    }
    Some(env.fields)
}

/// Convert one parsed diagnostic into a Finding, deduplicating against
/// the running set. Returns `None` when the diagnostic is a repeat
/// (cargo-deny re-emits the same license-rejected diagnostic for every
/// crate touched by it).
fn diag_to_finding(
    diag: &Diagnostic,
    seen_keys: &mut std::collections::HashSet<String>,
) -> Option<Finding> {
    let crate_name = diag.first_crate_name().unwrap_or_default();
    let dedup_key = format!("{}|{}|{crate_name}", diag.code, diag.message);
    if !seen_keys.insert(dedup_key) {
        return None;
    }
    let severity = map_severity(&diag.severity, &diag.code);
    let message = if crate_name.is_empty() {
        diag.message.clone()
    } else {
        format!("[{crate_name}] {}", diag.message)
    };
    let detail = collect_detail(diag);

    let mut f = Finding::new("cargo-deny", Category::Maintenance, severity, message)
        .with_code(diag.code.clone());
    if let Some(d) = detail {
        f = f.with_detail(d);
    }
    Some(f)
}

/// Build the `detail` string from a diagnostic's first label + first
/// 4 notes. Returns `None` when there's nothing to include — the
/// Finding then omits the detail field entirely.
fn collect_detail(diag: &Diagnostic) -> Option<String> {
    let mut lines: Vec<String> = vec![];
    if let Some(label) = diag.first_label_message() {
        if !label.is_empty() {
            lines.push(label);
        }
    }
    for note in diag.notes.iter().take(4) {
        lines.push(note.clone());
    }
    if lines.is_empty() {
        None
    } else {
        Some(lines.join("\n"))
    }
}

fn map_severity(level: &str, code: &str) -> Severity {
    // Banned-crate hits and duplicate-version hits are quality signals
    // but not security incidents — Medium.
    // License rejections are policy violations — escalate to High.
    // Unknown source (typosquat surface) is High.
    match (level, code) {
        ("error", c) if c.starts_with("license") || c == "rejected" => Severity::High,
        ("error", "unknown-source" | "unknown-git" | "unknown-registry") => Severity::High,
        ("error", _) => Severity::Medium,
        ("warning", _) => Severity::Low,
        _ => Severity::Info,
    }
}

// --- cargo-deny --format=json schema (trimmed to fields we use). ---

#[derive(Debug, Deserialize)]
struct DiagnosticEnvelope {
    r#type: String,
    fields: Diagnostic,
}

#[derive(Debug, Deserialize)]
struct Diagnostic {
    code: String,
    severity: String,
    message: String,
    #[serde(default)]
    notes: Vec<String>,
    #[serde(default)]
    graphs: Vec<Graph>,
    #[serde(default)]
    labels: Vec<Label>,
}

impl Diagnostic {
    fn first_crate_name(&self) -> Option<String> {
        self.graphs.first().map(|g| g.krate.name.clone())
    }
    fn first_label_message(&self) -> Option<String> {
        self.labels.first().map(|l| l.message.clone())
    }
}

#[derive(Debug, Deserialize)]
struct Graph {
    #[serde(rename = "Krate")]
    krate: Krate,
}

#[derive(Debug, Deserialize)]
struct Krate {
    name: String,
}

#[derive(Debug, Deserialize)]
struct Label {
    #[serde(default)]
    message: String,
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;

    #[test]
    fn parses_a_license_rejected_diagnostic() {
        // Trimmed real cargo-deny output. Tests the "license rejected"
        // path that triggers when a dep ships under a license not on
        // the allow list.
        let json = r#"{"type":"diagnostic","fields":{"code":"rejected","severity":"error","message":"failed to satisfy license requirements","notes":["MIT - MIT License"],"graphs":[{"Krate":{"name":"clap","version":"4.6.1"}}],"labels":[{"message":"rejected: license is not explicitly allowed","span":"MIT"}]}}"#;
        let findings = parse_deny_stream(json);
        assert_eq!(findings.len(), 1);
        let f = &findings[0];
        assert_eq!(f.auditor, "cargo-deny");
        assert_eq!(f.category, Category::Maintenance);
        assert_eq!(f.severity, Severity::High, "license rejection is High");
        assert_eq!(f.code.as_deref(), Some("rejected"));
        assert!(f.message.contains("[clap]"));
        assert!(f.detail.as_deref().unwrap().contains("rejected"));
    }

    #[test]
    fn dedupes_repeated_diagnostics_for_same_crate() {
        // cargo-deny re-emits the same rejection per dep-graph path. We
        // collapse them by (code, message, crate) so the report shows
        // one finding per actual violation.
        let json = r#"{"type":"diagnostic","fields":{"code":"rejected","severity":"error","message":"failed to satisfy license requirements","notes":[],"graphs":[{"Krate":{"name":"clap","version":"4.6.1"}}],"labels":[]}}
{"type":"diagnostic","fields":{"code":"rejected","severity":"error","message":"failed to satisfy license requirements","notes":[],"graphs":[{"Krate":{"name":"clap","version":"4.6.1"}}],"labels":[]}}"#;
        let findings = parse_deny_stream(json);
        assert_eq!(findings.len(), 1, "duplicate diagnostics must collapse");
    }

    #[test]
    fn maps_warning_to_low() {
        let json = r#"{"type":"diagnostic","fields":{"code":"yanked","severity":"warning","message":"crate has been yanked","notes":[],"graphs":[{"Krate":{"name":"foo","version":"1.0.0"}}],"labels":[]}}"#;
        let findings = parse_deny_stream(json);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Low);
    }

    #[test]
    fn ignores_non_diagnostic_envelopes() {
        let json = r#"{"type":"summary","fields":{"foo":1}}"#;
        assert!(parse_deny_stream(json).is_empty());
    }

    #[test]
    fn ignores_blank_and_non_json_lines() {
        let txt = "\n  \nnot json at all\n{not valid}\n";
        assert!(parse_deny_stream(txt).is_empty());
    }

    #[test]
    fn unknown_source_maps_to_high() {
        let json = r#"{"type":"diagnostic","fields":{"code":"unknown-registry","severity":"error","message":"crate from unknown registry","notes":[],"graphs":[{"Krate":{"name":"sus-crate","version":"0.1.0"}}],"labels":[]}}"#;
        let findings = parse_deny_stream(json);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::High, "unknown-source is High");
    }
}
