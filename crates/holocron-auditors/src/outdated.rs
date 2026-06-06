//! cargo-outdated auditor — wraps `cargo outdated --format json` to
//! surface dependencies behind their latest compatible / latest absolute
//! version.
//!
//! Severity ladder:
//!   - Major behind (`compat == "---"`)  → Medium
//!   - Minor behind                       → Low
//!   - Patch behind                       → Info
//!
//! The Medium tier surfaces real upgrade work; Info-level patch drift
//! shows up in the count without dragging the grade down.

use async_trait::async_trait;
use holocron_core::{Auditor, AuditorMeta, Category, Finding, Severity};
use serde::Deserialize;
use std::path::Path;
use std::process::Stdio;
use tokio::process::Command;

#[derive(Debug, Default)]
pub struct OutdatedAuditor;

const META: AuditorMeta = AuditorMeta { name: "cargo-outdated", category: Category::Maintenance };

#[async_trait]
impl Auditor for OutdatedAuditor {
    fn meta(&self) -> AuditorMeta {
        META
    }

    async fn check_available(&self) -> anyhow::Result<()> {
        which::which("cargo-outdated").map(|_| ()).map_err(|e| anyhow::anyhow!("{e}"))
    }

    async fn install(&self) -> anyhow::Result<()> {
        let status =
            Command::new("cargo").args(["install", "cargo-outdated", "--locked"]).status().await?;
        anyhow::ensure!(status.success(), "cargo install cargo-outdated failed");
        Ok(())
    }

    async fn run(&self, target: &Path) -> anyhow::Result<Vec<Finding>> {
        let output = Command::new("cargo")
            .current_dir(target)
            // depth=1 = direct deps only. Avoids noise from transitive
            // deps the project can't directly bump.
            .args(["outdated", "--format", "json", "--depth", "1"])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .await?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        Ok(parse_outdated_stream(&stdout))
    }
}

/// Parse cargo-outdated's NDJSON output. Each line is a workspace-member
/// envelope with the member's name and its outdated dependencies.
fn parse_outdated_stream(text: &str) -> Vec<Finding> {
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    text.lines()
        .filter_map(parse_member_line)
        .flat_map(|env| env.dependencies.into_iter().map(move |dep| (env.crate_name.clone(), dep)))
        .filter_map(|(member, dep)| dep_to_finding(&member, &dep, &mut seen))
        .collect()
}

/// Parse a single NDJSON line into a `WorkspaceMember`. Returns `None`
/// for blank lines, non-JSON, and malformed envelopes.
fn parse_member_line(line: &str) -> Option<WorkspaceMember> {
    let line = line.trim();
    if !line.starts_with('{') {
        return None;
    }
    serde_json::from_str(line).ok()
}

/// Convert one `Dependency` into a Finding, deduplicating across
/// workspace members (the same dep shared between members would
/// otherwise surface twice). Returns `None` when the dep is current
/// (nothing to flag) or already seen.
fn dep_to_finding(
    member: &str,
    dep: &Dependency,
    seen: &mut std::collections::HashSet<String>,
) -> Option<Finding> {
    let kind = classify(dep);
    let severity = severity_for(kind)?;
    let key = format!("{}@{}->{}", dep.name, dep.project, dep.latest);
    if !seen.insert(key) {
        return None;
    }
    let (verb, code) = match kind {
        UpdateKind::Major => ("major", "outdated-major"),
        UpdateKind::Minor => ("minor", "outdated-minor"),
        UpdateKind::Patch => ("patch", "outdated-patch"),
        // unreachable: severity_for(Current) returns None and we
        // already short-circuited.
        UpdateKind::Current => return None,
    };
    let message =
        format!("`{}` {verb} upgrade available: {} → {}", dep.name, dep.project, dep.latest);
    let detail = format!(
        "Workspace member: {member}\nKind: {}\nProject: {}\nCompat: {}\nLatest: {}",
        dep.kind, dep.project, dep.compat, dep.latest,
    );
    Some(
        Finding::new("cargo-outdated", Category::Maintenance, severity, message)
            .with_code(code)
            .with_detail(detail),
    )
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum UpdateKind {
    Current,
    Patch,
    Minor,
    Major,
}

fn classify(dep: &Dependency) -> UpdateKind {
    // compat == "---" means there is no semver-compatible newer version —
    // i.e. the latest available is a major upgrade.
    if dep.compat == "---" || dep.compat.is_empty() {
        return UpdateKind::Major;
    }
    // If project version equals latest, nothing to do.
    if dep.project == dep.latest {
        return UpdateKind::Current;
    }
    // Otherwise compare the version components to decide minor vs patch.
    match (parse_semver(&dep.project), parse_semver(&dep.latest)) {
        (Some(p), Some(l)) if l.major > p.major => UpdateKind::Major,
        (Some(p), Some(l)) if l.minor > p.minor => UpdateKind::Minor,
        _ => UpdateKind::Patch,
    }
}

const fn severity_for(kind: UpdateKind) -> Option<Severity> {
    match kind {
        UpdateKind::Current => None,
        UpdateKind::Major => Some(Severity::Medium),
        UpdateKind::Minor => Some(Severity::Low),
        UpdateKind::Patch => Some(Severity::Info),
    }
}

#[derive(Debug, Clone, Copy)]
struct SemverParts {
    major: u32,
    minor: u32,
}

fn parse_semver(s: &str) -> Option<SemverParts> {
    let mut parts = s.split('.');
    let major = parts.next()?.parse().ok()?;
    let minor = parts.next()?.parse().ok()?;
    Some(SemverParts { major, minor })
}

// --- cargo-outdated --format json schema (trimmed to fields we use). ---

#[derive(Debug, Deserialize)]
struct WorkspaceMember {
    crate_name: String,
    #[serde(default)]
    dependencies: Vec<Dependency>,
}

#[derive(Debug, Deserialize)]
struct Dependency {
    name: String,
    project: String,
    compat: String,
    latest: String,
    kind: String,
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;

    #[test]
    fn major_upgrade_is_medium_severity() {
        let json = r#"{"crate_name":"foo","dependencies":[{"name":"thiserror","project":"1.0.69","compat":"---","latest":"2.0.18","kind":"Normal","platform":null}]}"#;
        let findings = parse_outdated_stream(json);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Medium);
        assert_eq!(findings[0].code.as_deref(), Some("outdated-major"));
        assert!(findings[0].message.contains("thiserror"));
        assert!(findings[0].message.contains("1.0.69 → 2.0.18"));
    }

    #[test]
    fn minor_upgrade_is_low_severity() {
        // chrono 0.4.44 → 0.4.45 is a patch (Info), so use real minor: 0.4.x → 0.5.y
        let json = r#"{"crate_name":"foo","dependencies":[{"name":"semver","project":"1.0.28","compat":"1.1.0","latest":"1.1.0","kind":"Normal","platform":null}]}"#;
        let findings = parse_outdated_stream(json);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Low);
        assert_eq!(findings[0].code.as_deref(), Some("outdated-minor"));
    }

    #[test]
    fn patch_upgrade_is_info_severity() {
        let json = r#"{"crate_name":"foo","dependencies":[{"name":"chrono","project":"0.4.44","compat":"0.4.45","latest":"0.4.45","kind":"Normal","platform":null}]}"#;
        let findings = parse_outdated_stream(json);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Info);
        assert_eq!(findings[0].code.as_deref(), Some("outdated-patch"));
    }

    #[test]
    fn fully_up_to_date_yields_no_finding() {
        let json = r#"{"crate_name":"foo","dependencies":[{"name":"clap","project":"4.6.1","compat":"4.6.1","latest":"4.6.1","kind":"Normal","platform":null}]}"#;
        assert!(parse_outdated_stream(json).is_empty());
    }

    #[test]
    fn dedupes_dep_shared_across_workspace_members() {
        let json = r#"{"crate_name":"foo","dependencies":[{"name":"thiserror","project":"1.0.69","compat":"---","latest":"2.0.18","kind":"Normal","platform":null}]}
{"crate_name":"bar","dependencies":[{"name":"thiserror","project":"1.0.69","compat":"---","latest":"2.0.18","kind":"Normal","platform":null}]}"#;
        let findings = parse_outdated_stream(json);
        assert_eq!(findings.len(), 1, "same dep across two members should dedup to one finding");
    }

    #[test]
    fn empty_member_yields_no_findings() {
        let json = r#"{"crate_name":"holocron-cli","dependencies":[]}"#;
        assert!(parse_outdated_stream(json).is_empty());
    }

    #[test]
    fn ignores_warning_lines_before_json() {
        let txt = "warning: Feature rustls-tls of package reqwest has been obsolete\n{\"crate_name\":\"foo\",\"dependencies\":[]}";
        // The warning line doesn't start with '{' so it's skipped; the empty deps
        // line yields no findings either, so total is zero.
        assert!(parse_outdated_stream(txt).is_empty());
    }

    #[test]
    fn semver_parse_handles_three_parts() {
        let s = parse_semver("1.2.3").unwrap();
        assert_eq!(s.major, 1);
        assert_eq!(s.minor, 2);
        assert!(parse_semver("not-a-version").is_none());
    }
}
