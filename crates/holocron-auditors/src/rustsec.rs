//! cargo-audit auditor — wraps `cargo audit --json` to surface
//! `RustSec` advisories against the project's `Cargo.lock`.

use async_trait::async_trait;
use holocron_core::{Auditor, AuditorMeta, Category, Finding, Severity};
use serde::Deserialize;
use std::path::Path;
use std::process::Stdio;
use tokio::process::Command;

#[derive(Debug, Default)]
pub struct RustSecAuditor;

const META: AuditorMeta = AuditorMeta { name: "cargo-audit", category: Category::Security };

#[async_trait]
impl Auditor for RustSecAuditor {
    fn meta(&self) -> AuditorMeta {
        META
    }

    async fn check_available(&self) -> anyhow::Result<()> {
        which::which("cargo-audit").map(|_| ()).map_err(|e| anyhow::anyhow!("{e}"))
    }

    async fn install(&self) -> anyhow::Result<()> {
        let status =
            Command::new("cargo").args(["install", "cargo-audit", "--locked"]).status().await?;
        anyhow::ensure!(status.success(), "cargo install cargo-audit failed");
        Ok(())
    }

    async fn run(&self, target: &Path) -> anyhow::Result<Vec<Finding>> {
        // cargo-audit refuses to run without a Cargo.lock. If one is
        // missing, we generate it on demand (read-only audit shouldn't
        // mutate the project's commit graph, but the lockfile is just
        // a build artifact).
        if !target.join("Cargo.lock").is_file() {
            let _ = Command::new("cargo")
                .current_dir(target)
                .args(["generate-lockfile", "--quiet"])
                .status()
                .await;
        }

        let output = Command::new("cargo")
            .current_dir(target)
            .args(["audit", "--json"])
            .stdin(Stdio::null())
            .output()
            .await?;

        // cargo-audit exits non-zero (1) when it finds vulns. That's
        // not a failure for us — we still parse the JSON.
        let stdout = String::from_utf8_lossy(&output.stdout);
        let report: AuditReport = match serde_json::from_str(&stdout) {
            Ok(r) => r,
            Err(e) => {
                let stderr = String::from_utf8_lossy(&output.stderr);
                anyhow::bail!("failed to parse cargo-audit JSON: {e}; stderr: {stderr}");
            }
        };

        Ok(report_to_findings(&report))
    }
}

fn report_to_findings(report: &AuditReport) -> Vec<Finding> {
    let mut findings = Vec::new();

    for v in &report.vulnerabilities.list {
        let sev = cvss_to_severity(v.advisory.cvss.as_deref());
        let pkg = format!("{}@{}", v.package.name, v.package.version);
        let title = format!("{}: {}", v.advisory.id, v.advisory.title);
        let mut detail = format!(
            "Package: {pkg}\nAdvisory: {url}\nDate: {date}\n",
            url = v.advisory.url.as_deref().unwrap_or("(no url)"),
            date = v.advisory.date.as_deref().unwrap_or("(no date)"),
        );
        if let Some(patched) = &v.versions {
            if !patched.patched.is_empty() {
                use std::fmt::Write as _;
                let _ = writeln!(detail, "Patched in: {}", patched.patched.join(", "));
            }
        }
        findings.push(
            Finding::new("cargo-audit", Category::Security, sev, title)
                .with_code(v.advisory.id.clone())
                .with_detail(detail),
        );
    }

    // Warnings cover unmaintained / yanked deps — lower severity.
    for (kind, warnings) in &report.warnings.0 {
        for w in warnings {
            let title = format!(
                "{}: {}",
                kind,
                w.advisory.as_ref().map_or_else(|| w.package.name.clone(), |a| a.title.clone())
            );
            let detail = format!(
                "Kind: {kind}\nPackage: {}@{}\n{detail_extra}",
                w.package.name,
                w.package.version,
                detail_extra = w
                    .advisory
                    .as_ref()
                    .and_then(|a| a.url.as_deref())
                    .map(|u| format!("Advisory: {u}\n"))
                    .unwrap_or_default(),
            );
            let sev = if kind == "yanked" { Severity::Low } else { Severity::Info };
            let mut f =
                Finding::new("cargo-audit", Category::Maintenance, sev, title).with_detail(detail);
            if let Some(adv) = &w.advisory {
                f = f.with_code(adv.id.clone());
            }
            findings.push(f);
        }
    }

    findings
}

fn cvss_to_severity(cvss: Option<&str>) -> Severity {
    let Some(c) = cvss else { return Severity::High };
    // CVSS strings look like "CVSS:3.1/AV:N/AC:L/.../I:H/A:H" — pulling
    // a base score out of the vector cleanly is non-trivial. Default to
    // High when present, escalate to Critical when the vector includes
    // both AV:N and I:H or A:H (Network attack vector + High impact).
    let net = c.contains("AV:N");
    let high_impact = c.contains("I:H") || c.contains("A:H") || c.contains("C:H");
    if net && high_impact {
        Severity::Critical
    } else {
        Severity::High
    }
}

// --- cargo-audit JSON schema (trimmed to what we use). ---

#[derive(Debug, Deserialize, Default)]
struct AuditReport {
    #[serde(default)]
    vulnerabilities: VulnList,
    #[serde(default)]
    warnings: WarningMap,
}

#[derive(Debug, Deserialize, Default)]
struct VulnList {
    #[serde(default)]
    list: Vec<Vulnerability>,
}

#[derive(Debug, Deserialize)]
struct Vulnerability {
    advisory: Advisory,
    package: Package,
    #[serde(default)]
    versions: Option<Versions>,
}

#[derive(Debug, Deserialize)]
struct Advisory {
    id: String,
    title: String,
    #[serde(default)]
    url: Option<String>,
    #[serde(default)]
    date: Option<String>,
    #[serde(default)]
    cvss: Option<String>,
}

#[derive(Debug, Deserialize)]
struct Package {
    name: String,
    version: String,
}

#[derive(Debug, Deserialize)]
struct Versions {
    #[serde(default)]
    patched: Vec<String>,
}

#[derive(Debug, Default)]
struct WarningMap(Vec<(String, Vec<Warning>)>);

impl<'de> Deserialize<'de> for WarningMap {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        // warnings is keyed by warning kind ("unmaintained", "yanked", ...).
        let raw: std::collections::BTreeMap<String, Vec<Warning>> =
            std::collections::BTreeMap::deserialize(deserializer)?;
        Ok(Self(raw.into_iter().collect()))
    }
}

#[derive(Debug, Deserialize)]
struct Warning {
    package: Package,
    #[serde(default)]
    advisory: Option<Advisory>,
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

    #[test]
    fn parses_a_minimal_clean_report() {
        let json = r#"{"database":{},"lockfile":{},"settings":{},"vulnerabilities":{"found":false,"count":0,"list":[]},"warnings":{}}"#;
        let report: AuditReport = serde_json::from_str(json).unwrap();
        assert!(report.vulnerabilities.list.is_empty());
        assert!(report.warnings.0.is_empty());
        assert!(report_to_findings(&report).is_empty());
    }

    #[test]
    fn parses_a_single_vulnerability() {
        let json = r#"{
          "vulnerabilities": {
            "found": true,
            "count": 1,
            "list": [{
              "advisory": {
                "id": "RUSTSEC-2023-0001",
                "title": "Some scary thing",
                "url": "https://rustsec.org/advisories/RUSTSEC-2023-0001",
                "date": "2023-01-01",
                "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
              },
              "package": { "name": "evil-crate", "version": "0.1.0" },
              "versions": { "patched": [">=0.2.0"] }
            }]
          }
        }"#;
        let report: AuditReport = serde_json::from_str(json).unwrap();
        let findings = report_to_findings(&report);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].category, Category::Security);
        assert_eq!(findings[0].severity, Severity::Critical, "AV:N + I:H = Critical");
        assert_eq!(findings[0].code.as_deref(), Some("RUSTSEC-2023-0001"));
        assert!(findings[0].message.contains("Some scary thing"));
    }

    #[test]
    fn unmaintained_warning_becomes_info_finding() {
        let json = r#"{
          "vulnerabilities": { "found": false, "count": 0, "list": [] },
          "warnings": {
            "unmaintained": [{
              "package": { "name": "old-crate", "version": "0.0.1" },
              "advisory": {
                "id": "RUSTSEC-2020-9999",
                "title": "Crate is unmaintained",
                "url": "https://rustsec.org/x"
              }
            }]
          }
        }"#;
        let report: AuditReport = serde_json::from_str(json).unwrap();
        let findings = report_to_findings(&report);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].category, Category::Maintenance);
        assert_eq!(findings[0].severity, Severity::Info);
    }
}
