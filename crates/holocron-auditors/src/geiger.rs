//! cargo-geiger auditor — wraps `cargo geiger --output-format Json` to surface
//! `unsafe` code surface across the project and its dependencies.
//!
//! cargo-geiger counts unsafe functions, methods, expressions, item impls,
//! and item traits separately for "used" code paths vs "unused" (only the
//! used count matters for risk). We surface findings at the package level:
//! one finding per dependency with any unsafe-in-used.
//!
//! Severity ladder (heuristic — `unsafe` is context-dependent, see the
//! cargo-geiger README's "Stigma around Unsafe" note):
//!  * the target project's OWN crates with any unsafe → High (direct
//!    surface area in the code being audited)
//!  * direct dependencies with unsafe in used code → Medium
//!  * transitive dependencies with unsafe in used code → Low
//!  * packages that `#![forbid(unsafe_code)]` → no finding (good signal)
//!
//! This intentionally does NOT count `unsafe` in unused code paths — many
//! crates have unsafe behind feature flags that aren't enabled in this
//! build, and counting them inflates the noise.
//!
//! Category: Security. Unsafe-surface is supply-chain-adjacent — a CVE in
//! an unsafe block in a transitive dep is materially more dangerous than
//! one in safe code.

use async_trait::async_trait;
use holocron_core::{Auditor, AuditorMeta, Category, Finding, Severity};
use serde::Deserialize;
use std::path::Path;
use std::process::Stdio;
use tokio::process::Command;

#[derive(Debug, Default)]
pub struct GeigerAuditor;

const META: AuditorMeta = AuditorMeta { name: "cargo-geiger", category: Category::Security };

#[async_trait]
impl Auditor for GeigerAuditor {
    fn meta(&self) -> AuditorMeta {
        META
    }

    async fn check_available(&self) -> anyhow::Result<()> {
        which::which("cargo-geiger").map(|_| ()).map_err(|e| anyhow::anyhow!("{e}"))
    }

    async fn install(&self) -> anyhow::Result<()> {
        let status =
            Command::new("cargo").args(["install", "cargo-geiger", "--locked"]).status().await?;
        anyhow::ensure!(status.success(), "cargo install cargo-geiger failed");
        Ok(())
    }

    async fn run(&self, target: &Path) -> anyhow::Result<Vec<Finding>> {
        // cargo-geiger CANNOT run from a virtual manifest, even with
        // --package. It needs to be invoked from a directory whose
        // Cargo.toml describes an actual package. So we discover the
        // workspace members and their manifest paths, then run geiger
        // once per member from that member's directory.
        let members = workspace_members(target).await?;
        if members.is_empty() {
            anyhow::bail!(
                "no runnable packages found in {} — cargo-geiger needs at least one bin or lib",
                target.display()
            );
        }

        // Local crate names — for severity classification (workspace
        // members get High severity for unsafe in their own code).
        let local_ids: std::collections::HashSet<String> =
            members.iter().map(|m| m.name.clone()).collect();

        let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
        let mut all_findings = Vec::new();

        for member in &members {
            // Member's directory is the parent of its manifest.
            let Some(member_dir) = member.manifest_path.parent() else {
                eprintln!(
                    "[holocron geiger] skipping member {} with no parent dir: {}",
                    member.name,
                    member.manifest_path.display()
                );
                continue;
            };

            let output = Command::new("cargo")
                .current_dir(member_dir)
                .args(["geiger", "--output-format", "Json", "--all-features"])
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .output()
                .await?;

            let stdout = String::from_utf8_lossy(&output.stdout);
            if stdout.trim().is_empty() {
                let stderr = String::from_utf8_lossy(&output.stderr);
                eprintln!(
                    "[holocron geiger] no JSON for {} (exit {}); stderr: {stderr}",
                    member.name, output.status
                );
                continue;
            }

            let report: SafetyReport = serde_json::from_str(&stdout).map_err(|e| {
                anyhow::anyhow!("failed to parse cargo-geiger JSON for {}: {e}", member.name)
            })?;

            // Build direct-dep set FOR THIS MEMBER: any package that
            // appears as a dependency of a local crate is "direct".
            let mut direct_ids: std::collections::HashSet<String> =
                std::collections::HashSet::new();
            for entry in &report.packages {
                if local_ids.contains(&entry.package.id.name) {
                    for dep in &entry.package.dependencies {
                        direct_ids.insert(dep.name.clone());
                    }
                }
            }

            for finding in report_to_findings(&report, &local_ids, &direct_ids) {
                let key = format!("{}|{}", finding.code.as_deref().unwrap_or(""), finding.message);
                if seen.insert(key) {
                    all_findings.push(finding);
                }
            }
        }

        Ok(all_findings)
    }
}

/// Discover workspace members + their manifest paths via `cargo metadata`.
async fn workspace_members(target: &Path) -> anyhow::Result<Vec<WorkspaceMember>> {
    let output = Command::new("cargo")
        .current_dir(target)
        .args(["metadata", "--no-deps", "--format-version", "1"])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .await?;
    anyhow::ensure!(
        output.status.success(),
        "cargo metadata failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let meta: CargoMetadata = serde_json::from_slice(&output.stdout)
        .map_err(|e| anyhow::anyhow!("failed to parse cargo metadata JSON: {e}"))?;
    Ok(meta
        .packages
        .into_iter()
        .map(|p| WorkspaceMember {
            name: p.name,
            manifest_path: std::path::PathBuf::from(p.manifest_path),
        })
        .collect())
}

struct WorkspaceMember {
    name: String,
    manifest_path: std::path::PathBuf,
}

#[derive(Debug, Deserialize)]
struct CargoMetadata {
    #[serde(default)]
    packages: Vec<CargoMetadataPackage>,
}

#[derive(Debug, Deserialize)]
struct CargoMetadataPackage {
    name: String,
    manifest_path: String,
}

fn report_to_findings(
    report: &SafetyReport,
    local_ids: &std::collections::HashSet<String>,
    direct_ids: &std::collections::HashSet<String>,
) -> Vec<Finding> {
    let mut findings = Vec::new();
    for entry in &report.packages {
        let used = &entry.unsafety.used;
        if !used.has_unsafe() {
            continue;
        }
        let name = &entry.package.id.name;
        let version = &entry.package.id.version;
        let severity = if local_ids.contains(name) {
            Severity::High
        } else if direct_ids.contains(name) {
            Severity::Medium
        } else {
            Severity::Low
        };
        let total_unsafe = used.total_unsafe();
        let breakdown = format!(
            "Functions: {}/{}, Methods: {}/{}, Exprs: {}/{}, ItemImpls: {}/{}, ItemTraits: {}/{}",
            used.functions.unsafe_,
            used.functions.safe + used.functions.unsafe_,
            used.methods.unsafe_,
            used.methods.safe + used.methods.unsafe_,
            used.exprs.unsafe_,
            used.exprs.safe + used.exprs.unsafe_,
            used.item_impls.unsafe_,
            used.item_impls.safe + used.item_impls.unsafe_,
            used.item_traits.unsafe_,
            used.item_traits.safe + used.item_traits.unsafe_,
        );
        let context = if local_ids.contains(name) {
            "local crate"
        } else if direct_ids.contains(name) {
            "direct dependency"
        } else {
            "transitive dependency"
        };
        let detail = format!(
            "Package: {name}@{version} ({context})\nUnsafe items (used code path only): {total_unsafe}\n{breakdown}",
        );
        findings.push(
            Finding::new(
                "cargo-geiger",
                Category::Security,
                severity,
                format!("{name}@{version}: {total_unsafe} unsafe item(s) reachable"),
            )
            .with_code(format!("unsafe-surface:{name}"))
            .with_detail(detail),
        );
    }
    findings
}

// --- cargo-geiger-serde JSON schema (trimmed to what we use). ---
//
// The full schema lives in https://github.com/rust-secure-code/cargo-geiger
// at `cargo-geiger-serde/src/report.rs`. We model only the SafetyReport
// shape (the default output of `cargo geiger --output-format Json`).
// The `packages` field is serialized as a JSON array of ReportEntry, not
// a map — see `entry_serde` in the upstream crate.

#[derive(Debug, Deserialize)]
struct SafetyReport {
    #[serde(default)]
    packages: Vec<ReportEntry>,
}

#[derive(Debug, Deserialize)]
struct ReportEntry {
    package: PackageInfo,
    unsafety: UnsafeInfo,
}

#[derive(Debug, Deserialize)]
struct PackageInfo {
    id: PackageId,
    #[serde(default)]
    dependencies: Vec<PackageId>,
}

#[derive(Debug, Deserialize, Clone)]
struct PackageId {
    name: String,
    version: String,
}

#[derive(Debug, Deserialize)]
struct UnsafeInfo {
    used: CounterBlock,
}

#[derive(Debug, Deserialize, Default)]
struct CounterBlock {
    #[serde(default)]
    functions: Count,
    #[serde(default)]
    exprs: Count,
    #[serde(default)]
    item_impls: Count,
    #[serde(default)]
    item_traits: Count,
    #[serde(default)]
    methods: Count,
}

impl CounterBlock {
    const fn has_unsafe(&self) -> bool {
        self.functions.unsafe_ > 0
            || self.exprs.unsafe_ > 0
            || self.item_impls.unsafe_ > 0
            || self.item_traits.unsafe_ > 0
            || self.methods.unsafe_ > 0
    }

    const fn total_unsafe(&self) -> u64 {
        self.functions.unsafe_
            + self.exprs.unsafe_
            + self.item_impls.unsafe_
            + self.item_traits.unsafe_
            + self.methods.unsafe_
    }
}

#[derive(Debug, Deserialize, Default, Clone)]
struct Count {
    #[serde(default)]
    safe: u64,
    #[serde(default, rename = "unsafe_")]
    unsafe_: u64,
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
    use std::collections::HashSet;

    fn local() -> HashSet<String> {
        let mut s = HashSet::new();
        s.insert("my-app".to_string());
        s
    }

    fn direct() -> HashSet<String> {
        let mut s = HashSet::new();
        s.insert("serde".to_string());
        s
    }

    #[test]
    fn parses_minimal_safe_report() {
        let json = r#"{"packages": []}"#;
        let report: SafetyReport = serde_json::from_str(json).unwrap();
        assert!(report.packages.is_empty());
        assert!(report_to_findings(&report, &local(), &direct()).is_empty());
    }

    #[test]
    fn packages_with_no_unsafe_produce_no_finding() {
        let json = r#"{
            "packages": [{
                "package": {
                    "id": {"name": "pure-safe", "version": "1.0.0", "source": "registry+https://github.com/rust-lang/crates.io-index"},
                    "dependencies": [],
                    "dev_dependencies": [],
                    "build_dependencies": []
                },
                "unsafety": {
                    "used": {"functions": {"safe": 10, "unsafe_": 0}, "exprs": {"safe": 100, "unsafe_": 0}, "item_impls": {"safe": 5, "unsafe_": 0}, "item_traits": {"safe": 2, "unsafe_": 0}, "methods": {"safe": 20, "unsafe_": 0}},
                    "unused": {"functions": {"safe": 0, "unsafe_": 0}, "exprs": {"safe": 0, "unsafe_": 0}, "item_impls": {"safe": 0, "unsafe_": 0}, "item_traits": {"safe": 0, "unsafe_": 0}, "methods": {"safe": 0, "unsafe_": 0}},
                    "forbids_unsafe": false
                }
            }]
        }"#;
        let report: SafetyReport = serde_json::from_str(json).unwrap();
        let findings = report_to_findings(&report, &local(), &direct());
        assert!(findings.is_empty(), "no unsafe in used → no finding");
    }

    #[test]
    fn local_crate_with_unsafe_is_high() {
        let json = r#"{
            "packages": [{
                "package": {
                    "id": {"name": "my-app", "version": "0.1.0", "source": null},
                    "dependencies": [], "dev_dependencies": [], "build_dependencies": []
                },
                "unsafety": {
                    "used": {"functions": {"safe": 1, "unsafe_": 1}, "exprs": {"safe": 0, "unsafe_": 3}, "item_impls": {"safe": 0, "unsafe_": 0}, "item_traits": {"safe": 0, "unsafe_": 0}, "methods": {"safe": 0, "unsafe_": 0}},
                    "unused": {"functions": {"safe": 0, "unsafe_": 0}, "exprs": {"safe": 0, "unsafe_": 0}, "item_impls": {"safe": 0, "unsafe_": 0}, "item_traits": {"safe": 0, "unsafe_": 0}, "methods": {"safe": 0, "unsafe_": 0}},
                    "forbids_unsafe": false
                }
            }]
        }"#;
        let report: SafetyReport = serde_json::from_str(json).unwrap();
        let findings = report_to_findings(&report, &local(), &direct());
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::High, "local crate unsafe should be High");
        assert_eq!(findings[0].category, Category::Security);
        assert!(findings[0].message.contains("my-app"));
        assert!(findings[0].message.contains("4 unsafe"));
    }

    #[test]
    fn direct_dep_with_unsafe_is_medium() {
        let json = r#"{
            "packages": [{
                "package": {
                    "id": {"name": "serde", "version": "1.0.200", "source": "registry+https://github.com/rust-lang/crates.io-index"},
                    "dependencies": [], "dev_dependencies": [], "build_dependencies": []
                },
                "unsafety": {
                    "used": {"functions": {"safe": 0, "unsafe_": 0}, "exprs": {"safe": 0, "unsafe_": 5}, "item_impls": {"safe": 0, "unsafe_": 0}, "item_traits": {"safe": 0, "unsafe_": 0}, "methods": {"safe": 0, "unsafe_": 2}},
                    "unused": {"functions": {"safe": 0, "unsafe_": 0}, "exprs": {"safe": 0, "unsafe_": 0}, "item_impls": {"safe": 0, "unsafe_": 0}, "item_traits": {"safe": 0, "unsafe_": 0}, "methods": {"safe": 0, "unsafe_": 0}},
                    "forbids_unsafe": false
                }
            }]
        }"#;
        let report: SafetyReport = serde_json::from_str(json).unwrap();
        let findings = report_to_findings(&report, &local(), &direct());
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Medium);
    }

    #[test]
    fn transitive_dep_with_unsafe_is_low() {
        let json = r#"{
            "packages": [{
                "package": {
                    "id": {"name": "libc", "version": "0.2.0", "source": "registry+https://github.com/rust-lang/crates.io-index"},
                    "dependencies": [], "dev_dependencies": [], "build_dependencies": []
                },
                "unsafety": {
                    "used": {"functions": {"safe": 0, "unsafe_": 1}, "exprs": {"safe": 0, "unsafe_": 0}, "item_impls": {"safe": 0, "unsafe_": 0}, "item_traits": {"safe": 0, "unsafe_": 0}, "methods": {"safe": 0, "unsafe_": 0}},
                    "unused": {"functions": {"safe": 0, "unsafe_": 0}, "exprs": {"safe": 0, "unsafe_": 0}, "item_impls": {"safe": 0, "unsafe_": 0}, "item_traits": {"safe": 0, "unsafe_": 0}, "methods": {"safe": 0, "unsafe_": 0}},
                    "forbids_unsafe": false
                }
            }]
        }"#;
        let report: SafetyReport = serde_json::from_str(json).unwrap();
        let findings = report_to_findings(&report, &local(), &direct());
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Low, "transitive should be Low");
    }

    #[test]
    fn unused_unsafe_does_not_count() {
        // Crate has unsafe in unused code paths only → no finding.
        // (Many crates have unsafe behind feature flags not enabled.)
        let json = r#"{
            "packages": [{
                "package": {
                    "id": {"name": "feature-gated", "version": "1.0.0", "source": "registry+https://github.com/rust-lang/crates.io-index"},
                    "dependencies": [], "dev_dependencies": [], "build_dependencies": []
                },
                "unsafety": {
                    "used": {"functions": {"safe": 0, "unsafe_": 0}, "exprs": {"safe": 0, "unsafe_": 0}, "item_impls": {"safe": 0, "unsafe_": 0}, "item_traits": {"safe": 0, "unsafe_": 0}, "methods": {"safe": 0, "unsafe_": 0}},
                    "unused": {"functions": {"safe": 0, "unsafe_": 100}, "exprs": {"safe": 0, "unsafe_": 200}, "item_impls": {"safe": 0, "unsafe_": 10}, "item_traits": {"safe": 0, "unsafe_": 5}, "methods": {"safe": 0, "unsafe_": 20}},
                    "forbids_unsafe": false
                }
            }]
        }"#;
        let report: SafetyReport = serde_json::from_str(json).unwrap();
        let findings = report_to_findings(&report, &local(), &direct());
        assert!(findings.is_empty(), "unsafe in unused code shouldn't tank the grade");
    }
}
