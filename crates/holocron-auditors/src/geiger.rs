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
        anyhow::ensure!(
            !members.is_empty(),
            "no runnable packages found in {} — cargo-geiger needs at least one bin or lib",
            target.display()
        );

        // Local crate names — for severity classification (workspace
        // members get High severity for unsafe in their own code).
        let local_ids: std::collections::HashSet<String> =
            members.iter().map(|m| m.name.clone()).collect();

        let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
        let mut all_findings = Vec::new();
        // #38: track success/failure so we can distinguish "geiger ran
        // clean on everything" from "geiger silently failed on every
        // member" — the latter must surface as Failed, not Ok(empty).
        let mut members_succeeded: usize = 0;
        let mut first_member_failure: Option<(String, String)> = None;

        for member in &members {
            match run_geiger_for_member(member, &local_ids).await? {
                MemberOutcome::Ok(findings) => {
                    for finding in findings {
                        let key = format!(
                            "{}|{}",
                            finding.code.as_deref().unwrap_or(""),
                            finding.message
                        );
                        if seen.insert(key) {
                            all_findings.push(finding);
                        }
                    }
                    members_succeeded += 1;
                }
                MemberOutcome::Failed(stderr) => {
                    if first_member_failure.is_none() {
                        first_member_failure = Some((member.name.clone(), stderr));
                    }
                }
            }
        }

        // #38: if cargo-geiger failed on EVERY workspace member, the
        // category was not measured at all. Don't return Ok(empty) —
        // that would inflate the grade. Propagate as Err so the runner
        // marks the auditor Failed and the grader marks Security as
        // Skipped (advisory grade, exit code 3).
        check_geiger_completeness(members.len(), members_succeeded, first_member_failure.as_ref())?;

        Ok(all_findings)
    }
}

/// What happened when we ran geiger against a single workspace member.
enum MemberOutcome {
    /// Geiger produced parseable JSON. The (already-classified) Findings
    /// are ready to splice into the audit's accumulator after dedup.
    Ok(Vec<Finding>),
    /// Geiger produced no usable JSON for this member (empty stdout,
    /// non-zero exit, or unparseable output). Carries the stderr blob
    /// for the caller's diagnostic. NOT an error itself — only an error
    /// when EVERY member ends in this state (handled by
    /// `check_geiger_completeness`).
    Failed(String),
}

/// Invoke `cargo geiger` for one workspace member and either return
/// classified Findings (success) or the stderr blob (failure). Pulled
/// out of `GeigerAuditor::run` so its cyclomatic stays under threshold
/// (#38: the new completeness check + this dispatch loop together
/// pushed `run()` to cyc=16; extracting this drops it back below).
async fn run_geiger_for_member(
    member: &WorkspaceMember,
    local_ids: &std::collections::HashSet<String>,
) -> anyhow::Result<MemberOutcome> {
    let Some(member_dir) = member.manifest_path.parent() else {
        eprintln!(
            "[holocron geiger] skipping member {} with no parent dir: {}",
            member.name,
            member.manifest_path.display()
        );
        return Ok(MemberOutcome::Failed("(no parent dir)".to_string()));
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
        return Ok(MemberOutcome::Failed(stderr.trim().to_string()));
    }

    let report: SafetyReport = serde_json::from_str(&stdout).map_err(|e| {
        anyhow::anyhow!("failed to parse cargo-geiger JSON for {}: {e}", member.name)
    })?;

    // Build direct-dep set FOR THIS MEMBER: any package that
    // appears as a dependency of a local crate is "direct".
    let mut direct_ids: std::collections::HashSet<String> = std::collections::HashSet::new();
    for entry in &report.packages {
        if local_ids.contains(&entry.package.id.name) {
            for dep in &entry.package.dependencies {
                direct_ids.insert(dep.name.clone());
            }
        }
    }

    Ok(MemberOutcome::Ok(report_to_findings(&report, local_ids, &direct_ids)))
}

/// Decide whether a cargo-geiger run that produced `members_succeeded`
/// of `members_attempted` is acceptable. Returns `Err` if NO members
/// succeeded (silent failure mode — would otherwise inflate the grade),
/// logs a warning to stderr if SOME but not all succeeded (partial
/// measurement). Pulled out of `run()` so it's testable without
/// shelling out to cargo-geiger (#38).
fn check_geiger_completeness(
    members_attempted: usize,
    members_succeeded: usize,
    first_failure: Option<&(String, String)>,
) -> anyhow::Result<()> {
    if members_succeeded == 0 && members_attempted > 0 {
        let (member, stderr) = first_failure
            .cloned()
            .unwrap_or_else(|| ("(unknown)".to_string(), "(no stderr captured)".to_string()));
        anyhow::bail!(
            "cargo-geiger failed on every workspace member ({members_attempted} attempted, \
             0 succeeded). First failure was on `{member}`: {stderr}"
        );
    }
    if members_succeeded < members_attempted {
        eprintln!(
            "[holocron geiger] WARNING: only {members_succeeded}/{members_attempted} workspace \
             members measured cleanly; unsafe-surface findings may be incomplete."
        );
    }
    Ok(())
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
        // Severity ladder — geiger findings are extremely chatty in any
        // non-trivial dep tree (libc, mio, parking_lot all carry unsafe
        // by necessity). We surface real signal only for local + direct;
        // transitive unsafe is Info (no grade penalty) but still appears
        // in the report so reviewers can audit the surface if they want.
        let severity = if local_ids.contains(name) {
            Severity::High
        } else if direct_ids.contains(name) {
            Severity::Low
        } else {
            Severity::Info
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
    fn direct_dep_with_unsafe_is_low() {
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
        assert_eq!(findings[0].severity, Severity::Low, "direct dep is Low (rare-but-real)");
    }

    #[test]
    fn transitive_dep_with_unsafe_is_info() {
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
        assert_eq!(
            findings[0].severity,
            Severity::Info,
            "transitive is Info (advisory; no grade penalty for std-adjacent unsafe)"
        );
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

    // ── #38 silent-failure prevention tests ─────────────────────────────

    #[test]
    fn all_members_fail_returns_err() {
        // 3 members attempted, 0 succeeded → must Err so the runner
        // marks the auditor Failed and the grader marks Security Skipped.
        let first_failure =
            Some(("holocron-core".to_string(), "valuable@0.1.1 not found".to_string()));
        let result = check_geiger_completeness(3, 0, first_failure.as_ref());
        assert!(result.is_err(), "all members failing must propagate as Err");
        let err = format!("{}", result.unwrap_err());
        assert!(err.contains("0 succeeded"), "error must explain count: {err}");
        assert!(err.contains("holocron-core"), "error must name first failing member: {err}");
        assert!(
            err.contains("valuable@0.1.1"),
            "error must include the upstream stderr blob: {err}"
        );
    }

    #[test]
    fn all_members_fail_without_captured_stderr_still_errs() {
        // Edge case: first_failure is None (theoretically possible if
        // all members fell through some other guard). Must still Err.
        let result = check_geiger_completeness(2, 0, None);
        assert!(result.is_err());
        let err = format!("{}", result.unwrap_err());
        assert!(err.contains("(unknown)"), "fallback member name: {err}");
        assert!(err.contains("(no stderr captured)"), "fallback stderr: {err}");
    }

    #[test]
    fn partial_member_failure_returns_ok() {
        // 4 attempted, 2 succeeded → Ok (partial measurement). Stderr
        // warning is best-effort; we only assert the return type here.
        let first_failure = Some(("holocron-cli".to_string(), "some error".to_string()));
        let result = check_geiger_completeness(4, 2, first_failure.as_ref());
        assert!(result.is_ok(), "partial success must NOT err (the findings we got are real)");
    }

    #[test]
    fn all_members_succeed_returns_ok_quietly() {
        // 3 attempted, 3 succeeded → Ok, no warning expected.
        let result = check_geiger_completeness(3, 3, None);
        assert!(result.is_ok());
    }

    #[test]
    fn zero_members_attempted_returns_ok() {
        // Defensive: empty workspace would have bailed earlier in run(),
        // but check_geiger_completeness called with (0, 0, None) should
        // not Err (no measurement was even attempted).
        let result = check_geiger_completeness(0, 0, None);
        assert!(result.is_ok(), "empty attempt count must not be conflated with silent failure");
    }
}
