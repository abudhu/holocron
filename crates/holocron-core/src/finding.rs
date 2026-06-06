//! The [`Finding`] type — the shared data structure every auditor emits.
//!
//! A finding captures one observation from one auditor about one piece of
//! code. The fingerprint is designed to be stable across runs even when
//! line numbers shift due to cosmetic edits, so consumers can diff
//! reports over time without false churn.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::cmp::Ordering;
use std::fmt;
use std::path::PathBuf;

/// Severity of a finding. Ordered most-to-least serious for display sorting.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum Severity {
    /// Production-breaking. `RustSec` CVE, miscompilation, UB.
    Critical,
    /// Likely-real bug or vuln. Most clippy `correctness` lints, high-CVSS CVEs.
    High,
    /// Code smell with real risk. Clippy `suspicious`/`perf` warnings, medium CVEs.
    Medium,
    /// Style nit, minor optimization, low-priority cleanup.
    Low,
    /// FYI. Unmaintained dep, deprecation notice, complexity threshold near limit.
    Info,
}

impl Severity {
    /// Numeric weight used by [`crate::grade::Grade`] to penalize the score.
    /// Higher = worse.
    #[must_use]
    pub const fn weight(self) -> f64 {
        match self {
            Self::Critical => 0.50,
            Self::High => 0.20,
            Self::Medium => 0.05,
            Self::Low => 0.01,
            Self::Info => 0.0,
        }
    }

    /// Sort order for display. Critical comes first.
    #[must_use]
    pub const fn rank(self) -> u8 {
        match self {
            Self::Critical => 0,
            Self::High => 1,
            Self::Medium => 2,
            Self::Low => 3,
            Self::Info => 4,
        }
    }
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Critical => f.write_str("Critical"),
            Self::High => f.write_str("High"),
            Self::Medium => f.write_str("Medium"),
            Self::Low => f.write_str("Low"),
            Self::Info => f.write_str("Info"),
        }
    }
}

/// Coarse category each finding belongs to. Feeds [`crate::grade::Grade`]'s
/// per-category scoring.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum Category {
    /// CVEs, `RustSec` advisories, unsafe surface in own crates.
    Security,
    /// Clippy / rustc warnings about idiom, correctness, suspicious code.
    Lints,
    /// Cyclomatic / cognitive complexity, maintainability index hits.
    Complexity,
    /// Unused dependencies, unused exports, dead modules.
    DeadCode,
    /// Outdated deps, yanked crates, license / supply-chain hygiene.
    Maintenance,
}

impl Category {
    /// All categories — used when iterating to build a grade report.
    pub const ALL: [Self; 5] =
        [Self::Security, Self::Lints, Self::Complexity, Self::DeadCode, Self::Maintenance];
}

impl fmt::Display for Category {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Security => f.write_str("Security"),
            Self::Lints => f.write_str("Lints"),
            Self::Complexity => f.write_str("Complexity"),
            Self::DeadCode => f.write_str("Dead Code"),
            Self::Maintenance => f.write_str("Maintenance"),
        }
    }
}

/// Where in the source tree a finding lives.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Location {
    pub file: PathBuf,
    pub line: Option<u32>,
    pub column: Option<u32>,
    pub snippet: Option<String>,
}

impl Location {
    #[must_use]
    pub fn new(file: impl Into<PathBuf>) -> Self {
        Self { file: file.into(), line: None, column: None, snippet: None }
    }

    #[must_use]
    pub fn at(file: impl Into<PathBuf>, line: u32) -> Self {
        Self { file: file.into(), line: Some(line), column: None, snippet: None }
    }

    #[must_use]
    pub fn at_col(file: impl Into<PathBuf>, line: u32, column: u32) -> Self {
        Self { file: file.into(), line: Some(line), column: Some(column), snippet: None }
    }
}

impl fmt::Display for Location {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.file.display())?;
        if let Some(l) = self.line {
            write!(f, ":{l}")?;
            if let Some(c) = self.column {
                write!(f, ":{c}")?;
            }
        }
        Ok(())
    }
}

/// One observation from one auditor about one piece of code.
///
/// Findings are intended to be both human-readable (rendered into the
/// Markdown report) and machine-parseable (serialized into the JSON
/// sidecar). The `fingerprint` field is a stable identifier across runs
/// so consumers can diff reports without churn from cosmetic line shifts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Finding {
    /// Auditor that emitted this finding (e.g. `"clippy"`, `"cargo-audit"`).
    pub auditor: String,
    /// Coarse category this finding contributes to.
    pub category: Category,
    /// Severity — drives both sort order and grade penalty.
    pub severity: Severity,
    /// Stable code, when the underlying tool has one
    /// (e.g. `"clippy::unwrap_used"`, `"RUSTSEC-2023-0001"`).
    pub code: Option<String>,
    /// One-line summary suitable for tables.
    pub message: String,
    /// Optional multi-line detail (full explanation, advisory URL, etc.).
    pub detail: Option<String>,
    /// `file:line:col` where the finding lives. Some auditors (e.g.
    /// `cargo-audit`) emit project-wide findings with no location.
    pub location: Option<Location>,
    /// Stable hash for cross-run dedup. See [`Finding::compute_fingerprint`].
    pub fingerprint: String,
    /// True when an `[[allowlist]]` rule in `.holocronrc.toml` matches
    /// this finding (#29). Allowlisted findings still appear in the
    /// report (under their own section, with the reason) but are
    /// EXCLUDED from category scores and the overall grade.
    /// Defaults to `false` — older JSON sidecars (schema v1) parse
    /// cleanly because `#[serde(default)]` fills in the absence.
    #[serde(default)]
    pub allowlisted: bool,
    /// Human-readable rationale from the rc rule that matched. None
    /// when not allowlisted, or when the rule omitted `reason`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allowlist_reason: Option<String>,
}

impl Finding {
    /// Construct a finding and auto-compute its fingerprint from the
    /// other fields. Prefer this over manually setting `fingerprint`.
    #[must_use]
    pub fn new(
        auditor: impl Into<String>,
        category: Category,
        severity: Severity,
        message: impl Into<String>,
    ) -> Self {
        let auditor = auditor.into();
        let message = message.into();
        let fingerprint = Self::compute_fingerprint(&auditor, None, None, &message);
        Self {
            auditor,
            category,
            severity,
            code: None,
            message,
            detail: None,
            location: None,
            fingerprint,
            allowlisted: false,
            allowlist_reason: None,
        }
    }

    /// Attach a lint / advisory code and recompute the fingerprint.
    #[must_use]
    pub fn with_code(mut self, code: impl Into<String>) -> Self {
        self.code = Some(code.into());
        self.refresh_fingerprint();
        self
    }

    /// Attach a multi-line detail string. Doesn't affect fingerprint.
    #[must_use]
    pub fn with_detail(mut self, detail: impl Into<String>) -> Self {
        self.detail = Some(detail.into());
        self
    }

    /// Attach a source location and recompute the fingerprint.
    /// Note: only the *file* contributes to the fingerprint, not the
    /// line — that's what makes the hash stable across cosmetic edits.
    #[must_use]
    pub fn with_location(mut self, location: Location) -> Self {
        self.location = Some(location);
        self.refresh_fingerprint();
        self
    }

    fn refresh_fingerprint(&mut self) {
        let file = self.location.as_ref().map(|l| l.file.as_path());
        self.fingerprint =
            Self::compute_fingerprint(&self.auditor, self.code.as_deref(), file, &self.message);
    }

    /// Compute the stable fingerprint hex string.
    ///
    /// `auditor + code + file + normalized_message` are hashed with
    /// SHA-256 and truncated to 16 hex chars (64 bits) — plenty of
    /// collision-resistance for a single project's findings, short enough
    /// to be readable. The message is normalized by collapsing whitespace
    /// and lowercasing so trivial wording tweaks don't churn the hash.
    #[must_use]
    pub fn compute_fingerprint(
        auditor: &str,
        code: Option<&str>,
        file: Option<&std::path::Path>,
        message: &str,
    ) -> String {
        let mut hasher = Sha256::new();
        hasher.update(auditor.as_bytes());
        hasher.update(b"\0");
        hasher.update(code.unwrap_or("").as_bytes());
        hasher.update(b"\0");
        hasher
            .update(file.map(|p| p.to_string_lossy().into_owned()).unwrap_or_default().as_bytes());
        hasher.update(b"\0");
        hasher.update(normalize_message(message).as_bytes());
        let digest = hasher.finalize();
        hex::encode(&digest[..8])
    }
}

fn normalize_message(message: &str) -> String {
    message.split_whitespace().collect::<Vec<_>>().join(" ").to_lowercase()
}

impl Ord for Finding {
    fn cmp(&self, other: &Self) -> Ordering {
        // Display order: severity (high first), then category, then file path, then message.
        self.severity
            .rank()
            .cmp(&other.severity.rank())
            .then_with(|| format!("{:?}", self.category).cmp(&format!("{:?}", other.category)))
            .then_with(|| {
                let l = self.location.as_ref().map(|l| l.file.to_string_lossy().into_owned());
                let r = other.location.as_ref().map(|l| l.file.to_string_lossy().into_owned());
                l.cmp(&r)
            })
            .then_with(|| self.message.cmp(&other.message))
    }
}

impl PartialOrd for Finding {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
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
    use std::path::PathBuf;

    #[test]
    fn fingerprint_stable_across_whitespace_changes() {
        let a = Finding::compute_fingerprint(
            "clippy",
            Some("clippy::unwrap_used"),
            None,
            "called `unwrap` on a `Result` value",
        );
        let b = Finding::compute_fingerprint(
            "clippy",
            Some("clippy::unwrap_used"),
            None,
            "Called   `unwrap`  on a  `Result`  value",
        );
        assert_eq!(a, b, "whitespace + case differences must not change the fingerprint");
    }

    #[test]
    fn fingerprint_stable_across_line_changes() {
        let path = PathBuf::from("src/lib.rs");
        let a = Finding::new("clippy", Category::Lints, Severity::Medium, "uses `unwrap`")
            .with_code("clippy::unwrap_used")
            .with_location(Location::at(&path, 42));
        let b = Finding::new("clippy", Category::Lints, Severity::Medium, "uses `unwrap`")
            .with_code("clippy::unwrap_used")
            .with_location(Location::at(&path, 999));
        assert_eq!(a.fingerprint, b.fingerprint, "line changes must not affect fingerprint");
    }

    #[test]
    fn fingerprint_changes_when_file_differs() {
        let a = Finding::new("clippy", Category::Lints, Severity::Medium, "uses `unwrap`")
            .with_code("clippy::unwrap_used")
            .with_location(Location::at("src/lib.rs", 42));
        let b = Finding::new("clippy", Category::Lints, Severity::Medium, "uses `unwrap`")
            .with_code("clippy::unwrap_used")
            .with_location(Location::at("src/main.rs", 42));
        assert_ne!(
            a.fingerprint, b.fingerprint,
            "different files must produce different fingerprints"
        );
    }

    #[test]
    fn severity_ordering_critical_first() {
        let mut findings = vec![
            Finding::new("a", Category::Lints, Severity::Low, "low"),
            Finding::new("a", Category::Lints, Severity::Critical, "critical"),
            Finding::new("a", Category::Lints, Severity::High, "high"),
            Finding::new("a", Category::Lints, Severity::Info, "info"),
            Finding::new("a", Category::Lints, Severity::Medium, "medium"),
        ];
        findings.sort();
        let order: Vec<_> = findings.iter().map(|f| f.severity).collect();
        assert_eq!(
            order,
            vec![
                Severity::Critical,
                Severity::High,
                Severity::Medium,
                Severity::Low,
                Severity::Info
            ]
        );
    }

    #[test]
    fn severity_weight_monotonic() {
        assert!(Severity::Critical.weight() > Severity::High.weight());
        assert!(Severity::High.weight() > Severity::Medium.weight());
        assert!(Severity::Medium.weight() > Severity::Low.weight());
        assert!(Severity::Low.weight() > Severity::Info.weight());
    }

    #[test]
    fn fingerprint_is_16_hex_chars() {
        let f = Finding::new("clippy", Category::Lints, Severity::Low, "x");
        assert_eq!(f.fingerprint.len(), 16);
        assert!(f.fingerprint.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn location_displays_file_line_col() {
        let l = Location::at_col("src/main.rs", 10, 5);
        assert_eq!(l.to_string(), "src/main.rs:10:5");
        let l2 = Location::at("src/main.rs", 10);
        assert_eq!(l2.to_string(), "src/main.rs:10");
        let l3 = Location::new("src/main.rs");
        assert_eq!(l3.to_string(), "src/main.rs");
    }
}
