//! `.holocronrc.toml` config loader.
//!
//! Schema mirrors the template shipped by `holocron init` (`#15`).
//! Holocron 0.2.x reads `[gate]` and `[complexity]` only — every other
//! section deserializes but is silently ignored. Future issues
//! (`#28`–`#30`) will wire the rest in. Unknown keys at any level are
//! tolerated for forward compatibility.
//!
//! Loading is lazy and explicit: `HolocronConfig::load_from(target_dir)`
//! walks up looking for a `.holocronrc.toml` (cargo-style) and returns
//! `Default` if none found. Parse errors short-circuit with an
//! `anyhow::Error` that names the file path so users can find the bad
//! line; TOML's own error already carries the column.
//!
//! ## Layering with CLI flags
//!
//! The CLI is responsible for the precedence rule (explicit flag > rc >
//! default). This module only loads + validates; it doesn't merge.

use crate::Letter;
use serde::Deserialize;
use std::path::{Path, PathBuf};
use std::str::FromStr;

/// Root config object. All sections are optional — missing means "use
/// the built-in defaults for that section".
#[derive(Debug, Default, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct HolocronConfig {
    pub gate: GateConfig,
    pub complexity: ComplexityConfig,
    // Placeholders for #28–#30. Deserialize but currently unused by the
    // runtime. They live here so users can pre-stage their preferences
    // and so the rc parser doesn't reject them as unknown fields.
    pub auditors: AuditorsConfig,
    pub weights: WeightsConfig,
    #[serde(rename = "allowlist", default)]
    pub allowlist: Vec<AllowlistEntry>,
}

/// `[gate]` — CI threshold (read by the CLI when `--fail-below` is
/// omitted).
#[derive(Debug, Default, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct GateConfig {
    /// Optional letter grade. Stored as `String` here so we can produce
    /// a useful parse error with the original input — `Letter` itself
    /// has no serde impl with positional context.
    pub fail_below: Option<String>,
}

impl GateConfig {
    /// Parse the stored letter, if any. Returns `Ok(None)` when unset.
    ///
    /// # Errors
    /// Returns an error when `fail_below` is set but does not parse as a
    /// valid letter grade. The error message names the bad input and
    /// lists the valid options so the user can correct their rc file.
    pub fn fail_below_letter(&self) -> anyhow::Result<Option<Letter>> {
        self.fail_below.as_deref().map_or(Ok(None), |s| {
            Letter::from_str(s.trim()).map(Some).map_err(|e| {
                anyhow::anyhow!(
                    "invalid `[gate] fail_below` letter `{s}`: {e}. \
                     Valid: A+, A, A-, B+, B, B-, C+, C, C-, D+, D, D-, F"
                )
            })
        })
    }
}

/// `[complexity]` — overrides for `ComplexityThresholds` in the
/// `rust-code-analysis` auditor.
///
/// Schema notes:
///   * `cyclomatic_medium` / `cognitive_medium` map to the auditor's
///     `*_warn` thresholds (renamed because "warn" is overloaded across
///     the codebase — severity is what matters to users, not internal
///     thresholding terminology).
///   * `cognitive_high` is reserved for a future change (the auditor's
///     `ComplexityThresholds` struct has only 3 fields today; adding a
///     fourth is in scope for a follow-up). Setting it in rc today is
///     accepted but has no effect — documented as such in the template.
#[derive(Debug, Default, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ComplexityConfig {
    pub cyclomatic_medium: Option<u32>,
    pub cyclomatic_high: Option<u32>,
    pub cognitive_medium: Option<u32>,
    /// Reserved for future wiring; deserialized but not yet consumed.
    /// See the `[complexity]` block in the rc template for status.
    pub cognitive_high: Option<u32>,
}

impl ComplexityConfig {
    /// Validate the rc values without applying them. Called by the CLI
    /// before audit so bad config fails fast with line context.
    ///
    /// # Errors
    /// Returns an error if `cyclomatic_high <= cyclomatic_medium` or
    /// either medium threshold is zero. Other invalid combinations
    /// (negative numbers) can't occur because the types are `u32`.
    pub fn validate(&self) -> anyhow::Result<()> {
        if let (Some(m), Some(h)) = (self.cyclomatic_medium, self.cyclomatic_high) {
            anyhow::ensure!(
                h > m,
                "[complexity] cyclomatic_high ({h}) must be greater than cyclomatic_medium ({m})"
            );
        }
        if let Some(m) = self.cyclomatic_medium {
            anyhow::ensure!(m > 0, "[complexity] cyclomatic_medium must be > 0");
        }
        if let Some(m) = self.cognitive_medium {
            anyhow::ensure!(m > 0, "[complexity] cognitive_medium must be > 0");
        }
        Ok(())
    }
}

/// `[auditors]` — toggle individual auditors on/off (#28, #32).
#[derive(Debug, Default, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct AuditorsConfig {
    pub clippy: Option<bool>,
    #[serde(rename = "cargo-audit")]
    pub cargo_audit: Option<bool>,
    #[serde(rename = "cargo-machete")]
    pub cargo_machete: Option<bool>,
    #[serde(rename = "cargo-deny")]
    pub cargo_deny: Option<bool>,
    #[serde(rename = "cargo-outdated")]
    pub cargo_outdated: Option<bool>,
    #[serde(rename = "cargo-geiger")]
    pub cargo_geiger: Option<bool>,
    /// Opt-in mutation testing (#32). Not run by default; even when
    /// set to `true` here, the CLI's `--with-mutants` flag must also
    /// be passed for cargo-mutants to be added to the audit set.
    /// Setting this to `false` is the explicit kill switch (e.g. in
    /// a project rc) so it won't run even if a user passes
    /// `--with-mutants`.
    #[serde(rename = "cargo-mutants")]
    pub cargo_mutants: Option<bool>,
    #[serde(rename = "rust-code-analysis")]
    pub rust_code_analysis: Option<bool>,
}

/// `[weights]` — placeholder for #30.
#[derive(Debug, Default, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct WeightsConfig {
    pub security: Option<f64>,
    pub lints: Option<f64>,
    pub complexity: Option<f64>,
    pub dead_code: Option<f64>,
    pub maintenance: Option<f64>,
}

/// `[[allowlist]]` — suppress specific findings by fingerprint, auditor,
/// code, message prefix, and/or file path (#29).
///
/// A finding is allowlisted when EVERY specified field matches it.
/// At least one match field must be set (a completely empty entry
/// would otherwise suppress all findings — the loader rejects those
/// at validation time). `reason` is for human/audit purposes and is
/// echoed back in the report's "Allowlisted Findings" section.
///
/// Path matching is a simple substring check (case-sensitive) — full
/// glob support can come later if there's demand. Substring is enough
/// for the common case ("crates/holocron-core/src/grade.rs").
#[derive(Debug, Default, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct AllowlistEntry {
    /// 16-char hex fingerprint copied from `holocron explain` output or
    /// the JSON sidecar. Most precise way to suppress a single finding.
    pub fingerprint: Option<String>,
    /// Auditor tool name, e.g. "clippy", "cargo-audit", "rust-code-analysis".
    pub auditor: Option<String>,
    /// Lint/rule code, e.g. `clippy::missing_errors_doc`,
    /// `RUSTSEC-2024-0001`, `complexity-warn`.
    pub code: Option<String>,
    /// Message must START WITH this string (case-sensitive). Useful for
    /// catch-all clippy lints with parameterized messages.
    pub message_prefix: Option<String>,
    /// File path must CONTAIN this substring (case-sensitive). E.g.
    /// `path = "crates/holocron-core/src/grade.rs"` or
    /// `path = "tests/"` to allowlist a whole directory.
    pub path: Option<String>,
    /// Required human-readable rationale. Echoed in the report.
    pub reason: Option<String>,
}

impl AllowlistEntry {
    /// Returns true when this entry has no match fields set (would
    /// suppress everything). Loader-time validation rejects such entries.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.fingerprint.is_none()
            && self.auditor.is_none()
            && self.code.is_none()
            && self.message_prefix.is_none()
            && self.path.is_none()
    }

    /// Does this rule match the given finding? Match semantic: AND
    /// across every specified field. An entry with only `auditor =
    /// "clippy"` matches any clippy finding; an entry with both
    /// `auditor = "clippy"` and `code = "clippy::unwrap_used"` matches
    /// only clippy `unwrap_used` findings; etc.
    #[must_use]
    pub fn matches(&self, f: &crate::Finding) -> bool {
        match_fingerprint(self.fingerprint.as_deref(), &f.fingerprint)
            && match_auditor(self.auditor.as_deref(), &f.auditor)
            && match_code(self.code.as_deref(), f.code.as_deref())
            && match_message_prefix(self.message_prefix.as_deref(), &f.message)
            && match_path(self.path.as_deref(), f.location.as_ref())
    }
}

// ── per-field match helpers ────────────────────────────────────────
// Each returns true when the rule's field passes (either unset, or
// set and matching the finding's value). Extracted from
// `AllowlistEntry::matches` to keep its cyclomatic complexity below
// threshold (#29 path / fix for the regression #29 introduced).

fn match_fingerprint(rule: Option<&str>, finding: &str) -> bool {
    rule.is_none_or(|fp| fp == finding)
}

fn match_auditor(rule: Option<&str>, finding: &str) -> bool {
    rule.is_none_or(|a| a == finding)
}

fn match_code(rule: Option<&str>, finding: Option<&str>) -> bool {
    // Exact match against the optional code field. None on either
    // side when the rule specifies one means no match (you can't
    // allowlist by code a finding that has no code).
    rule.is_none_or(|c| finding == Some(c))
}

fn match_message_prefix(rule: Option<&str>, finding: &str) -> bool {
    rule.is_none_or(|mp| finding.starts_with(mp))
}

fn match_path(rule: Option<&str>, finding: Option<&crate::Location>) -> bool {
    // Substring against the location's file path. None on either side
    // when the rule specifies one means no match — intentional, prevents
    // accidental suppression of project-wide CVE findings.
    rule.is_none_or(|p| finding.is_some_and(|loc| loc.file.to_string_lossy().contains(p)))
}

/// Apply allowlist rules to a set of findings in place.
///
/// Each finding is marked `allowlisted = true` and gets `allowlist_reason`
/// populated with the matching rule's `reason` (or a default explanation
/// when the rule omitted one). Findings already allowlisted by an earlier
/// rule are skipped — first match wins, so listing more specific rules
/// first preserves their reasons.
///
/// Returns the count of findings that were newly allowlisted.
pub fn apply_allowlist(findings: &mut [crate::Finding], rules: &[AllowlistEntry]) -> usize {
    let mut count = 0_usize;
    for finding in findings.iter_mut() {
        if finding.allowlisted {
            continue;
        }
        for rule in rules {
            if rule.matches(finding) {
                finding.allowlisted = true;
                finding.allowlist_reason = Some(
                    rule.reason.clone().unwrap_or_else(|| "matched [[allowlist]] rule".to_string()),
                );
                count += 1;
                break;
            }
        }
    }
    count
}

impl HolocronConfig {
    /// Walk up from `start_dir` looking for `.holocronrc.toml`. Returns
    /// `Ok(Default)` if none found. Parse errors are surfaced as-is.
    ///
    /// Also returns the resolved path the config was loaded from
    /// (`None` when defaults are used), so callers can quote it in
    /// error messages.
    ///
    /// # Errors
    /// Returns an error if the rc file is present but unreadable
    /// (permission, IO), unparseable as TOML (malformed syntax,
    /// unknown fields), or contains an invalid `[gate].fail_below`
    /// letter or out-of-range `[complexity]` threshold. Errors quote
    /// the file path so users can find the bad line.
    pub fn load_from(start_dir: &Path) -> anyhow::Result<(Self, Option<PathBuf>)> {
        let Some(path) = find_rc(start_dir) else {
            return Ok((Self::default(), None));
        };
        let body = std::fs::read_to_string(&path)
            .map_err(|e| anyhow::anyhow!("reading {}: {e}", path.display()))?;
        let cfg: Self = toml::from_str(&body)
            .map_err(|e| anyhow::anyhow!("parsing {}: {e}", path.display()))?;
        cfg.complexity
            .validate()
            .map_err(|e| anyhow::anyhow!("invalid [complexity] in {}: {e}", path.display()))?;
        // Validate gate eagerly too so the user sees the error before
        // audit spends 30s spinning up.
        cfg.gate
            .fail_below_letter()
            .map_err(|e| anyhow::anyhow!("invalid [gate] in {}: {e}", path.display()))?;
        // Validate allowlist: every entry needs at least one match
        // field (#29). An empty entry would suppress every finding.
        for (i, entry) in cfg.allowlist.iter().enumerate() {
            if entry.is_empty() {
                return Err(anyhow::anyhow!(
                    "invalid [[allowlist]] entry #{} in {}: at least one of \
                     fingerprint, auditor, code, message_prefix, or path must be set",
                    i + 1,
                    path.display()
                ));
            }
        }
        Ok((cfg, Some(path)))
    }
}

/// Cargo-style walk-up: check the current dir, then each ancestor.
fn find_rc(start: &Path) -> Option<PathBuf> {
    let mut here = start.to_path_buf();
    loop {
        let candidate = here.join(".holocronrc.toml");
        if candidate.is_file() {
            return Some(candidate);
        }
        if !here.pop() {
            return None;
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;
    use crate::{Category, Finding, Location, Severity};
    use tempfile::TempDir;

    fn write_rc(dir: &Path, body: &str) -> PathBuf {
        let p = dir.join(".holocronrc.toml");
        std::fs::write(&p, body).unwrap();
        p
    }

    #[test]
    fn missing_rc_returns_default() {
        let d = TempDir::new().unwrap();
        let (cfg, path) = HolocronConfig::load_from(d.path()).unwrap();
        assert!(path.is_none());
        assert!(cfg.gate.fail_below.is_none());
        assert!(cfg.complexity.cyclomatic_medium.is_none());
    }

    #[test]
    fn empty_rc_returns_default() {
        let d = TempDir::new().unwrap();
        let p = write_rc(d.path(), "");
        let (cfg, path) = HolocronConfig::load_from(d.path()).unwrap();
        assert_eq!(path.as_deref(), Some(p.as_path()));
        assert!(cfg.gate.fail_below.is_none());
    }

    #[test]
    fn rc_gate_fail_below_parses_to_letter() {
        let d = TempDir::new().unwrap();
        write_rc(d.path(), "[gate]\nfail_below = \"B-\"\n");
        let (cfg, _) = HolocronConfig::load_from(d.path()).unwrap();
        assert_eq!(cfg.gate.fail_below_letter().unwrap(), Some(Letter::BMinus));
    }

    #[test]
    fn rc_gate_fail_below_unicode_minus_works() {
        let d = TempDir::new().unwrap();
        // Unicode minus, not ASCII dash
        write_rc(d.path(), "[gate]\nfail_below = \"A−\"\n");
        let (cfg, _) = HolocronConfig::load_from(d.path()).unwrap();
        assert_eq!(cfg.gate.fail_below_letter().unwrap(), Some(Letter::AMinus));
    }

    #[test]
    fn rc_gate_fail_below_invalid_letter_errors_at_load() {
        let d = TempDir::new().unwrap();
        write_rc(d.path(), "[gate]\nfail_below = \"ZZZ\"\n");
        let err = HolocronConfig::load_from(d.path()).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("ZZZ"), "error should quote the bad letter, got: {msg}");
        assert!(msg.contains(".holocronrc.toml"), "error should name the file, got: {msg}");
    }

    #[test]
    fn rc_complexity_thresholds_parse() {
        let d = TempDir::new().unwrap();
        write_rc(
            d.path(),
            "
                [complexity]
                cyclomatic_medium = 10
                cyclomatic_high = 20
                cognitive_medium = 15
            ",
        );
        let (cfg, _) = HolocronConfig::load_from(d.path()).unwrap();
        assert_eq!(cfg.complexity.cyclomatic_medium, Some(10));
        assert_eq!(cfg.complexity.cyclomatic_high, Some(20));
        assert_eq!(cfg.complexity.cognitive_medium, Some(15));
    }

    #[test]
    fn rc_complexity_high_must_exceed_medium() {
        let d = TempDir::new().unwrap();
        write_rc(d.path(), "[complexity]\ncyclomatic_medium = 25\ncyclomatic_high = 15\n");
        let err = HolocronConfig::load_from(d.path()).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("greater than"), "got: {msg}");
    }

    #[test]
    fn rc_complexity_zero_threshold_errors() {
        let d = TempDir::new().unwrap();
        write_rc(d.path(), "[complexity]\ncyclomatic_medium = 0\n");
        let err = HolocronConfig::load_from(d.path()).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("> 0"), "got: {msg}");
    }

    #[test]
    fn walks_up_to_find_rc() {
        let d = TempDir::new().unwrap();
        let nested = d.path().join("crates").join("foo");
        std::fs::create_dir_all(&nested).unwrap();
        write_rc(d.path(), "[gate]\nfail_below = \"A-\"\n");
        let (cfg, path) = HolocronConfig::load_from(&nested).unwrap();
        assert!(path.as_ref().is_some_and(|p| p.starts_with(d.path())));
        assert_eq!(cfg.gate.fail_below_letter().unwrap(), Some(Letter::AMinus));
    }

    #[test]
    fn unknown_top_level_section_rejected() {
        // deny_unknown_fields catches typos at every level.
        let d = TempDir::new().unwrap();
        write_rc(d.path(), "[gait]\nfail_below = \"A-\"\n");
        let err = HolocronConfig::load_from(d.path()).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("gait") || msg.contains("unknown field"), "got: {msg}");
    }

    #[test]
    fn placeholder_sections_still_parse_for_forward_compat() {
        let d = TempDir::new().unwrap();
        write_rc(
            d.path(),
            r#"
                [auditors]
                cargo-geiger = false

                [weights]
                security = 0.5

                [[allowlist]]
                fingerprint = "deadbeefdeadbeef"
                reason = "false positive"
            "#,
        );
        let (cfg, _) = HolocronConfig::load_from(d.path()).unwrap();
        assert_eq!(cfg.auditors.cargo_geiger, Some(false));
        assert_eq!(cfg.weights.security, Some(0.5));
        assert_eq!(cfg.allowlist.len(), 1);
        assert_eq!(cfg.allowlist[0].fingerprint.as_deref(), Some("deadbeefdeadbeef"));
    }

    #[test]
    fn full_template_round_trips() {
        // The template shipped by `holocron init` should always parse.
        // Loosely: any uncommented subset must round-trip without error.
        let d = TempDir::new().unwrap();
        write_rc(
            d.path(),
            r#"
                [gate]
                fail_below = "A-"

                [auditors]
                clippy = true
                cargo-audit = true
                cargo-machete = true
                cargo-deny = true
                cargo-outdated = true
                cargo-geiger = true
                rust-code-analysis = true

                [complexity]
                cyclomatic_medium = 15
                cyclomatic_high = 25
                cognitive_medium = 20
                cognitive_high = 35

                [weights]
                security = 0.30
                lints = 0.20
                complexity = 0.20
                dead_code = 0.15
                maintenance = 0.15
            "#,
        );
        let (cfg, _) = HolocronConfig::load_from(d.path()).unwrap();
        assert_eq!(cfg.gate.fail_below_letter().unwrap(), Some(Letter::AMinus));
        assert_eq!(cfg.complexity.cyclomatic_medium, Some(15));
        assert_eq!(cfg.weights.maintenance, Some(0.15));
    }

    // ─── #29 allowlist tests ──────────────────────────────────────

    fn finding_for_test(
        auditor: &str,
        code: Option<&str>,
        msg: &str,
        path: Option<&str>,
    ) -> Finding {
        let mut f = Finding::new(auditor, Category::Lints, Severity::Medium, msg);
        if let Some(c) = code {
            f = f.with_code(c);
        }
        if let Some(p) = path {
            f = f.with_location(Location::at(p, 1));
        }
        f
    }

    #[test]
    fn allowlist_empty_entry_rejected_at_load() {
        let d = TempDir::new().unwrap();
        write_rc(d.path(), "[[allowlist]]\nreason = \"oops, no match fields\"\n");
        let err = HolocronConfig::load_from(d.path()).unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("at least one of"), "got: {msg}");
        assert!(msg.contains("allowlist"));
    }

    #[test]
    fn allowlist_loads_with_one_field_set() {
        let d = TempDir::new().unwrap();
        write_rc(d.path(), "[[allowlist]]\nauditor = \"clippy\"\nreason = \"intentional\"\n");
        let (cfg, _) = HolocronConfig::load_from(d.path()).unwrap();
        assert_eq!(cfg.allowlist.len(), 1);
        assert_eq!(cfg.allowlist[0].auditor.as_deref(), Some("clippy"));
    }

    #[test]
    fn matches_by_auditor_alone() {
        let rule =
            AllowlistEntry { auditor: Some("clippy".to_string()), ..AllowlistEntry::default() };
        let f = finding_for_test("clippy", Some("clippy::unwrap_used"), "x", None);
        assert!(rule.matches(&f));
        let f2 = finding_for_test("cargo-audit", None, "x", None);
        assert!(!rule.matches(&f2));
    }

    #[test]
    fn matches_by_code_alone() {
        let rule = AllowlistEntry {
            code: Some("complexity-warn".to_string()),
            ..AllowlistEntry::default()
        };
        let f = finding_for_test("rust-code-analysis", Some("complexity-warn"), "x", None);
        assert!(rule.matches(&f));
        let f2 = finding_for_test("clippy", Some("clippy::unwrap_used"), "x", None);
        assert!(!rule.matches(&f2));
    }

    #[test]
    fn matches_requires_all_specified_fields() {
        // auditor + code both set -> only finding matching BOTH passes.
        let rule = AllowlistEntry {
            auditor: Some("clippy".to_string()),
            code: Some("clippy::unwrap_used".to_string()),
            ..AllowlistEntry::default()
        };
        let f_match = finding_for_test("clippy", Some("clippy::unwrap_used"), "x", None);
        let f_wrong_code = finding_for_test("clippy", Some("clippy::expect_used"), "x", None);
        let f_wrong_aud =
            finding_for_test("rust-code-analysis", Some("clippy::unwrap_used"), "x", None);
        assert!(rule.matches(&f_match));
        assert!(!rule.matches(&f_wrong_code));
        assert!(!rule.matches(&f_wrong_aud));
    }

    #[test]
    fn matches_path_substring() {
        let rule = AllowlistEntry { path: Some("tests/".to_string()), ..AllowlistEntry::default() };
        let f_in = finding_for_test("clippy", None, "x", Some("crates/foo/tests/it.rs"));
        let f_out = finding_for_test("clippy", None, "x", Some("crates/foo/src/lib.rs"));
        let f_noloc = finding_for_test("clippy", None, "x", None);
        assert!(rule.matches(&f_in));
        assert!(!rule.matches(&f_out));
        // Path rule against a finding with no location => no match.
        assert!(!rule.matches(&f_noloc));
    }

    #[test]
    fn apply_allowlist_marks_matched_and_returns_count() {
        let mut findings = vec![
            finding_for_test("clippy", Some("clippy::unwrap_used"), "msg1", Some("src/a.rs")),
            finding_for_test("clippy", Some("clippy::expect_used"), "msg2", Some("src/b.rs")),
            finding_for_test("cargo-audit", Some("RUSTSEC-2024-0001"), "vuln", None),
        ];
        let rules = vec![AllowlistEntry {
            auditor: Some("clippy".to_string()),
            code: Some("clippy::unwrap_used".to_string()),
            reason: Some("intentional in this module".to_string()),
            ..AllowlistEntry::default()
        }];
        let count = apply_allowlist(&mut findings, &rules);
        assert_eq!(count, 1);
        assert!(findings[0].allowlisted);
        assert_eq!(findings[0].allowlist_reason.as_deref(), Some("intentional in this module"));
        assert!(!findings[1].allowlisted);
        assert!(!findings[2].allowlisted);
    }

    #[test]
    fn apply_allowlist_first_match_wins() {
        // Two rules both match the same finding; first wins, second
        // never fires (no count, no reason override).
        let mut findings =
            vec![finding_for_test("clippy", Some("clippy::unwrap_used"), "msg", None)];
        let rules = vec![
            AllowlistEntry {
                auditor: Some("clippy".to_string()),
                reason: Some("first rule".to_string()),
                ..AllowlistEntry::default()
            },
            AllowlistEntry {
                code: Some("clippy::unwrap_used".to_string()),
                reason: Some("second rule".to_string()),
                ..AllowlistEntry::default()
            },
        ];
        let count = apply_allowlist(&mut findings, &rules);
        assert_eq!(count, 1);
        assert_eq!(findings[0].allowlist_reason.as_deref(), Some("first rule"));
    }

    #[test]
    fn apply_allowlist_default_reason_when_rule_omits_it() {
        let mut findings = vec![finding_for_test("clippy", None, "msg", None)];
        let rules = vec![AllowlistEntry {
            auditor: Some("clippy".to_string()),
            ..AllowlistEntry::default()
        }];
        apply_allowlist(&mut findings, &rules);
        assert_eq!(findings[0].allowlist_reason.as_deref(), Some("matched [[allowlist]] rule"));
    }
}
