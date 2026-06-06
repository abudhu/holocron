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
    /// Errors when the letter is present but malformed.
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

/// `[auditors]` — placeholder for #28.
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

/// `[[allowlist]]` — placeholder for #29.
#[derive(Debug, Default, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct AllowlistEntry {
    pub fingerprint: Option<String>,
    pub auditor: Option<String>,
    pub code: Option<String>,
    pub message_prefix: Option<String>,
    pub reason: Option<String>,
}

impl HolocronConfig {
    /// Walk up from `start_dir` looking for `.holocronrc.toml`. Returns
    /// `Ok(Default)` if none found. Parse errors are surfaced as-is.
    ///
    /// Also returns the resolved path the config was loaded from
    /// (`None` when defaults are used), so callers can quote it in
    /// error messages.
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
}
