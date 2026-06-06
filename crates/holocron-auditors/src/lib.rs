//! Holocron's external-tool auditors. Each module wraps one CLI tool
//! and exposes a struct implementing [`holocron_core::Auditor`].
//!
//! See `OneDev` issues #4–#7, #16, #18 for the per-auditor design notes.

pub mod clippy;
pub mod deny;
pub mod geiger;
pub mod machete;
pub mod mutants;
pub mod outdated;
pub mod runners;
pub mod rust_code_analysis;
pub mod rustsec;

pub use clippy::ClippyAuditor;
pub use deny::DenyAuditor;
pub use geiger::GeigerAuditor;
pub use machete::MacheteAuditor;
pub use mutants::MutantsAuditor;
pub use outdated::OutdatedAuditor;
pub use rust_code_analysis::{ComplexityAuditor, ComplexityThresholds};
pub use rustsec::RustSecAuditor;

use std::sync::Arc;

use holocron_core::AuditorResult;

/// The default v0.2 auditor set with no config-driven overrides.
/// Equivalent to [`default_set_with_thresholds`] called with
/// [`ComplexityThresholds::default()`].
#[must_use]
pub fn default_set() -> Vec<Arc<dyn holocron_core::Auditor>> {
    default_set_with_thresholds(ComplexityThresholds::default())
}

/// The default v0.2 auditor set with caller-provided complexity
/// thresholds. The CLI layer derives `thresholds` from
/// `.holocronrc.toml`'s `[complexity]` section (`#31`).
///
/// `cargo-mutants` is NOT included by default — it's opt-in via
/// [`default_set_partitioned`] with `include_mutants = true`.
/// Rationale (#32): cargo-mutants takes 30min-many-hours on real
/// workspaces and isn't appropriate for every audit.
#[must_use]
pub fn default_set_with_thresholds(
    thresholds: ComplexityThresholds,
) -> Vec<Arc<dyn holocron_core::Auditor>> {
    vec![
        Arc::new(ClippyAuditor { extra_warn_flags: vec![] }),
        Arc::new(RustSecAuditor),
        Arc::new(MacheteAuditor),
        Arc::new(ComplexityAuditor { thresholds }),
        Arc::new(DenyAuditor),
        Arc::new(OutdatedAuditor),
        Arc::new(GeigerAuditor),
    ]
}

/// Partition the default set against an `[auditors]` rc section.
///
/// Returns:
///   * `enabled`: auditors the runner should execute (rc set them to
///     `true` or didn't mention them — opt-out, not opt-in).
///   * `disabled`: synthetic Skipped results for the auditors the rc
///     turned off, ready to splice into the `RunOutcome`. The grader
///     will mark each affected category as Skipped.
///
/// When `include_mutants` is true, the cargo-mutants auditor is added
/// to the candidate set before partitioning. It still respects the rc
/// `[auditors].cargo-mutants = false` opt-out (#32).
///
/// CLI usage:
/// ```ignore
/// let (enabled, disabled) = default_set_partitioned(thresholds, &rc.auditors, args.with_mutants);
/// for a in enabled { runner = runner.with_auditor(a); }
/// let mut outcome = runner.run().await?;
/// outcome.auditor_results.extend(disabled);
/// ```
#[must_use]
pub fn default_set_partitioned(
    thresholds: ComplexityThresholds,
    rc: &holocron_core::AuditorsConfig,
    include_mutants: bool,
) -> (Vec<Arc<dyn holocron_core::Auditor>>, Vec<AuditorResult>) {
    let mut all = default_set_with_thresholds(thresholds);
    if include_mutants {
        all.push(Arc::new(MutantsAuditor));
    }
    let mut enabled: Vec<Arc<dyn holocron_core::Auditor>> = Vec::with_capacity(all.len());
    let mut disabled: Vec<AuditorResult> = Vec::new();
    for a in all {
        let meta = a.meta();
        if is_disabled(meta.name, rc) {
            disabled.push(AuditorResult::skipped_disabled(meta));
        } else {
            enabled.push(a);
        }
    }
    (enabled, disabled)
}

/// Returns true when the rc explicitly disables the named auditor.
/// Missing keys default to enabled (opt-out semantic).
fn is_disabled(name: &str, rc: &holocron_core::AuditorsConfig) -> bool {
    let key = match name {
        "clippy" => rc.clippy,
        "cargo-audit" => rc.cargo_audit,
        "cargo-machete" => rc.cargo_machete,
        "cargo-deny" => rc.cargo_deny,
        "cargo-outdated" => rc.cargo_outdated,
        "cargo-geiger" => rc.cargo_geiger,
        "cargo-mutants" => rc.cargo_mutants,
        "rust-code-analysis" => rc.rust_code_analysis,
        _ => return false, // unknown auditor name — never disable by accident
    };
    matches!(key, Some(false))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use holocron_core::{AuditorsConfig, RunStatus};

    fn rc_with_disabled(names: &[&str]) -> AuditorsConfig {
        let mut rc = AuditorsConfig::default();
        for n in names {
            match *n {
                "clippy" => rc.clippy = Some(false),
                "cargo-audit" => rc.cargo_audit = Some(false),
                "cargo-machete" => rc.cargo_machete = Some(false),
                "cargo-deny" => rc.cargo_deny = Some(false),
                "cargo-outdated" => rc.cargo_outdated = Some(false),
                "cargo-geiger" => rc.cargo_geiger = Some(false),
                "rust-code-analysis" => rc.rust_code_analysis = Some(false),
                other => panic!("unknown auditor name in test: {other}"),
            }
        }
        rc
    }
    #[test]
    fn default_partition_with_empty_rc_enables_all_seven() {
        let (enabled, disabled) = default_set_partitioned(
            ComplexityThresholds::default(),
            &AuditorsConfig::default(),
            false,
        );
        assert_eq!(enabled.len(), 7);
        assert!(disabled.is_empty());
    }

    #[test]
    fn rc_disable_drops_auditor_from_enabled_list() {
        let rc = rc_with_disabled(&["cargo-geiger"]);
        let (enabled, disabled) =
            default_set_partitioned(ComplexityThresholds::default(), &rc, false);
        assert_eq!(enabled.len(), 6);
        assert_eq!(disabled.len(), 1);
        assert_eq!(disabled[0].auditor, "cargo-geiger");
        assert_eq!(disabled[0].status, RunStatus::SkippedDisabled);
        assert!(disabled[0].error.as_deref().unwrap().contains(".holocronrc.toml"));
    }

    #[test]
    fn rc_explicit_true_does_not_disable() {
        // cargo-geiger = true should keep it enabled (opt-out semantic;
        // explicit true is the same as missing).
        let rc = AuditorsConfig { cargo_geiger: Some(true), ..AuditorsConfig::default() };
        let (enabled, disabled) =
            default_set_partitioned(ComplexityThresholds::default(), &rc, false);
        assert_eq!(enabled.len(), 7);
        assert!(disabled.is_empty());
    }

    #[test]
    fn rc_disabling_all_seven_yields_empty_enabled() {
        let rc = rc_with_disabled(&[
            "clippy",
            "cargo-audit",
            "cargo-machete",
            "cargo-deny",
            "cargo-outdated",
            "cargo-geiger",
            "rust-code-analysis",
        ]);
        let (enabled, disabled) =
            default_set_partitioned(ComplexityThresholds::default(), &rc, false);
        assert!(enabled.is_empty());
        assert_eq!(disabled.len(), 7);
        for r in &disabled {
            assert_eq!(r.status, RunStatus::SkippedDisabled);
        }
    }
}
