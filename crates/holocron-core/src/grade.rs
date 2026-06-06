//! Grade calculator — synthesizes a weighted letter grade from a set of
//! findings + auditor results.
//!
//! The grading philosophy is intentionally opinionated. The goal is a
//! single readable signal ("B−"), not statistical purity.

use crate::auditor::{AuditorResult, RunStatus};
use crate::finding::Category;
use serde::{Deserialize, Serialize};
use std::fmt;

/// Letter grade. Stored as an enum so `Ord` is the natural order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum Letter {
    F,
    DMinus,
    D,
    DPlus,
    CMinus,
    C,
    CPlus,
    BMinus,
    B,
    BPlus,
    AMinus,
    A,
    APlus,
}

impl Letter {
    /// Map a 0.0–1.0 score to a letter grade. Cutoffs follow a
    /// standard US academic curve.
    #[must_use]
    pub fn from_score(score: f64) -> Self {
        let s = score.clamp(0.0, 1.0);
        // Standard cutoffs (slightly compressed at the top).
        if s >= 0.97 {
            Self::APlus
        } else if s >= 0.93 {
            Self::A
        } else if s >= 0.90 {
            Self::AMinus
        } else if s >= 0.87 {
            Self::BPlus
        } else if s >= 0.83 {
            Self::B
        } else if s >= 0.80 {
            Self::BMinus
        } else if s >= 0.77 {
            Self::CPlus
        } else if s >= 0.73 {
            Self::C
        } else if s >= 0.70 {
            Self::CMinus
        } else if s >= 0.67 {
            Self::DPlus
        } else if s >= 0.63 {
            Self::D
        } else if s >= 0.60 {
            Self::DMinus
        } else {
            Self::F
        }
    }

    /// Returns true if the grade is C− or better. Used as the default
    /// CI gate threshold by `holocron audit`.
    #[must_use]
    pub const fn is_passing(self) -> bool {
        matches!(
            self,
            Self::A
                | Self::APlus
                | Self::AMinus
                | Self::BPlus
                | Self::B
                | Self::BMinus
                | Self::CPlus
                | Self::C
                | Self::CMinus
        )
    }
}

impl fmt::Display for Letter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::APlus => "A+",
            Self::A => "A",
            Self::AMinus => "A−",
            Self::BPlus => "B+",
            Self::B => "B",
            Self::BMinus => "B−",
            Self::CPlus => "C+",
            Self::C => "C",
            Self::CMinus => "C−",
            Self::DPlus => "D+",
            Self::D => "D",
            Self::DMinus => "D−",
            Self::F => "F",
        };
        f.write_str(s)
    }
}

impl std::str::FromStr for Letter {
    type Err = String;

    /// Parse a letter grade. Accepts both ASCII `-` and the proper Unicode
    /// minus sign `−` (which is what [`Display`] emits) so users can
    /// round-trip `--fail-below "$(holocron audit --print-grade)"` without
    /// shell-escaping worries.
    // holocron: ignore complexity-warn -- 13-arm dispatch table by design (one arm per grade letter A+ through F). Splitting adds indirection without reducing essential complexity.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // Normalize: trim, collapse the Unicode minus to ASCII '-', uppercase.
        let normalized = s.trim().replace('\u{2212}', "-").to_ascii_uppercase();
        match normalized.as_str() {
            "A+" => Ok(Self::APlus),
            "A" => Ok(Self::A),
            "A-" => Ok(Self::AMinus),
            "B+" => Ok(Self::BPlus),
            "B" => Ok(Self::B),
            "B-" => Ok(Self::BMinus),
            "C+" => Ok(Self::CPlus),
            "C" => Ok(Self::C),
            "C-" => Ok(Self::CMinus),
            "D+" => Ok(Self::DPlus),
            "D" => Ok(Self::D),
            "D-" => Ok(Self::DMinus),
            "F" => Ok(Self::F),
            other => Err(format!(
                "unknown grade '{other}' — expected one of A+, A, A-, B+, B, B-, C+, C, C-, D+, D, D-, F"
            )),
        }
    }
}

/// Per-category outcome — either a real measurement or a documented absence.
///
/// The two variants exist so failed auditors don't silently grade as
/// the old `0.85` fallback. `Graded` carries the score; `Skipped`
/// carries a reason (the auditor failed, timed out, or wasn't
/// installed). See #24.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum CategoryScore {
    Graded { category: Category, score: f64, letter: Letter, finding_count: usize },
    Skipped { category: Category, reason: String },
}

impl CategoryScore {
    /// The category this score is for. Works for both variants so
    /// callers can iterate without matching when they only need the
    /// label (e.g. for rendering a row in order).
    #[must_use]
    pub const fn category(&self) -> Category {
        match self {
            Self::Graded { category, .. } | Self::Skipped { category, .. } => *category,
        }
    }

    #[must_use]
    pub const fn is_skipped(&self) -> bool {
        matches!(self, Self::Skipped { .. })
    }
}

/// Aggregate grade report for one audit run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GradeReport {
    pub overall_score: f64,
    pub overall_letter: Letter,
    pub by_category: Vec<CategoryScore>,
}

impl GradeReport {
    /// True if at least one category surfaced as `Skipped` — meaning an
    /// auditor failed/timed-out/was-missing and we have no measurement
    /// for it. The CLI uses this to set a distinct exit code so
    /// "tooling broken" stays distinguishable from "code regressed".
    #[must_use]
    pub fn any_skipped(&self) -> bool {
        self.by_category.iter().any(CategoryScore::is_skipped)
    }
}

/// Compute a grade report from a set of auditor results.
pub struct Grade<'a> {
    results: &'a [AuditorResult],
    weights: [(Category, f64); 5],
}

impl<'a> Grade<'a> {
    /// Default weights for each category in the overall score. Sums to
    /// 1.0. Security dominates because a CVE is a more existential risk
    /// than a complexity hotspot.
    ///
    /// Override at runtime via [`Grade::with_weights`] — the CLI wires
    /// `.holocronrc.toml`'s `[weights]` section through this path (#30).
    pub const CATEGORY_WEIGHTS: [(Category, f64); 5] = [
        (Category::Security, 0.30),
        (Category::Lints, 0.20),
        (Category::Complexity, 0.20),
        (Category::DeadCode, 0.15),
        (Category::Maintenance, 0.15),
    ];

    #[must_use]
    pub const fn new(results: &'a [AuditorResult]) -> Self {
        Self { results, weights: Self::CATEGORY_WEIGHTS }
    }

    /// Override the per-category weights (e.g. from
    /// `.holocronrc.toml`'s `[weights]` section). Weights need not sum
    /// to 1.0 — the renormalization in [`Grade::compute`] (originally
    /// for skipped categories) handles any positive scale. Callers
    /// SHOULD warn the user when the sum drifts far from 1.0 since the
    /// reported overall is then on a non-intuitive scale.
    #[must_use]
    pub const fn with_weights(mut self, weights: [(Category, f64); 5]) -> Self {
        self.weights = weights;
        self
    }

    /// Compute the full grade report.
    ///
    /// Overall score is a weighted average over only the `Graded`
    /// categories — skipped ones drop out and the remaining weights are
    /// renormalized. Rationale: a tooling outage shouldn't silently
    /// degrade a clean codebase's grade. If every category is skipped
    /// (no auditors ran at all), overall is 0.0 (F); the CLI surfaces
    /// that separately via `any_skipped()` + exit code 3.
    #[must_use]
    pub fn compute(&self) -> GradeReport {
        let by_category: Vec<CategoryScore> =
            Category::ALL.iter().map(|&cat| self.category_score(cat)).collect();

        let (weighted_sum, total_weight) =
            self.weights.iter().fold((0.0_f64, 0.0_f64), |(s, w), (cat, weight)| {
                by_category.iter().find(|cs| cs.category() == *cat).map_or((s, w), |cs| match cs {
                    CategoryScore::Graded { score, .. } => (s + score * weight, w + weight),
                    CategoryScore::Skipped { .. } => (s, w),
                })
            });

        let overall_score = if total_weight > 0.0 { weighted_sum / total_weight } else { 0.0 };

        GradeReport {
            overall_score,
            overall_letter: Letter::from_score(overall_score),
            by_category,
        }
    }

    fn category_score(&self, category: Category) -> CategoryScore {
        // If an auditor that owns this category failed / timed out /
        // wasn't installed, surface it as Skipped — NOT as a graded
        // fallback. Was #24: the old 0.85 fallback silently masked
        // tooling outages as code-quality signal.
        //
        // SPECIAL CASE for #28: a SkippedDisabled (user intent — they
        // disabled this auditor in rc) does NOT block the category if
        // ANOTHER auditor for the same category produced Ok results.
        // Intent != outage. Only when ALL auditors for a category are
        // degraded (or disabled) does the category become Skipped.
        let has_ok = self
            .results
            .iter()
            .any(|r| r.category == category && matches!(r.status, RunStatus::Ok));
        let degraded = self.results.iter().find(|r| {
            r.category == category
                && matches!(
                    r.status,
                    RunStatus::Failed
                        | RunStatus::TimedOut
                        | RunStatus::SkippedMissing
                        | RunStatus::SkippedDisabled
                )
                // SkippedDisabled is intent — only matters if no other
                // auditor for the category produced Ok results.
                && !(matches!(r.status, RunStatus::SkippedDisabled) && has_ok)
        });
        if let Some(r) = degraded {
            return CategoryScore::Skipped {
                category,
                reason: r
                    .error
                    .clone()
                    .unwrap_or_else(|| format!("auditor {} reported {:?}", r.auditor, r.status)),
            };
        }

        let findings: Vec<_> = self
            .results
            .iter()
            .flat_map(|r| r.findings.iter())
            .filter(|f| f.category == category)
            .collect();
        // #29: allowlisted findings still surface in the report but
        // don't affect the grade. Filter them out of both the count
        // and the penalty.
        let active: Vec<_> = findings.iter().filter(|f| !f.allowlisted).copied().collect();
        let finding_count = active.len();
        let penalty: f64 = active.iter().map(|f| f.severity.weight()).sum();
        let score = (1.0 - penalty).max(0.0);

        CategoryScore::Graded { category, score, letter: Letter::from_score(score), finding_count }
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
    use crate::auditor::AuditorMeta;
    use crate::finding::{Category, Finding, Severity};
    use std::time::Duration;

    fn auditor_result_with(category: Category, findings: Vec<Finding>) -> AuditorResult {
        AuditorResult::ok(
            AuditorMeta { name: "test", category },
            findings,
            Duration::from_millis(1),
        )
    }

    #[test]
    fn empty_results_yield_a_plus() {
        let report = Grade::new(&[]).compute();
        assert_eq!(report.overall_letter, Letter::APlus);
        assert!((report.overall_score - 1.0).abs() < 1e-9);
    }

    #[test]
    fn one_critical_security_finding_tanks_grade() {
        let results = vec![auditor_result_with(
            Category::Security,
            vec![Finding::new("audit", Category::Security, Severity::Critical, "RCE in foo-bar")],
        )];
        let report = Grade::new(&results).compute();

        let sec = report.by_category.iter().find(|c| c.category() == Category::Security).unwrap();
        // 1.0 - 0.5 = 0.5 → F
        match sec {
            CategoryScore::Graded { score, letter, .. } => {
                assert!((score - 0.5).abs() < 1e-9);
                assert_eq!(*letter, Letter::F);
            }
            CategoryScore::Skipped { .. } => panic!("Security should be Graded here"),
        }
    }

    #[test]
    fn many_low_lints_degrade_lints_grade_proportionally() {
        let findings: Vec<Finding> = (0..10)
            .map(|i| Finding::new("clippy", Category::Lints, Severity::Low, format!("nit-{i}")))
            .collect();
        let report = Grade::new(&[auditor_result_with(Category::Lints, findings)]).compute();
        let lints = report.by_category.iter().find(|c| c.category() == Category::Lints).unwrap();
        // 1.0 - 10*0.01 = 0.9 → A−
        match lints {
            CategoryScore::Graded { score, letter, .. } => {
                assert!((score - 0.9).abs() < 1e-9);
                assert_eq!(*letter, Letter::AMinus);
            }
            CategoryScore::Skipped { .. } => panic!("Lints should be Graded here"),
        }
    }

    #[test]
    fn clean_categories_stay_at_a_plus() {
        let report = Grade::new(&[auditor_result_with(Category::Lints, vec![])]).compute();
        for cs in &report.by_category {
            match cs {
                CategoryScore::Graded { score, letter, .. } => {
                    assert!((score - 1.0).abs() < 1e-9);
                    assert_eq!(*letter, Letter::APlus);
                }
                CategoryScore::Skipped { .. } => {
                    panic!("no auditors failed, nothing should be Skipped")
                }
            }
        }
    }

    #[test]
    fn weights_sum_to_one() {
        let sum: f64 = Grade::CATEGORY_WEIGHTS.iter().map(|(_, w)| w).sum();
        assert!((sum - 1.0).abs() < 1e-9, "weights must sum to 1.0; got {sum}");
    }

    #[test]
    fn letter_cutoffs_are_monotonic() {
        let inputs = [0.0_f64, 0.5, 0.6, 0.7, 0.75, 0.8, 0.85, 0.9, 0.95, 1.0];
        let mut prev = Letter::F;
        for s in inputs {
            let g = Letter::from_score(s);
            assert!(
                g >= prev,
                "letter must be non-decreasing in score, but {prev:?} → {g:?} at {s}"
            );
            prev = g;
        }
    }

    #[test]
    fn passing_threshold_is_c_minus() {
        assert!(Letter::CMinus.is_passing());
        assert!(!Letter::DPlus.is_passing());
        assert!(!Letter::F.is_passing());
        assert!(Letter::APlus.is_passing());
    }

    #[test]
    fn letter_roundtrips_display_to_fromstr() {
        use std::str::FromStr;
        for l in [
            Letter::APlus,
            Letter::A,
            Letter::AMinus,
            Letter::BPlus,
            Letter::B,
            Letter::BMinus,
            Letter::CPlus,
            Letter::C,
            Letter::CMinus,
            Letter::DPlus,
            Letter::D,
            Letter::DMinus,
            Letter::F,
        ] {
            let s = l.to_string();
            let parsed =
                Letter::from_str(&s).unwrap_or_else(|e| panic!("failed to parse {s:?}: {e}"));
            assert_eq!(parsed, l, "round-trip failed for {l:?} → {s:?}");
        }
    }

    #[test]
    fn letter_fromstr_accepts_ascii_dash_and_lowercase() {
        use std::str::FromStr;
        assert_eq!(Letter::from_str("A-").unwrap(), Letter::AMinus);
        assert_eq!(Letter::from_str("a-").unwrap(), Letter::AMinus);
        assert_eq!(Letter::from_str(" b+ ").unwrap(), Letter::BPlus);
        // Unicode minus from Display:
        assert_eq!(Letter::from_str("A−").unwrap(), Letter::AMinus);
    }

    #[test]
    fn letter_fromstr_rejects_garbage() {
        use std::str::FromStr;
        let err = Letter::from_str("Z").unwrap_err();
        assert!(err.contains("unknown grade"));
        assert!(Letter::from_str("").is_err());
        assert!(Letter::from_str("E").is_err());
    }

    // --- Issue #24: failed auditors must surface as Skipped, not 0.85 ---

    fn failed_result(category: Category, name: &'static str, msg: &str) -> AuditorResult {
        AuditorResult::failed(AuditorMeta { name, category }, msg, Duration::from_millis(10))
    }

    #[test]
    fn failed_auditor_surfaces_as_skipped_not_graded_b() {
        // cargo-audit failed (e.g. network blip fetching advisory-db).
        // The Security category should be Skipped, NOT graded 0.85.
        let results =
            vec![failed_result(Category::Security, "cargo-audit", "advisory db fetch failed")];
        let report = Grade::new(&results).compute();

        let sec = report
            .by_category
            .iter()
            .find(|c| c.category() == Category::Security)
            .expect("Security should appear in by_category");
        match sec {
            CategoryScore::Skipped { reason, .. } => {
                assert!(
                    reason.contains("fetch failed") || reason.to_lowercase().contains("failed"),
                    "skip reason should describe what failed, got: {reason}"
                );
            }
            CategoryScore::Graded { score, letter, .. } => {
                panic!(
                    "expected Skipped for failed auditor, got Graded score={score} letter={letter:?} (this is the #24 bug)"
                );
            }
        }
    }

    #[test]
    fn overall_grade_renormalizes_when_a_category_is_skipped() {
        // Security (weight 0.30) is skipped; remaining 0.70 weight is
        // split across 4 clean categories. A clean codebase should still
        // come out at 1.0, not be penalized for a tooling outage.
        let results = vec![
            failed_result(Category::Security, "cargo-audit", "outage"),
            AuditorResult::ok(
                AuditorMeta { name: "clippy", category: Category::Lints },
                vec![],
                Duration::from_millis(1),
            ),
            AuditorResult::ok(
                AuditorMeta { name: "rust-code-analysis", category: Category::Complexity },
                vec![],
                Duration::from_millis(1),
            ),
            AuditorResult::ok(
                AuditorMeta { name: "cargo-machete", category: Category::DeadCode },
                vec![],
                Duration::from_millis(1),
            ),
            AuditorResult::ok(
                AuditorMeta { name: "cargo-deny", category: Category::Maintenance },
                vec![],
                Duration::from_millis(1),
            ),
        ];
        let report = Grade::new(&results).compute();
        assert!(
            (report.overall_score - 1.0).abs() < 1e-9,
            "expected overall 1.0 (skipped category drops out of weighted average), got {}",
            report.overall_score
        );
        assert_eq!(report.overall_letter, Letter::APlus);
    }

    #[test]
    fn report_exposes_any_skipped_for_cli_exit_decisions() {
        let results = vec![failed_result(Category::Security, "cargo-audit", "outage")];
        let report = Grade::new(&results).compute();
        assert!(
            report.any_skipped(),
            "GradeReport::any_skipped() must return true when a category is Skipped"
        );

        // Negative case: no failures → no skipped categories.
        let clean = Grade::new(&[auditor_result_with(Category::Lints, vec![])]).compute();
        assert!(!clean.any_skipped(), "clean run must not report any skipped");
    }

    #[test]
    fn timed_out_auditor_also_surfaces_as_skipped() {
        // Same contract as Failed — a timeout means "we have no signal",
        // not "code quality is 0.85".
        let timeout_result = AuditorResult::timed_out(
            AuditorMeta { name: "rust-code-analysis", category: Category::Complexity },
            Duration::from_secs(300),
        );
        let report = Grade::new(&[timeout_result]).compute();
        let complexity =
            report.by_category.iter().find(|c| c.category() == Category::Complexity).unwrap();
        assert!(
            matches!(complexity, CategoryScore::Skipped { .. }),
            "timed-out auditor should produce Skipped, not Graded"
        );
    }

    #[test]
    fn skipped_missing_auditor_also_surfaces_as_skipped() {
        // The binary isn't on PATH and --install-missing is false.
        // Same contract: report it explicitly, don't grade-by-fallback.
        let skipped = AuditorResult::skipped_missing(AuditorMeta {
            name: "cargo-deny",
            category: Category::Maintenance,
        });
        let report = Grade::new(&[skipped]).compute();
        let maint =
            report.by_category.iter().find(|c| c.category() == Category::Maintenance).unwrap();
        assert!(
            matches!(maint, CategoryScore::Skipped { .. }),
            "SkippedMissing auditor should produce Skipped category"
        );
    }

    #[test]
    fn skipped_disabled_with_ok_sibling_keeps_category_graded() {
        // #28: when ONE auditor in a category is disabled via rc but
        // another auditor for the same category produced Ok results,
        // the category stays Graded (intent != outage). Maintenance is
        // shared by cargo-deny + cargo-outdated; disabling cargo-deny
        // alone should leave Maintenance graded by cargo-outdated.
        use crate::AuditorMeta;
        let results = vec![
            AuditorResult::ok(
                AuditorMeta { name: "cargo-outdated", category: Category::Maintenance },
                vec![],
                Duration::from_millis(10),
            ),
            AuditorResult::skipped_disabled(AuditorMeta {
                name: "cargo-deny",
                category: Category::Maintenance,
            }),
        ];
        let report = Grade::new(&results).compute();
        let maint = report
            .by_category
            .iter()
            .find(|c| c.category() == Category::Maintenance)
            .expect("Maintenance must be present");
        assert!(
            matches!(maint, CategoryScore::Graded { .. }),
            "Maintenance should stay Graded when cargo-outdated is Ok despite cargo-deny disabled, got: {maint:?}"
        );
    }

    #[test]
    fn skipped_disabled_alone_still_skips_category() {
        // #28: when ALL auditors for a category are SkippedDisabled,
        // the category IS Skipped. Disabling every Maintenance auditor
        // (cargo-deny + cargo-outdated) should still produce Skipped.
        use crate::AuditorMeta;
        let results = vec![
            AuditorResult::skipped_disabled(AuditorMeta {
                name: "cargo-outdated",
                category: Category::Maintenance,
            }),
            AuditorResult::skipped_disabled(AuditorMeta {
                name: "cargo-deny",
                category: Category::Maintenance,
            }),
        ];
        let report = Grade::new(&results).compute();
        let maint = report
            .by_category
            .iter()
            .find(|c| c.category() == Category::Maintenance)
            .expect("Maintenance must be present");
        assert!(
            matches!(maint, CategoryScore::Skipped { .. }),
            "Maintenance should be Skipped when all auditors disabled, got: {maint:?}"
        );
    }
}
