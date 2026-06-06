//! Markdown report renderer.

use crate::Report;
use holocron_core::{Category, CategoryScore, Finding, RunStatus, Severity};
use std::fmt::Write;

const MAX_FINDINGS_PER_CATEGORY: usize = 50;

/// Render the full report to a Markdown string.
#[must_use]
pub fn render_markdown(report: &Report<'_>) -> String {
    let mut out = String::with_capacity(8192);
    write_header(report, &mut out);
    write_grade_card(report, &mut out);
    write_summary_table(report, &mut out);
    write_auditor_status(report, &mut out);
    for cat in Category::ALL {
        write_category_section(report, cat, &mut out);
    }
    write_allowlisted_section(report, &mut out);
    out
}

/// Render the "Allowlisted Findings" section listing every finding the
/// rc rules suppressed from the grade, with the matching rule's reason.
/// Skipped entirely when no findings were allowlisted (#29).
fn write_allowlisted_section(report: &Report<'_>, out: &mut String) {
    let allow: Vec<&Finding> = report.findings.iter().filter(|f| f.allowlisted).collect();
    if allow.is_empty() {
        return;
    }
    let _ = writeln!(out, "## Allowlisted Findings ({})", allow.len());
    let _ = writeln!(out);
    let _ = writeln!(
        out,
        "These findings matched either an `[[allowlist]]` rule in \
         `.holocronrc.toml` or an inline `// holocron: ignore <code>` \
         annotation in source, and were excluded from the category \
         scores and overall grade. Listed here for audit-trail purposes."
    );
    let _ = writeln!(out);
    for f in allow {
        let location = f.location.as_ref().map(|l| format!(" `{l}`")).unwrap_or_default();
        let code = f.code.as_deref().map(|c| format!(" `{c}`")).unwrap_or_default();
        let reason = f.allowlist_reason.as_deref().unwrap_or("(no reason given)");
        let _ = writeln!(
            out,
            "- **{}** [{}]{location} —{code} {}",
            f.severity,
            f.category,
            escape_md(&f.message)
        );
        let _ = writeln!(out, "  > Reason: {}", escape_md(reason));
    }
    let _ = writeln!(out);
}

fn write_header(report: &Report<'_>, out: &mut String) {
    let _ = writeln!(out, "# Holocron Audit — {}", short_target(&report.header.target_path));
    let _ = writeln!(out);
    let _ = writeln!(
        out,
        "Generated: {} UTC | Holocron {} | Target: `{}`{}",
        report.header.generated_at.format("%Y-%m-%d %H:%M:%S"),
        report.header.holocron_version,
        report.header.target_path,
        report.header.target_commit.as_deref().map_or(String::new(), |c| format!(" @ `{c}`")),
    );
    let _ = writeln!(out);
}

fn write_grade_card(report: &Report<'_>, out: &mut String) {
    let _ = writeln!(
        out,
        "## Grade: **{}**  ({:.2})",
        report.grade.overall_letter, report.grade.overall_score
    );
    let _ = writeln!(out);
    if report.grade.overall_letter.is_passing() {
        let _ = writeln!(out, "_Result: PASS — overall grade is C− or better._");
    } else {
        let _ = writeln!(out, "_Result: FAIL — overall grade is below C−._");
    }
    let _ = writeln!(out);
}

fn write_summary_table(report: &Report<'_>, out: &mut String) {
    let _ = writeln!(out, "| Category    | Grade | Score | Findings | Status                |");
    let _ = writeln!(out, "|-------------|-------|-------|----------|-----------------------|");
    for cs in &report.grade.by_category {
        match cs {
            CategoryScore::Graded { category, score, letter, finding_count } => {
                let _ = writeln!(
                    out,
                    "| {:<11} | {:<5} | {:>5.2} | {:>8} | ok                    |",
                    category.to_string(),
                    letter.to_string(),
                    score,
                    finding_count,
                );
            }
            CategoryScore::Skipped { category, reason } => {
                // Keep the reason short for the table cell; full text
                // appears in the Auditor Errors section below.
                let short_reason = if reason.len() > 40 {
                    format!("{}…", &reason[..40])
                } else {
                    reason.clone()
                };
                let _ = writeln!(
                    out,
                    "| {:<11} | —     |   —   |        — | _skipped: {}_ |",
                    category.to_string(),
                    escape_md(&short_reason),
                );
            }
        }
    }
    let _ = writeln!(out);

    if report.grade.any_skipped() {
        let _ = writeln!(
            out,
            "> ⚠️  One or more categories were skipped because their auditor failed, \
             timed out, or wasn't installed. The overall grade was computed over the \
             remaining categories only — treat it as advisory until the skipped \
             auditors run cleanly. See the Auditor Errors section below for detail."
        );
        let _ = writeln!(out);
    }
}

fn write_auditor_status(report: &Report<'_>, out: &mut String) {
    let _ = writeln!(out, "## Auditor Status");
    let _ = writeln!(out);
    let _ = writeln!(out, "| Auditor              | Status         | Duration | Findings |");
    let _ = writeln!(out, "|----------------------|----------------|---------:|---------:|");
    for r in &report.outcome.auditor_results {
        let status = match r.status {
            RunStatus::Ok => "✓ ok",
            RunStatus::Failed => "✗ failed",
            RunStatus::TimedOut => "⌛ timed out",
            RunStatus::SkippedMissing => "⊘ skipped (not installed)",
            RunStatus::SkippedDisabled => "⊘ skipped (disabled in rc)",
        };
        let _ = writeln!(
            out,
            "| {:<20} | {:<14} | {:>7.1}s | {:>8} |",
            r.auditor,
            status,
            r.duration.as_secs_f64(),
            r.findings.len(),
        );
    }
    let _ = writeln!(out);

    // If any auditor failed, surface the errors prominently.
    let failures: Vec<_> = report
        .outcome
        .auditor_results
        .iter()
        .filter(|r| {
            r.error.is_some()
                && !matches!(
                    r.status,
                    RunStatus::Ok | RunStatus::SkippedMissing | RunStatus::SkippedDisabled
                )
        })
        .collect();
    if !failures.is_empty() {
        let _ = writeln!(out, "### Auditor Errors");
        let _ = writeln!(out);
        for r in failures {
            let _ = writeln!(
                out,
                "- **{}** — {}",
                r.auditor,
                r.error.as_deref().unwrap_or("(no detail)")
            );
        }
        let _ = writeln!(out);
    }
}

fn write_category_section(report: &Report<'_>, category: Category, out: &mut String) {
    // #29: allowlisted findings get their own section at the end of
    // the report — filter them out of the per-category lists so users
    // see only what actually affected the grade.
    let in_cat: Vec<&Finding> =
        report.findings.iter().filter(|f| f.category == category && !f.allowlisted).collect();
    let _ = writeln!(out, "## {category}");
    let _ = writeln!(out);

    if in_cat.is_empty() {
        let _ = writeln!(out, "_No findings._");
        let _ = writeln!(out);
        return;
    }

    // Group by severity.
    for sev in [Severity::Critical, Severity::High, Severity::Medium, Severity::Low, Severity::Info]
    {
        let group: Vec<&&Finding> = in_cat.iter().filter(|f| f.severity == sev).collect();
        if group.is_empty() {
            continue;
        }
        let _ = writeln!(out, "### {sev} ({})", group.len());
        let _ = writeln!(out);
        for (i, f) in group.iter().take(MAX_FINDINGS_PER_CATEGORY).enumerate() {
            write_finding(f, out);
            if i == MAX_FINDINGS_PER_CATEGORY - 1 && group.len() > MAX_FINDINGS_PER_CATEGORY {
                let _ = writeln!(
                    out,
                    "- ... _{} more findings at this severity — see JSON sidecar._",
                    group.len() - MAX_FINDINGS_PER_CATEGORY
                );
            }
        }
        let _ = writeln!(out);
    }
}

fn write_finding(f: &Finding, out: &mut String) {
    let location = f.location.as_ref().map(|l| format!(" `{l}`")).unwrap_or_default();
    let code = f.code.as_deref().map(|c| format!(" `{c}`")).unwrap_or_default();
    let _ = writeln!(out, "- **{}**{location} —{code} {}", f.severity, escape_md(&f.message));
    if let Some(detail) = &f.detail {
        // Detail in a blockquote — wraps nicely without breaking lists.
        for line in detail.lines().take(8) {
            let _ = writeln!(out, "  > {}", escape_md(line));
        }
    }
}

fn escape_md(s: &str) -> String {
    // Minimal escape: just `|` so table-cell rendering doesn't break.
    s.replace('|', "\\|")
}

fn short_target(path: &str) -> String {
    std::path::Path::new(path)
        .file_name()
        .map_or_else(|| path.to_string(), |n| n.to_string_lossy().into_owned())
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
    use holocron_core::auditor::AuditorMeta;
    use holocron_core::{AuditorResult, Finding, Grade, RunOutcome};
    use std::time::Duration;

    fn fixture() -> (RunOutcome, holocron_core::GradeReport) {
        let mut r = AuditorResult::ok(
            AuditorMeta { name: "clippy", category: Category::Lints },
            vec![Finding::new("clippy", Category::Lints, Severity::Medium, "uses `unwrap`")
                .with_code("clippy::unwrap_used")
                .with_location(holocron_core::Location::at("src/lib.rs", 42))],
            Duration::from_millis(1234),
        );
        r.duration = Duration::from_millis(1234);
        let outcome = RunOutcome {
            target: std::path::PathBuf::from("/tmp/proj"),
            started_at: chrono::Utc::now(),
            total_duration: Duration::from_secs(2),
            auditor_results: vec![r],
        };
        let grade = Grade::new(&outcome.auditor_results).compute();
        (outcome, grade)
    }

    #[test]
    fn rendered_markdown_contains_grade_and_finding() {
        let (outcome, grade) = fixture();
        let report = Report::new(&outcome, &grade);
        let md = render_markdown(&report);
        assert!(md.contains("# Holocron Audit"));
        assert!(md.contains("## Grade:"));
        assert!(md.contains("Lints"));
        assert!(md.contains("clippy::unwrap_used"));
        assert!(md.contains("src/lib.rs:42"));
    }

    #[test]
    fn empty_categories_render_no_findings_placeholder() {
        let outcome = RunOutcome {
            target: std::path::PathBuf::from("/tmp/proj"),
            started_at: chrono::Utc::now(),
            total_duration: Duration::ZERO,
            auditor_results: vec![],
        };
        let grade = Grade::new(&outcome.auditor_results).compute();
        let report = Report::new(&outcome, &grade);
        let md = render_markdown(&report);
        assert!(md.contains("_No findings._"));
    }

    #[test]
    fn skipped_category_renders_em_dash_not_fallback_score() {
        // #24: when cargo-audit fails, the summary table must show the
        // Security row as Skipped (em-dash for grade/score) — NOT the
        // old `B 0.85` fallback.
        let outcome = RunOutcome {
            target: std::path::PathBuf::from("/tmp/proj"),
            started_at: chrono::Utc::now(),
            total_duration: Duration::ZERO,
            auditor_results: vec![AuditorResult::failed(
                holocron_core::auditor::AuditorMeta {
                    name: "cargo-audit",
                    category: Category::Security,
                },
                "network unreachable: advisory db fetch failed",
                Duration::from_millis(50),
            )],
        };
        let grade = Grade::new(&outcome.auditor_results).compute();
        let report = Report::new(&outcome, &grade);
        let md = render_markdown(&report);

        let security_row = md
            .lines()
            .find(|l| l.starts_with("| Security"))
            .expect("summary table should have a Security row");
        assert!(
            security_row.contains('—') || security_row.to_lowercase().contains("skipped"),
            "expected Skipped marker in Security row, got: {security_row}"
        );
        assert!(
            !security_row.contains("0.85"),
            "must NOT show the old fallback score, got: {security_row}"
        );
        assert!(
            md.contains("auditor outage")
                || md.contains("auditors failed")
                || md.contains("treat it as advisory"),
            "summary must include a warning banner when any category is skipped"
        );
    }
}
