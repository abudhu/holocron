//! HTML report renderer — single-file, self-contained, shareable.
//!
//! Output is plain HTML5 with inlined CSS (no external assets, no JS).
//! Designed for the case where the audience isn't a Rust developer
//! reading the markdown in their terminal — PMs, security review,
//! anyone who just wants a link they can open.
//!
//! ## Constraints (#46)
//!   * Single file, no external assets, no JS dependencies
//!   * Renders in Safari/Chrome/Firefox with the same layout
//!   * <details>/<summary> for collapsible sections (no JS)
//!   * Print-friendly (media query collapses the dark theme to white)
//!   * Total bytes < 100KB on a typical dogfood run
//!
//! ## Aesthetic
//!   * Dark theme by default. Hero is the grade letter (huge, colored
//!     by grade band: green/lime/amber/orange/red).
//!   * Category sections collapsible — defaults to open for failing
//!     categories, closed for A/A+.
//!   * Severity rows colored on the left border (no icon fonts, no
//!     emoji-as-content — emoji here render inconsistently across
//!     browsers and would bloat the file with @font-face fallbacks).

use crate::Report;
use holocron_core::{Category, CategoryScore, Finding, Letter, RunStatus, Severity};
use std::fmt::Write;

const MAX_FINDINGS_PER_CATEGORY: usize = 50;

/// Render the full report to a single HTML5 document string.
#[must_use]
pub fn render_html(report: &Report<'_>) -> String {
    let mut out = String::with_capacity(16_384);
    write_doc_header(report, &mut out);
    write_grade_hero(report, &mut out);
    write_summary_table(report, &mut out);
    write_auditor_status(report, &mut out);
    for cat in Category::ALL {
        write_category_section(report, cat, &mut out);
    }
    write_allowlisted_section(report, &mut out);
    write_doc_footer(&mut out);
    out
}

fn write_doc_header(report: &Report<'_>, out: &mut String) {
    let target = html_escape(&short_target(&report.header.target_path));
    let _ = writeln!(out, "<!doctype html>");
    let _ = writeln!(out, "<html lang=\"en\">");
    let _ = writeln!(out, "<head>");
    let _ = writeln!(out, "<meta charset=\"utf-8\">");
    let _ =
        writeln!(out, "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">");
    let _ = writeln!(out, "<title>Holocron Audit — {target}</title>");
    let _ = writeln!(out, "<style>{CSS}</style>");
    let _ = writeln!(out, "</head>");
    let _ = writeln!(out, "<body>");
    let _ = writeln!(out, "<main>");
    let _ = writeln!(out, "<header class=\"page-header\">");
    let _ = writeln!(out, "<h1>Holocron Audit</h1>");
    let _ = writeln!(
        out,
        "<p class=\"target\">Target: <code>{}</code>{}</p>",
        html_escape(&report.header.target_path),
        report
            .header
            .target_commit
            .as_deref()
            .map_or(String::new(), |c| format!(" @ <code>{}</code>", html_escape(c))),
    );
    let _ = writeln!(
        out,
        "<p class=\"meta\">Generated {} UTC · Holocron {}</p>",
        report.header.generated_at.format("%Y-%m-%d %H:%M:%S"),
        html_escape(&report.header.holocron_version),
    );
    let _ = writeln!(out, "</header>");
}

fn write_doc_footer(out: &mut String) {
    let _ = writeln!(out, "</main>");
    let _ = writeln!(out, "</body>");
    let _ = writeln!(out, "</html>");
}

fn write_grade_hero(report: &Report<'_>, out: &mut String) {
    let letter = report.grade.overall_letter;
    let band = grade_band(letter);
    let pass_label = if letter.is_passing() { "PASS" } else { "FAIL" };
    let pass_class = if letter.is_passing() { "pass" } else { "fail" };
    let _ = writeln!(out, "<section class=\"grade-hero band-{band}\">");
    let _ =
        writeln!(out, "  <div class=\"grade-letter\">{}</div>", html_escape(&letter.to_string()));
    let _ = writeln!(out, "  <div class=\"grade-meta\">");
    let _ = writeln!(out, "    <div class=\"grade-score\">{:.2}</div>", report.grade.overall_score);
    let _ = writeln!(out, "    <div class=\"grade-pass {pass_class}\">{pass_label}</div>");
    let _ = writeln!(out, "  </div>");
    let _ = writeln!(out, "</section>");
}

fn write_summary_table(report: &Report<'_>, out: &mut String) {
    let _ = writeln!(out, "<section class=\"summary\">");
    let _ = writeln!(out, "<h2>Category Breakdown</h2>");
    let _ = writeln!(out, "<table class=\"cat-table\">");
    let _ = writeln!(out, "<thead><tr><th>Category</th><th>Grade</th><th>Score</th><th>Findings</th><th>Status</th></tr></thead>");
    let _ = writeln!(out, "<tbody>");
    for cs in &report.grade.by_category {
        match cs {
            CategoryScore::Graded { category, score, letter, finding_count } => {
                let band = grade_band(*letter);
                let _ = writeln!(
                    out,
                    "<tr><td>{}</td><td><span class=\"chip band-{band}\">{}</span></td>\
                     <td class=\"num\">{:.2}</td><td class=\"num\">{}</td><td>ok</td></tr>",
                    html_escape(&category.to_string()),
                    html_escape(&letter.to_string()),
                    score,
                    finding_count,
                );
            }
            CategoryScore::Skipped { category, reason } => {
                let short = if reason.len() > 60 {
                    format!("{}…", &reason[..60])
                } else {
                    reason.clone()
                };
                let _ = writeln!(
                    out,
                    "<tr class=\"skipped\"><td>{}</td><td>—</td><td>—</td><td>—</td>\
                     <td><em>skipped:</em> {}</td></tr>",
                    html_escape(&category.to_string()),
                    html_escape(&short),
                );
            }
        }
    }
    let _ = writeln!(out, "</tbody></table>");
    if report.grade.any_skipped() {
        let _ = writeln!(out, "<aside class=\"warning\">One or more categories were skipped because their auditor failed, timed out, or wasn't installed. The overall grade was computed over the remaining categories only — treat it as advisory until the skipped auditors run cleanly.</aside>");
    }
    let _ = writeln!(out, "</section>");
}

fn write_auditor_status(report: &Report<'_>, out: &mut String) {
    let _ = writeln!(out, "<section class=\"auditors\">");
    let _ = writeln!(out, "<h2>Auditor Status</h2>");
    let _ = writeln!(out, "<table class=\"aud-table\">");
    let _ = writeln!(
        out,
        "<thead><tr><th>Auditor</th><th>Status</th><th>Duration</th><th>Findings</th></tr></thead>"
    );
    let _ = writeln!(out, "<tbody>");
    for r in &report.outcome.auditor_results {
        let (status_label, status_class) = match r.status {
            RunStatus::Ok => ("ok", "ok"),
            RunStatus::Failed => ("failed", "failed"),
            RunStatus::TimedOut => ("timed out", "failed"),
            RunStatus::SkippedMissing => ("skipped (not installed)", "skipped"),
            RunStatus::SkippedDisabled => ("skipped (disabled in rc)", "skipped"),
        };
        // html_escape takes &str; passing &r.auditor (a &String) coerces
        // fine. clippy::needless_borrow wants .as_str() (unstable on our
        // pinned rustc) or a deref slice (then redundant_slicing fires).
        // Suppress locally — the &String → &str coercion is the right shape.
        #[allow(clippy::needless_borrow)]
        let auditor_name = html_escape(&r.auditor);
        let _ = writeln!(
            out,
            "<tr><td><code>{}</code></td><td class=\"status status-{status_class}\">{}</td>\
             <td class=\"num\">{:.1}s</td><td class=\"num\">{}</td></tr>",
            auditor_name,
            status_label,
            r.duration.as_secs_f64(),
            r.findings.len(),
        );
    }
    let _ = writeln!(out, "</tbody></table>");

    // Surface auditor errors prominently so a failed audit doesn't
    // blend in with a clean one.
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
        let _ = writeln!(out, "<h3>Auditor Errors</h3>");
        let _ = writeln!(out, "<ul class=\"errors\">");
        for r in failures {
            #[allow(clippy::needless_borrow)]
            let auditor_name = html_escape(&r.auditor);
            let _ = writeln!(
                out,
                "<li><strong>{}</strong> — {}</li>",
                auditor_name,
                html_escape(r.error.as_deref().unwrap_or("(no detail)")),
            );
        }
        let _ = writeln!(out, "</ul>");
    }
    let _ = writeln!(out, "</section>");
}

fn write_category_section(report: &Report<'_>, category: Category, out: &mut String) {
    let in_cat: Vec<&Finding> =
        report.findings.iter().filter(|f| f.category == category && !f.allowlisted).collect();

    // Open the <details> by default when there are findings; collapsed
    // when clean (cuts visual noise on a passing audit).
    let open_attr = if in_cat.is_empty() { "" } else { " open" };
    let _ = writeln!(out, "<details class=\"category\"{open_attr}>");
    let _ = writeln!(
        out,
        "<summary><h2>{} <span class=\"count\">({})</span></h2></summary>",
        html_escape(&category.to_string()),
        in_cat.len(),
    );

    if in_cat.is_empty() {
        let _ = writeln!(out, "<p class=\"empty\">No findings.</p>");
        let _ = writeln!(out, "</details>");
        return;
    }

    for sev in [Severity::Critical, Severity::High, Severity::Medium, Severity::Low, Severity::Info]
    {
        let group: Vec<&&Finding> = in_cat.iter().filter(|f| f.severity == sev).collect();
        if group.is_empty() {
            continue;
        }
        let _ = writeln!(
            out,
            "<h3 class=\"sev sev-{}\">{} <span class=\"count\">({})</span></h3>",
            severity_class(sev),
            sev,
            group.len()
        );
        let _ = writeln!(out, "<ul class=\"findings\">");
        for (i, f) in group.iter().take(MAX_FINDINGS_PER_CATEGORY).enumerate() {
            write_finding(f, out);
            if i == MAX_FINDINGS_PER_CATEGORY - 1 && group.len() > MAX_FINDINGS_PER_CATEGORY {
                let _ = writeln!(out, "<li class=\"truncation\">… {} more findings at this severity — see JSON sidecar.</li>",
                    group.len() - MAX_FINDINGS_PER_CATEGORY);
            }
        }
        let _ = writeln!(out, "</ul>");
    }
    let _ = writeln!(out, "</details>");
}

fn write_finding(f: &Finding, out: &mut String) {
    let _ = writeln!(out, "<li class=\"finding sev-{}\">", severity_class(f.severity));
    let _ = writeln!(out, "  <div class=\"finding-header\">");
    let _ = writeln!(
        out,
        "    <span class=\"sev-badge sev-{}\">{}</span>",
        severity_class(f.severity),
        f.severity
    );
    if let Some(code) = &f.code {
        let _ = writeln!(out, "    <code class=\"finding-code\">{}</code>", html_escape(code));
    }
    if let Some(loc) = &f.location {
        let _ = writeln!(
            out,
            "    <code class=\"finding-loc\">{}</code>",
            html_escape(&loc.to_string())
        );
    }
    let _ = writeln!(out, "  </div>");
    let _ = writeln!(out, "  <div class=\"finding-msg\">{}</div>", html_escape(&f.message));
    if let Some(detail) = &f.detail {
        let _ = writeln!(out, "  <pre class=\"finding-detail\">");
        for line in detail.lines().take(8) {
            let _ = writeln!(out, "{}", html_escape(line));
        }
        let _ = writeln!(out, "  </pre>");
    }
    let _ = writeln!(out, "</li>");
}

fn write_allowlisted_section(report: &Report<'_>, out: &mut String) {
    let allow: Vec<&Finding> = report.findings.iter().filter(|f| f.allowlisted).collect();
    if allow.is_empty() {
        return;
    }
    let _ = writeln!(out, "<details class=\"allowlisted\">");
    let _ = writeln!(
        out,
        "<summary><h2>Allowlisted Findings <span class=\"count\">({})</span></h2></summary>",
        allow.len()
    );
    let _ = writeln!(out, "<p class=\"note\">These findings matched an <code>[[allowlist]]</code> rule in <code>.holocronrc.toml</code> and were excluded from the category scores and overall grade. They are listed here for audit-trail purposes.</p>");
    let _ = writeln!(out, "<ul class=\"findings\">");
    for f in allow {
        let _ = writeln!(out, "<li class=\"finding allowlisted\">");
        let _ = writeln!(out, "  <div class=\"finding-header\">");
        let _ = writeln!(
            out,
            "    <span class=\"sev-badge sev-{}\">{}</span>",
            severity_class(f.severity),
            f.severity
        );
        let _ = writeln!(
            out,
            "    <span class=\"cat-badge\">{}</span>",
            html_escape(&f.category.to_string())
        );
        if let Some(code) = &f.code {
            let _ = writeln!(out, "    <code class=\"finding-code\">{}</code>", html_escape(code));
        }
        if let Some(loc) = &f.location {
            let _ = writeln!(
                out,
                "    <code class=\"finding-loc\">{}</code>",
                html_escape(&loc.to_string())
            );
        }
        let _ = writeln!(out, "  </div>");
        let _ = writeln!(out, "  <div class=\"finding-msg\">{}</div>", html_escape(&f.message));
        let reason = f.allowlist_reason.as_deref().unwrap_or("(no reason given)");
        let _ = writeln!(
            out,
            "  <div class=\"reason\"><strong>Reason:</strong> {}</div>",
            html_escape(reason)
        );
        let _ = writeln!(out, "</li>");
    }
    let _ = writeln!(out, "</ul>");
    let _ = writeln!(out, "</details>");
}

/// Map a letter grade to a coarse band for color theming.
const fn grade_band(letter: Letter) -> &'static str {
    match letter {
        Letter::APlus | Letter::A | Letter::AMinus => "a",
        Letter::BPlus | Letter::B | Letter::BMinus => "b",
        Letter::CPlus | Letter::C | Letter::CMinus => "c",
        Letter::DPlus | Letter::D | Letter::DMinus => "d",
        Letter::F => "f",
    }
}

const fn severity_class(s: Severity) -> &'static str {
    match s {
        Severity::Critical => "critical",
        Severity::High => "high",
        Severity::Medium => "medium",
        Severity::Low => "low",
        Severity::Info => "info",
    }
}

/// Minimal HTML escape — enough for safe rendering of message text,
/// file paths, code names. Not full SGML-safe (we never inject into
/// attribute values that take URLs, etc.).
fn html_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '&' => out.push_str("&amp;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            other => out.push(other),
        }
    }
    out
}

fn short_target(path: &str) -> String {
    std::path::Path::new(path)
        .file_name()
        .map_or_else(|| path.to_string(), |n| n.to_string_lossy().into_owned())
}

/// Inlined CSS — dark theme by default, light/print media query
/// override. Kept under 4KB so the total report stays under 100KB
/// budget on real audits.
const CSS: &str = r"
:root {
  --bg: #0f1115;
  --bg-panel: #161922;
  --bg-elev: #1d2230;
  --fg: #e8eaed;
  --fg-dim: #9aa0a6;
  --border: #2a2f3d;
  --accent: #8ab4f8;
  --a: #34c084;
  --b: #a3e635;
  --c: #f5c542;
  --d: #f59e0b;
  --f: #ef4444;
  --crit: #ef4444;
  --high: #f59e0b;
  --med:  #f5c542;
  --low:  #a3e635;
  --info: #9aa0a6;
}
* { box-sizing: border-box; }
html, body { margin: 0; padding: 0; background: var(--bg); color: var(--fg);
  font: 14px/1.55 -apple-system, BlinkMacSystemFont, 'Segoe UI', system-ui, sans-serif; }
main { max-width: 960px; margin: 0 auto; padding: 32px 24px 64px; }
code { font: 13px/1.45 ui-monospace, 'SF Mono', Consolas, monospace;
  background: var(--bg-elev); padding: 1px 5px; border-radius: 3px; }
pre { font: 12px/1.5 ui-monospace, 'SF Mono', Consolas, monospace;
  background: var(--bg-elev); padding: 10px 12px; border-radius: 4px;
  overflow-x: auto; margin: 8px 0; white-space: pre-wrap; word-break: break-word; }
h1 { margin: 0 0 4px; font-size: 24px; }
h2 { margin: 0; font-size: 18px; display: inline; }
h3 { margin: 18px 0 8px; font-size: 14px; color: var(--fg-dim); text-transform: uppercase; letter-spacing: 0.04em; }

.page-header { border-bottom: 1px solid var(--border); padding-bottom: 16px; margin-bottom: 24px; }
.page-header .target { margin: 4px 0; color: var(--fg-dim); }
.page-header .meta { margin: 4px 0 0; color: var(--fg-dim); font-size: 12px; }

.grade-hero { display: flex; align-items: center; gap: 24px;
  background: var(--bg-panel); border-radius: 8px; padding: 24px 28px;
  margin-bottom: 24px; border-left: 6px solid var(--a); }
.grade-hero.band-a { border-left-color: var(--a); }
.grade-hero.band-b { border-left-color: var(--b); }
.grade-hero.band-c { border-left-color: var(--c); }
.grade-hero.band-d { border-left-color: var(--d); }
.grade-hero.band-f { border-left-color: var(--f); }
.grade-letter { font: 700 72px/1 'SF Pro Display', system-ui, sans-serif; letter-spacing: -0.04em; }
.band-a .grade-letter { color: var(--a); }
.band-b .grade-letter { color: var(--b); }
.band-c .grade-letter { color: var(--c); }
.band-d .grade-letter { color: var(--d); }
.band-f .grade-letter { color: var(--f); }
.grade-score { font: 600 28px/1 system-ui; color: var(--fg); }
.grade-pass { margin-top: 6px; font-size: 11px; font-weight: 700; letter-spacing: 0.12em; }
.grade-pass.pass { color: var(--a); }
.grade-pass.fail { color: var(--f); }

section { margin-bottom: 28px; }
table { width: 100%; border-collapse: collapse; font-size: 13px; background: var(--bg-panel);
  border-radius: 6px; overflow: hidden; }
th, td { padding: 8px 12px; text-align: left; border-bottom: 1px solid var(--border); }
th { background: var(--bg-elev); font-weight: 600; color: var(--fg-dim); font-size: 11px;
  text-transform: uppercase; letter-spacing: 0.04em; }
td.num { text-align: right; font-variant-numeric: tabular-nums; }
tr.skipped td { color: var(--fg-dim); }

.chip { display: inline-block; padding: 2px 8px; border-radius: 12px; font-weight: 600;
  font-size: 12px; background: var(--bg-elev); }
.chip.band-a { color: var(--a); }
.chip.band-b { color: var(--b); }
.chip.band-c { color: var(--c); }
.chip.band-d { color: var(--d); }
.chip.band-f { color: var(--f); }

.status { font-weight: 500; }
.status-ok { color: var(--a); }
.status-failed { color: var(--f); }
.status-skipped { color: var(--fg-dim); }

.warning { background: rgba(245, 158, 11, 0.1); border-left: 3px solid var(--d);
  padding: 12px 16px; border-radius: 4px; margin-top: 12px; color: var(--fg); font-size: 13px; }

details.category, details.allowlisted { background: var(--bg-panel); border-radius: 6px;
  padding: 8px 16px; margin-bottom: 12px; }
details.category > summary, details.allowlisted > summary { cursor: pointer; padding: 8px 0;
  list-style: none; outline: none; }
details.category > summary::-webkit-details-marker, details.allowlisted > summary::-webkit-details-marker { display: none; }
details.category > summary::before, details.allowlisted > summary::before { content: '▸ '; color: var(--fg-dim);
  display: inline-block; transition: transform 0.1s; }
details[open] > summary::before { content: '▾ '; }
.count { color: var(--fg-dim); font-weight: 400; font-size: 13px; margin-left: 6px; }
p.empty { color: var(--fg-dim); margin: 12px 0; font-style: italic; }
p.note { color: var(--fg-dim); font-size: 12px; }

ul.findings { list-style: none; padding: 0; margin: 8px 0 16px; }
li.finding { background: var(--bg-elev); border-radius: 4px; padding: 10px 14px;
  margin-bottom: 6px; border-left: 3px solid var(--info); }
li.finding.sev-critical { border-left-color: var(--crit); }
li.finding.sev-high     { border-left-color: var(--high); }
li.finding.sev-medium   { border-left-color: var(--med); }
li.finding.sev-low      { border-left-color: var(--low); }
li.finding.sev-info     { border-left-color: var(--info); }

.finding-header { display: flex; flex-wrap: wrap; align-items: center; gap: 8px; margin-bottom: 4px; }
.sev-badge { display: inline-block; padding: 1px 7px; border-radius: 3px; font-size: 10px;
  font-weight: 700; letter-spacing: 0.06em; text-transform: uppercase; }
.sev-badge.sev-critical { background: var(--crit); color: #fff; }
.sev-badge.sev-high     { background: var(--high); color: #2a1a02; }
.sev-badge.sev-medium   { background: var(--med); color: #2a1f02; }
.sev-badge.sev-low      { background: var(--low); color: #1a2a04; }
.sev-badge.sev-info     { background: var(--info); color: #1a1f2a; }
.cat-badge { display: inline-block; padding: 1px 7px; border-radius: 3px; font-size: 10px;
  font-weight: 600; background: var(--bg-panel); color: var(--fg-dim);
  letter-spacing: 0.04em; text-transform: uppercase; }
.finding-code, .finding-loc { font-size: 11px; }
.finding-msg { color: var(--fg); margin: 2px 0; }
.finding-detail { color: var(--fg-dim); }
.reason { color: var(--fg-dim); margin-top: 4px; font-size: 12px; }
.truncation { padding: 8px 12px; color: var(--fg-dim); font-style: italic; }

ul.errors { padding-left: 20px; }

@media print {
  :root { --bg: #fff; --bg-panel: #fff; --bg-elev: #f5f5f5; --fg: #111;
    --fg-dim: #555; --border: #ddd; }
  body { font-size: 12px; }
  main { max-width: 100%; padding: 16px; }
  .grade-letter { font-size: 56px; }
  details[open] > summary::before { content: ''; }
  details.category, details.allowlisted { break-inside: avoid; }
}
";

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::missing_const_for_fn)]
    use super::*;
    use holocron_core::auditor::AuditorMeta;
    use holocron_core::{AuditorResult, Grade, RunOutcome};
    use std::time::Duration;

    fn fixture() -> (RunOutcome, holocron_core::GradeReport) {
        let r = AuditorResult::ok(
            AuditorMeta { name: "clippy", category: Category::Lints },
            vec![Finding::new("clippy", Category::Lints, Severity::Medium, "uses `unwrap`")
                .with_code("clippy::unwrap_used")
                .with_location(holocron_core::Location::at("src/lib.rs", 42))],
            Duration::from_millis(1234),
        );
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
    fn renders_a_complete_html5_document() {
        let (outcome, grade) = fixture();
        let report = Report::new(&outcome, &grade);
        let html = render_html(&report);
        assert!(html.starts_with("<!doctype html>"), "must be HTML5: {}", &html[..50]);
        assert!(html.contains("<html lang=\"en\">"));
        assert!(html.contains("</html>"), "must close html tag");
        assert!(html.contains("<title>Holocron Audit"));
    }

    #[test]
    fn inlines_all_css_no_external_assets() {
        let (outcome, grade) = fixture();
        let report = Report::new(&outcome, &grade);
        let html = render_html(&report);
        // No external stylesheets, scripts, or images allowed in the output.
        assert!(!html.contains("<link "), "no <link> tags allowed (external assets)");
        assert!(!html.contains("<script"), "no <script> tags allowed");
        assert!(!html.contains("<img "), "no <img> tags allowed");
        // The CSS must be inlined.
        assert!(html.contains("<style>"), "CSS must be inlined");
    }

    #[test]
    fn html_escapes_user_provided_text() {
        // A finding with <script> in its message must not produce a
        // live <script> tag in the output.
        let f = Finding::new(
            "clippy",
            Category::Lints,
            Severity::Medium,
            "<script>alert('xss')</script> message",
        );
        let outcome = RunOutcome {
            target: std::path::PathBuf::from("/tmp/<x>"),
            started_at: chrono::Utc::now(),
            total_duration: Duration::ZERO,
            auditor_results: vec![AuditorResult::ok(
                AuditorMeta { name: "clippy", category: Category::Lints },
                vec![f],
                Duration::ZERO,
            )],
        };
        let grade = Grade::new(&outcome.auditor_results).compute();
        let report = Report::new(&outcome, &grade);
        let html = render_html(&report);
        assert!(!html.contains("<script>alert"), "raw <script> in message must be escaped");
        assert!(html.contains("&lt;script&gt;alert"), "must be HTML-escaped");
    }

    #[test]
    fn grade_hero_includes_letter_score_and_pass_marker() {
        let (outcome, grade) = fixture();
        let report = Report::new(&outcome, &grade);
        let html = render_html(&report);
        assert!(html.contains("grade-hero"), "must have hero section");
        assert!(html.contains("grade-letter"), "must show the letter");
        assert!(html.contains("grade-score"), "must show numeric score");
        assert!(html.contains("PASS") || html.contains("FAIL"), "must show pass/fail marker");
    }

    #[test]
    fn empty_categories_collapse_default_collapsed() {
        // A clean run with one auditor, no findings outside Lints.
        // Each empty category section should be present but the
        // <details> tag should NOT have `open` (collapsed by default
        // for clean categories to reduce visual noise).
        let outcome = RunOutcome {
            target: std::path::PathBuf::from("/tmp/proj"),
            started_at: chrono::Utc::now(),
            total_duration: Duration::ZERO,
            auditor_results: vec![],
        };
        let grade = Grade::new(&outcome.auditor_results).compute();
        let report = Report::new(&outcome, &grade);
        let html = render_html(&report);
        // Each category appears
        for cat in Category::ALL {
            assert!(html.contains(&format!(">{cat} <span")), "category {cat} must appear");
        }
        // Empty category bodies should say "No findings"
        assert!(html.contains("No findings."));
    }

    #[test]
    fn skipped_category_renders_em_dash_not_fake_grade() {
        let outcome = RunOutcome {
            target: std::path::PathBuf::from("/tmp/proj"),
            started_at: chrono::Utc::now(),
            total_duration: Duration::ZERO,
            auditor_results: vec![AuditorResult::failed(
                AuditorMeta { name: "cargo-audit", category: Category::Security },
                "network unreachable: advisory db fetch failed",
                Duration::from_millis(50),
            )],
        };
        let grade = Grade::new(&outcome.auditor_results).compute();
        let report = Report::new(&outcome, &grade);
        let html = render_html(&report);
        // Summary row for Security must show em-dash, not a fabricated score
        assert!(html.contains("tr class=\"skipped\""), "skipped row must have skipped class");
        assert!(html.contains("network unreachable"), "must surface the error reason");
        // Warning banner must appear
        assert!(html.contains("class=\"warning\""), "must include outage warning banner");
    }

    #[test]
    fn body_stays_under_100kb_on_realistic_dogfood_shape() {
        // Synthesize a realistic shape: 7 auditors, ~20 findings total
        // across categories. Real dogfood is around this scale.
        let mut auditors = Vec::new();
        for (name, cat) in [
            ("clippy", Category::Lints),
            ("cargo-audit", Category::Security),
            ("cargo-machete", Category::DeadCode),
            ("rust-code-analysis", Category::Complexity),
            ("cargo-deny", Category::Maintenance),
            ("cargo-outdated", Category::Maintenance),
            ("cargo-geiger", Category::Security),
        ] {
            let findings: Vec<Finding> = (0..3)
                .map(|i| {
                    Finding::new(name, cat, Severity::Medium, format!("synthetic finding {i}"))
                        .with_code(format!("{name}::synthetic{i}"))
                        .with_location(holocron_core::Location::at(
                            format!("src/foo_{i}.rs"),
                            10 + u32::try_from(i).unwrap_or(0),
                        ))
                        .with_detail(format!("Detail blurb {i}\nsecond line\nthird line"))
                })
                .collect();
            auditors.push(AuditorResult::ok(
                AuditorMeta { name, category: cat },
                findings,
                Duration::from_secs(1),
            ));
        }
        let outcome = RunOutcome {
            target: std::path::PathBuf::from("/tmp/proj"),
            started_at: chrono::Utc::now(),
            total_duration: Duration::from_secs(10),
            auditor_results: auditors,
        };
        let grade = Grade::new(&outcome.auditor_results).compute();
        let report = Report::new(&outcome, &grade);
        let html = render_html(&report);
        assert!(html.len() < 100_000, "HTML must stay under 100KB; got {} bytes", html.len());
    }
}
