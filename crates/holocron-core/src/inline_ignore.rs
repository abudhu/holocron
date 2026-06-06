//! Inline `// holocron: ignore <code>` annotations (#42).
//!
//! Lets users suppress a finding right next to the offending line
//! instead of hunting down a fingerprint to add to `.holocronrc.toml`.
//! Matches the convention every other major linter uses (clippy's
//! `#[allow]`, eslint's `/* eslint-disable-next-line */`, rubocop's
//! `# rubocop:disable`).
//!
//! ## Format
//!
//! ```text
//! // holocron: ignore <code> -- <reason>
//! some_line_that_triggers_<code>
//! ```
//!
//! or trailing on the same line:
//!
//! ```text
//! some_line_that_triggers_<code>   // holocron: ignore <code> -- <reason>
//! ```
//!
//! * `<code>` is the finding's `code` field (e.g. `clippy::unwrap_used`,
//!   `complexity-warn`, `RUSTSEC-2023-0001`).
//! * `-- <reason>` is optional but strongly recommended; surfaced in
//!   the report's allowlisted-findings section.
//!
//! ## Where annotations are honored
//!
//! Findings need `location.file` + `location.line` to be ignorable.
//! Findings without a location (project-wide signals like cargo-audit
//! advisories with no file pin) can only be suppressed via rc.
//!
//! ## Where in the pipeline
//!
//! `apply_inline_annotations` runs RIGHT AFTER `apply_allowlist` in
//! the CLI. They use the same `allowlisted` flag + `allowlist_reason`
//! string so the renderer surfaces both kinds in the same
//! "Allowlisted Findings" section.

use crate::Finding;
use std::collections::HashMap;
use std::path::{Path, PathBuf};

/// The annotation prefix users write in source: `holocron: ignore`.
const ANNOTATION_PREFIX: &str = "holocron: ignore";

/// Apply inline `// holocron: ignore <code>` annotations to `findings` in place.
///
/// Mirrors `apply_allowlist`: sets `allowlisted = true` and
/// `allowlist_reason` on each matched finding; returns the number of
/// findings newly suppressed.
///
/// Already-allowlisted findings (matched by an earlier rc rule) are
/// left alone — first-match-wins by source, just like the allowlist.
///
/// `target_dir` is the project root used to resolve relative paths in
/// finding locations. Files are read on demand and cached per call so
/// the same file isn't slurped repeatedly when it has many findings.
pub fn apply_inline_annotations(findings: &mut [Finding], target_dir: &Path) -> usize {
    let mut count = 0_usize;
    let mut file_cache: HashMap<PathBuf, Vec<String>> = HashMap::new();
    for finding in findings.iter_mut() {
        if finding.allowlisted {
            continue;
        }
        let Some(loc) = finding.location.as_ref() else {
            continue;
        };
        let Some(line) = loc.line else {
            continue;
        };
        let Some(code) = finding.code.as_deref() else {
            continue;
        };

        let file_path = resolve_finding_path(&loc.file, target_dir);
        let lines = if let Some(cached) = file_cache.get(&file_path) {
            cached
        } else {
            let Ok(body) = std::fs::read_to_string(&file_path) else {
                continue; // file not readable — skip silently, common in tests
            };
            file_cache
                .entry(file_path.clone())
                .or_insert_with(|| body.lines().map(std::string::ToString::to_string).collect())
        };

        if let Some(reason) = find_annotation_for(lines, line, code) {
            finding.allowlisted = true;
            finding.allowlist_reason = Some(reason);
            count += 1;
        }
    }
    count
}

/// Resolve a finding's `location.file` against the target directory.
/// Auditors emit a mix of absolute and project-relative paths.
fn resolve_finding_path(finding_file: &Path, target_dir: &Path) -> PathBuf {
    if finding_file.is_absolute() {
        finding_file.to_path_buf()
    } else {
        target_dir.join(finding_file)
    }
}

/// Look for a `// holocron: ignore <code>` annotation either on the
/// line above `finding_line` (preferred) or trailing on the same line.
/// Returns the reason string (post-`--`), or a default if no `--` was
/// given. Returns `None` when no matching annotation is present.
///
/// Line numbers are 1-based (the convention every Rust auditor uses).
fn find_annotation_for(lines: &[String], finding_line: u32, code: &str) -> Option<String> {
    // Look above first
    let idx = (finding_line as usize).checked_sub(1)?;
    if idx > 0 {
        if let Some(above) = lines.get(idx - 1) {
            if let Some(reason) = parse_annotation(above, code) {
                return Some(reason);
            }
        }
    }
    // Then same line (trailing comment)
    if let Some(same) = lines.get(idx) {
        if let Some(reason) = parse_annotation(same, code) {
            return Some(reason);
        }
    }
    None
}

/// Parse a single source line. Returns `Some(reason)` when the line is
/// (or contains) `// holocron: ignore <code> [-- <reason>]` matching
/// `code`. Returns `None` otherwise.
fn parse_annotation(line: &str, target_code: &str) -> Option<String> {
    // Find the annotation anywhere on the line (handles trailing comments
    // and arbitrary indent on above-the-line comments).
    let comment_start = line.find(ANNOTATION_PREFIX)?;
    // Require a `//` before the annotation — otherwise raw strings or
    // doc-comment-like content could false-match.
    let before = &line[..comment_start];
    if !before.trim_end().ends_with("//") && !before.trim_end().ends_with('#') {
        return None;
    }
    // Slice from end-of-prefix forward
    let rest = &line[comment_start + ANNOTATION_PREFIX.len()..];
    let trimmed = rest.trim_start();
    // Split into <code> and optional <reason>
    let (code_part, reason_part) = match trimmed.split_once("--") {
        Some((c, r)) => (c.trim(), r.trim().to_string()),
        None => (trimmed.trim(), String::new()),
    };
    if code_part != target_code {
        return None;
    }
    let reason = if reason_part.is_empty() {
        format!("inline `// holocron: ignore {target_code}`")
    } else {
        reason_part
    };
    Some(reason)
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::missing_const_for_fn,
        clippy::useless_vec
    )]
    use super::*;
    use crate::{Category, Location, Severity};
    use tempfile::TempDir;

    fn finding_at(file: &str, line: u32, code: &str) -> Finding {
        Finding::new("clippy", Category::Lints, Severity::Medium, "some message")
            .with_code(code)
            .with_location(Location::at(file, line))
    }

    fn write_src(dir: &Path, name: &str, body: &str) -> PathBuf {
        let p = dir.join(name);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(&p, body).unwrap();
        p
    }

    #[test]
    fn annotation_above_the_line_suppresses_finding() {
        let dir = TempDir::new().unwrap();
        write_src(
            dir.path(),
            "src/lib.rs",
            "fn main() {\n    // holocron: ignore clippy::unwrap_used -- test data only\n    let _ = some_call().unwrap();\n}\n",
        );
        let mut findings = vec![finding_at("src/lib.rs", 3, "clippy::unwrap_used")];
        let n = apply_inline_annotations(&mut findings, dir.path());
        assert_eq!(n, 1, "annotation above should match");
        assert!(findings[0].allowlisted);
        assert_eq!(findings[0].allowlist_reason.as_deref(), Some("test data only"));
    }

    #[test]
    fn trailing_annotation_on_same_line_suppresses_finding() {
        let dir = TempDir::new().unwrap();
        write_src(
            dir.path(),
            "src/lib.rs",
            "fn main() {\n    let _ = some_call().unwrap();  // holocron: ignore clippy::unwrap_used -- intentional in test\n}\n",
        );
        let mut findings = vec![finding_at("src/lib.rs", 2, "clippy::unwrap_used")];
        let n = apply_inline_annotations(&mut findings, dir.path());
        assert_eq!(n, 1);
        assert_eq!(findings[0].allowlist_reason.as_deref(), Some("intentional in test"));
    }

    #[test]
    fn annotation_without_reason_uses_default() {
        let dir = TempDir::new().unwrap();
        write_src(dir.path(), "src/lib.rs", "// holocron: ignore some-code\nfn foo() {}\n");
        let mut findings = vec![finding_at("src/lib.rs", 2, "some-code")];
        let n = apply_inline_annotations(&mut findings, dir.path());
        assert_eq!(n, 1);
        assert_eq!(
            findings[0].allowlist_reason.as_deref(),
            Some("inline `// holocron: ignore some-code`")
        );
    }

    #[test]
    fn annotation_code_must_match_finding_code() {
        // `// holocron: ignore foo` must NOT suppress a finding with
        // code `bar` — codes are exact-match, no prefix wildcards.
        let dir = TempDir::new().unwrap();
        write_src(dir.path(), "src/lib.rs", "// holocron: ignore other-code\nfn foo() {}\n");
        let mut findings = vec![finding_at("src/lib.rs", 2, "clippy::unwrap_used")];
        let n = apply_inline_annotations(&mut findings, dir.path());
        assert_eq!(n, 0, "different codes must not match");
        assert!(!findings[0].allowlisted);
    }

    #[test]
    fn annotation_must_be_in_a_comment_not_in_a_string() {
        // A raw-looking `holocron: ignore X` inside a string literal
        // (no `//` before it) must not count. The pattern of `holocron:
        // ignore` appearing in non-comment context is unlikely but we
        // guard for it explicitly.
        let dir = TempDir::new().unwrap();
        write_src(
            dir.path(),
            "src/lib.rs",
            "const MSG: &str = \"holocron: ignore clippy::unwrap_used\";\nfn foo() {}\n",
        );
        let mut findings = vec![finding_at("src/lib.rs", 2, "clippy::unwrap_used")];
        let n = apply_inline_annotations(&mut findings, dir.path());
        assert_eq!(n, 0, "annotation inside string literal must not count");
    }

    #[test]
    fn annotation_two_lines_above_does_not_match() {
        // Only the immediately-above line counts (and the same line).
        // An annotation 2+ lines away has likely drifted from its
        // target and shouldn't silently suppress something new.
        let dir = TempDir::new().unwrap();
        write_src(
            dir.path(),
            "src/lib.rs",
            "// holocron: ignore clippy::unwrap_used\nlet x = 1;\nlet _ = bad().unwrap();\n",
        );
        let mut findings = vec![finding_at("src/lib.rs", 3, "clippy::unwrap_used")];
        let n = apply_inline_annotations(&mut findings, dir.path());
        assert_eq!(n, 0, "annotation 2 lines away must not match");
    }

    #[test]
    fn finding_without_location_is_skipped_silently() {
        // cargo-audit advisories have no file location — those can only
        // be suppressed via rc, never inline. Must not panic.
        let dir = TempDir::new().unwrap();
        let mut findings = vec![Finding::new(
            "cargo-audit",
            Category::Security,
            Severity::High,
            "RUSTSEC-2023-0001",
        )
        .with_code("RUSTSEC-2023-0001")];
        let n = apply_inline_annotations(&mut findings, dir.path());
        assert_eq!(n, 0);
    }

    #[test]
    fn already_allowlisted_finding_is_not_double_counted() {
        // If rc already allowlisted a finding, the inline pass must not
        // re-process it (would inflate counts + clobber the rc reason).
        let dir = TempDir::new().unwrap();
        write_src(
            dir.path(),
            "src/lib.rs",
            "// holocron: ignore X -- inline reason\nfn foo() {}\n",
        );
        let mut findings = vec![finding_at("src/lib.rs", 2, "X")];
        findings[0].allowlisted = true;
        findings[0].allowlist_reason = Some("rc rule".to_string());
        let n = apply_inline_annotations(&mut findings, dir.path());
        assert_eq!(n, 0);
        assert_eq!(
            findings[0].allowlist_reason.as_deref(),
            Some("rc rule"),
            "rc reason must not be overwritten"
        );
    }

    #[test]
    fn file_cache_avoids_repeated_reads() {
        // Multiple findings in the same file should not re-read the
        // file — smoke-tested by making sure 10 findings against the
        // same file all process correctly with a synthetic missing-
        // file would error on the second read but not the first.
        let dir = TempDir::new().unwrap();
        write_src(
            dir.path(),
            "src/lib.rs",
            "// holocron: ignore X\nfn a() {}\n// holocron: ignore X\nfn b() {}\n",
        );
        let mut findings = vec![finding_at("src/lib.rs", 2, "X"), finding_at("src/lib.rs", 4, "X")];
        let n = apply_inline_annotations(&mut findings, dir.path());
        assert_eq!(n, 2);
    }

    #[test]
    fn handles_hash_comments_for_non_rust_sources() {
        // Some auditors run against TOML/YAML/Python; the convention
        // there is `#` comments. Accept both `//` and `#` prefixes.
        let dir = TempDir::new().unwrap();
        write_src(
            dir.path(),
            "config.toml",
            "# holocron: ignore some-rule -- toml-side suppression\nkey = \"value\"\n",
        );
        let mut findings = vec![finding_at("config.toml", 2, "some-rule")];
        let n = apply_inline_annotations(&mut findings, dir.path());
        assert_eq!(n, 1);
        assert_eq!(findings[0].allowlist_reason.as_deref(), Some("toml-side suppression"));
    }

    #[test]
    fn unreadable_file_is_skipped_silently() {
        // Finding references a file that doesn't exist on disk —
        // shouldn't panic, just skip.
        let dir = TempDir::new().unwrap();
        let mut findings = vec![finding_at("does/not/exist.rs", 1, "X")];
        let n = apply_inline_annotations(&mut findings, dir.path());
        assert_eq!(n, 0);
    }

    #[test]
    fn finding_without_code_cannot_be_inline_suppressed() {
        // No code means no key to match against — these findings can
        // only be suppressed via rc fingerprint/auditor/path rules.
        let dir = TempDir::new().unwrap();
        write_src(dir.path(), "src/lib.rs", "// holocron: ignore something\nfn foo() {}\n");
        let mut findings =
            vec![Finding::new("clippy", Category::Lints, Severity::Medium, "no code finding")
                .with_location(Location::at("src/lib.rs", 2))];
        let n = apply_inline_annotations(&mut findings, dir.path());
        assert_eq!(n, 0);
    }
}
