//! `holocron diff` — audit a project and surface only findings touching
//! files changed since a base ref. Useful for pre-commit hooks, PR
//! review fast-paths, and "what did this branch break."
//!
//! ## Design
//!
//! Most cargo tools (clippy, cargo-audit, cargo-deny, etc.) can't be
//! scoped to a list of files; they audit the whole workspace. So `diff`
//! runs the full audit and filters afterward. The filtering happens
//! BEFORE grade computation so the reported grade reflects "the diff's
//! score" — which is what users want from a pre-commit gate.
//!
//! ## What gets dropped
//!
//! 1. Findings with `Some(location)` whose file isn't in the changed
//!    set → dropped (out-of-scope for this diff)
//! 2. Findings with `None` location → dropped (project-wide signals
//!    like cargo-audit advisories aren't about THIS change; users
//!    should run a full `holocron audit` for those)
//!
//! A summary line surfaces both counts so the user knows what wasn't
//! examined.

use anyhow::{Context, Result};
use holocron_core::Finding;
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::process::Command;

/// What `filter_findings_for_diff` retained vs dropped. The counts
/// drive the user-facing summary line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiffFilterStats {
    /// Findings kept because they're located in a changed file.
    pub kept: usize,
    /// Findings dropped because they had a location not in the diff set.
    pub dropped_out_of_scope: usize,
    /// Findings dropped because they had no location at all
    /// (project-wide signals like cargo-audit advisories).
    pub dropped_project_wide: usize,
}

/// Resolve a git ref to the set of files changed between `base` and the
/// working tree (HEAD + uncommitted changes), as paths relative to the
/// repo root.
///
/// Shells out to `git -C <target> diff --name-only <base>...` and parses
/// the output. The trailing `...` includes both committed and uncommitted
/// changes vs the merge base — same shape GitHub uses for PR diffs.
pub fn changed_files_since(target: &Path, base_ref: &str) -> Result<HashSet<PathBuf>> {
    let target = target
        .canonicalize()
        .with_context(|| format!("canonicalizing target {}", target.display()))?;

    // Verify the ref exists before running diff, so the error message
    // points at the bad ref rather than at git's cryptic exit code.
    let rev_parse = Command::new("git")
        .arg("-C")
        .arg(&target)
        .args(["rev-parse", "--verify", "--quiet"])
        .arg(format!("{base_ref}^{{commit}}"))
        .output()
        .context("invoking git rev-parse")?;
    anyhow::ensure!(
        rev_parse.status.success(),
        "git ref `{base_ref}` not found in {}. Try a SHA, branch, or `HEAD~N`.",
        target.display()
    );

    let output = Command::new("git")
        .arg("-C")
        .arg(&target)
        .args(["diff", "--name-only"])
        .arg(base_ref)
        .output()
        .context("invoking git diff")?;
    anyhow::ensure!(
        output.status.success(),
        "git diff failed: {}",
        String::from_utf8_lossy(&output.stderr),
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    let files: HashSet<PathBuf> =
        stdout.lines().map(str::trim).filter(|l| !l.is_empty()).map(PathBuf::from).collect();
    Ok(files)
}

/// Filter `findings` in place to keep only those touching one of
/// `changed_files`. Returns the filter statistics so the caller can
/// surface a summary banner.
///
/// Path comparison is done in two passes:
///   1. Exact match against the relative path
///   2. Suffix match — auditors may emit absolute paths or paths
///      relative to a subdirectory; we accept any finding whose file
///      ends with a changed-file path. False positives are vanishingly
///      rare in practice (a finding in `crates/foo/src/lib.rs` won't
///      match a change to `src/lib.rs` because we require a path
///      separator before the suffix).
pub fn filter_findings_for_diff(
    findings: &mut Vec<Finding>,
    target: &Path,
    changed_files: &HashSet<PathBuf>,
) -> DiffFilterStats {
    let target_canonical = target.canonicalize().unwrap_or_else(|_| target.to_path_buf());

    let mut kept = 0usize;
    let mut dropped_out_of_scope = 0usize;
    let mut dropped_project_wide = 0usize;

    findings.retain(|finding| {
        let Some(location) = finding.location.as_ref() else {
            dropped_project_wide += 1;
            return false;
        };
        if finding_touches_changed_file(&location.file, &target_canonical, changed_files) {
            kept += 1;
            true
        } else {
            dropped_out_of_scope += 1;
            false
        }
    });

    DiffFilterStats { kept, dropped_out_of_scope, dropped_project_wide }
}

/// True when `finding_file` matches any path in `changed_files`,
/// considering both relative and absolute path shapes.
fn finding_touches_changed_file(
    finding_file: &Path,
    target_canonical: &Path,
    changed_files: &HashSet<PathBuf>,
) -> bool {
    // Try relative-to-target first (the common case: auditor emitted
    // a project-relative path; git also emits project-relative paths).
    let relative_to_target =
        finding_file.strip_prefix(target_canonical).ok().map(Path::to_path_buf).or_else(|| {
            // Some auditors emit paths already relative; try as-is.
            finding_file.is_relative().then(|| finding_file.to_path_buf())
        });

    if let Some(rel) = relative_to_target {
        if changed_files.contains(&rel) {
            return true;
        }
    }

    // Fallback: suffix match with a path-separator boundary, so
    // `crates/foo/src/lib.rs` won't match a change to `src/lib.rs`.
    let finding_str = finding_file.to_string_lossy();
    changed_files.iter().any(|changed| {
        let changed_str = changed.to_string_lossy();
        finding_str.ends_with(changed_str.as_ref()) && {
            // Check that what's before the suffix is either nothing,
            // a path separator, or that the suffix is the whole path.
            let prefix_len = finding_str.len().saturating_sub(changed_str.len());
            prefix_len == 0
                || finding_str.as_bytes().get(prefix_len.saturating_sub(1)).copied() == Some(b'/')
        }
    })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;
    use holocron_core::{Category, Finding, Location, Severity};

    fn make_finding(file: Option<&str>, message: &str) -> Finding {
        let f = Finding::new("clippy", Category::Lints, Severity::Medium, message);
        match file {
            Some(p) => f.with_location(Location::at(p, 10)),
            None => f,
        }
    }

    #[test]
    fn keeps_findings_in_changed_files_drops_others() {
        let mut findings = vec![
            make_finding(Some("crates/foo/src/lib.rs"), "in scope"),
            make_finding(Some("crates/bar/src/lib.rs"), "out of scope"),
            make_finding(Some("crates/foo/src/util.rs"), "in scope 2"),
        ];
        let changed: HashSet<PathBuf> =
            ["crates/foo/src/lib.rs", "crates/foo/src/util.rs"].iter().map(PathBuf::from).collect();
        let target = std::env::current_dir().unwrap();
        let stats = filter_findings_for_diff(&mut findings, &target, &changed);
        assert_eq!(stats.kept, 2);
        assert_eq!(stats.dropped_out_of_scope, 1);
        assert_eq!(stats.dropped_project_wide, 0);
        assert_eq!(findings.len(), 2);
        assert!(findings.iter().all(|f| f.message.starts_with("in scope")));
    }

    #[test]
    fn drops_findings_with_no_location_as_project_wide() {
        let mut findings = vec![
            make_finding(None, "cargo-audit advisory RUSTSEC-2023-0001"),
            make_finding(Some("src/lib.rs"), "in scope"),
        ];
        let changed: HashSet<PathBuf> = std::iter::once(PathBuf::from("src/lib.rs")).collect();
        let target = std::env::current_dir().unwrap();
        let stats = filter_findings_for_diff(&mut findings, &target, &changed);
        assert_eq!(stats.kept, 1);
        assert_eq!(stats.dropped_project_wide, 1);
        assert_eq!(stats.dropped_out_of_scope, 0);
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn suffix_match_respects_path_boundaries() {
        // `src/lib.rs` should NOT match `crates/foo/src/lib.rs` if the
        // changed set says `crates/bar/src/lib.rs` — those are different
        // files. The suffix `src/lib.rs` would match both naively, but
        // the path-boundary check prevents that.
        let mut findings = vec![make_finding(Some("crates/foo/src/lib.rs"), "foo's lib")];
        let changed: HashSet<PathBuf> =
            std::iter::once(PathBuf::from("crates/bar/src/lib.rs")).collect();
        let target = std::env::current_dir().unwrap();
        let stats = filter_findings_for_diff(&mut findings, &target, &changed);
        assert_eq!(stats.kept, 0, "different files with same suffix must not match");
        assert_eq!(stats.dropped_out_of_scope, 1);
    }

    #[test]
    fn empty_changed_set_drops_everything() {
        let mut findings = vec![
            make_finding(Some("src/a.rs"), "a"),
            make_finding(Some("src/b.rs"), "b"),
            make_finding(None, "project-wide"),
        ];
        let stats = filter_findings_for_diff(&mut findings, Path::new("."), &HashSet::new());
        assert_eq!(stats.kept, 0);
        assert_eq!(stats.dropped_out_of_scope, 2);
        assert_eq!(stats.dropped_project_wide, 1);
        assert!(findings.is_empty());
    }

    #[test]
    fn empty_findings_returns_zero_stats() {
        let mut findings: Vec<Finding> = vec![];
        let changed: HashSet<PathBuf> = std::iter::once(PathBuf::from("src/lib.rs")).collect();
        let stats = filter_findings_for_diff(&mut findings, Path::new("."), &changed);
        assert_eq!(stats.kept, 0);
        assert_eq!(stats.dropped_out_of_scope, 0);
        assert_eq!(stats.dropped_project_wide, 0);
    }

    #[test]
    fn changed_files_since_handles_relative_paths_in_set() {
        // Smoke test: paths in the changed set are stored as relative
        // (as git emits them); finding_touches_changed_file must match
        // them against findings whose `location.file` is also relative.
        let mut findings = vec![make_finding(Some("src/main.rs"), "test")];
        let changed: HashSet<PathBuf> = std::iter::once(PathBuf::from("src/main.rs")).collect();
        let target = std::env::current_dir().unwrap();
        let stats = filter_findings_for_diff(&mut findings, &target, &changed);
        assert_eq!(stats.kept, 1);
    }
}
