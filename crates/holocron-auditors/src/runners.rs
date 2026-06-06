//! Shared subprocess-completeness helpers for auditors that shell out to
//! external tools.
//!
//! Background (#38 → #39): every auditor that runs a CLI tool faces the
//! same trap — if the tool exits non-zero and produces no parseable
//! output, returning `Ok(vec![])` silently inflates the project's grade
//! to "no findings." That's worse than the auditor not existing: the
//! product told the user "you're clean" when really the measurement
//! never happened.
//!
//! `check_singleshot_completeness` is the single-invocation analogue of
//! `geiger::check_geiger_completeness` — same idea, simpler shape because
//! these auditors invoke their tool exactly once instead of looping per
//! workspace member.

/// Decide whether a single-shot auditor invocation is "complete enough
/// to trust." Returns `Err` when the underlying process clearly failed
/// to measure anything: non-zero exit AND zero parsed findings AND
/// non-empty stderr. Any of those signals alone is fine (clean tools
/// exit zero, some clean tools emit informational stderr, and some
/// tools exit non-zero by design when findings are present).
///
/// The pathology this guards against: cargo-audit's advisory DB
/// unreachable, cargo-deny crashing on a malformed config, cargo-outdated
/// segfaulting in a container — all of which historically silently
/// produced 0-finding Ok-returns that the grader treated as "clean A+."
///
/// Returns `Ok(())` for every plausibly-honest outcome:
///   * exit succeeded → trust the (possibly empty) findings
///   * exit failed but findings present → tool's "I exit non-zero when I
///     find something" contract (cargo-audit, cargo-deny, cargo-machete)
///   * exit failed, no findings, no stderr → tool said nothing to say
///
/// Returns `Err` only for: exit failed AND no findings AND stderr ≠ empty,
/// which is the unmistakable "the tool tried to tell us something went
/// wrong" shape.
///
/// `exit_succeeded` is `ExitStatus::success()`; carrying the bool instead
/// of the whole `ExitStatus` keeps the helper trivially portable (cargo
/// targets unix + windows + wasi differently) and trivially testable
/// without per-platform `from_raw` calls.
pub(crate) fn check_singleshot_completeness(
    tool_name: &str,
    exit_succeeded: bool,
    findings_count: usize,
    stderr: &str,
) -> anyhow::Result<()> {
    if exit_succeeded {
        return Ok(());
    }
    if findings_count > 0 {
        return Ok(());
    }
    let stderr = stderr.trim();
    if stderr.is_empty() {
        return Ok(());
    }
    anyhow::bail!(
        "{tool_name} exited non-zero and produced 0 findings; the run is being \
         marked Failed so the grader reports the category as Skipped instead \
         of inflating the grade. stderr: {stderr}"
    );
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;

    #[test]
    fn exit_zero_always_ok_even_with_stderr_noise() {
        // cargo tools often emit informational warnings to stderr while
        // exiting cleanly (e.g. "warning: unused feature"). That's fine.
        let r = check_singleshot_completeness(
            "cargo-audit",
            true,
            0,
            "warning: ignoring obsolete feature flag",
        );
        assert!(r.is_ok(), "exit 0 must always be ok regardless of stderr: {r:?}");
    }

    #[test]
    fn nonzero_exit_with_findings_is_ok() {
        // cargo-audit / cargo-deny / cargo-machete all exit non-zero
        // when they find something. As long as we got findings, the
        // tool worked as designed.
        let r = check_singleshot_completeness("cargo-audit", false, 3, "some stderr");
        assert!(r.is_ok(), "non-zero exit with findings is the tool's contract: {r:?}");
    }

    #[test]
    fn nonzero_exit_no_findings_no_stderr_is_ok() {
        // Edge case: tool died completely silently (no stdout, no
        // stderr, non-zero exit). Can't prove it was a failure mode
        // vs. a no-op, so don't false-positive.
        let r = check_singleshot_completeness("cargo-audit", false, 0, "");
        assert!(r.is_ok(), "silent non-zero exit shouldn't false-positive: {r:?}");
    }

    #[test]
    fn nonzero_exit_no_findings_whitespace_stderr_is_ok() {
        // Whitespace-only stderr is the same as empty.
        let r = check_singleshot_completeness("cargo-audit", false, 0, "   \n\t  ");
        assert!(r.is_ok());
    }

    #[test]
    fn nonzero_exit_no_findings_with_stderr_bails() {
        // The classic silent-failure shape this guard exists for.
        let r = check_singleshot_completeness(
            "cargo-audit",
            false,
            0,
            "error: couldn't fetch advisory database from https://github.com/rustsec/advisory-db",
        );
        assert!(r.is_err(), "the silent-failure shape MUST bail");
        let err = format!("{}", r.unwrap_err());
        assert!(err.contains("cargo-audit"), "error must name the tool: {err}");
        assert!(err.contains("0 findings"), "error must explain the count: {err}");
        assert!(err.contains("advisory database"), "error must include upstream stderr: {err}");
    }

    #[test]
    fn tool_name_appears_in_error_for_diagnostic_routing() {
        // The error message ends up in the AuditorResult and the Markdown
        // report — needs to name the failing tool for the user to act on.
        let r = check_singleshot_completeness("cargo-deny", false, 0, "fatal: kaboom");
        assert!(r.is_err());
        let err = format!("{}", r.unwrap_err());
        assert!(err.contains("cargo-deny"), "diagnostic must route to the failing tool: {err}");
    }
}
