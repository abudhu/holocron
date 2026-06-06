//! Holocron core library.
//!
//! Hosts the [`Auditor`] trait, the parallel [`Runner`], the [`Finding`]
//! model, and the [`Grade`] calculator. The CLI in `holocron-cli` is a
//! thin wrapper that wires these pieces together and renders the
//! results to Markdown + JSON.
//!
//! See `OneDev` issues #3, #8, #9 for the design discussions.

#![doc(html_root_url = "https://onedev.amitbudhu.com/holocron")]

pub mod auditor;
pub mod finding;
pub mod grade;
pub mod runner;

pub use auditor::{Auditor, AuditorMeta, AuditorResult, RunStatus};
pub use finding::{Category, Finding, Location, Severity};
pub use grade::{CategoryScore, Grade, GradeReport, Letter};
pub use runner::{RunOutcome, Runner};

/// Crate version, exposed for report headers and the CLI's `--version`.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Returns the crate version string.
#[must_use]
pub const fn version() -> &'static str {
    VERSION
}

#[cfg(test)]
mod tests {
    use super::version;

    #[test]
    fn version_is_non_empty() {
        assert!(!version().is_empty());
    }
}
