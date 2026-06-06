//! Holocron core library.
//!
//! v0.1 stub: this crate will host the `Auditor` trait, `Runner`, `Finding`
//! model, and grade calculator. See `OneDev` issues #3, #8, #9 for the
//! design landing here.

#![doc(html_root_url = "https://onedev.amitbudhu.com/holocron")]

/// Crate version, exposed for the CLI's `--version` output and report headers.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Placeholder so the crate compiles before #3 lands.
///
/// This will be replaced by the real `Auditor` trait + `Runner` in issue #3.
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
