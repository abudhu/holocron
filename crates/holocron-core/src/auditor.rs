//! The [`Auditor`] trait — every external tool that contributes findings
//! implements this interface. The [`Runner`](crate::runner::Runner) drives
//! them in parallel.

use crate::finding::{Category, Finding};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::time::Duration;

/// The category an auditor primarily contributes to. Used to label the
/// grade-report sections — individual findings may still cross-cut other
/// categories.
#[derive(Debug, Clone, Copy)]
pub struct AuditorMeta {
    pub name: &'static str,
    pub category: Category,
}

/// Final status of one auditor run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RunStatus {
    /// Tool ran and produced findings (possibly zero).
    Ok,
    /// Tool was skipped because the binary is missing and install was disabled.
    SkippedMissing,
    /// Tool ran but exited non-zero or produced unparseable output.
    Failed,
    /// Tool exceeded the configured timeout.
    TimedOut,
}

/// The outcome of one auditor run, including findings and timing.
#[derive(Debug, Clone)]
pub struct AuditorResult {
    pub auditor: &'static str,
    pub category: Category,
    pub status: RunStatus,
    pub findings: Vec<Finding>,
    pub duration: Duration,
    pub error: Option<String>,
}

impl AuditorResult {
    #[must_use]
    pub const fn ok(meta: AuditorMeta, findings: Vec<Finding>, duration: Duration) -> Self {
        Self {
            auditor: meta.name,
            category: meta.category,
            status: RunStatus::Ok,
            findings,
            duration,
            error: None,
        }
    }

    #[must_use]
    pub fn failed(meta: AuditorMeta, error: impl Into<String>, duration: Duration) -> Self {
        Self {
            auditor: meta.name,
            category: meta.category,
            status: RunStatus::Failed,
            findings: vec![],
            duration,
            error: Some(error.into()),
        }
    }

    #[must_use]
    pub fn timed_out(meta: AuditorMeta, duration: Duration) -> Self {
        Self {
            auditor: meta.name,
            category: meta.category,
            status: RunStatus::TimedOut,
            findings: vec![],
            duration,
            error: Some(format!("exceeded timeout of {duration:?}")),
        }
    }

    #[must_use]
    pub fn skipped_missing(meta: AuditorMeta) -> Self {
        Self {
            auditor: meta.name,
            category: meta.category,
            status: RunStatus::SkippedMissing,
            findings: vec![],
            duration: Duration::ZERO,
            error: Some(
                "binary not found and --install-missing is false; install manually to enable"
                    .to_string(),
            ),
        }
    }
}

/// The plug-in surface every external audit tool implements.
///
/// Auditors are async because most of them shell out to subprocesses,
/// and the [`Runner`](crate::runner::Runner) executes them concurrently
/// via [`tokio::task::JoinSet`].
#[async_trait]
pub trait Auditor: Send + Sync {
    /// Stable name + category metadata.
    fn meta(&self) -> AuditorMeta;

    /// Check whether the auditor's external tool is available. Default
    /// impl returns `Ok(())` — tools that need an external binary should
    /// override this to call e.g. `which::which("cargo-audit")`.
    async fn check_available(&self) -> anyhow::Result<()> {
        Ok(())
    }

    /// Install the auditor's external tool. Called by the [`Runner`] only
    /// when `check_available()` returned `Err` and the user opted in to
    /// `--install-missing`. Default impl returns an error explaining
    /// there's no automated install path.
    async fn install(&self) -> anyhow::Result<()> {
        anyhow::bail!("no automated install for {}", self.meta().name)
    }

    /// Run the audit against the target project root. Implementations
    /// should respect cancellation by using `tokio::select!` with the
    /// runner-provided timeout — the [`Runner`] wraps every call in a
    /// `tokio::time::timeout` so a misbehaving auditor can't block the
    /// pipeline.
    async fn run(&self, target: &Path) -> anyhow::Result<Vec<Finding>>;
}
