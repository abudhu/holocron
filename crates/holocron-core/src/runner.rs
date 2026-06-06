//! The parallel [`Runner`] — orchestrates a set of [`Auditor`]s against
//! a target Rust project and collects their results.

use crate::auditor::{Auditor, AuditorResult, RunStatus};
use crate::finding::Finding;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::task::JoinSet;
use tokio::time::timeout;
use tracing::{info, warn};

/// Aggregate result of one run across all configured auditors.
#[derive(Debug, Clone)]
pub struct RunOutcome {
    pub target: PathBuf,
    pub started_at: chrono::DateTime<chrono::Utc>,
    pub total_duration: Duration,
    pub auditor_results: Vec<AuditorResult>,
}

impl RunOutcome {
    /// Flattened list of every finding across all auditors, sorted and
    /// deduplicated by stable fingerprint. Cargo emits the same clippy
    /// warning once per target (lib, lib test, doctest, bin, ...); dedup
    /// collapses them so the human report and the grade math both see
    /// each finding exactly once.
    #[must_use]
    pub fn all_findings(&self) -> Vec<Finding> {
        let mut seen = std::collections::HashSet::<String>::new();
        let mut all: Vec<Finding> = self
            .auditor_results
            .iter()
            .flat_map(|r| r.findings.clone())
            .filter(|f| seen.insert(f.fingerprint.clone()))
            .collect();
        all.sort();
        all
    }

    /// Did any auditor fail outright?
    #[must_use]
    pub fn any_failures(&self) -> bool {
        self.auditor_results
            .iter()
            .any(|r| matches!(r.status, RunStatus::Failed | RunStatus::TimedOut))
    }
}

/// Orchestrates a set of auditors. Build with [`Runner::new`], then
/// register auditors with [`Runner::with_auditor`], then call
/// [`Runner::run`].
pub struct Runner {
    target: PathBuf,
    auditors: Vec<Arc<dyn Auditor>>,
    per_auditor_timeout: Duration,
    install_missing: bool,
}

impl Runner {
    /// Construct a runner aimed at a target project root (must contain
    /// `Cargo.toml`).
    #[must_use]
    pub fn new(target: impl Into<PathBuf>) -> Self {
        Self {
            target: target.into(),
            auditors: vec![],
            per_auditor_timeout: Duration::from_secs(300),
            install_missing: false,
        }
    }

    /// Register an auditor.
    #[must_use]
    pub fn with_auditor(mut self, auditor: Arc<dyn Auditor>) -> Self {
        self.auditors.push(auditor);
        self
    }

    /// Override the per-auditor timeout. Default 5 minutes.
    #[must_use]
    pub const fn with_timeout(mut self, t: Duration) -> Self {
        self.per_auditor_timeout = t;
        self
    }

    /// Allow the runner to install missing external binaries. Off by default
    /// — the CLI sets this from `--install-missing`.
    #[must_use]
    pub const fn with_install_missing(mut self, install: bool) -> Self {
        self.install_missing = install;
        self
    }

    /// Run every registered auditor in parallel. Each auditor is wrapped in
    /// `tokio::time::timeout`; if it panics or returns `Err`, that auditor's
    /// result reports `Failed` but the rest of the pipeline keeps going.
    ///
    /// # Errors
    /// Returns an error if `target` is not a Rust project (no `Cargo.toml`).
    pub async fn run(self) -> anyhow::Result<RunOutcome> {
        anyhow::ensure!(
            self.target.join("Cargo.toml").is_file(),
            "target {} does not look like a Rust project (no Cargo.toml at root)",
            self.target.display()
        );

        let started_at = chrono::Utc::now();
        let start = Instant::now();
        let target = Arc::new(self.target.clone());

        let mut set: JoinSet<AuditorResult> = JoinSet::new();
        for auditor in &self.auditors {
            let auditor = Arc::clone(auditor);
            let target = Arc::clone(&target);
            let auditor_timeout = self.per_auditor_timeout;
            let install_missing = self.install_missing;
            set.spawn(async move {
                run_one(auditor, target.as_path(), auditor_timeout, install_missing).await
            });
        }

        let mut results = Vec::with_capacity(self.auditors.len());
        while let Some(joined) = set.join_next().await {
            match joined {
                Ok(result) => results.push(result),
                Err(e) => {
                    warn!(error = %e, "auditor task panicked or was cancelled");
                }
            }
        }

        // Stable ordering: by AuditorMeta.name so the report layout is deterministic.
        results.sort_by(|a, b| a.auditor.cmp(b.auditor));

        Ok(RunOutcome {
            target: self.target,
            started_at,
            total_duration: start.elapsed(),
            auditor_results: results,
        })
    }
}

async fn run_one(
    auditor: Arc<dyn Auditor>,
    target: &Path,
    auditor_timeout: Duration,
    install_missing: bool,
) -> AuditorResult {
    let meta = auditor.meta();
    let start = Instant::now();

    // Pre-flight: is the tool available?
    if let Err(e) = auditor.check_available().await {
        if install_missing {
            info!(auditor = meta.name, "binary missing — attempting install");
            if let Err(install_err) = auditor.install().await {
                return AuditorResult::failed(
                    meta,
                    format!(
                        "availability check failed: {e}; install attempt failed: {install_err}"
                    ),
                    start.elapsed(),
                );
            }
        } else {
            return AuditorResult::skipped_missing(meta);
        }
    }

    // Run with timeout — a hung auditor cannot stall the whole pipeline.
    match timeout(auditor_timeout, auditor.run(target)).await {
        Ok(Ok(findings)) => AuditorResult::ok(meta, findings, start.elapsed()),
        Ok(Err(e)) => AuditorResult::failed(meta, e.to_string(), start.elapsed()),
        Err(_) => AuditorResult::timed_out(meta, auditor_timeout),
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
    use async_trait::async_trait;
    // Reserved for future use — leaves room for tracking auditor invocation counts in tests.
    #[allow(dead_code)]
    static INVOCATIONS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    use tempfile::TempDir;

    struct FakeAuditor {
        name: &'static str,
        findings_count: usize,
        delay_ms: u64,
        fail: bool,
    }

    #[async_trait]
    impl Auditor for FakeAuditor {
        fn meta(&self) -> AuditorMeta {
            AuditorMeta { name: self.name, category: Category::Lints }
        }
        async fn run(&self, _target: &Path) -> anyhow::Result<Vec<Finding>> {
            tokio::time::sleep(Duration::from_millis(self.delay_ms)).await;
            if self.fail {
                anyhow::bail!("simulated failure in {}", self.name);
            }
            Ok((0..self.findings_count)
                .map(|i| Finding::new(self.name, Category::Lints, Severity::Low, format!("f-{i}")))
                .collect())
        }
    }

    struct SlowAuditor;
    #[async_trait]
    impl Auditor for SlowAuditor {
        fn meta(&self) -> AuditorMeta {
            AuditorMeta { name: "slow", category: Category::Lints }
        }
        async fn run(&self, _target: &Path) -> anyhow::Result<Vec<Finding>> {
            tokio::time::sleep(Duration::from_secs(60)).await;
            Ok(vec![])
        }
    }

    fn make_target() -> TempDir {
        let d = TempDir::new().unwrap();
        std::fs::write(
            d.path().join("Cargo.toml"),
            "[package]\nname=\"x\"\nversion=\"0.1.0\"\nedition=\"2021\"\n",
        )
        .unwrap();
        d
    }

    #[tokio::test]
    async fn runs_multiple_auditors_in_parallel() {
        let target = make_target();
        let start = Instant::now();
        let outcome = Runner::new(target.path())
            .with_auditor(Arc::new(FakeAuditor {
                name: "a",
                findings_count: 2,
                delay_ms: 100,
                fail: false,
            }))
            .with_auditor(Arc::new(FakeAuditor {
                name: "b",
                findings_count: 3,
                delay_ms: 100,
                fail: false,
            }))
            .with_auditor(Arc::new(FakeAuditor {
                name: "c",
                findings_count: 1,
                delay_ms: 100,
                fail: false,
            }))
            .run()
            .await
            .unwrap();
        let elapsed = start.elapsed();

        assert_eq!(outcome.auditor_results.len(), 3);
        assert_eq!(outcome.all_findings().len(), 6);
        // If they ran serially, we'd be at >=300ms. Parallel should be near 100ms (give it 250ms slack on slow CI).
        assert!(
            elapsed < Duration::from_millis(250),
            "expected parallel execution (~100ms), got {elapsed:?}"
        );
    }

    #[tokio::test]
    async fn isolates_failing_auditor() {
        let target = make_target();
        let outcome = Runner::new(target.path())
            .with_auditor(Arc::new(FakeAuditor {
                name: "good",
                findings_count: 1,
                delay_ms: 10,
                fail: false,
            }))
            .with_auditor(Arc::new(FakeAuditor {
                name: "bad",
                findings_count: 0,
                delay_ms: 10,
                fail: true,
            }))
            .run()
            .await
            .unwrap();

        let good = outcome.auditor_results.iter().find(|r| r.auditor == "good").unwrap();
        let bad = outcome.auditor_results.iter().find(|r| r.auditor == "bad").unwrap();
        assert_eq!(good.status, RunStatus::Ok);
        assert_eq!(bad.status, RunStatus::Failed);
        assert!(bad.error.as_deref().unwrap().contains("simulated failure"));
        assert!(outcome.any_failures());
    }

    #[tokio::test]
    async fn enforces_per_auditor_timeout() {
        let target = make_target();
        let outcome = Runner::new(target.path())
            .with_timeout(Duration::from_millis(100))
            .with_auditor(Arc::new(SlowAuditor))
            .run()
            .await
            .unwrap();

        let result = &outcome.auditor_results[0];
        assert_eq!(result.status, RunStatus::TimedOut);
    }

    #[tokio::test]
    async fn rejects_non_rust_target() {
        let d = TempDir::new().unwrap();
        let err = Runner::new(d.path())
            .with_auditor(Arc::new(FakeAuditor {
                name: "a",
                findings_count: 0,
                delay_ms: 0,
                fail: false,
            }))
            .run()
            .await
            .unwrap_err();
        assert!(err.to_string().contains("Cargo.toml"));
    }
}
