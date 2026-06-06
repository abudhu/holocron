//! Complexity auditor — wraps `rust-code-analysis-cli` to extract
//! cyclomatic, cognitive, and maintainability metrics per function,
//! and flags hotspots above configurable thresholds.

use async_trait::async_trait;
use holocron_core::{Auditor, AuditorMeta, Category, Finding, Location, Severity};
use serde::Deserialize;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use tempfile::TempDir;
use tokio::process::Command;
use walkdir::WalkDir;

/// Thresholds for what counts as a complexity "hotspot".
#[derive(Debug, Clone, Copy)]
pub struct ComplexityThresholds {
    pub cyclomatic_warn: u32,
    pub cyclomatic_high: u32,
    pub cognitive_warn: u32,
}

impl Default for ComplexityThresholds {
    fn default() -> Self {
        Self { cyclomatic_warn: 15, cyclomatic_high: 25, cognitive_warn: 20 }
    }
}

/// Auditor that runs rust-code-analysis over the `src/` tree.
#[derive(Debug, Default)]
pub struct ComplexityAuditor {
    pub thresholds: ComplexityThresholds,
}

const META: AuditorMeta =
    AuditorMeta { name: "rust-code-analysis", category: Category::Complexity };

#[async_trait]
impl Auditor for ComplexityAuditor {
    fn meta(&self) -> AuditorMeta {
        META
    }

    async fn check_available(&self) -> anyhow::Result<()> {
        which::which("rust-code-analysis-cli").map(|_| ()).map_err(|e| anyhow::anyhow!("{e}"))
    }

    async fn install(&self) -> anyhow::Result<()> {
        let status = Command::new("cargo")
            .args([
                "install",
                "--git",
                "https://github.com/mozilla/rust-code-analysis",
                "rust-code-analysis-cli",
                "--locked",
            ])
            .status()
            .await?;
        anyhow::ensure!(status.success(), "cargo install rust-code-analysis-cli failed");
        Ok(())
    }

    async fn run(&self, target: &Path) -> anyhow::Result<Vec<Finding>> {
        // rust-code-analysis-cli writes one JSON file per source file
        // into the `-o` directory. We point it at every `src/` tree we
        // can find (workspaces have multiple).
        let src_dirs = find_src_dirs(target);
        if src_dirs.is_empty() {
            // Fall back to scanning the whole target.
            return run_against(self, target, target).await;
        }
        let mut all = Vec::new();
        for dir in src_dirs {
            let findings = run_against(self, target, &dir).await?;
            all.extend(findings);
        }
        Ok(all)
    }
}

async fn run_against(
    auditor: &ComplexityAuditor,
    project_root: &Path,
    scan_root: &Path,
) -> anyhow::Result<Vec<Finding>> {
    let out = TempDir::new()?;
    let status = Command::new("rust-code-analysis-cli")
        .arg("-p")
        .arg(scan_root)
        .arg("-m")
        .arg("-O")
        .arg("json")
        .arg("-o")
        .arg(out.path())
        .arg("--language-type=rust")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .await?;
    anyhow::ensure!(status.success(), "rust-code-analysis-cli exited {status}");

    let mut findings = Vec::new();
    for entry in WalkDir::new(out.path()).into_iter().filter_map(Result::ok) {
        if !entry.file_type().is_file() {
            continue;
        }
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        let bytes = std::fs::read(path)?;
        let file_report: FileMetrics = match serde_json::from_slice(&bytes) {
            Ok(r) => r,
            Err(_) => continue,
        };
        collect_hotspots(&file_report, project_root, &auditor.thresholds, &mut findings);
    }
    Ok(findings)
}

/// Safe-truncating `f64 → u32` for complexity metrics. Saturates at `u32::MAX`.
///
/// The bounds checks above mean the final cast is provably safe, but
/// clippy can't prove that statically — hence the targeted allows.
#[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
fn f64_to_u32(v: f64) -> u32 {
    let r = v.round();
    if r.is_sign_negative() {
        0
    } else if r >= f64::from(u32::MAX) {
        u32::MAX
    } else {
        r as u32
    }
}

fn collect_hotspots(
    file: &FileMetrics,
    project_root: &Path,
    thresholds: &ComplexityThresholds,
    out: &mut Vec<Finding>,
) {
    let root = file.as_space();
    walk_spaces(&root, &file.name, project_root, thresholds, out);
}

fn walk_spaces(
    space: &Space,
    file_name: &str,
    project_root: &Path,
    thresholds: &ComplexityThresholds,
    out: &mut Vec<Finding>,
) {
    let cyclomatic = space.metrics.cyclomatic.map_or(0_u32, |c| f64_to_u32(c.sum));
    let cognitive = space.metrics.cognitive.map_or(0_u32, |c| f64_to_u32(c.sum));

    // Flag functions only — file-level totals are also reported but we
    // don't want to double-count them as findings (they aggregate the
    // function totals).
    if matches!(space.kind.as_str(), "function" | "method" | "closure") {
        let severity = if cyclomatic >= thresholds.cyclomatic_high {
            Severity::High
        } else if cyclomatic >= thresholds.cyclomatic_warn || cognitive >= thresholds.cognitive_warn
        {
            Severity::Medium
        } else {
            Severity::Info
        };

        if !matches!(severity, Severity::Info) {
            let display_path = display_path(file_name, project_root);
            let msg = format!(
                "function `{}` is complex: cyclomatic={cyclomatic}, cognitive={cognitive}",
                space.name.as_deref().unwrap_or("(anonymous)"),
            );
            let loc = Location::at(&display_path, space.start_line);
            let detail = format!(
                "Thresholds: cyclomatic warn ≥ {}, high ≥ {}; cognitive warn ≥ {}.\n\
                 Function spans lines {}–{} ({} lines).",
                thresholds.cyclomatic_warn,
                thresholds.cyclomatic_high,
                thresholds.cognitive_warn,
                space.start_line,
                space.end_line,
                space.end_line.saturating_sub(space.start_line) + 1,
            );
            out.push(
                Finding::new("rust-code-analysis", Category::Complexity, severity, msg)
                    .with_code(if cyclomatic >= thresholds.cyclomatic_high {
                        "complexity-high"
                    } else {
                        "complexity-warn"
                    })
                    .with_detail(detail)
                    .with_location(loc),
            );
        }
    }

    for child in &space.spaces {
        walk_spaces(child, file_name, project_root, thresholds, out);
    }
}

fn display_path(file_name: &str, project_root: &Path) -> PathBuf {
    let p = Path::new(file_name);
    p.strip_prefix(project_root).map_or_else(|_| p.to_path_buf(), PathBuf::from)
}

fn find_src_dirs(root: &Path) -> Vec<PathBuf> {
    let mut dirs = Vec::new();
    for entry in WalkDir::new(root)
        .max_depth(4)
        .into_iter()
        .filter_entry(|e| {
            // Don't descend into target/, .git/, node_modules/, etc.
            let name = e.file_name().to_string_lossy();
            !matches!(
                name.as_ref(),
                "target" | ".git" | "node_modules" | ".cargo-home" | ".holocron"
            )
        })
        .filter_map(Result::ok)
    {
        if entry.file_type().is_dir() && entry.file_name() == "src" {
            // Make sure its parent has a Cargo.toml — that's a real crate dir.
            if entry.path().parent().is_some_and(|p| p.join("Cargo.toml").is_file()) {
                dirs.push(entry.path().to_path_buf());
            }
        }
    }
    dirs
}

// --- rust-code-analysis JSON schema (trimmed). ---

#[derive(Debug, Deserialize)]
struct FileMetrics {
    name: String,
    #[serde(default)]
    spaces: Vec<Space>,
    #[serde(default)]
    metrics: Metrics,
    #[serde(default)]
    kind: String,
    #[serde(default)]
    start_line: u32,
    #[serde(default)]
    end_line: u32,
}

// Recursive — each Space can contain child Spaces (modules, fns, etc.)
#[derive(Debug, Deserialize)]
struct Space {
    #[serde(default)]
    name: Option<String>,
    kind: String,
    start_line: u32,
    end_line: u32,
    #[serde(default)]
    metrics: Metrics,
    #[serde(default)]
    spaces: Vec<Self>,
}

#[derive(Debug, Deserialize, Default)]
struct Metrics {
    #[serde(default)]
    cyclomatic: Option<MetricGroup>,
    #[serde(default)]
    cognitive: Option<MetricGroup>,
}

#[derive(Debug, Deserialize, Default, Clone, Copy)]
struct MetricGroup {
    #[serde(default)]
    sum: f64,
}

// Convert FileMetrics → Space for the top-level walk so we can reuse
// `walk_spaces`. We treat the file root as a synthetic space.
impl FileMetrics {
    fn as_space(&self) -> Space {
        Space {
            name: Some(self.name.clone()),
            kind: self.kind.clone(),
            start_line: self.start_line,
            end_line: self.end_line,
            metrics: self.metrics.clone(),
            spaces: self.spaces.clone(),
        }
    }
}

// Need Clone for spaces in as_space; derive it.
impl Clone for Space {
    fn clone(&self) -> Self {
        Self {
            name: self.name.clone(),
            kind: self.kind.clone(),
            start_line: self.start_line,
            end_line: self.end_line,
            metrics: self.metrics.clone(),
            spaces: self.spaces.clone(),
        }
    }
}
impl Clone for Metrics {
    fn clone(&self) -> Self {
        Self { cyclomatic: self.cyclomatic, cognitive: self.cognitive }
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

    fn space(name: &str, kind: &str, cyc: u32, cog: u32) -> Space {
        Space {
            name: Some(name.to_string()),
            kind: kind.to_string(),
            start_line: 10,
            end_line: 80,
            metrics: Metrics {
                cyclomatic: Some(MetricGroup { sum: f64::from(cyc) }),
                cognitive: Some(MetricGroup { sum: f64::from(cog) }),
            },
            spaces: vec![],
        }
    }

    #[test]
    fn flags_high_cyclomatic_function() {
        let file = FileMetrics {
            name: "/tmp/proj/src/lib.rs".to_string(),
            spaces: vec![space("complex_fn", "function", 30, 10)],
            metrics: Metrics::default(),
            kind: "unit".to_string(),
            start_line: 1,
            end_line: 200,
        };
        let mut findings = vec![];
        collect_hotspots(
            &file,
            Path::new("/tmp/proj"),
            &ComplexityThresholds::default(),
            &mut findings,
        );
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::High);
        assert!(findings[0].message.contains("complex_fn"));
    }

    #[test]
    fn ignores_simple_functions() {
        let file = FileMetrics {
            name: "/tmp/proj/src/lib.rs".to_string(),
            spaces: vec![space("simple_fn", "function", 3, 2)],
            metrics: Metrics::default(),
            kind: "unit".to_string(),
            start_line: 1,
            end_line: 50,
        };
        let mut findings = vec![];
        collect_hotspots(
            &file,
            Path::new("/tmp/proj"),
            &ComplexityThresholds::default(),
            &mut findings,
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn medium_severity_at_warn_threshold() {
        let file = FileMetrics {
            name: "/tmp/proj/src/lib.rs".to_string(),
            spaces: vec![space("medium_fn", "function", 18, 5)],
            metrics: Metrics::default(),
            kind: "unit".to_string(),
            start_line: 1,
            end_line: 50,
        };
        let mut findings = vec![];
        collect_hotspots(
            &file,
            Path::new("/tmp/proj"),
            &ComplexityThresholds::default(),
            &mut findings,
        );
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Medium);
    }
}
