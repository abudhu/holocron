//! cargo-machete auditor — wraps `cargo machete` to find dependencies
//! declared in `Cargo.toml` that no source file actually imports.

use async_trait::async_trait;
use holocron_core::{Auditor, AuditorMeta, Category, Finding, Location, Severity};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use tokio::process::Command;

#[derive(Debug, Default)]
pub struct MacheteAuditor;

const META: AuditorMeta = AuditorMeta { name: "cargo-machete", category: Category::DeadCode };

#[async_trait]
impl Auditor for MacheteAuditor {
    fn meta(&self) -> AuditorMeta {
        META
    }

    async fn check_available(&self) -> anyhow::Result<()> {
        which::which("cargo-machete").map(|_| ()).map_err(|e| anyhow::anyhow!("{e}"))
    }

    async fn install(&self) -> anyhow::Result<()> {
        let status =
            Command::new("cargo").args(["install", "cargo-machete", "--locked"]).status().await?;
        anyhow::ensure!(status.success(), "cargo install cargo-machete failed");
        Ok(())
    }

    async fn run(&self, target: &Path) -> anyhow::Result<Vec<Finding>> {
        let output = Command::new("cargo")
            .current_dir(target)
            .args(["machete"])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .await?;

        // cargo-machete exits 1 when it finds unused deps. Not a failure.
        let stdout = String::from_utf8_lossy(&output.stdout);
        Ok(parse_machete_text(&stdout, target))
    }
}

/// Parse cargo-machete's stdout. Real output looks like:
///
/// ```text
/// cargo-machete found the following unused dependencies in this directory:
/// holocron-auditors -- ./crates/holocron-auditors/Cargo.toml:
///     cargo_metadata
///     tracing
/// holocron-core -- ./crates/holocron-core/Cargo.toml:
///     ...
///
/// (boilerplate footer about ignoring deps follows)
/// ```
///
/// We extract one Finding per dependency, scoped to the manifest path
/// reported in the header for that crate's block.
fn parse_machete_text(text: &str, target_root: &Path) -> Vec<Finding> {
    let mut findings = Vec::new();
    let mut current_manifest: Option<PathBuf> = None;
    let mut inside_findings = false;
    for raw_line in text.lines() {
        let line_trimmed_right = raw_line.trim_end();
        // Top-level header tells us we're entering the findings block.
        if line_trimmed_right.starts_with("cargo-machete found the following unused dependencies") {
            inside_findings = true;
            continue;
        }
        if !inside_findings {
            continue;
        }
        // A blank line ends the findings block. Anything after is footer text.
        if line_trimmed_right.is_empty() {
            inside_findings = false;
            current_manifest = None;
            continue;
        }
        // Crate header: "crate-name -- ./path/Cargo.toml:"
        if let Some((_, rest)) = line_trimmed_right.split_once(" -- ") {
            let manifest = rest.trim_end_matches(':').trim();
            current_manifest = Some(resolve_manifest_path(target_root, manifest));
            continue;
        }
        // Dep line: starts with whitespace, contains a single token.
        let dep = raw_line.trim();
        if dep.is_empty() || dep.contains(char::is_whitespace) {
            continue;
        }
        let Some(manifest) = current_manifest.clone() else { continue };
        let short = short_manifest(&manifest, target_root);
        let loc = Location::new(&manifest);
        findings.push(
            Finding::new(
                "cargo-machete",
                Category::DeadCode,
                Severity::Low,
                format!("unused dependency `{dep}` declared in {short}"),
            )
            .with_code("unused-dep")
            .with_location(loc),
        );
    }
    findings
}

fn resolve_manifest_path(target_root: &Path, raw: &str) -> PathBuf {
    let p = Path::new(raw.trim_start_matches("./"));
    if p.is_absolute() {
        p.to_path_buf()
    } else {
        target_root.join(p)
    }
}

fn short_manifest(manifest: &Path, target_root: &Path) -> String {
    manifest
        .strip_prefix(target_root)
        .map_or_else(|_| manifest.display().to_string(), |p| p.display().to_string())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;

    #[test]
    fn parses_real_machete_output() {
        let txt = "\
cargo-machete found the following unused dependencies in this directory:
holocron-auditors -- ./crates/holocron-auditors/Cargo.toml:
\tcargo_metadata
\ttracing
holocron-core -- ./crates/holocron-core/Cargo.toml:
\tserde_json
\tthiserror

If you believe cargo-machete has detected an unused dependency incorrectly,
you can add the dependency to the list of dependencies to ignore in the
";
        let findings = parse_machete_text(txt, Path::new("/tmp/proj"));
        assert_eq!(findings.len(), 4);
        let msgs: Vec<_> = findings.iter().map(|f| f.message.clone()).collect();
        assert!(msgs.iter().any(|m| m.contains("`cargo_metadata`")));
        assert!(msgs.iter().any(|m| m.contains("`tracing`")));
        assert!(msgs.iter().any(|m| m.contains("`serde_json`")));
        assert!(msgs.iter().any(|m| m.contains("`thiserror`")));
        // None of the boilerplate words should leak in:
        assert!(!msgs.iter().any(|m| m.contains("believe") || m.contains("ignore")));
    }

    #[test]
    fn empty_output_yields_no_findings() {
        assert!(parse_machete_text("All dependencies are used.\n", Path::new("/tmp")).is_empty());
    }

    #[test]
    fn footer_after_findings_is_ignored() {
        // Blank line then prose — must NOT be parsed as deps.
        let txt = "cargo-machete found the following unused dependencies in this directory:
crate-a -- ./Cargo.toml:
\tdead_dep

If you believe this is wrong, edit the manifest.
this directory
Done!";
        let findings = parse_machete_text(txt, Path::new("/tmp"));
        assert_eq!(findings.len(), 1);
        assert!(findings[0].message.contains("`dead_dep`"));
    }
}
