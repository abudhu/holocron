//! Clippy auditor — wraps `cargo clippy --message-format=json`.
//!
//! Cargo emits NDJSON to stdout. Each line that's a `compiler-message`
//! and carries a clippy lint code becomes a [`Finding`]. We override
//! severity for `clippy::correctness` lints (always High) because the
//! tool's "warning" level under-sells them.

use async_trait::async_trait;
use holocron_core::{Auditor, AuditorMeta, Category, Finding, Location, Severity};
use serde::Deserialize;
use std::path::Path;
use std::process::Stdio;
use tokio::process::Command;

/// Auditor that wraps `cargo clippy` with pedantic + nursery groups.
#[derive(Debug, Default)]
pub struct ClippyAuditor {
    /// Optionally pass extra `-W` / `-A` flags. Empty = use the
    /// pedantic + nursery defaults.
    pub extra_warn_flags: Vec<String>,
}

const META: AuditorMeta = AuditorMeta { name: "clippy", category: Category::Lints };

#[async_trait]
impl Auditor for ClippyAuditor {
    fn meta(&self) -> AuditorMeta {
        META
    }

    async fn check_available(&self) -> anyhow::Result<()> {
        // Clippy is a rustup component, not a standalone binary. We
        // probe it via `cargo clippy --version`.
        let out = Command::new("cargo").arg("clippy").arg("--version").output().await;
        match out {
            Ok(o) if o.status.success() => Ok(()),
            Ok(o) => anyhow::bail!(
                "cargo clippy --version exited {}: {}",
                o.status,
                String::from_utf8_lossy(&o.stderr)
            ),
            Err(e) => anyhow::bail!("cargo not available: {e}"),
        }
    }

    async fn install(&self) -> anyhow::Result<()> {
        let status = Command::new("rustup").args(["component", "add", "clippy"]).status().await?;
        anyhow::ensure!(status.success(), "rustup component add clippy failed");
        Ok(())
    }

    async fn run(&self, target: &Path) -> anyhow::Result<Vec<Finding>> {
        let mut cmd = Command::new("cargo");
        cmd.current_dir(target)
            .arg("clippy")
            .arg("--all-targets")
            .arg("--all-features")
            .arg("--message-format=json")
            .arg("--quiet")
            .arg("--")
            .arg("-W")
            .arg("clippy::pedantic")
            .arg("-W")
            .arg("clippy::nursery");
        for flag in &self.extra_warn_flags {
            cmd.arg("-W").arg(flag);
        }
        cmd.stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped());

        let output = cmd.output().await?;
        // Note: clippy returns non-zero when there are warnings; we
        // explicitly do NOT pass -D warnings here because we want to
        // collect every diagnostic regardless of severity.
        let stdout = String::from_utf8_lossy(&output.stdout);
        let findings = parse_clippy_stream(&stdout, target);
        Ok(findings)
    }
}

/// Parse a stream of newline-delimited cargo JSON messages and extract
/// clippy findings.
fn parse_clippy_stream(stdout: &str, target_root: &Path) -> Vec<Finding> {
    let mut findings = Vec::new();
    for line in stdout.lines() {
        let line = line.trim();
        if line.is_empty() || !line.starts_with('{') {
            continue;
        }
        let msg: CargoMessage = match serde_json::from_str(line) {
            Ok(m) => m,
            Err(_) => continue,
        };
        if msg.reason != "compiler-message" {
            continue;
        }
        let Some(diag) = msg.message else { continue };
        let Some(code_struct) = diag.code.as_ref() else { continue };
        // We only care about clippy lints, not rustc lints (which fmt/clippy can also surface).
        if !code_struct.code.starts_with("clippy::") {
            continue;
        }
        let severity = clippy_severity(&code_struct.code, &diag.level);
        let location = diag.spans.iter().find(|s| s.is_primary).map(|span| {
            // Cargo emits paths relative to the workspace root; resolve to absolute for clarity.
            let abs = target_root.join(&span.file_name);
            Location::at_col(abs, span.line_start, span.column_start)
        });

        let mut f = Finding::new("clippy", Category::Lints, severity, diag.message.clone())
            .with_code(code_struct.code.clone());
        if let Some(loc) = location {
            f = f.with_location(loc);
        }
        if !diag.rendered.is_empty() {
            f = f.with_detail(diag.rendered.clone());
        }
        findings.push(f);
    }
    findings
}

fn clippy_severity(code: &str, level: &str) -> Severity {
    // `clippy::correctness` lints are always High regardless of level.
    if code.starts_with("clippy::correctness") {
        return Severity::High;
    }
    if code.starts_with("clippy::perf") || code.starts_with("clippy::suspicious") {
        return Severity::Medium;
    }
    if code.starts_with("clippy::nursery") {
        return Severity::Low;
    }
    match level {
        "error" => Severity::High,
        "warning" => Severity::Medium,
        _ => Severity::Info,
    }
}

// --- Minimal cargo JSON message types — just enough to extract clippy diagnostics. ---

#[derive(Debug, Deserialize)]
struct CargoMessage {
    reason: String,
    #[serde(default)]
    message: Option<Diagnostic>,
}

#[derive(Debug, Deserialize)]
struct Diagnostic {
    message: String,
    code: Option<DiagnosticCode>,
    level: String,
    #[serde(default)]
    spans: Vec<DiagnosticSpan>,
    #[serde(default)]
    rendered: String,
}

#[derive(Debug, Deserialize)]
struct DiagnosticCode {
    code: String,
}

#[derive(Debug, Deserialize)]
struct DiagnosticSpan {
    file_name: String,
    line_start: u32,
    column_start: u32,
    is_primary: bool,
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

    #[test]
    fn parses_a_clippy_diagnostic_line() {
        // Minimal hand-crafted cargo JSON message with one clippy primary span.
        let json = r#"{"reason":"compiler-message","package_id":"x 0.1.0","manifest_path":"/tmp/Cargo.toml","target":{"name":"x","kind":["lib"],"src_path":"/tmp/src/lib.rs"},"message":{"message":"called `unwrap` on a `Result` value","code":{"code":"clippy::unwrap_used","explanation":null},"level":"warning","spans":[{"file_name":"src/lib.rs","byte_start":0,"byte_end":10,"line_start":42,"line_end":42,"column_start":5,"column_end":15,"is_primary":true,"text":[],"label":null,"suggested_replacement":null,"suggestion_applicability":null,"expansion":null}],"children":[],"rendered":"warning: called `unwrap` ...\n"}}"#;
        let findings = parse_clippy_stream(json, Path::new("/tmp"));
        assert_eq!(findings.len(), 1);
        let f = &findings[0];
        assert_eq!(f.auditor, "clippy");
        assert_eq!(f.category, Category::Lints);
        assert_eq!(f.code.as_deref(), Some("clippy::unwrap_used"));
        let loc = f.location.as_ref().unwrap();
        assert_eq!(loc.line, Some(42));
        assert_eq!(loc.column, Some(5));
    }

    #[test]
    fn ignores_non_clippy_messages() {
        let json = r#"{"reason":"compiler-artifact"}
{"reason":"compiler-message","message":{"message":"x","code":{"code":"dead_code","explanation":null},"level":"warning","spans":[],"children":[],"rendered":""}}"#;
        let findings = parse_clippy_stream(json, Path::new("/tmp"));
        assert!(
            findings.is_empty(),
            "rustc-level dead_code should be skipped (handled by other auditors)"
        );
    }

    #[test]
    fn correctness_lints_are_high() {
        assert_eq!(clippy_severity("clippy::correctness::any_lint", "warning"), Severity::High);
    }

    #[test]
    fn perf_lints_are_medium() {
        assert_eq!(clippy_severity("clippy::perf::needless_collect", "warning"), Severity::Medium);
    }
}
