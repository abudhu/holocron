# Changelog

All notable changes to Holocron will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added — v0.1 (end-to-end audit pipeline)
- Cargo workspace: `holocron-cli` (binary) + `holocron-core` (data model, runner, grade math) + `holocron-auditors` (external tool wrappers) + `holocron-report` (Markdown + JSON renderers)
- `Finding` model with severity (Critical/High/Medium/Low/Info), category (Security/Lints/Complexity/DeadCode/Maintenance), location, and stable SHA-256 fingerprint for cross-run dedup
- `Auditor` trait + `Runner` with parallel `tokio::JoinSet` execution, per-auditor timeouts, isolated panic/error handling
- Four production auditors:
  - `clippy` (pedantic + nursery) — parses cargo `--message-format=json`
  - `cargo-audit` — RustSec advisories with CVSS-derived severity
  - `cargo-machete` — unused-dep detection from text output
  - `rust-code-analysis-cli` — per-function complexity (cyclomatic + cognitive)
- Weighted A–F grade calculator (Security 30% / Lints 20% / Complexity 20% / DeadCode 15% / Maintenance 15%)
- Markdown report + JSON sidecar (`schema_version: 1`); default paths `/tmp/holocron-<slug>-<ts>.{md,json}`
- `holocron audit <path>` CLI with `--output`, `--no-json`, `--install-missing`, `--timeout` flags
- 37 unit tests (model invariants, parser fixtures, grade math, runner concurrency)

### Added — infrastructure
- MIT license
- OneDev CI: cargo fmt --check + clippy -D warnings + test all + release smoke build (~ 2 min cold, ~30s warm)
- Pedantic + nursery clippy enabled on every crate; Holocron dogfoods its own auditor on every push

### Verified
- `holocron audit ~/Git/holocron` → **A+ (0.98)** in 0.85s
- `holocron audit ~/Git/containerly/backend` → **F (0.30)** in 5.8s; caught 1 Critical CVE (RUSTSEC-2023-0071 Marvin Attack) + 3 High CVEs (webpki), 770 lint findings, 1 cyclomatic-complexity-112 function
