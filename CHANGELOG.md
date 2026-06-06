# Changelog

All notable changes to Holocron will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added — v0.2 (configurable, multi-format, sharper)

#### Subcommands
- `holocron diff <base-ref> <path>` — audit a project but score only findings touching files changed since `<base-ref>`. Filters after audit, before grade, so the reported grade reflects "this diff's score." Pre-commit-hook friendly. (#41)
- `holocron init [<dir>]` — generate a starter `.holocronrc.toml` with every section documented inline; `--force` overwrites.
- `holocron explain <fingerprint>` — look up a single finding by 16-char hex fingerprint, render an LLM-friendly Markdown explanation block ready to paste into a coding agent. Auto-discovers the most recent sidecar; `--from` to specify.

#### Auditors (4 → 8; default set is 7, cargo-mutants opt-in)
- `cargo-deny` — license / banned-crate / duplicate / unknown-source policy (Maintenance). Ships a sensible default `deny.toml` when the target project has none.
- `cargo-outdated` — direct-dep version drift (Maintenance), depth=1 to avoid transitive noise.
- `cargo-geiger` — `unsafe` surface in the dep tree (Security). Severity ladder: own crate High, direct dep Low, transitive Info.
- `cargo-mutants` — mutation-testing coverage (Complexity). Opt-in only via `--with-mutants` flag because it takes 30 min – several hours on real workspaces. Each MISSED mutant becomes a Medium Complexity finding. Honors `cargo-mutants = false` in rc as kill switch even when the flag is passed.

#### Output formats (1 → 4)
- SARIF v2.1.0 sidecar via `--sarif`, for GitHub Code Scanning / Azure DevOps ingestion.
- HTML report via `--html` — single-file, no external assets, no JavaScript, dark theme with `@media print` fallback. Grade letter as hero, severity-colored finding cards, `<details>` for collapsible sections, < 100KB on real audits. (#46)

#### Configuration (`.holocronrc.toml`)
- `[gate]` — default `--fail-below` threshold (active).
- `[complexity]` — override cyclomatic + cognitive severity ladder (active).
- `[auditors]` — per-auditor opt-out toggles (active, #28).
- `[weights]` — override per-category weights in the overall grade (active, #30).
- `[[allowlist]]` — suppress specific findings from grade math by fingerprint / auditor / code / message-prefix / path. Empty entries rejected at load (active, #29).
- All sections validate with `deny_unknown_fields`; typos like `cargo-geigr` are rejected at load with line/column + the list of valid keys.

#### Inline suppression (#42)
- `// holocron: ignore <code> -- <reason>` annotations suppress a finding at the source instead of via fingerprint lookup in rc.
- Accepts comment above the offending line OR trailing on the same line.
- Accepts both `//` and `#` comment prefixes (Rust + TOML/YAML/Python).
- Marks finding `allowlisted = true`, surfaces in the report's "Allowlisted Findings" section with the rationale.
- Runs after rc allowlist; first-match-wins on overlap.

#### CI / DX
- `--progress` flag with `auto` / `tty` (in-place spinner) / `log` (timestamped events, CI-friendly) / `off` modes (#36).
- `--install-missing` opts into auto-installing missing auditor binaries; default is to surface them as Skipped.
- `--timeout` for per-auditor wall-clock cap, default 600s.
- `cargo-binstall` bootstrap in the CI buildspec drops cold-cache install from ~5 min to ~1 min (#33).
- `cargo-home` cache key + dogfood gate at A− or better.

#### Honest grading
- **Silent-failure guard** on every shell-out auditor (#39): if the tool exits non-zero, produces no parseable findings, AND wrote to stderr, the auditor returns `Failed` (not `Ok([])`). Category gets marked Skipped instead of being silently graded A+. Shipped for cargo-audit, cargo-deny, cargo-outdated, and cargo-geiger (#38 special case for per-member iteration).
- Bonus bug caught by the guard on its first dogfood run: cargo-deny's `--config` flag was passed before the `check` subcommand, where the tool rejects it. cargo-deny had been silently dead for months. Fix puts `--config` after `check`. Net effect: Maintenance went A 0.95 (1 finding, cargo-deny dead) → A 0.94 (2 findings, both auditors live).
- Categories with all auditors skipped now render `—` (em-dash) in the report, not a fabricated `B 0.85` fallback (#24).

#### Allowlist matchers
- `match_path` does substring matching against the location file path (case-sensitive).
- `match_message_prefix` does `starts_with` against the finding message.
- `match_fingerprint`, `match_auditor`, `match_code` are exact.
- All AND-ed: an entry with only `auditor = "clippy"` matches every clippy finding; adding `code = "clippy::unwrap_used"` narrows it.

### Changed
- Test count: 37 → **170** across the four crates.
- Default audit grade scaffold: skipped categories no longer collapse to a fake `B 0.85` — they render as Skipped + reason, and the overall is computed over the remaining graded categories.
- `audit()` cyclomatic complexity stays below threshold by extracting per-step helpers (`apply_rc_allowlist_step`, `apply_inline_annotation_step`, `apply_diff_filter`) — caught twice by the tool itself during this sprint.

### Verified
- `holocron audit ~/Git/holocron` → **A+ (0.99)** in ~2s with one inline-annotated finding (`Letter::from_str` is a 13-arm dispatch table by design).
- OneDev CI #32: SUCCESSFUL on `27d23e4` in 129s (cold cache 7 min via cargo-binstall).
- HTML report dogfood: 11.6 KB, renders cleanly in Safari/Chrome/Firefox, print-friendly.

## [0.1.0] — initial end-to-end audit pipeline

### Added
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
