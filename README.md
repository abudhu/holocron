# Holocron

> *"A Jedi holocron is a repository of wisdom — open it and the truth of your codebase is revealed."*

**Holocron** is a Rust codebase auditor. It runs eight analyzers in parallel against your project (clippy, cargo-audit, cargo-machete, cargo-deny, cargo-outdated, cargo-geiger, rust-code-analysis, plus opt-in cargo-mutants) and emits a single graded report card you can hand to an LLM, gate a CI build on, or paste into a code review.

## Status

🟢 **v0.2 shipping.** Seven auditors in the default set, one opt-in (cargo-mutants), three subcommands (`audit`, `init`, `explain`), Markdown + JSON + SARIF v2.1.0 output, full `.holocronrc.toml` support (gate, complexity, auditors, weights, allowlist), live progress display, and a CI dogfood gate. See the [issue tracker](https://onedev.amitbudhu.com/holocron/~issues) for what's next.

Holocron eats its own dogfood — every push runs `holocron audit .` and gates the build on the grade. Current self-grade: **A (0.97)** with one finding allowlisted as intentional design.

## Quick start

```bash
# Install Holocron from source (not on crates.io yet)
git clone https://onedev.amitbudhu.com/holocron
cd holocron
cargo install --path crates/holocron-cli --locked

# Install the auditor binaries Holocron drives (one-time, ~5 min from source)
cargo install cargo-audit cargo-machete cargo-deny cargo-outdated cargo-geiger --locked
cargo install --git https://github.com/mozilla/rust-code-analysis rust-code-analysis-cli --locked
rustup component add clippy

# Or with cargo-binstall (faster — pulls precompiled GitHub release artefacts, ~1 min)
cargo install cargo-binstall --locked
cargo binstall --no-confirm cargo-audit cargo-machete cargo-deny cargo-outdated cargo-geiger
cargo install --git https://github.com/mozilla/rust-code-analysis rust-code-analysis-cli --locked

# Audit a project
holocron audit ~/Git/my-rust-project
```

You get a live progress display on stderr while auditors run, a grade card on stdout when they finish, a Markdown report at `/tmp/holocron-<slug>-<ts>.md`, and a JSON sidecar at the same path with `.json`.

## What gets graded

Five categories × eight auditors (seven default + one opt-in):

| Category    | Auditor(s)                                       | What it surfaces                                            |
| :---------- | :----------------------------------------------- | :---------------------------------------------------------- |
| Security    | cargo-audit, cargo-geiger                        | RUSTSEC advisories, `unsafe` surface in your dep tree       |
| Lints       | clippy                                           | Style, correctness, performance lints (default + pedantic)  |
| Complexity  | rust-code-analysis, cargo-mutants¹               | Cyclomatic + cognitive complexity, missed-mutant test gaps  |
| Dead Code   | cargo-machete                                    | Unused dependencies in your Cargo.toml                      |
| Maintenance | cargo-deny, cargo-outdated                       | License/banned-crate policy violations, outdated deps       |

¹ cargo-mutants is opt-in via `--with-mutants`. It's slow (30 min – several hours on real workspaces), so the default set leaves it out.

Each finding has a severity (Info, Low, Medium, High, Critical). The category score is `1.0 - sum(severity_weights)` clamped to `[0, 1]`. Overall grade is a weighted average across categories (defaults: Security 0.30, Lints 0.20, Complexity 0.20, Dead Code 0.15, Maintenance 0.15 — all five are overridable via `[weights]` in rc).

## Subcommands

### `holocron audit <path>`

The main act. Walks `<path>` until it finds a `Cargo.toml`, runs all enabled auditors in parallel, writes the report.

Useful flags:

| Flag                    | Effect                                                                                |
| :---------------------- | :------------------------------------------------------------------------------------ |
| `--output <file>`       | Override the default `/tmp/holocron-<slug>-<ts>.md` location                          |
| `--no-json`             | Skip the JSON sidecar                                                                 |
| `--sarif`               | Also emit a SARIF v2.1.0 sidecar for GitHub Code Scanning / Azure DevOps              |
| `--fail-below <GRADE>`  | CI gate: exit 1 if the overall grade is below this letter (`A+`, `A`, `A-`, …, `F`)   |
| `--install-missing`     | Auto-install missing auditor binaries (otherwise they surface as Skipped)             |
| `--with-mutants`        | Add cargo-mutants to the audit set. Test-quality signal; expect 30 min – many hours   |
| `--progress <mode>`     | `auto` (default), `tty` (spinner block), `log` (timestamped events), `off`            |
| `--timeout <secs>`      | Per-auditor timeout, default 600                                                      |

Exit codes:

- `0` — clean, or gate passed AND no categories were skipped
- `1` — `--fail-below` gate failed (quality regression)
- `2` — invalid args, broken config, or unparseable rc file (fast-fail)
- `3` — auditor outage (one or more categories couldn't be measured); overall grade is advisory

### `holocron init [<dir>]`

Drops a heavily-commented `.holocronrc.toml` template into the target dir (default: current dir). Every supported section is documented inline.

```bash
cd my-project
holocron init
git add .holocronrc.toml
```

### `holocron explain <fingerprint>`

Looks up a single finding by 16-char hex fingerprint and prints an LLM-friendly Markdown block ready to paste into Cortana / Codex / Claude Code:

```bash
# Auto-discovers the most recent /tmp/holocron-*.json sidecar
holocron explain a1b2c3d4e5f60718

# Or specify the sidecar
holocron explain a1b2c3d4e5f60718 --from /tmp/holocron-my-proj-<ts>.json

# Pipe straight into an agent
holocron explain a1b2c3d4e5f60718 | pbcopy
```

Output is a 3-section Markdown block: finding metadata, full diagnostic, and a prompt template asking the LLM to read the file, explain the lint, propose the diff, and call out trade-offs.

## CI integration

### OneDev (used by holocron itself)

See `.onedev-buildspec.yml` in this repo for the canonical pattern. Key points:

```yaml
# Dogfood step: holocron audits itself
- type: CommandStep
  name: dogfood (holocron audits itself)
  runInContainer: true
  image: rust:1.84-bookworm
  interpreter:
    type: ShellInterpreter
    shell: /bin/bash
    commands: |
      set -euxo pipefail
      # Pre-warm rustup so parallel auditors don't race on the
      # /usr/local/rustup/downloads .partial rename.
      cargo --version
      rustup component add clippy 2>/dev/null || true
      # --progress log keeps CI output deterministic + parseable.
      ./target/release/holocron audit . --progress log --fail-below A-
```

⚠️ **OneDev buildspec gotcha**: do NOT use bash `$@` or `${arr[@]}` in `commands:` blocks. OneDev's parser treats `@var@` as variable interpolation; an unpaired bare `@` invalidates the spec and silently kills `BranchUpdateTrigger`. Ship `scripts/check-buildspec-atsigns.sh` (in this repo) as a pre-flight CI step.

**Cold-cache install speedup**: prefer `cargo binstall` over `cargo install` for the auditor binaries — precompiled GitHub release artefacts vs from-source compiles. The repo's buildspec does this; install step drops from ~5 min to ~1 min on a cold cache.

### GitHub Actions + Code Scanning

```yaml
- run: holocron audit . --sarif --output /tmp/audit.md --fail-below A-
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: /tmp/audit.sarif
```

## Configuration: `.holocronrc.toml`

Cargo-style walk-up: Holocron looks for `.holocronrc.toml` in the target dir, then ancestors. Generate the template with `holocron init`. Every section below is wired and active.

```toml
# [gate] — CI default for --fail-below when the flag is omitted.
# Explicit --fail-below on the command line wins.
[gate]
fail_below = "A-"

# [complexity] — override the rust-code-analysis severity ladder.
# Missing keys keep the built-in defaults (cyc 15/25, cog 20/35).
[complexity]
cyclomatic_medium = 15
cyclomatic_high   = 25
cognitive_medium  = 20
cognitive_high    = 35

# [auditors] — opt out of specific auditors. Opt-out semantic: missing
# key = enabled, explicit true = enabled, explicit false = disabled.
# Disabling all auditors in a category marks that category as Skipped
# (advisory grade, exit code 3). Disabling one auditor in a multi-auditor
# category (e.g. cargo-deny in Maintenance) leaves the category graded
# by the remaining auditor (cargo-outdated in this case).
[auditors]
clippy             = true
cargo-audit        = true
cargo-machete      = true
cargo-deny         = true
cargo-outdated     = true
cargo-geiger       = true
rust-code-analysis = true
# cargo-mutants is opt-in via --with-mutants; set false here as a
# kill switch even when the flag is passed.
cargo-mutants      = false

# [weights] — override per-category weights in the overall grade.
# Default sums to 1.0; if your overrides don't sum to 1.0 the grader
# renormalizes and emits a stderr warning.
[weights]
security    = 0.30
lints       = 0.20
complexity  = 0.20
dead_code   = 0.15
maintenance = 0.15

# [[allowlist]] — suppress specific findings from the grade math.
# Allowlisted findings still appear in the report's "Allowlisted
# Findings" section with the reason; they're excluded from category
# scores. Match by AND across set fields: fingerprint, auditor, code,
# message_prefix, path (substring against the file path). At least
# one field must be set (an empty entry is rejected at load).
[[allowlist]]
auditor = "rust-code-analysis"
code    = "complexity-warn"
path    = "crates/holocron-core/src/grade.rs"
reason  = "Letter::from_str is a 13-arm dispatch table by design (one arm per grade A+ through F)."
```

## Why this tool exists

- **Fallow** does this beautifully for TypeScript/JavaScript. The Rust ecosystem has the pieces — they're just not unified.
- A single graded report is more LLM-portable than eight different tool outputs. `holocron explain <fp> | pbcopy` and paste it into any coding agent.
- Holocron grades itself on every push. The same gate that protects your project protects this one.

## Architecture

```
crates/
  holocron-core/       Auditor trait, Runner, Finding model, Grade math, Config schema,
                       allowlist matcher, AuditorEvent progress channel.
  holocron-auditors/   One module per CLI tool wrapper: clippy, deny, geiger, machete,
                       mutants, outdated, rust_code_analysis, rustsec.
  holocron-report/     Markdown, JSON, SARIF renderers.
  holocron-cli/        Wires it together: audit / init / explain subcommands, --with-mutants,
                       --progress display, rc merge.
```

All four crates lint at `clippy::pedantic + clippy::nursery + -D warnings`. Test suite: 134 passing.

## License

MIT — see [LICENSE](./LICENSE).

## Author

Amit Budhu — [github.com/abudhu](https://github.com/abudhu)
