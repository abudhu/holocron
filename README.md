# Holocron

> *"A Jedi holocron is a repository of wisdom — open it and the truth of your codebase is revealed."*

**Holocron** is a Rust codebase auditor. It runs seven analyzers in parallel against your project (clippy, cargo-audit, cargo-machete, cargo-deny, cargo-outdated, cargo-geiger, rust-code-analysis) and emits a single graded report card you can hand to an LLM, gate a CI build on, or paste into a code review.

## Status

🟢 **v0.2 shipping.** Seven auditors live, three subcommands (`audit`, `init`, `explain`), Markdown + JSON + SARIF v2.1.0 output, partial `.holocronrc.toml` support, CI dogfood gate. See the [issue tracker](https://onedev.amitbudhu.com/holocron/~issues) for the open backlog.

Holocron eats its own dogfood — every push runs `holocron audit .` and gates the build on the grade.

## Quick start

```bash
# Install from source (the repo isn't on crates.io yet)
git clone https://onedev.amitbudhu.com/holocron
cd holocron
cargo install --path crates/holocron-cli --locked

# Install the auditor binaries Holocron drives (one-time)
cargo install cargo-audit cargo-machete cargo-deny cargo-outdated cargo-geiger --locked
cargo install --git https://github.com/mozilla/rust-code-analysis rust-code-analysis-cli --locked
rustup component add clippy

# Audit a project
holocron audit ~/Git/my-rust-project
```

You get a grade card on stdout, a Markdown report at `/tmp/holocron-<slug>-<ts>.md`, and a JSON sidecar at the same path with `.json`.

## What gets graded

Five categories × seven auditors:

| Category    | Auditor(s)                                 | What it surfaces                                            |
| :---------- | :----------------------------------------- | :---------------------------------------------------------- |
| Security    | cargo-audit, cargo-geiger                  | RUSTSEC advisories, `unsafe` surface in your dep tree       |
| Lints       | clippy                                     | Style, correctness, performance lints (default + pedantic)  |
| Complexity  | rust-code-analysis                         | Cyclomatic + cognitive complexity hotspots per function     |
| Dead Code   | cargo-machete                              | Unused dependencies in your Cargo.toml                      |
| Maintenance | cargo-deny, cargo-outdated                 | License/banned-crate policy violations, outdated deps       |

Each finding has a severity (Info, Low, Medium, High, Critical). The category score is `1.0 - sum(severity_weights)` clamped to [0, 1]. Overall grade is a weighted average across categories (defaults: Security 0.30, Lints 0.20, Complexity 0.20, Dead Code 0.15, Maintenance 0.15 — overridable via rc).

## Subcommands

### `holocron audit <path>`

The main act. Walks `<path>` until it finds a `Cargo.toml`, runs all seven auditors in parallel, writes the report.

Useful flags:

| Flag                    | Effect                                                                                |
| :---------------------- | :------------------------------------------------------------------------------------ |
| `--output <file>`       | Override the default `/tmp/holocron-<slug>-<ts>.md` location                          |
| `--no-json`             | Skip the JSON sidecar                                                                 |
| `--sarif`               | Also emit a SARIF v2.1.0 sidecar for GitHub Code Scanning / Azure DevOps              |
| `--fail-below <GRADE>`  | CI gate: exit 1 if the overall grade is below this letter (A+, A, A-, …, F)           |
| `--install-missing`     | Auto-install missing auditor binaries (otherwise they surface as Skipped)             |
| `--timeout <secs>`      | Per-auditor timeout, default 600s                                                     |

Exit codes:
- `0` — clean, or gate passed AND no categories were skipped
- `1` — `--fail-below` gate failed (quality regression)
- `2` — invalid args, broken config, or unparseable rc file (fast-fail)
- `3` — auditor outage (one or more categories couldn't be measured); overall grade is advisory

### `holocron init [<dir>]`

Drops a heavily-commented `.holocronrc.toml` template into the target dir (default: current dir). The template documents every supported config section and marks which ones are active vs reserved.

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
      # Pre-warm rustup so parallel auditors don't race
      cargo --version
      rustup component add clippy 2>/dev/null || true
      ./target/release/holocron audit . --fail-below A-
```

⚠️ **OneDev buildspec gotcha**: do NOT use bash `$@` or `${arr[@]}` in `commands:` blocks. OneDev's parser treats `@var@` as variable interpolation; an unpaired bare `@` invalidates the spec and silently kills `BranchUpdateTrigger`. Ship `scripts/check-buildspec-atsigns.sh` (in this repo) as a pre-flight CI step.

### GitHub Actions + Code Scanning

```yaml
- run: holocron audit . --sarif --output /tmp/audit.md --fail-below A-
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: /tmp/audit.sarif
```

## Configuration: `.holocronrc.toml`

Cargo-style walk-up: Holocron looks for `.holocronrc.toml` in the target dir, then ancestors. Generate the template with `holocron init`. Currently wired sections:

```toml
[gate]
# Default for --fail-below when the flag is omitted. Explicit flag wins.
fail_below = "A-"

[complexity]
# Override the rust-code-analysis severity ladder. Missing keys keep
# defaults (cyc 15/25, cog 20/35).
cyclomatic_medium = 15
cyclomatic_high   = 25
cognitive_medium  = 20
cognitive_high    = 35
```

Reserved (deserialize but no-op today): `[auditors]`, `[weights]`, `[[allowlist]]` — wired in by issues #28, #30, #29.

## Why this tool exists

- **Fallow** does this beautifully for TypeScript/JavaScript. The Rust ecosystem has the pieces — they're just not unified.
- A single graded report is more LLM-portable than seven different tool outputs. `holocron explain <fp> | pbcopy` and paste it into any coding agent.
- Holocron grades itself on every push. The same gate that protects your project protects this one.

## Roadmap

Tracked in OneDev. The natural next chunks:

- **Runtime config completion**: `[auditors]` (#28), `[weights]` (#30), `[[allowlist]]` (#29)
- **UX**: live progress display during audits (#36)
- **More auditors**: opt-in cargo-mutants for test-quality (#32)
- **CI**: cold-cache build time 13min → <5min (#33)

## Architecture

```
crates/
  holocron-core/       Auditor trait, Runner, Finding model, Grade math, Config schema
  holocron-auditors/   One module per CLI tool wrapper (clippy, deny, geiger, machete,
                       outdated, rust_code_analysis, rustsec)
  holocron-report/     Markdown, JSON, SARIF renderers
  holocron-cli/        Thin wrapper: audit / init / explain subcommands
```

All four crates lint at `clippy::pedantic + clippy::nursery + -D warnings`. Default test suite: 105+ passing.

## License

MIT — see [LICENSE](./LICENSE).

## Author

Amit Budhu — [github.com/abudhu](https://github.com/abudhu)
