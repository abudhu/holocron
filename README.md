# Holocron

> *"A Jedi holocron is a repository of wisdom — open it and the truth of your codebase is revealed."*

**Holocron** is a Rust codebase auditor that runs multiple analyzers (clippy, cargo-audit, cargo-machete, rust-code-analysis, and more) in parallel against your project and produces a single graded report you can feed to an LLM, a CI gate, or a human reviewer.

## Status

🚧 **Early development.** v0.1 in progress — see the [issue tracker](https://onedev.amitbudhu.com/holocron/~issues) for the milestone-1 backlog.

## What it does

1. Walks into your Rust project (must contain `Cargo.toml`).
2. Runs each registered auditor in parallel: clippy, cargo-audit, cargo-machete, rust-code-analysis, etc.
3. Aggregates findings into a unified `Finding` model (severity, category, file:line, fingerprint).
4. Computes a weighted letter grade (A–F) per category and overall.
5. Emits a Markdown report and a JSON sidecar.

## Why

- **Fallow** does this beautifully for TypeScript/JavaScript. The Rust ecosystem has the pieces — they're just not unified.
- A single graded report is more LLM-portable than seven different tool outputs. Paste it into Codex, Claude Code, or any agent and ask it to fix the findings.
- Holocron **eats its own dogfood**: CI runs `holocron audit .` on every push and gates merges on the grade.

## Install (once published)

```bash
cargo install --git https://onedev.amitbudhu.com/holocron
```

## Usage (target shape — not yet implemented)

```bash
holocron audit ~/Git/my-rust-project
# → /tmp/holocron-my-rust-project-<unix-ts>.md
# → /tmp/holocron-my-rust-project-<unix-ts>.json
```

## License

MIT — see [LICENSE](./LICENSE).

## Author

Amit Budhu
