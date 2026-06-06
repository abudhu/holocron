# Contributing to Holocron

Thanks for considering a contribution. This project is small and
opinionated — please read this file before opening a PR so we don't
waste each other's time.

## Quick start

```bash
# Clone
git clone https://onedev.amitbudhu.com/holocron
cd holocron

# Install Holocron + its eight auditor binaries (fast path via binstall)
cargo install --path crates/holocron-cli --locked
cargo install cargo-binstall --locked
cargo binstall --no-confirm cargo-audit cargo-machete cargo-deny cargo-outdated cargo-geiger
cargo install --git https://github.com/mozilla/rust-code-analysis rust-code-analysis-cli --locked
rustup component add clippy

# Verify your toolchain matches CI
rustup update stable    # CI runs Rust 1.96+; older toolchains miss lints

# Run the full test + lint pipeline (mirrors CI)
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
./target/release/holocron audit . --fail-below A-
```

If `cargo test --workspace` is green and `holocron audit .` reports
A− or better, your branch is ready for review.

## Workflow

1. **File an issue first** (or pick an existing one) on
   <https://onedev.amitbudhu.com/holocron/~issues>. Drive-by feature PRs
   without a discussion get closed.
2. **Branch off `main`**. Name it `feat/<short-desc>` or `fix/<short-desc>`.
3. **Test-first when fixing bugs.** A failing test that reproduces the
   bug before the fix lands keeps regressions out.
4. **Keep commits logical.** One commit per coherent change; squash
   fixup commits before opening the PR.
5. **Open a PR** with a description that explains *why*, not just *what*.

## Code style

- **Pedantic + nursery clippy** on every crate, with `-D warnings`.
  Run `cargo clippy --workspace --all-targets -- -D warnings` before
  pushing. If you genuinely need to suppress a lint, do so with the
  narrowest possible `#[allow(...)]` at the smallest scope, and add a
  one-line comment explaining why.
- **`rustfmt` on default settings.** Run `cargo fmt --all` before
  committing. CI will reject unformatted code.
- **Doc comments on public APIs.** Even one-liners are fine; what
  matters is that someone reading the docs.rs page can figure out
  what's going on. `clippy::missing_docs_in_private_items` is off,
  so internal helpers don't need them.
- **Test coverage for new logic.** Every new module ships its own
  `#[cfg(test)] mod tests` block. We don't enforce a coverage
  percentage, but every code path with branching logic should have at
  least one test exercising each branch.
- **Holocron grades its own grade.** Your changes must not drop the
  dogfood grade below A− or the CI gate will fail. If a real finding
  surfaces, fix it; if it's a false positive, suppress it via an
  inline `// holocron: ignore <code> -- <reason>` annotation (preferred)
  or a `.holocronrc.toml` `[[allowlist]]` entry.

## Signed commits (required for `main`)

This repo expects every commit on `main` to be cryptographically signed.
GitHub Guard (the Reddit moderation bot used in some communities where
Rust tools get shared) reads this signal; unsigned commits drop the
project's trust score.

Easiest path: SSH-based commit signing (works with the same key you
push with).

```bash
# Tell git to sign with your SSH key
git config --global gpg.format ssh
git config --global user.signingkey ~/.ssh/id_ed25519.pub
git config --global commit.gpgsign true
git config --global tag.gpgsign true

# Optional: tell git which SSH keys count as trusted signers
# (Required for `git log --show-signature` to verify locally; not
# required for the signature to show up green on GitHub/OneDev.)
echo "your-email@example.com $(cat ~/.ssh/id_ed25519.pub)" \
  >> ~/.config/git/allowed_signers
git config --global gpg.ssh.allowedSignersFile ~/.config/git/allowed_signers
```

GPG-based signing also works:

```bash
# After importing your GPG key
git config --global user.signingkey <YOUR_KEY_ID>
git config --global commit.gpgsign true
```

Then push your *public* key to your GitHub account (Settings → SSH
and GPG keys → New SSH signing key, or New GPG key).

Verify a commit is signed before pushing:

```bash
git log --show-signature -1
# Should show "Good signature from ..." not "No signature"
```

If you push unsigned commits to a branch destined for `main`, you'll
be asked to re-sign and force-push or to reset and recommit.

## Reporting bugs / security issues

- **General bugs:** file an issue on
  <https://onedev.amitbudhu.com/holocron/~issues>.
- **Security vulnerabilities:** see [SECURITY.md](./SECURITY.md). Do
  NOT open a public issue for security problems.

## Project layout

```
crates/
  holocron-core/       Auditor trait, Runner, Finding model, Grade math,
                       Config schema, allowlist matcher, inline-annotation parser.
  holocron-auditors/   One module per CLI tool wrapper. Shared runners.rs
                       has the silent-failure-guard helper.
  holocron-report/     Markdown, JSON, SARIF, HTML renderers.
  holocron-cli/        Subcommands, --html / --sarif output, --progress display,
                       rc merge, inline-annotation pass, diff filter.

scripts/               Reusable bash helpers (check-buildspec-atsigns.sh).
docs/plans/            Historical implementation plans, kept for archaeology.
```

Each crate has its own `Cargo.toml` with its own lint config. The
workspace root `Cargo.toml` defines shared deps + version pins.

## License

By contributing, you agree your code is released under this project's
[MIT license](./LICENSE).
