# Security Policy

## Supported Versions

Holocron is pre-1.0 and ships from `main`. Only the latest commit on
`main` receives security fixes.

| Version    | Supported |
| :--------- | :-------- |
| `main` (HEAD) | ✅ |
| Anything else | ❌ |

## Reporting a Vulnerability

Please report security issues **privately** — do NOT open a public issue.

**Preferred:** email **me@amitbudhu.com** with:

- A description of the vulnerability
- Steps to reproduce (proof-of-concept code is welcome)
- The commit SHA you tested against
- Your name / handle if you'd like credit in the advisory

**Backup channel:** if email isn't responsive within 72 hours, open a
private security advisory on the upstream mirror (when one exists) or
DM the maintainer directly.

## What to expect

| Stage            | Timeline |
| :--------------- | :------- |
| Initial response | ≤ 72 hours |
| Triage + reproduction | ≤ 7 days |
| Fix on `main` (or risk-acceptance writeup) | ≤ 30 days for High/Critical |
| Public disclosure | After a fix has shipped, coordinated with the reporter |

## Scope

In scope:

- The Holocron CLI binary (`crates/holocron-cli`)
- All four library crates (`holocron-core`, `holocron-auditors`, `holocron-report`, plus the CLI)
- The default `deny.toml` shipped by `cargo-deny` integration
- The shipped HTML report renderer (XSS in user-controlled finding text, etc.)

Out of scope:

- Vulnerabilities in the third-party tools Holocron drives (clippy,
  cargo-audit, cargo-deny, etc.) — report those upstream
- Operational security of CI environments where Holocron runs
- Auditor-tool *false negatives* (a CVE the underlying tool missed isn't
  a Holocron vulnerability)

## Self-audit

Holocron runs `holocron audit .` on every push and gates the build at
grade A− or better. The current build status and self-grade are
visible at <https://onedev.amitbudhu.com/holocron/~builds>.

If you find a vulnerability that Holocron itself *should have caught*
in its self-audit, please report it the same way — and tell us which
auditor missed it so we can file an upstream bug too.
