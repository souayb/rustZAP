# Contributing to RustZAP

Thank you for helping improve RustZAP. This guide explains how to set up a dev environment, what we expect in changes, and how to stay within ethical and legal boundaries for a **security scanner** project.

---

## Before you start

### Legal and ethical use

RustZAP is a tool that can probe and stress-test web applications. **Only use it against systems you own or have explicit written permission to test.** Contributors must not use the project to enable abuse. Pull requests that push clearly malicious defaults, undisclosed third-party exfiltration, or “phone home” behavior without transparency will not be accepted.

### Prerequisites

- **Rust** toolchain: **1.75+** (see `README.md`).
- **Git**.
- Familiarity with safe HTTP testing (lab targets, localhost, documented demo apps like OWASP Juice Shop).

---

## Getting the code

```bash
git clone <your-fork-or-upstream-url>
cd rustzap
./scripts/install-hooks.sh    # Windows: scripts\install-hooks.cmd
cargo build
cargo run -- --help
```

Optional: use `rustup` to pin a stable toolchain if your distro ships an older compiler.

### Git hooks (Linux, macOS, Windows)

Install **once** after clone so `git commit` / `git push` run the same checks CI uses. This sets **local** `core.hooksPath` only (it does not change your global Git config).

```bash
# Linux, macOS, or Git Bash
./scripts/install-hooks.sh
```

```powershell
# Windows PowerShell
.\scripts\install-hooks.ps1
```

```bat
REM Windows cmd (no PowerShell execution-policy issues)
scripts\install-hooks.cmd
```

On Windows, install [Git for Windows](https://gitforwindows.org/) so hooks run under bash, plus [rustup](https://rustup.rs/) (`rustup component add rustfmt clippy`).

| Hook | When | Checks |
|------|------|--------|
| `pre-commit` | every commit | `cargo fmt --all -- --check`; reject generated reports/secrets; whitespace / conflict markers |
| `pre-push` | every push | `cargo clippy --workspace --all-targets -- -D warnings`; `cargo test --workspace` |

CI (`.github/workflows/ci.yml`) runs `scripts/dev-check.sh ci` on **Ubuntu, macOS, and Windows**.

Do not commit scanner output (`report.json`, `rustzap-report.json`, `analyze-report.json`, `*.sarif`, files under `reports/`). Those are produced by the app; write them under `reports/` (gitignored) or outside the repo.

Bypass (local only, not for PRs): `git commit --no-verify` / `git push --no-verify`, or `RUSTZAP_SKIP_HOOKS=1`. Uninstall: `./scripts/install-hooks.sh --uninstall`.

---

## Project pointers

| Document | Purpose |
|----------|---------|
| `README.md` | User-facing install, CLI usage, Docker |
| `FEATURE.md` | DAST module **implementation status** + backlog (platform specs in IMPLEMENTATION_PLAN) |
| `IMPLEMENTATION_PLAN.md` | Phased implementation specs, JSON/schema, CLI plans, acceptance checklists |
| `CLAUDE.md` | Architecture notes, plugin wiring traps, verification commands (useful for humans too) |
| `SOFTWARE_DESIGN_DOCUMENT.md` | Broader platform / orchestration context |

---

## Development workflow

### Commands we expect to pass

From the repository root:

```bash
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings
cargo build
cargo test
```

If you change CLI behavior or defaults, smoke-test:

```bash
cargo run -- plugins
cargo run -- scan --target https://example.com --passive-only --depth 1 --output /tmp/rustzap-smoke.json
```

Use **your own lab targets** for aggressive `--plugins` runs.

### Code style

- Match existing patterns in the file you edit (imports, error handling with `anyhow`, logging with `tracing`).
- Prefer **small, focused pull requests** over large mixed refactor-and-feature PRs.
- Do not commit **secrets** (API keys, `.env` with real credentials, personal tokens).
- Do not commit **generated reports** (`*-report.json`, `*.sarif`, `reports/*` except `.gitkeep`).
- Preserve stable **`plugin` strings** on `Finding` values (e.g. `passive/cors`, `active/sqli`) unless you are intentionally making a breaking change and updating downstream docs.

### Adding a feature

1. **Check [`FEATURE.md`](./FEATURE.md)** for shipped vs backlog scanner work, and **`IMPLEMENTATION_PLAN.md`** for platform features (analyze, audit, SARIF, HTTP worker, agents).
2. Decide where it lives:
   - **Passive checks** → `src/passive.rs` (helpers + `PassiveScanner::check_url`).
   - **Active plugins** → `src/active.rs` (`ScanPlugin`) or a submodule; register in `ActiveScanner::new` and `list_plugins()`.
   - **Crawl / discovery** → `src/spider.rs`.
3. Add **tests** when behavior is non-trivial (golden headers/body, mock server, or unit tests for pure logic).
4. Update **`README.md`** if users see new flags, commands, or plugin names.
5. If you ship a **Phase** from **`IMPLEMENTATION_PLAN.md`**, update that doc’s checklist and status prose in the same change set.

**Important:** `README.md` may list plugins that are not yet registered in the binary. If you add plugins, ensure `cargo run -- plugins` matches the documentation, or fix the docs in the same PR.

---

## Submitting changes

1. **Open an issue first** for large features or design decisions (optional but recommended); reference it in the PR.
2. Create a **topic branch** (e.g. `feat/security-txt`, `fix/report-escaping`).
3. Commit with **clear messages** describing *why* the change exists.
4. Open a **pull request** that:
   - Describes the problem and the solution.
   - Lists how you tested (commands + target type: unit, local server, etc.).
   - Keeps unrelated formatting churn out of the diff.

We do not require a formal CLA or DCO unless the maintainers add one later; use your real identity in commits as usual for open source.

---

## Reporting security issues in RustZAP itself

If you find a **vulnerability in this codebase** (not a finding from scanning a target), report it privately to the maintainers (e.g. GitHub Security Advisories or a contact listed on the repo) instead of filing a public issue first, so users can be notified responsibly.

---

## Community conduct

Be constructive and respectful in issues and reviews. Focus feedback on the code and the user impact. Harassment or bad-faith behavior is not acceptable.

---

## License

By contributing, you agree that your contributions will be licensed under the same terms as the project (**MIT**, see `LICENSE` / `Cargo.toml`).

---

Thank you for helping make RustZAP safer and more useful for **authorized** security testing.
