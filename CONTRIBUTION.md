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

CI (`.github/workflows/ci.yml`) runs `scripts/dev-check.sh ci` on **Ubuntu, macOS, and Windows**, plus a separate **vscode-extension** job (`npm ci`, compile, unit tests).

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
| `vscode-extension/README.md` | VS Code extension (analyze + scan MVP) |

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

### VS Code extension

Changes under `vscode-extension/` should pass:

```bash
cd vscode-extension && npm ci && npm run compile && npm test
```

Rust-only contributors are not required to run npm locally; CI runs the extension job on Ubuntu.

#### Testing in VS Code (manual)

The extension is a thin wrapper around the `rustzap` CLI. To try it locally:

**1. Build the CLI** (from the repository root):

```bash
cargo build --release
```

**2. Build the extension**:

```bash
cd vscode-extension
npm ci
npm run compile
npm test
```

**3. Open the extension folder in VS Code or Cursor** (not the whole repo — `F5` uses `vscode-extension/.vscode/launch.json`):

```bash
code vscode-extension
```

**4. Launch the Extension Development Host**

- Open **Run and Debug** (`Cmd+Shift+D` / `Ctrl+Shift+D`)
- Select **Run Extension**
- Press **F5**

A second editor window opens (**Extension Development Host**). That is where you exercise the extension.

**5. Run commands in the Extension Development Host**

1. **File → Open Folder…** and pick a project to analyze (e.g. `tests/fixtures/native_app` for a quick smoke test).
2. Open the **Command Palette** (`Cmd+Shift+P` / `Ctrl+Shift+P`):
   - **RustZAP: Analyze Workspace** — static analysis (`--tools native` by default)
   - **RustZAP: Scan URL** — passive DAST (legal confirmation required; use only authorized targets, e.g. `https://example.com`)
3. On first analyze, confirm **Allow analysis** (one-time per folder).
4. For scans, read the legal warning and choose **Run scan**.

**6. Where to check results**

| Place | What you should see |
|-------|---------------------|
| **Status bar** | `RustZAP: risk N · M finding(s)` — click to focus the sidebar |
| **RustZAP** activity bar (shield icon) | Summary, **Inventory**, **Attack plan**, **Findings** tree |
| **Problems** (`Cmd+Shift+M`) | File/line diagnostics (info uses **Information** severity by default) |
| **Notification actions** | **Open summary**, **View attack plan**, **Open JSON** after each run |
| **Output → RustZAP** | Exact CLI command and logs |

Toolbar on the findings view: analyze, scan, clear, **open last JSON report**.

Use **RustZAP: Show Report Summary** or click the summary row for a markdown roll-up (inventory, attack plan, modules). Findings without a file location open a **details** tab instead of jumping to code.

**7. If `rustzap` is not on PATH**

In the Extension Development Host, set **rustzap.path** in settings to your built binary, for example:

- macOS/Linux: `<repo>/target/release/rustzap`
- Windows: `<repo>\target\release\rustzap.exe`

The extension also auto-detects `target/release/rustzap` and `target/debug/rustzap` when the opened workspace is this repository.

**Quick smoke test:** F5 → open `tests/fixtures/native_app` → **RustZAP: Analyze Workspace** → expect findings in the sidebar and Problems (e.g. secrets / DOM sinks).

More detail: [`vscode-extension/README.md`](vscode-extension/README.md).

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
