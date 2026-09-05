# CLAUDE.md — Guidance for AI assistants (Claude Code / Cursor)

Use this file so changes to **RustZAP** are correct, safe, and shippable. When in doubt, **read the referenced source** before editing.

---

## Project identity

- **Name:** `rustzap` (crate `rustzap`, binary `rustzap`)
- **Edition:** Rust 2021; target **Rust 1.75+** per `README.md`
- **Purpose:** Web security scanner (spider, passive analysis, active plugins, proxy, stress tester, TUI) inspired by OWASP ZAP. Unified console can shell out to external tools (`src/tools.rs`, `src/installer.rs`).

---

## Legal and safety (non-negotiable)

- **Only scan targets you own or have explicit written permission to test.** Unauthorized scanning is illegal.
- `analyze` / `audit` must **ask before reading a local repo**. CLI: TTY prompt, or `--yes` in CI. TUI Analyze tab: confirmation dialog, then `assume_yes` only after **Y**. Do not walk the filesystem silently.
- Do not add **default-on** intrusive behavior (aggressive path brute force, OOB callbacks to third parties, etc.) without **explicit CLI flags** and README warnings.
- Destructive or high-rate tests belong behind opt-in flags and local integration tests — never hard-coded against real domains.

---

## Build, format, and verify

Run from the repository root (directory containing `Cargo.toml`):

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo build
cargo build --release
```

Before saying work is complete:

```bash
cargo test
```

(There are **195** integration + unit tests today — **adding tests for new logic is strongly preferred**, especially for passive helpers, native static analyzers, TUI analyze helpers, and report serialization. Golden passive matrix: `tests/passive_golden.rs`.)

### Smoke run (after build)

```bash
cargo run -- plugins
cargo run -- scan --target https://example.com --passive-only --depth 1 --output /tmp/zap-test.json
```

Use **localhost or lab targets** (e.g. docker-compose Juice-Shop from README) for invasive `--plugins` runs.

---

## Repository layout (mental map)

| Path | Role |
|------|------|
| `src/main.rs` | CLI (`clap`), subcommands, module declarations — **must list every `mod`** used |
| `src/scanner.rs` | `run_scan`: spider → passive → active → `Report` |
| `src/spider.rs` | Crawl same-host HTML links; queue + depth |
| `src/passive.rs` | Header/body checks; `PassiveScanner::check_url` |
| `src/active.rs` | `ScanPlugin` trait; **registered** active plugins |
| `src/sqli_advanced.rs` | Extra `ScanPlugin` types — **verify whether `mod sqli_advanced` exists in `main.rs`** when debugging “plugin missing” |
| `src/report.rs` | JSON/CSV/HTML report; `Finding` aggregation |
| `src/types.rs` | `Finding`, `Severity`, `DiscoveredUrl`, … |
| `src/proxy.rs` | Intercepting proxy |
| `src/stress.rs` | Load testing CLI |
| `src/tui/` | Ratatui UI (`mod.rs` + `analyze.rs` + `agent.rs`); Scan URL + Analyze repo + Agent tab; plugin defaults stay in sync with CLI |
| `src/tools.rs` | External tool detection + execution |
| `src/installer.rs` | OS-aware companion tool installs |
| `src/analyze/` | `analyze`/`audit`: Semgrep/Trivy/Gitleaks/Checkov parsers + **native** inventory/JS/forms (`inventory.rs`, `gitignore.rs`, `native/`, `static_report.rs`) |
| `src/ad/` | `ad`: native Active Directory / NTLM-relay detector (Tier A) — LDAP posture (`ldap.rs`), Ghost-SPN (`spn.rs`), NTLM flags (`ntlm.rs`), computer enumeration (`enumerate.rs`); I/O behind traits in `probe.rs` (`directory.rs`/`dns.rs` live impls). Detection-only, authorization-gated. |
| `FEATURE.md` | Implemented passive/active items + backlog; platform detail in `IMPLEMENTATION_PLAN.md` |
| `IMPLEMENTATION_PLAN.md` | **Detailed specs** for analyze/audit, JSON `modules`/`static`, SARIF, `serve`, agentic mode |
| `SOFTWARE_DESIGN_DOCUMENT.md` | Platform / SDD context (orchestration, UFF, workers) |

---

## Architecture rules

### Scan pipeline

1. **Spider** discovers `DiscoveredUrl` values (GET-focused extraction).
2. **Passive** runs on discovered URLs (`PassiveScanner::scan_all`); **skips non-GET** in current code.
3. **Active** runs when not `passive_only`; `ActiveScanner` filters plugins by `--plugins` (substring match or `all`).
4. **Report** merges findings; JSON is the primary machine-readable contract for downstream platforms. Module roll-up is printed after scans and surfaced in the TUI; serialization of **`modules`** into JSON is specified in **`IMPLEMENTATION_PLAN.md`** Phase 1 (`report.rs` must stay in sync with `print_module_summary` / `summarize_modules`).

### Active plugins (`ScanPlugin`)

- Defined in `src/active.rs` (and optionally `src/sqli_advanced.rs`).
- Each plugin: `name()`, `description()`, `async fn scan(&self, client, target) -> Vec<Finding>`.
- **Registration:** plugins must appear in `ActiveScanner::new`’s `all_plugins` vec **and** `list_plugins()` if you want `rustzap plugins` to list truthfully.
- **Selection:** `enabled` uses **substring** matching on plugin name (case-insensitive) or literal `all`.

### Active scan gating (critical)

In `active.rs`, URLs **without** query parameters are **skipped** for active scanning unless the URL string contains `'?'`. Do not “fix” this without understanding impact on crawl-only pages and traffic volume.

### Passive checks

- Add new checks as functions returning `Vec<Finding>`, then call them from `PassiveScanner::check_url`.
- Use stable `plugin` strings: e.g. `passive/cors`, `passive/missing-headers` — downstream normalizers depend on consistency.
- Populate `cwe` / `owasp_category` when applicable (`Finding::with_cwe`, `with_owasp`).

### HTTP client

- Built via `scanner::build_client` / `ScanConfig`: timeouts, TLS verify (`insecure`), cookies, auth headers, redirects (limited).
- Active + agent HTTP go through `safety::HttpSafetyGate` (`--read-only-safe`, `--max-rps`, `--attack` → `SafetyPolicy`). Circuit breaker aborts on 5xx/latency spikes.

---

## Documentation drift trap

**README.md** lists many active plugins (extended SQLi, NoSQL, etc.). Some implementations live only in `src/sqli_advanced.rs` and may **not** be mounted in `main.rs`.

**Before claiming a plugin exists:**

1. `rg "mod sqli_advanced" src/main.rs`
2. `rg "all_plugins" -n src/active.rs`
3. Run `cargo run -- plugins`

If README and binary disagree, **fix README or wire the module** — do not leave users believing a plugin runs when it does not.

---

## Adding a new scanner capability

1. Read **`FEATURE.md`** for what's shipped vs backlog; **`IMPLEMENTATION_PLAN.md`** for phased specs.
2. Choose **passive** (header/body) vs **active** (`ScanPlugin`) vs **spider** (discovery).
3. Add **stable** `plugin` identifiers and OWASP/CWE metadata where appropriate.
4. Extend CLI defaults (`--plugins` in `main.rs`, TUI defaults in `src/tui/`) only when the feature is **safe and expected**.
5. Add **tests** or local mock-server checks for deterministic behavior.
6. Update **README.md** only if user-facing behavior or flags change.

### Scope discipline

- Match existing style (imports, error types, `anyhow`, `tracing`).
- Avoid unrelated refactors, drive-by formatting of untouched files, or new docs the user did not ask for.
- Keep diffs minimal and purposeful.

---

## `Finding` and reports

- `Finding::new` / builders live in `src/types.rs`.
- Report schema is consumed by the broader DevSecOps design — avoid renaming JSON fields without a versioning/migration story.
- `Report::new` sorts findings by severity; risk score is derived in `report.rs`. Analyze `--tools native` adds optional JSON `"static"` (`inventory`, `risk_breakdown`, `detection_checks`, `attack_plan`) via `Report::with_static` — omitted when native did not run.

---

## Git and commits

- **Do not create git commits** unless the user explicitly asks.
- Do not change **git config** (except repo-local `core.hooksPath` via `scripts/install-hooks.sh`), use **force push** to main, or **destructive** git operations unless explicitly requested.
- Follow repository hook rules (`.githooks/` + `scripts/dev-check.sh`); if a commit fails hooks, fix the issue and create a **new** commit (do not amend pushed commits).

---

## Docker / compose

- `Dockerfile` and `docker-compose.yml` exist per README. After CLI changes, ensure **entrypoint still invokes** the correct default (bare `rustzap` may open TUI — verify `Dockerfile` CMD).

---

## Checklist before finishing a task

- [ ] `cargo fmt`, `cargo clippy -D warnings`, `cargo build` succeed
- [ ] `cargo test` succeeds (or new tests added if behavior changed)
- [ ] Plugin list / README / `FEATURE.md` aligned with actual registration in code
- [ ] No generated reports committed (`*-report.json`, `reports/*` except `.gitkeep`)
- [ ] No unauthorized-scan assumptions; intrusive features are opt-in
- [ ] Stable `plugin` strings preserved or documented for breaking changes

---

## Quick reference commands

| Goal | Command |
|------|---------|
| List active plugins | `cargo run -- plugins` |
| Passive-only scan | `cargo run -- scan --target URL --passive-only -o out.json` |
| Full scan | `cargo run -- scan --target URL --plugins xss,sqli -o out.json` |
| SARIF (Code Scanning) | `cargo run -- scan --target URL -o out.sarif` or `--sarif-out out.sarif` |
| Analyze / audit | `cargo run -- analyze . --tools native --yes -o a.json` · `cargo run -- analyze ~/src/myapp --tools semgrep,trivy,gitleaks,native,checkov --yes` · `cargo run -- audit . --target URL --yes …` (positional `REPO` overrides `--repo`; TTY prompts for path if omitted; consent: TTY prompt, or `--yes` in CI; missing Semgrep falls back to native unless `--tools` was set; `--checkov-json` skips spawn) |
| OpenAPI / HAR / Nuclei | `cargo run -- scan --target URL --openapi-path oas.json` · `--har-path rec.har` · `--nuclei` / `--nuclei-jsonl` (opt-in) |
| Spider only | `cargo run -- spider --target URL` |
| Active Directory (AD) | `cargo run -- ad --domain corp.local --dc-ip 10.0.0.1 --null-auth --checks spn,ldap --yes` (detection-only; authorization-gated; password via `--password-env RZ_AD_PASS`) |
| TUI | `cargo run -- tui` or bare `cargo run` (tab 2 = Scan URL, tab 6 / `a` = Analyze repo, tab 7 = Agent) |

---

*End of CLAUDE.md — update this file when build requirements, module wiring, or safety defaults change.*
