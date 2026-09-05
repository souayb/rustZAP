# RustZAP — Detailed implementation plan

This document turns the platform roadmap into **actionable specs**: file layout, data contracts, CLI shapes, phased deliverables, and acceptance criteria. It extends the high-level vision in [`SOFTWARE_DESIGN_DOCUMENT.md`](./SOFTWARE_DESIGN_DOCUMENT.md) and complements module ideas in [`FEATURE.md`](./FEATURE.md).

**Status legend**

| Label | Meaning |
|-------|---------|
| **Done** | Shipped in the current tree |
| **Planned** | Spec’d here; not implemented |
| **Partial** | Some plumbing exists; completion work listed |

---

## Table of contents

1. [Goals and constraints](#1-goals-and-constraints)
2. [Current architecture (as implemented)](#2-current-architecture-as-implemented)
3. [Target architecture](#3-target-architecture)
4. [Reference open-source integrations](#4-reference-open-source-integrations)
5. [Phase 1 — JSON report modules, analyze CLI, Semgrep](#phase-1--json-report-modules-analyze-cli-semgrep)
6. [Phase 2 — Multi-tool audit, correlation, SARIF](#phase-2--multi-tool-audit-correlation-sarif)
7. [Phase 2.5 — Full-repo static depth](#phase-25--full-repo-static-depth)
8. [Phase 3 — OpenAPI/HAR, Nuclei, DAST depth](#phase-3--openapihar-nuclei-dast-depth)
9. [Phase 4 — HTTP API worker mode](#phase-4--http-api-worker-mode)
10. [Phase 5 — Agentic security](#phase-5--agentic-security)
11. [Phase 6 — Platform and long tail](#phase-6--platform-and-long-tail)
12. [Testing strategy](#11-testing-strategy)
13. [Documentation maintenance](#12-documentation-maintenance)

---

## 1. Goals and constraints

### 1.1 Product goals

- **Unified machine-readable output**: One JSON contract (evolving additively) for DAST + future SAST/SCA/tool runs, suitable for CI and the Unified Finding Format (UFF) described in the SDD.
- **Code analysis in the CLI**: Today Semgrep/Trivy/Gitleaks run from the TUI with streamed logs only — bring **parsed findings** into `Finding` and reports.
- **Optional agentic mode**: Human-in-the-loop, scope-enforced, never default-on; aligns with patterns from [Strix](https://github.com/usestrix/strix), [PentAGI](https://github.com/vxcontrol/pentagi), and OWASP Agentic guidance.
- **DAST parity growth**: Borrow breadth ideas from [OWASP ZAP](https://www.zaproxy.org/), [Argus](https://github.com/jasonxtn/Argus), and optional template engines ([Nuclei](https://github.com/projectdiscovery/nuclei)).

### 1.2 Non-negotiables (from `CLAUDE.md`)

- No unauthorized-scan assumptions; intrusive behavior stays **opt-in** and documented.
- Stable `Finding::plugin` prefixes where possible (`passive/`, `active/`, `sast/`, `sca/`, …). Breaking renames require a version/migration note in this file and README.
- New high-rate or exploitation features: explicit flags + README warnings + tests on mock/lab targets.

---

## 2. Current architecture (as implemented)

### 2.1 Scan pipeline (**Done**)

`scanner::run_scan` / `run_scan_with_events`:

1. **Spider** → `Vec<DiscoveredUrl>`
2. **Passive** → findings merged by `PassiveScanner`
3. **Active** → `ActiveScanner` + `ScanPlugin`s (URLs without query params skipped unless plugin uses `always_run()`)
4. **TLS** (`tls.rs`) + **Intel** (`intel.rs`, env-gated)
5. **Report** (`report.rs`): JSON primary; CSV/HTML secondary

CLI entry: `src/main.rs` subcommands (`scan`, `spider`, `proxy`, `passive`, `plugins`, `tui`, `install`, `stress`).

### 2.2 Module roll-up (**Partial**)

- **CLI / TUI**: `types::summarize_modules` + `passive::known_plugin_names`, `ActiveScanner::enabled_module_names`, `tls::known_plugin_names`, `intel::known_plugin_names` drive the **MODULES** banner and `ScanEvent::ModuleRan`.
- **JSON report**: `Report` in `report.rs` includes `modules[]` and optional `correlations[]` (Phase 1–2 **Done**).

### 2.3 External tools (**Partial**)

- `tools.rs`: detects tools, spawns processes, streams lines as `ToolEvent`.
- **Gap**: no JSON parse path from Semgrep/Trivy/Gitleaks into `Finding`.

### 2.4 Key types (**Done**)

- `Finding`, `ModuleSummary`, `DiscoveredUrl`, `UrlSource` — `src/types.rs`
- `ScanEvent` — `src/events.rs`
- `ScanPlugin` — `src/active.rs`

---

## 3. Target architecture

```text
                         ┌─────────────────────────────────────┐
                         │ CLI: scan | analyze | audit | agent │
                         │      serve (future HTTP worker)      │
                         └─────────────────┬───────────────────┘
                                           │
           ┌───────────────────────────────┼───────────────────────────────┐
           │                               │                               │
           ▼                               ▼                               ▼
   ┌───────────────┐              ┌─────────────────┐               ┌─────────────┐
   │ scanner.rs    │              │ analyze/audit   │               │ agent/      │
   │ (existing)    │              │ orchestrator    │               │ (Phase 5)   │
   └───────┬───────┘              └────────┬────────┘               └──────┬──────┘
           │                               │                               │
           │         ┌─────────────────────┴─────────────────────┐         │
           │         │ normalize (UFF-ish Finding assembly)       │◄────────┘
           │         └─────────────────────┬─────────────────────┘
           │                               │
           ▼                               ▼
   ┌───────────────────────────────────────────────────────────────────────┐
   │ report.rs — JSON + optional SARIF; modules[], correlations[], static{}  │
   └───────────────────────────────────────────────────────────────────────┘
```

**New top-level Rust modules (Planned)**

| Path | Responsibility |
|------|----------------|
| `src/analyze/mod.rs` | Orchestrate static/tool scans from CLI |
| `src/analyze/semgrep.rs` | Parse Semgrep JSON → `Vec<Finding>` |
| `src/analyze/trivy.rs` | Parse Trivy JSON → `Vec<Finding>` |
| `src/analyze/gitleaks.rs` | Parse Gitleaks JSON → `Vec<Finding>` |
| `src/analyze/inventory.rs` | Repo walk: languages, frameworks, entrypoints (Phase 2.5) |
| `src/analyze/native/` | Built-in JS secrets/URLs, DOM sinks, forms, params (Phase 2.5) |
| `src/analyze/static_report.rs` | Aggregate `Report.static` (risk, detection_checks, attack_plan) |
| `src/analyze/checkov.rs` | Parse Checkov JSON → `Vec<Finding>` (`iac/checkov`; opt-in, noisy) |
| `src/normalize/mod.rs` | Shared helpers: severity mapping, plugin id rules |
| `src/correlate.rs` | Rule-based join of static + dynamic findings (Phase 2) |
| `src/sarif.rs` | Emit SARIF 2.1 for GitHub Code Scanning (Phase 2) |
| `src/agent/mod.rs` | Agent loop, tool registry, safety — Phase 5 only |

Each new `mod` must be declared in `src/main.rs` (or a `lib.rs` if the project splits later).

---

## 4. Reference open-source integrations

| Project | Role | Integration style |
|---------|------|-------------------|
| [Semgrep](https://github.com/semgrep/semgrep) | SAST | Subprocess `--json`; map rules → `Finding` |
| [Trivy](https://github.com/aquasecurity/trivy) | SCA / fs | `--format json`; CVE + path |
| [Gitleaks](https://github.com/gitleaks/gitleaks) | Secrets | JSON report mode |
| [Checkov](https://github.com/bridgecrewio/checkov) | IaC | JSON output; optional `--framework` filters |
| [Nuclei](https://github.com/projectdiscovery/nuclei) | Template DAST | Subprocess `-jsonl` or `-json-export` |
| [OWASP ZAP](https://www.zaproxy.org/) | UX / parity | Concepts: context, HAR, authenticated scan |
| [Argus](https://github.com/jasonxtn/Argus) | Module ideas | Naming + breadth reference (`FEATURE.md`) |
| [Strix](https://github.com/usestrix/strix) | Agentic + CI | Headless flags, sandbox, PoC validation patterns |
| [PentAGI](https://github.com/vxcontrol/pentagi) | Multi-agent pentest | Planning + memory graph inspiration |
| [Agent-Smith](https://github.com/0x0pointer/agent-smith) | Full-stack flows | Repo → routes/sinks → DAST pivot |
| [Crucible](https://github.com/crucible-security/crucible) | Agentic AI security | LLM/agent abuse test modules |

---

## Phase 1 — JSON report modules, analyze CLI, Semgrep

**Objective**: Close the SDD §9.1 gap for JSON consumers and ship the first **code analyzer** path in the CLI.

### 1.1 JSON report: `modules` array (**Planned**)

**Schema (additive)**

Extend `report::Report` with an optional field (use `#[serde(default)]` if deserializing old reports is ever needed):

```json
{
  "meta": { "...": "..." },
  "summary": { "...": "..." },
  "modules": [
    {
      "name": "active/sqli",
      "findings": 1,
      "max_severity": "critical",
      "quiet": false
    }
  ],
  "urls": [],
  "findings": []
}
```

**Implementation steps**

1. Add `pub modules: Vec<ModuleSummary>` to `Report` in `src/report.rs` (or wrap in `Option<Vec<ModuleSummary>>` — prefer **required empty vec** for new writes, `Option` only if backward compat for parsers that omit the field matters).
2. Change `Report::new` signature to accept `modules: Vec<ModuleSummary>` **or** compute inside `Report::from_scan(...)` helper that duplicates the **same known-module list** as `scanner::print_module_summary`:
   - `passive::known_plugin_names()`
   - `ActiveScanner::enabled_module_names()`
   - `tls::known_plugin_names()` if TLS ran
   - `intel::known_plugin_names()` if intel enabled  
   Recommendation: extract a small `scanner::compute_module_summaries(findings, scan_context) -> Vec<ModuleSummary>` to avoid divergence between CLI banner and JSON.
3. Update `scanner::run_scan` and `run_scan_with_events` completion paths wherever `Report::new` is called.
4. **Acceptance**: A passive-only scan against `example.com` produces JSON with `modules` including quiet passive plugins; active scan lists enabled `active/*` modules.

### 1.2 New subcommand: `analyze` (**Planned**)

**CLI shape (recommended)**

```text
rustzap analyze [REPO] [--repo <PATH>] [--semgrep-json <file.json>] --output <file.json>
```

- Positional `REPO` overrides `--repo`. If neither is given, a TTY prompts `Repository path [.] :` (empty → `.`); non-TTY defaults to `.` only with `--yes`.
- For Phase 1, `rustzap analyze` is **Semgrep-first only** (default `--tools semgrep`). Missing Semgrep on PATH falls back to native unless `--tools` was passed explicitly.
- If `--semgrep-json` is provided, RustZAP parses it (no Semgrep runtime dependency).
- **Consent:** `analyze` and `audit` must not walk a local repo silently. A TTY prints an ask-before-access prompt; CI / non-TTY **must** pass `--yes` (`-y`). DAST-only `scan` is unchanged.

**Semgrep invocation**

- Command (default, when `--semgrep-json` is omitted): `semgrep scan --quiet --json --config auto .`
- Working directory: `repo` path.
- Parse stdout JSON on success; map each result to `Finding`:

| Semgrep field | `Finding` field |
|---------------|-----------------|
| `check_id` or rule id | `plugin`: `sast/semgrep` + `parameter`: check_id |
| `message` or `extra.message` | `title`, `description` |
| `path` + `start.line` | `location` + `url` as `file://...#Lx` |
| Severity from `extra.severity` or metadata | Map to `Severity` with a lookup table |

**Plugin ID rules**

- Prefix: `sast/semgrep` — stable module id for Phase 1 Semgrep results.
- `url`: Use `file://` + absolute path + optional `#L42` fragment for tooling, **or** `repo-relative` string in evidence only — pick one convention and document in README.

### 1.3 `Finding` extensions (**Planned**, backward compatible)

Add **optional** serde fields to `Finding` in `types.rs`:

```rust
#[serde(default, skip_serializing_if = "Option::is_none")]
pub source_tool: Option<String>,   // "semgrep", "rustzap", …

#[serde(default, skip_serializing_if = "Option::is_none")]
pub location: Option<CodeLocation>, // file + start line (+ optional end)

#[serde(default)]
pub poc_validated: bool,           // reserved for Phase 5; default false

#[serde(default)]
pub correlated_with: Vec<String>,  // Finding ids — Phase 2
```

```rust
pub struct CodeLocation {
    pub file: String,
    pub line_start: u32,
    pub line_end: Option<u32>,
}
```

Rules:

- Existing JSON consumers ignore unknown fields if they parse loosely; serde **skip** ensures minimal diff for empties.
- DAST findings leave `location: None`; SAST populates it.

### 1.4 Tests (**Planned**)

- **Unit**: Golden minimal Semgrep JSON fixture under `tests/fixtures/semgrep_small.json` → assert N findings and one `plugin` shape.
- **Integration**: `cargo test` with `#[cfg]` skipping if `semgrep` absent, **or** unit-only fixtures (preferred for CI determinism).

### 1.5 Phase 1 acceptance checklist

- [x] `rustzap scan -o report.json` includes `"modules": [...]` consistent with MODULES CLI block (`scanner::collect_scan` + `Report.modules`).
- [x] `rustzap analyze --repo . --output semgrep-findings.json` writes a valid report with `modules[]` (CI: `--semgrep-json tests/fixtures/semgrep_small.json`).
- [x] README documents `analyze` and the new JSON fields.

---

## Phase 2 — Multi-tool audit, correlation, SARIF

### 2.1 Subcommand: `audit` (**Done**)

```text
rustzap audit [--repo DIR] [--target URL] [--tools semgrep,trivy,gitleaks]
              [--correlate] [--output unified.json] [--sarif-out …] [--yes]
```

Execution model (implemented in `analyze/mod.rs`):

1. Confirm repo access (TTY prompt, or `--yes` in non-interactive / CI).
2. If `--target`: in-process `scanner::collect_scan`.
3. Static tools on `--repo` via `run_static_analysis` (fixture paths or subprocess).
4. Merge findings, build `modules[]`, optional `correlate_findings`, JSON + optional SARIF.

### 2.2 Parsers (**Done** for Semgrep, Trivy, Gitleaks, Checkov)

| Tool | Output flag | Mapper module |
|------|-------------|---------------|
| Trivy | `trivy fs --format json` | `analyze/trivy.rs` → `plugin` id `sca/trivy` |
| Gitleaks | `gitleaks detect --report-format json` | `analyze/gitleaks.rs` → `secrets/gitleaks` |
| Checkov | `checkov -d . -o json --quiet --compact` | `analyze/checkov.rs` → `iac/checkov` (opt-in; `--tools checkov` / `iac`; `--checkov-json`) |

### 2.3 Correlation engine (**Done**, extensible)

**File**: `src/correlate.rs`

**Deterministic rules**

1. Semgrep SQL-ish signal + `active/sqli*` when paths align → severity bump + pairwise `correlated_with`.
2. Trivy vulnerable package (from evidence) referenced in Semgrep fields/path + at least one HTTP(S) `active/*` or `passive/*` finding → tripartite correlation; **Critical** Trivy adds `elevated_severity` / may bump the linked web finding to High.

Emit **optional** `correlations[]`:

```json
"correlations": [
  {
    "id": "corr-<uuid>",
    "finding_ids": ["...", "..."],
    "reason": "SAST SQL sink + confirmed DAST SQLi",
    "elevated_severity": "critical"
  }
]
```

Report-level `correlations[]` plus per-finding `correlated_with` (best-effort).

### 2.4 SARIF export (**Done**)

**File**: `src/sarif.rs`  
**CLI**: `--sarif-out` on `analyze` / `audit`; **`scan`** supports `--output … .sarif` or `--sarif-out` alongside JSON/HTML/CSV.

Minimum: SARIF 2.1 `runs[].results[]` from `Finding` with regions from `CodeLocation` when present.

### 2.5 Phase 2 acceptance checklist

- [x] `audit` produces one JSON with mixed `plugin` prefixes (`audit_merges_static_fixtures_without_dast` test).
- [x] Correlation rules covered by unit tests (`correlate::tests`: SQLi path + Trivy/Semgrep/web).
- [ ] SARIF validates in GitHub’s upload (manual: README notes + `upload-sarif` workflow on your repo).

---

## Phase 2.5 — Full-repo static depth

**Status: Partial (P0+P1 done)** — native analyzers inspired by HacksGuard (risk score, `detection_checks`, parallel modules) and [Argus](https://github.com/jasonxtn/Argus) (JS secrets / DOM sinks / cookies / storage / postMessage / forms / params). No extra subprocesses; Semgrep/Trivy/Gitleaks remain optional siblings. Checkov / `iac/*` is still deferred.

### 2.5.1 Architecture

```text
rustzap analyze --repo . --tools semgrep,trivy,gitleaks,native
        │
        ▼
inventory (languages, frameworks, entrypoints)
        ▼
native analyzers in parallel (tokio spawn_blocking):
  js_surface | dom_sinks | forms | params
        ▼
aggregator (deterministic sort: plugin, file/url, line) → static{ … }
```

Walk skips `node_modules`, `target`, `.git`, `vendor`, `dist`, `build`, `__pycache__`, and other common generated trees, plus patterns from `.gitignore` and `.rustzapignore` (nested ignore files included). File cap: 4000. JS files over 512KB / `*.min.*` are skipped. Local fixture/repo analysis only — no network.

### 2.5.2 Report schema (`Report.static`, additive)

Omitted (`skip_serializing_if`) when `native` did not run so existing DAST/analyze reports stay compatible.

```json
"static": {
  "inventory": { "languages": [], "frameworks": [], "entrypoints": [] },
  "risk_score": 0,
  "risk_breakdown": {
    "secrets": 0, "sinks": 0, "config": 0, "sca": 0, "iac": 0
  },
  "detection_checks": [
    { "id": "js-dom-sinks", "triggered": true, "severity": "medium", "count": 12 }
  ],
  "attack_plan": [
    { "url": "/login", "method": "POST", "params": ["user","pass"], "reason": "form+password" }
  ]
}
```

`risk_breakdown` holds weighted category scores (secrets/sinks high; config from forms+params; sca/iac from `sca/*` and `iac/*` plugins if present). `risk_score` is the sum capped at 100.

### 2.5.3 Native modules (Argus mapping)

| Argus-style idea | RustZAP `plugin` | Check id | P0/P1 |
|------------------|------------------|----------|-------|
| Repo inventory | `sast/inventory` | `inventory` | Done |
| JS secret patterns | `sast/js-secrets` | `js-secrets` | Done |
| JS URLs / source maps | `sast/js-urls` | `js-urls` | Done |
| DOM sinks (+ `dangerouslySetInnerHTML`) | `sast/dom-sinks` | `js-dom-sinks` | Done |
| Cookies (`document.cookie` assign/access) | `sast/js-cookies` | `js-cookies` | Done (P1) |
| Web storage (`localStorage` / `sessionStorage`) | `sast/js-storage` | `js-storage` | Done (P1) |
| `postMessage(` | `sast/js-postmessage` | `js-postmessage` | Done (P1) |
| HTML / template forms | `sast/forms` | `forms` | Done |
| Parameter mining | `sast/params` | `params` | Done |
| Parallel analyzer threads | `tokio::join!` + `spawn_blocking` | — | Done (P1) |
| `.gitignore`-aware walk | `.gitignore` + `.rustzapignore` | — | Done (P1) |

Findings use `source_tool: "rustzap-native"`. Secret evidence is redacted.

### 2.5.4 CLI

```text
rustzap analyze [REPO] --tools native
rustzap analyze --repo <PATH> --tools native
rustzap analyze --repo <PATH> --tools semgrep,trivy,gitleaks,native --yes   # CI
rustzap audit   [REPO] --tools native[,semgrep,…] --yes
```

`AnalyzeTool::Native` alias: `native`. When selected, inventory + JS/HTML/param analyzers run **even without Semgrep**. Default `--tools` for `analyze` remains `semgrep` (native is opt-in).

**Files**

| Path | Role |
|------|------|
| `src/analyze/inventory.rs` | Walk + language/framework/entrypoint detection |
| `src/analyze/gitignore.rs` | `.gitignore` / `.rustzapignore` glob matching |
| `src/analyze/native/js_surface.rs` | Secrets, URLs, sourceMappingURL |
| `src/analyze/native/dom_sinks.rs` | DOM XSS + cookie / storage / postMessage sinks |
| `src/analyze/native/forms.rs` | `<form>` extract → `attack_plan` |
| `src/analyze/native/params.rs` | `req.query` / Flask / `@RequestParam` / … |
| `src/analyze/static_report.rs` | `StaticAnalysis` aggregator |
| `tests/fixtures/native_app/` | Tiny HTML + JS + Flask/Express fixture |

### 2.5.5 Phase 2.5 acceptance checklist

- [x] Repo inventory (`sast/inventory`) with languages / frameworks / entrypoints.
- [x] Native JS surface: secrets (redacted) + URLs + source maps.
- [x] DOM sinks including `dangerouslySetInnerHTML`.
- [x] Cookie / `localStorage` / `sessionStorage` / `postMessage` sinks (`sast/js-cookies`, `sast/js-storage`, `sast/js-postmessage`).
- [x] Form + param extractors populate `attack_plan`.
- [x] JSON `static{}` with `risk_breakdown`, `detection_checks`, `attack_plan`; omitted when native is off.
- [x] `rustzap analyze --tools native` (no Semgrep required); mixable with semgrep/trivy/gitleaks/checkov.
- [x] Fixture + unit tests; `cargo fmt`, `clippy -D warnings`, `cargo test`.
- [x] Parallel native analyzers (P1).
- [x] Gitignore-aware walk (P1; `.gitignore` + `.rustzapignore`; skip-list still covers generated trees).
- [x] Checkov / `iac/checkov` feeding `risk_breakdown.iac` (opt-in `--tools checkov`; not in analyze/audit defaults).

---

## Phase 3 — OpenAPI/HAR, Nuclei, DAST depth

### 3.1 OpenAPI import (**Done**)

- CLI: `--openapi-path` / `--openapi-url` on `scan`.
- `src/openapi.rs` → synthetic `DiscoveredUrl` (`UrlSource::OpenApi`) + info finding `passive/openapi-import`.
- Path templates filled with placeholder `1`; query param names appended so active plugins see `?`.

### 3.2 HAR replay (**Done**)

- CLI: `--har-path recording.har`.
- `src/har.rs` → same-origin filter vs `--target`; `UrlSource::Har`; dedupe method+URL.

### 3.3 Nuclei (**Done**, opt-in)

- CLI: `--nuclei` (spawn) or `--nuclei-jsonl` (fixture/CI).
- `src/nuclei.rs` → findings `active/nuclei/<template-id>`; never default-on.
- README warns on authorized scope only.

### 3.4 Phase 3 acceptance checklist

- [x] OpenAPI + HAR + Nuclei parsers covered by unit/fixture tests (`tests/phase3_import.rs`, `tests/fixtures/*`).
- [x] Nuclei behind explicit flag; README warns on scope.
- [ ] Optional: Juice-Shop lab walkthrough with a real OpenAPI file (manual).

---

## Phase 4 — HTTP API worker mode

### 4.1 `serve` subcommand (**Planned**)

```text
rustzap serve --listen 127.0.0.1:8090 [--auth-token ENV]
```

**MVP endpoints** (mirror SDD §6 subset)

| Method | Path | Body | Response |
|--------|------|------|----------|
| POST | `/api/v1/scans` | `{ "target", "plugins", "passive_only" }` | `{ "id" }` |
| GET | `/api/v1/scans/{id}` | — | status + path to report |
| GET | `/api/v1/scans/{id}/report` | — | JSON report |

**Implementation notes**

- Use `axum` or `warp` (new dependency — justify in PR).
- Run scans in `tokio::spawn` with job table `Arc<Mutex<HashMap<Uuid, JobState>>>`.
- **Security**: bind default `localhost`; prod requires token; document threat model.

### 4.2 Phase 4 acceptance checklist

- [ ] Docker Compose optional sidecar invoking `serve` documented.
- [ ] No default open bind on `0.0.0.0` without README warning.

---

## Phase 5 — Agentic security ✅ (core + Strix-inspired hardening)

### 5.1 Principles

- **Opt-in**: `rustzap agent ...` never implied by bare `rustzap`.
- **Scope file**: YAML/JSON listing allowed schemes, hosts, max requests/min, forbidden paths regex.
- **Approval gates**: autonomy matrix + Exploit-class tools (`run_plugin`, `scan_target`, `replay_request`, mutating `http_probe`, `ai_redteam`).
- **Explore-first**: Exploit tools denied until a successful recon tool (or non-empty frontier), unless `--ai-redteam` / `auto_approve`.
- **Safety**: `--read-only-safe`, `--max-rps`, `--attack` wire into `SafetyPolicy` / `HttpSafetyGate` on agent HTTP.
- **Trace**: append-only `agent-trace.jsonl` with tool calls + redacted headers.

Reference UX: non-interactive CI flag (`-n`) pattern from **Strix** docs.

### 5.2 `AgentTool` registry (**Shipped**)

Wrap without duplicating scanner logic: `scan_target`, `analyze_repo`, `run_plugin`, `http_probe`, `list_captures`, `replay_request`, `ai_redteam`, `spawn_subtask`, `export_autofix`.

Planner: `AgentBrain` with `LlmBrain` and `ScriptedBrain`.

### 5.3 AI red team module (**Shipped**)

`--ai-redteam` runs OWASP LLM Top-10 probes; confirmed hits attach curl `PocProof`.

### 5.4 Autofix export (**Shipped MVP**)

`rustzap autofix --report report.json --out patches/` and agent tool `export_autofix` write remediation prompt `.md` files for findings with `location` (no in-process LLM patch apply).

### 5.5 Phase 5 acceptance checklist

- [x] Agent cannot run without scope file (--scope required).
- [x] README “Ethics” section mentions LLM misuse and MCP risks.
- [x] SafetyPolicy wired to scan + agent HTTP; curl PoC on key confirmed findings.
- [x] Explore-first + Exploit reclassification.
- [ ] Docker sandbox / multi-agent Graph (explicitly out of scope — see FEATURE G5).

---

## Phase 7 — Active Directory / NTLM-relay detection ✅ (Tier A)

Adds a new assessment domain (Windows/AD identity) alongside Web (DAST) and
Code/IaC (SAST). New `src/ad/` module + `rustzap ad` subcommand.

- **Tier A (shipped):** native LDAP/LDAPS signing posture (`ad/ldap-signing`,
  `ad/ldap-channel-binding`), Ghost-SPN detection (`ad/ghost-spn`, LDAP SPN query +
  DNS), NTLM negotiate-flag inspection (`ad/ntlmv1`, `ad/ntlm-signing`, over HTTP/
  WinRM), and LDAP domain-computer enumeration (`ad/computer`, `--audit`).
- Network I/O sits behind `LdapDirectory` / `NtlmProbe` / `DnsResolver` traits
  (`src/ad/probe.rs`) with `ldap3`/`hickory-resolver`/`reqwest` live impls and
  in-memory mocks, so verdict logic unit-tests with **no live DC**.
- Findings flow through the existing `Finding` model, `write_report` (`modules`,
  SARIF/CSV/HTML), and a new `correlate_ad_relay_paths` rule that consolidates
  per-host weaknesses into one elevated **"NTLM relay exposure on <host>"** finding.
- **Safety:** detection only (no relay-target list, no coercion), explicit
  `rustzap ad` subcommand, authorization consent (TTY or `--yes`), bind password
  via `--password-env` (never argv). VS Code: `RustZAP: Scan Active Directory`
  command + Attack-paths tree section; credentials prompted, passed via env.
- **Tier B/C (planned):** native SMB2 signing probe; MS-RPC coercion
  (PetitPotam/PrinterBug/DFSCoerce), MSSQL/WinRM EPA, CVE-2025-33073 /
  CVE-2025-54918 / CVE-2019-1040; optional RelayKing shell-out cross-check.

**Acceptance:**
- [x] `rustzap ad` gated by consent (TTY prompt / `--yes`); refuses non-TTY without `--yes`.
- [x] AD findings produce `ad/*` module rows and a relay-path correlation in JSON/SARIF.
- [x] Validated against a real Samba AD DC (`tests/ad-lab/`): live LDAP bind, SPN + computer enumeration, DNS-based ghost-SPN, and `ad/ldap-signing` posture all fire; the run also surfaced and fixed a ghost-SPN false-positive class (Kerberos/GUID/short-name SPNs).

---

## Phase 6 — Platform and long tail

- Falco webhook ingest (`POST /webhooks/falco`) — extend `serve`.
- Native lightweight Rust SAST (tree-sitter) — **optional**, large scope.
- gRPC plugin SDK — align with SDD §9 Kubernetes worker story.
- Extend `CONTRIBUTION.md` with UFF normalization guidelines once `normalize/` grows.

---

## 11. Testing strategy

| Layer | Approach |
|-------|----------|
| Parsers | Fixture JSON → unit tests (`tests/fixtures/`). |
| Native static (2.5) | `tests/fixtures/native_app/` + unit tests in `analyze/native/*` and `tests/native_analyze.rs`. |
| Correlation | Synthetic `Finding` vectors. |
| Report | Snapshot or insta (see `FEATURE.md` backlog **D2** passive golden matrix). |
| HTTP API | `axum::Router` tests with `tower::ServiceExt`. |
| Agent | Mock `AgentBrain`; no live LLM in CI. |

**CI policy**: Prefer fixtures over requiring Semgrep/Nuclei in GitHub Actions; optional jobs with tools allowed.

---

## 12. Documentation maintenance

When implementing a phase:

1. Update this file’s **Status** (move sections from Planned → Done).
2. Update **README** CLI section and architecture tree.
3. Update **SOFTWARE_DESIGN_DOCUMENT.md** Phase roadmap checkboxes if present.
4. Keep **CHANGELOG** or GitHub Releases note (if project adopts them later).

---

*End of IMPLEMENTATION_PLAN.md*
