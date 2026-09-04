# RustZAP — Module roadmap and backlog

This document tracks **DAST / passive / discovery** ideas and what is still open. **Shipped behavior** for static analysis, `audit`, JSON `modules` / `static`, SARIF, correlation, and native full-repo analyzers lives in [`IMPLEMENTATION_PLAN.md`](./IMPLEMENTATION_PLAN.md) (Phases 1–2.5).

## How modules map to the codebase

| Kind | Where it lives | When it runs |
|------|----------------|--------------|
| **Passive** | `src/passive.rs` — helpers from `PassiveScanner::check_url` | Every discovered GET URL (headers + body) |
| **Active** | `src/active.rs` — `ScanPlugin` + `sqli_advanced.rs` | Query-param URLs (see `CLAUDE.md`; some plugins use `always_run`) |
| **Spider / discovery** | `src/spider.rs` — queue, `extract_urls`, robots/sitemap | Before passive/active |
| **TLS / transport** | `src/tls.rs` | Per unique host during scan |
| **Sensitive paths** | `src/sensitive_paths.rs` — opt-in plugin | When `--plugins` includes `sensitive-paths` |
| **External worker** | `src/tools.rs`, `src/installer.rs` | Optional shell-out to companion tools |
| **Native static** | `src/analyze/inventory.rs`, `src/analyze/native/` | `rustzap analyze --tools native` (Phase 2.5) or TUI tab **6·Analyze**. `analyze`/`audit` require repo consent (CLI prompt / `--yes`, or TUI `[Y]/[N]` dialog) |

Stable `plugin` strings (e.g. `passive/security-txt`, `active/sqli-error`) are part of the JSON contract.

### Evidence & confidence model (anti false-positive)

Active plugins must **prove** a payload caused the observed behavior rather than
self-validate on a weak substring match. Shared primitives live in `src/verify.rs`:

- **Baseline differential** — `Baseline::fetch` + `signature_is_new`: a DB
  error / metadata token only counts when it is *absent from the untouched
  response* and *appears after injection*.
- **Unique canaries** — `rand_token`: XSS/SSTI probes embed a per-request nonce
  so a match cannot come from unrelated page text.
- **Reflection guards** — raw (unencoded) reflection for XSS; indicators that
  are part of the injected URL are rejected for SSRF.
- **Content similarity** — `body_similarity`: boolean-blind SQLi compares
  response *structure* against the baseline and requires a reproduced TRUE/FALSE gap.

Every `Finding` now carries `confidence` (`tentative`/`firm`/`confirmed`) and
`poc_validated`. Baseline/canary-verified findings are `confirmed`; heuristics
that need human follow-up (e.g. dispatched OOB payloads) are `tentative`.
`active/sqli-oob` is inert unless a listener domain is supplied via
`RUSTZAP_OOB_DOMAIN`, since OOB can only be confirmed by an external callback.

---

## Implemented (verified in tree)

| Tier | Item | Notes |
|------|------|--------|
| **A1** | Security.txt | `passive/security-txt` — `src/passive.rs` + unit tests |
| **A2** | Robots / sitemap | `UrlSource::Robots`, caps — `src/spider.rs` + tests |
| **A3** | GraphQL introspection | `active/graphql-introspection` — `src/active.rs` |
| **A4** | HTTP methods | `active/http-methods` — `src/active.rs` |
| **A5** | Redirect chain | `active/redirect-chain` — `src/active.rs` (no shared `redirect.rs` helper) |
| **A6** | CSP review | `passive/csp-unsafe-directives` — `src/passive.rs` |
| **B1** | Tech fingerprint | `passive/tech-fingerprint` — `src/passive.rs` |
| **B2** | Sensitive paths | `active/sensitive-paths` — **opt-in via plugins** (curated list in `sensitive_paths.rs`; not on default plugin string) |
| **B3** | JWT heuristics | `passive/jwt-heuristic` — `src/passive.rs` |
| **C1** | TLS probe | `transport/tls-*` findings — `src/tls.rs`, wired from `scanner.rs` |
| **C2** | Intel (Shodan) | `src/intel.rs`, env-gated |
| **D1** | Advanced SQLi plugins | `mod sqli_advanced` in `main.rs`, merged in `ActiveScanner::new` |
| **D2** | Passive golden matrix | `tests/passive_golden.rs` + `passive::check_response_passive` harness |
| **E2** | Checkov IaC | `iac/checkov` — `src/analyze/checkov.rs`; `--tools checkov` / `iac`; `--checkov-json`; feeds `risk_breakdown.iac` when native also ran |
| **E1–E4** | Report `modules`, `analyze`, `audit`, SARIF | Per `IMPLEMENTATION_PLAN.md` Phases 1–2. Repo walk is gated: TTY prompt, `--yes` in CI, or TUI Analyze consent dialog |
| **E5** | OpenAPI / HAR / Nuclei | `--openapi-path`/`--openapi-url`, `--har-path`, `--nuclei` / `--nuclei-jsonl` (opt-in) |
| **E8** | Repo inventory | `sast/inventory` — languages, frameworks, entrypoints (`src/analyze/inventory.rs`) |
| **E9** | Native JS / DOM / forms / params | `sast/js-secrets`, `sast/js-urls`, `sast/dom-sinks`, `sast/js-cookies`, `sast/js-storage`, `sast/js-postmessage`, `sast/forms`, `sast/params` + JSON `static{ risk_breakdown, detection_checks, attack_plan }` — Phase 2.5 P0+P1 (parallel analyzers, `.gitignore` / `.rustzapignore` walk) |
| **E10** | TUI Analyze tab | `src/tui/analyze.rs` — tab 6 / `a`; consent `[Y]/[N]`; default tools `native`; writes `analyze-report.json` |
| **E11** | VS Code extension | `vscode-extension/` — analyze workspace + scan URL; Problems + findings tree; shells out to CLI |
| **F1** | Active Directory / NTLM-relay detector (Tier A) | `src/ad/` — `rustzap ad`; native LDAP signing posture, Ghost-SPN, NTLMv1/NTLM-signing flags, computer enumeration; `ad/*` plugin ids; per-host relay-path correlation; detection-only, authorization-gated |
| **F2** | VS Code AD command + attack-path tree | `vscode-extension/` — `RustZAP: Scan Active Directory`; renders `correlations` as an Attack paths section; creds via env, never settings |
| **G1** | Safety gate (wired) | `src/safety.rs` `HttpSafetyGate` — `--read-only-safe`, `--max-rps`, `--attack` → `SafetyPolicy` on scan/agent HTTP; RPS throttle + circuit breaker on active `get_response_body` + agent `send_and_capture` |
| **G2** | Curl PoC on confirmed findings | `src/agent/poc.rs` `attach_get_poc` / `build_poc_proof` — SQLi / XSS / path-traversal + AI red-team confirmed findings ship `poc` in JSON |
| **G3** | Agent explore-first + Exploit classes | `run_plugin` / `scan_target` / `replay_request` = Exploit; mutating `http_probe` elevated; recon-before-exploit gate; `export_autofix` tool + `rustzap autofix` |
| **G4** | Windows TUI key doubling fix | `src/tui/mod.rs` — only `KeyEventKind::Press` (Press+Release no longer doubles chars) |

Tier **E** tracks **E6** (`serve`) remains **planned**. Agentic tester (**E7**) is shipped with G1–G3 hardening — see IMPLEMENTATION_PLAN Phase 5.

---

## Backlog — TODO

1. **E6 — `rustzap serve` HTTP worker**  
   IMPLEMENTATION_PLAN Phase 4.

2. **B2 enhancement (optional)**
   User-supplied `--wordlist` for sensitive paths beyond the curated `SENSITIVE_PATHS` (still opt-in and rate-limited).

3. **A5 refactor (optional)**
   Extract redirect logic shared with open-redirect checks into something like `src/redirect_helpers.rs` if duplication grows.

4. **F3 — AD Tier B (native SMB signing)**
   Hand-rolled SMB2 `NEGOTIATE` signing/dialect probe (`ad/smb-signing`), building on the `src/ad/` trait seam.

5. **F4 — AD Tier C (RelayKing parity)**
   MS-RPC coercion detection (PetitPotam/PrinterBug/DFSCoerce), MSSQL/WinRM EPA, CVE-2025-33073 / CVE-2025-54918 / CVE-2019-1040 logic, and cross-host coercion→relay correlation. Optionally a RelayKing shell-out adapter as a cross-check for uncovered protocols. Large, multi-branch effort.

6. **G5 — Strix Docker sandbox / multi-agent** (not planned in-tree)
   External Strix CLI parity (sandbox exploit runtime, graph-of-agents) remains out of scope; prefer wiring RustZAP’s native gates and PoCs.

---

## Suggested priority

1. **Phases 4–6** when platform/orchestration needs `serve`, agents, or webhooks.  
2. Optional B2 `--wordlist` / A5 redirect helper cleanup.

---

## Ethics and scope

- Only scan targets you are authorized to test.  
- Intrusive checks stay **off by default**; document new flags in `README.md`.

---

## Reference: Argus naming (informative)

Not a port of [Argus](https://github.com/jasonxtn/Argus). Use it for naming inspiration; implementations follow this repo’s `ScanPlugin`, passive helpers, and report schema. Full-repo JS/HTML surface mapping is **Phase 2.5** (`sast/js-secrets`, `sast/dom-sinks`, `sast/js-cookies`, `sast/js-storage`, `sast/js-postmessage`, `sast/forms`, `sast/params`) — see [`IMPLEMENTATION_PLAN.md`](./IMPLEMENTATION_PLAN.md).
