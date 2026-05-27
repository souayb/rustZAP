# RustZAP — Module roadmap and backlog

This document tracks **DAST / passive / discovery** ideas and what is still open. **Shipped behavior** for static analysis, `audit`, JSON `modules`, SARIF, and correlation lives in [`IMPLEMENTATION_PLAN.md`](./IMPLEMENTATION_PLAN.md) (Phases 1–2 done there).

## How modules map to the codebase

| Kind | Where it lives | When it runs |
|------|----------------|--------------|
| **Passive** | `src/passive.rs` — helpers from `PassiveScanner::check_url` | Every discovered GET URL (headers + body) |
| **Active** | `src/active.rs` — `ScanPlugin` + `sqli_advanced.rs` | Query-param URLs (see `CLAUDE.md`; some plugins use `always_run`) |
| **Spider / discovery** | `src/spider.rs` — queue, `extract_urls`, robots/sitemap | Before passive/active |
| **TLS / transport** | `src/tls.rs` | Per unique host during scan |
| **Sensitive paths** | `src/sensitive_paths.rs` — opt-in plugin | When `--plugins` includes `sensitive-paths` |
| **External worker** | `src/tools.rs`, `src/installer.rs` | Optional shell-out to companion tools |

Stable `plugin` strings (e.g. `passive/security-txt`, `active/sqli-error`) are part of the JSON contract.

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
| **E1–E4** | Report `modules`, `analyze`, `audit`, SARIF | Per `IMPLEMENTATION_PLAN.md` Phases 1–2 (`report.rs`, `analyze/`, `correlate.rs`, `sarif.rs`) |

Tier **E** tracks **E5–E7** (OpenAPI/HAR, `serve`, agentic) remain **planned** — see IMPLEMENTATION_PLAN Phases 3–5.

---

## Backlog — TODO

These are **not** done or only partially aligned with older FEATURE wording:

1. **D2 — Passive golden / integration matrix**  
   Dedicated `tests/passive_golden.rs` (or similar) with shared mock HTTP fixtures / optional snapshot tests. Today passive behavior is covered mainly by unit tests inside `passive.rs`.

2. **E2 gap — IaC static analysis**  
   Checkov (or equivalent) parser + `iac/checkov`-style `plugin` prefix — deferred in IMPLEMENTATION_PLAN Phase 2.

3. **E5 — OpenAPI import, HAR replay, Nuclei**  
   IMPLEMENTATION_PLAN Phase 3.

4. **E6 — `rustzap serve` HTTP worker**  
   IMPLEMENTATION_PLAN Phase 4.

5. **E7 — Agentic `rustzap agent`**  
   IMPLEMENTATION_PLAN Phase 5 (opt-in only).

6. **B2 enhancement (optional)**  
   User-supplied `--wordlist` for sensitive paths beyond the curated `SENSITIVE_PATHS` (still opt-in and rate-limited).

7. **A5 refactor (optional)**  
   Extract redirect logic shared with open-redirect checks into something like `src/redirect_helpers.rs` if duplication grows.

---

## Suggested priority

1. **D2** if you want CI-grade regression coverage for passive checks.  
2. **IMPLEMENTATION_PLAN Phase 3** (OpenAPI/HAR/Nuclei) for attack-surface expansion.  
3. **Phases 4–6** when platform/orchestration needs `serve`, agents, or webhooks.

---

## Ethics and scope

- Only scan targets you are authorized to test.  
- Intrusive checks stay **off by default**; document new flags in `README.md`.

---

## Reference: Argus naming (informative)

Not a port of [Argus](https://github.com/jasonxtn/Argus). Use it for naming inspiration; implementations follow this repo’s `ScanPlugin`, passive helpers, and report schema.
