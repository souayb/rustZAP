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
| **E1–E4** | Report `modules`, `analyze`, `audit`, SARIF | Per `IMPLEMENTATION_PLAN.md` Phases 1–2 |
| **E5** | OpenAPI / HAR / Nuclei | `--openapi-path`/`--openapi-url`, `--har-path`, `--nuclei` / `--nuclei-jsonl` (opt-in) |

Tier **E** tracks **E6–E7** (`serve`, agentic) remain **planned** — see IMPLEMENTATION_PLAN Phases 4–5.

---

## Backlog — TODO

1. **E2 gap — IaC static analysis**  
   Checkov (or equivalent) parser + `iac/checkov`-style `plugin` prefix — deferred in IMPLEMENTATION_PLAN Phase 2.

2. **E6 — `rustzap serve` HTTP worker**  
   IMPLEMENTATION_PLAN Phase 4.

3. **E7 — Agentic `rustzap agent`**  
   IMPLEMENTATION_PLAN Phase 5 (opt-in only).

4. **B2 enhancement (optional)**  
   User-supplied `--wordlist` for sensitive paths beyond the curated `SENSITIVE_PATHS` (still opt-in and rate-limited).

5. **A5 refactor (optional)**  
   Extract redirect logic shared with open-redirect checks into something like `src/redirect_helpers.rs` if duplication grows.

---

## Suggested priority

1. **Phases 4–6** when platform/orchestration needs `serve`, agents, or webhooks.  
2. **Checkov** (E2) when IaC scanning is needed in `analyze`/`audit`.  
3. Optional B2 `--wordlist` / A5 redirect helper cleanup.

---

## Ethics and scope

- Only scan targets you are authorized to test.  
- Intrusive checks stay **off by default**; document new flags in `README.md`.

---

## Reference: Argus naming (informative)

Not a port of [Argus](https://github.com/jasonxtn/Argus). Use it for naming inspiration; implementations follow this repo’s `ScanPlugin`, passive helpers, and report schema.
