# RustZAP — Planned modules and implementation guide

This document proposes **new scanner modules** that extend RustZAP toward broader reconnaissance and web analysis (in the spirit of modular toolkits like [Argus](https://github.com/jasonxtn/Argus) `argus/modules/`) while staying aligned with the **Unified DevSecOps** design in `SOFTWARE_DESIGN_DOCUMENT.md`.

## How modules map to the codebase

| Kind | Where it lives | When it runs |
|------|----------------|--------------|
| **Passive** | `src/passive.rs` — helper fns called from `PassiveScanner::check_url` | Every discovered GET URL; uses response headers + body already fetched |
| **Active** | `src/active.rs` — type implementing `ScanPlugin` | URLs with query parameters (or extend rules per plugin) |
| **Spider / discovery** | `src/spider.rs` — seed queue, `extract_urls` | Expands crawl surface before passive/active |
| **TLS / transport** | New submodule e.g. `src/tls.rs` or checks inside passive using connection info | After HTTP handshake or via dedicated probe |
| **External worker** | `src/tools.rs` + platform orchestrator | Heavy tools (Nmap, Nikto); RustZAP only detects/runs binaries |

**Outputs:** every finding should use `crate::types::Finding` with a stable `plugin` string (e.g. `passive/security-txt`, `active/graphql-introspection`) so normalized reports and CI stay consistent.

---

## Tier A — High value, HTTP-only, good for CI fixtures

These need **no API keys** and can be tested with a local `axum`/`hyper` test server.

### A1. Security.txt probe

**Goal:** Fetch `https://target/.well-known/security.txt` (and optional `security.txt` at root) and report missing, invalid, or expired `Expires`.

**Tasks**

1. Add `check_security_txt(client, base_origin_url) -> Vec<Finding>` (or fold into `check_url` with origin derived from `url::Url::origin()`).
2. `GET` standard paths; treat 404 as informational finding; parse key fields (`Contact`, `Expires`) lightly.
3. Register plugin id `passive/security-txt`.
4. Add integration test: mock server returns 200 with body → no finding; 404 → info finding.

### A2. Sitemap & robots discovery (spider enrichment)

**Goal:** Parse `/robots.txt` for `Disallow`/`Allow` and `Sitemap:` lines; fetch listed sitemaps (with depth/size caps); enqueue URLs into the spider queue.

**Tasks**

1. In `Spider::crawl`, after successful GET, if path is `/` or `/robots.txt`, schedule fetch of `/robots.txt`.
2. Implement small parsers (line-based robots, XML sitemap index + urlset) with **max URL count** and **max response bytes** to avoid abuse.
3. New `UrlSource` variants if useful: `Robots`, `Sitemap`.
4. Tests: static strings for robots + minimal sitemap XML → expected discovered URLs.

### A3. GraphQL introspection probe (active)

**Goal:** For candidate URLs (e.g. `/graphql`, `/api/graphql`), `POST` introspection query; flag if schema is exposed.

**Tasks**

1. Add `GraphQlIntrospectionPlugin` implementing `ScanPlugin` with `name()` e.g. `graphql-introspection`.
2. Only run when path matches configurable allowlist or when response `Content-Type` suggests GraphQL.
3. Use a minimal introspection payload; detect `__schema` / `queryType` in JSON body.
4. Default plugin list: document in README; keep opt-in if noisy.

### A4. HTTP method enumeration (light active)

**Goal:** `OPTIONS` or `GET/POST/PUT/PATCH/DELETE` probe on the same path; report dangerous combo (e.g. `PUT` allowed on public resource).

**Tasks**

1. New `ScanPlugin` `http-methods` with strict rate limit and only on a **sample** of URLs (e.g. one per directory depth) to limit traffic.
2. Interpret `Allow` header from `OPTIONS` when present.
3. Plugin id `active/http-methods`.

### A5. Redirect chain analyzer (passive or active)

**Goal:** Follow redirects up to N hops; report open redirect candidates, HTTP→HTTPS downgrade, or excessive chains.

**Tasks**

1. Use `reqwest` with redirect policy **disabled**; manual loop with hop cap.
2. Emit findings for: loop detection, `Location` pointing to foreign scheme/host if same param reflected, etc.
3. Reuse overlap with `OpenRedirectPlugin` logic where possible (shared helper module `src/redirect.rs`).

### A6. Deep CSP review (passive)

**Goal:** Beyond “CSP missing”, parse `Content-Security-Policy` / `Content-Security-Policy-Report-Only` for unsafe directives (`unsafe-inline`, `unsafe-eval`, `*` sources).

**Tasks**

1. Add `check_csp_policy(url, headers) -> Vec<Finding>` after header presence checks.
2. Split on `;`, trim directives, flag high-risk tokens with severity Medium/Low.
3. Plugin ids like `passive/csp-unsafe-directives`.

---

## Tier B — Recon and correlation (narrow HTTP footprint)

### B1. technology stack fingerprint

**Goal:** Combine `Server`, `X-Powered-By`, `X-AspNet-Version`, script src patterns, and common framework markers in HTML → single informational finding (helps SDD correlation).

**Tasks**

1. Extend or complement `check_information_disclosure` with a structured `Vec<String>` “signals”.
2. Dedupe; cap list length in evidence field.
3. Plugin id `passive/tech-fingerprint`.

### B2. Well-known and backup path probe (light active)

**Goal:** Optional wordlist against origin: `/.git/HEAD`, `/.env`, `/backup.zip`, etc. **Must be opt-in** (`--plugins` or `--wordlist`).

**Tasks**

1. New CLI flag and `ScanConfig` field; default **off**.
2. Implement with concurrency cap and allowlist of “safe” patterns (HEAD requests, status + size only).
3. Plugin id `active/sensitive-paths`.

### B3. JWT surface inspection (passive)

**Goal:** Regex or base64-aware scan of HTML/JS for `eyJ` JWT shape; flag `alg:none`, missing `exp`, very long lifetime — **heuristic only**.

**Tasks**

1. Add body scanner helper; redact signature in evidence.
2. Plugin id `passive/jwt-heuristic`.

---

## Tier C — Transport and infrastructure (outside raw HTML)

### C1. TLS certificate summary (per host)

**Goal:** After TCP connect to `host:443`, pull cert expiry, SANs, weak algorithms if available via ecosystem crate (e.g. `tokio-rustls` / `rustls` peer cert).

**Tasks**

1. New `src/tls.rs` with `async fn probe_tls(host: &str, port: u16) -> Option<TlsSummary>`.
2. Call once per unique host during scan (dedupe).
3. Findings: expiry < 30 days, hostname mismatch stub.
4. Plugin id `transport/tls-summary`. Wire from `scanner::run_scan` after spider knows hosts.

### C2. Optional external intel hook

**Goal:** Pluggable HTTP client calls to Shodan/Censys/VirusTotal **only when env vars set**; platform keeps API keys.

**Tasks**

1. `IntelConfig` from env; no keys → skip.
2. Return `Finding::new(..., "intel/shodan", ...)` with external IDs in evidence.
3. Document legal/abuse limits in README.

---

## Tier D — Housekeeping aligned with existing code

### D1. Wire advanced SQLi plugins

**Goal:** `src/sqli_advanced.rs` already defines multiple `ScanPlugin` implementations; they are **not** mounted in `main.rs`.

**Tasks**

1. Add `mod sqli_advanced;` in `main.rs`.
2. In `ActiveScanner::new`, merge `sqli_advanced::plugins()` or push each boxed plugin into `all_plugins`.
3. Update default `--plugins` string and `active::list_plugins` / README.
4. Add at least one integration test with a tiny vulnerable mock (sqlite) if feasible, or unit test payload builders.

### D2. Passive-only coverage matrix

**Goal:** Document and test each passive `check_*` with golden HTTP responses.

**Tasks**

1. Create `tests/passive_golden.rs` with inline `HeaderMap` + body strings.
2. Optionally add `insta` snapshots for serialized `Finding` JSON.

---

## Suggested implementation order

1. **A2 (robots/sitemap)** — grows crawl coverage cheaply.
2. **A6 + A1** — improves passive depth without new network patterns.
3. **A3 + A4** — high-signal API issues for modern stacks.
4. **D1** — unlocks code already in repo.
5. **B2** — only after clear opt-in UX to avoid accidental aggressive scanning.
6. **C1 / C2** — when you need parity with recon workers in the SDD.

---

## Ethics and scope

- Only scan targets you are authorized to test.
- Tier **B** and **C** modules can be intrusive; gate them behind explicit flags and document in `README.md`.
- Prefer **passive** and **read-only** probes for shared CI environments.

---

## Reference: Argus naming (informative)

This roadmap is **not** a port of [Argus](https://github.com/jasonxtn/Argus/tree/main/argus/modules). Module filenames there (e.g. `graphql_introspection_probe.py`, `redirect_chain.py`, `security_txt.py`) are useful **inspiration** for naming and breadth; RustZAP implementations should match this repo’s `ScanPlugin` / passive patterns and JSON report contract.
