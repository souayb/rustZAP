# RustZAP 🦀🔐

A fast, fearless web application security scanner written in Rust, inspired by [OWASP ZAP](https://www.zaproxy.org/).

```
██████╗ ██╗   ██╗███████╗████████╗███████╗ █████╗ ██████╗ 
██╔══██╗██║   ██║██╔════╝╚══██╔══╝╚════██║██╔══██╗██╔══██╗
██████╔╝██║   ██║███████╗   ██║       ██╔╝███████║██████╔╝
██╔══██╗██║   ██║╚════██║   ██║      ██╔╝ ██╔══██║██╔═══╝ 
██║  ██║╚██████╔╝███████║   ██║      ██║  ██║  ██║██║     
╚═╝  ╚═╝ ╚═════╝ ╚══════╝   ╚═╝      ╚═╝  ╚═╝  ╚═╝╚═╝     
```

> ⚠️ **Legal Warning**: Only scan systems you own or have explicit written permission to test. Unauthorized scanning is illegal.

---

## Features

| Feature | Description |
|---|---|
| 🕷️ **Spider/Crawler** | Recursive link, form, and JS URL discovery + `robots.txt` / sitemap enrichment |
| 🔍 **Passive Scanner** | Headers, body, security.txt, deep CSP review, JWT heuristics, tech-stack fingerprint |
| 💥 **Active Scanner** | 22 plugins — XSS, full SQLi suite, NoSQL, SSRF, XXE, GraphQL introspection, HTTP methods, redirect chain, opt-in path probe |
| 🔐 **Transport Probe** | Per-host TLS cert summary — expiry, weak signature, hostname mismatch, self-signed |
| 🛰️ **Intel Hook** | Optional Shodan enrichment when `SHODAN_API_KEY` is set (no-op otherwise) |
| 🔀 **Intercepting Proxy** | HTTP(S) proxy for manual browsing + passive analysis |
| 📊 **JSON / CSV / HTML Reports** | Machine-readable findings with OWASP/CWE references |
| 🖥️ **Interactive TUI** | Five-tab Ratatui console — configure, launch, monitor scans, drill into findings |
| 🧰 **Unified Tool Console** | Detects & runs Semgrep, Trivy, Gitleaks, Checkov, Nmap, Nikto, Wapiti, Falco, Hashcat, John, Hydra and more from the TUI |
| 🚀 **Stress Tester** | 5-mode load tester with percentile latency, timeline, and JSON report |
| 📋 **Roadmap** | [FEATURE.md](FEATURE.md) (DAST status + backlog) · [IMPLEMENTATION_PLAN.md](IMPLEMENTATION_PLAN.md) (analyze/audit/agent/API) |

---

## Documentation

| Document | Contents |
|----------|----------|
| [README.md](README.md) | Install, Docker, CLI usage, architecture overview |
| [FEATURE.md](FEATURE.md) | Passive/active/spider **status table** + backlog; platform phases in IMPLEMENTATION_PLAN |
| [IMPLEMENTATION_PLAN.md](IMPLEMENTATION_PLAN.md) | **Detailed implementation spec**: JSON `modules`, `analyze`/`audit`/`serve`/`agent`, parsers, correlation, SARIF, tests |
| [SOFTWARE_DESIGN_DOCUMENT.md](SOFTWARE_DESIGN_DOCUMENT.md) | Unified DevSecOps platform, UFF, correlation engine, APIs |
| [CLAUDE.md](CLAUDE.md) | Contributor / AI assistant guardrails |
| [CONTRIBUTION.md](CONTRIBUTION.md) | PR workflow + dev expectations |

> **Note:** `rustzap analyze`, `rustzap audit`, JSON `"modules"`, `"correlations"`, and SARIF export are implemented per **`IMPLEMENTATION_PLAN.md`** Phases 1–2. Later phases (`serve`, `agent`, OpenAPI/Nuclei) remain planned.

---

## Installation

### Prebuilt installers (Linux / Windows / macOS)

Every tagged release publishes native installers for all three OSes, built by
[`.github/workflows/release.yml`](.github/workflows/release.yml) — see
[`packaging/README.md`](packaging/README.md) for how they're built and their
current signing status.

| OS | Formats |
|---|---|
| Linux | `.deb` (Debian/Ubuntu), `.rpm` (Fedora/RHEL), `AppImage` (portable) — x86_64 and arm64 |
| Windows | `.exe` installer (Inno Setup) — x86_64 |
| macOS | `.dmg` (universal2: Apple Silicon + Intel) |

Download from the [Releases page](https://github.com/souayb/rustZAP/releases),
verify against the release's `SHA256SUMS`, then install:

```bash
# Linux
sudo apt install ./rustzap-<version>-linux-amd64.deb      # Debian/Ubuntu
sudo dnf install ./rustzap-<version>-linux-x86_64.rpm      # Fedora/RHEL
chmod +x rustzap-<version>-linux-x86_64.AppImage && ./rustzap-<version>-linux-x86_64.AppImage   # portable

# macOS
open rustzap-<version>-macos-universal.dmg   # then run Install.command, or drag `rustzap` onto your PATH
```

```powershell
# Windows — run the downloaded rustzap-<version>-windows-x64.exe
```

A Homebrew formula is also generated per release (`packaging/homebrew/`); see
`packaging/README.md` for its current publishing status.

### From source

```bash
# Requires Rust 1.75+
git clone https://github.com/souayb/rustZAP
cd rustZAP
cargo build --release
./target/release/rustzap --help
```

### Install companion tools (OS-aware)

The SDD calls for a unified console driving Semgrep, Trivy, Gitleaks, Checkov, Nmap, Nikto, Wapiti, tshark, Hashcat, John, Hydra, Medusa, and Aircrack-ng. RustZAP can install them for you — it auto-detects your OS and dispatches to the right package manager.

```bash
rustzap install --list           # see what would be installed on this OS
rustzap install --dry-run        # print the exact commands, run nothing
rustzap install                  # interactive install (asks per tool)
rustzap install --yes            # non-interactive, install everything available
rustzap install --tool semgrep   # install just one tool
```

Supported package managers:

| OS | Manager |
|---|---|
| macOS | Homebrew |
| Debian / Ubuntu / Kali | apt + pipx |
| Fedora / RHEL / Rocky | dnf + pipx |
| Arch / Manjaro | pacman + pipx |
| Alpine | apk + pip3 |

The same logic is available as a standalone shell script:

```bash
./scripts/install-tools.sh --list       # show plan
./scripts/install-tools.sh --yes        # install everything available
./scripts/install-tools.sh --tool nmap  # install one
```

### Docker

A multi-stage `Dockerfile` ships RustZAP with all companion tools pre-installed (no host setup needed):

```bash
# Build the image (~600 MB, includes Semgrep/Trivy/Gitleaks/Nmap/...)
docker build -t rustzap .

# Drop into the TUI (interactive)
docker run --rm -it -v "$PWD/reports:/workspace" rustzap

# One-shot scan from CLI
docker run --rm -v "$PWD/reports:/workspace" rustzap \
    scan --target https://example.com --output /workspace/report.json

# Intercepting proxy on host port 8080
docker run --rm -p 8080:8080 rustzap proxy --listen 0.0.0.0:8080
```

### docker-compose

```bash
# Drop into the TUI
docker compose run --rm rustzap

# One-shot scan with reports written to ./reports/ on the host
docker compose run --rm rustzap scan --target https://example.com -o /workspace/report.json

# Bring up the optional Juice-Shop lab target
docker compose --profile labs up -d juice-shop
docker compose run --rm rustzap scan --target http://juice-shop:3000
```

The compose file mounts `./reports → /workspace` and exposes the intercepting proxy on `:8080`.

---

## Usage

### Full Scan (Spider + Passive + Active)

```bash
# Basic scan
rustzap scan --target https://example.com

# Deep scan with all plugins
rustzap scan \
  --target https://example.com \
  --depth 10 \
  --concurrency 20 \
  --output report.json

# Export to CSV or HTML formats
rustzap scan --target https://example.com --output report.csv
rustzap scan --target https://example.com --output report.html

# SARIF 2.1 (e.g. GitHub Code Scanning uploads)
rustzap scan --target https://example.com --output findings.sarif
rustzap scan --target https://example.com -o report.json --sarif-out findings.sarif

# Authenticated scan with cookies, API key, and Basic Auth
rustzap scan \
  --target https://app.example.com \
  --cookies "session=abc123; role=admin" \
  --auth "Bearer eyJhbGciOiJIUzI1NiJ9..." \
  --api-key "X-Api-Key: my-secret-key" \
  --basic-auth "username:password"

# Passive-only (no attack payloads sent)
rustzap scan --target https://example.com --passive-only

# Skip SSL verification (e.g. staging with self-signed cert)
rustzap scan --target https://staging.example.com --insecure

# Verbose output
rustzap scan --target https://example.com -vv

# Expand attack surface from OpenAPI / HAR (lab targets only)
rustzap scan --target https://lab.example.com \
  --openapi-path openapi.json --passive-only -o report.json
rustzap scan --target https://lab.example.com \
  --har-path recording.har --depth 2 -o report.json

# Opt-in Nuclei (requires `nuclei` on PATH — only against authorized targets)
rustzap scan --target https://lab.example.com --nuclei --passive-only -o report.json
# Or parse existing Nuclei JSONL without spawning:
rustzap scan --target https://lab.example.com --nuclei-jsonl nuclei-out.jsonl --passive-only -o report.json
```

> **Warning:** `--nuclei` runs ProjectDiscovery Nuclei templates against the target. Use only on systems you own or have explicit permission to test.

### Analyze & audit (static tools + optional DAST)

```bash
# Static analysis: Semgrep, Trivy (fs), Gitleaks (default: semgrep only)
rustzap analyze --repo . --tools semgrep,trivy,gitleaks --output analyze-report.json

# CI-friendly: parse existing tool JSON (no subprocess)
rustzap analyze --repo . \
  --semgrep-json tests/fixtures/semgrep_small.json \
  --trivy-json tests/fixtures/trivy_small.json \
  --gitleaks-json tests/fixtures/gitleaks_small.json \
  --output analyze-report.json

# Correlate SAST SQL signals with DAST SQLi + emit SARIF
rustzap analyze --repo . --semgrep-json semgrep.json --correlate \
  --output analyze-report.json --sarif-out analyze.sarif

# Unified audit: static tools + optional live scan against --target
rustzap audit --repo . --target https://lab.example.com \
  --tools semgrep,trivy,gitleaks --passive-only --depth 2 \
  --output audit-report.json --sarif-out audit.sarif
```

Scan and analyze/audit JSON reports include a **`modules`** array (per-plugin roll-up) and optional **`correlations`** when `--correlate` is set.

**GitHub Code Scanning:** build SARIF with `rustzap … --sarif-out rustzap.sarif` (or `scan --output rustzap.sarif`), upload the artifact with `github/codeql-action/upload-sarif` against your default branch or PR; confirm the run appears under the repository **Security** tab (manual check).

### Spider Only

```bash
rustzap spider --target https://example.com --depth 5
rustzap spider --target https://example.com --output urls.json
```

### Intercepting Proxy

```bash
# Start proxy on default port 8080
rustzap proxy

# Custom address + passive analysis of traffic
rustzap proxy --listen 0.0.0.0:9090 --passive --dump captured.json
```

Then configure your browser's HTTP proxy to `127.0.0.1:8080` and browse normally.
Press `Ctrl+C` to stop and save captured transactions.

### Interactive Pentesting Console (TUI)

RustZAP ships with a full multi-tab Ratatui-powered console — the operator's "single pane of glass" from the SDD. It lets you configure scans, launch them, watch live phase progress, browse findings, and drive the SDD's external tools (Semgrep, Trivy, Gitleaks, Checkov, Nmap, Nikto, Wapiti, Hashcat, John, Hydra, Medusa, Aircrack-ng, Wifite, Falco, tshark) — all without leaving the terminal.

```bash
rustzap            # bare command → drops straight into the TUI
rustzap tui        # explicit subcommand
rustzap ui         # alias
rustzap console    # alias
```

Running `rustzap` with no arguments launches the console immediately — useful as a daily-driver entry point. On launch the TUI auto-loads `report.json` or `rustzap-report.json` if either exists, so you can review prior scans without re-running.

#### Tabs

| Tab | What you see | What you can do |
|---|---|---|
| **1·Dashboard** | Target card, color-coded risk score (0–100), severity bar chart, top-20 findings | At-a-glance posture overview |
| **2·Scan** | Inline config form + 3 live phase gauges (Spider · Passive · Active) + streaming findings | Edit target/plugins/output, toggle passive/insecure, tune depth/concurrency, start/cancel scans |
| **3·Findings** | Findings list + scrolling detail pane (title, CWE, OWASP, evidence, solution) | Browse, severity-filter, deep-dive into each finding |
| **4·Tools** | Inventory of 15 SDD-listed tools with install status, role, default cmdline | Run any installed tool against the current target — output streams to Logs |
| **5·Logs** | Timestamped event stream from scans + tool runs (color-coded by type) | Scroll, jump to bottom, clear |

#### Key bindings

**Global**

| Key | Action |
|---|---|
| `1`–`5` | Jump to tab |
| `Tab` / `Shift+Tab` | Cycle tabs |
| `q` | Quit (aborts running scans/tools) |

**Scan tab**

| Key | Action |
|---|---|
| `t` | Edit target URL |
| `P` | Edit active-scan plugins (comma-separated) |
| `o` | Edit output file (`.json` / `.csv` / `.html`) |
| `p` | Toggle passive-only mode |
| `i` | Toggle insecure TLS |
| `+` / `-` | Increment / decrement crawl depth |
| `]` / `[` | Increment / decrement concurrency |
| `s` | Start scan |
| `x` | Cancel running scan |
| `Enter` / `Esc` | Commit / cancel field edit |

**Findings tab**

| Key | Action |
|---|---|
| `j` / `k` (or `↓` / `↑`) | Navigate findings |
| `PgUp` / `PgDn` | Scroll detail pane |
| `f` | Cycle severity filter (all → Critical → High → Medium → Low → Info → all) |
| `c` | Clear filter |

**Tools tab**

| Key | Action |
|---|---|
| `j` / `k` | Navigate tool list |
| `r` or `Enter` | Run the highlighted tool (uses configured target if required) |
| `R` | Re-detect tools on PATH |

**Logs tab**

| Key | Action |
|---|---|
| `j` / `k` / `PgUp` / `PgDn` | Scroll |
| `G` | Jump to bottom |
| `c` | Clear log buffer |

#### Quick walkthrough

```bash
rustzap tui            # opens the console
# → press '2' to go to the Scan tab
# → press 't', type https://example.com, Enter
# → press 's' to launch — Spider/Passive/Active gauges fill live
# → press '3' to browse findings, 'f' to filter by severity
# → press '4' to see which SDD tools are installed; 'r' runs the highlighted one
# → press '5' to watch live event logs
# → 'q' to quit
```

### Passive Analysis Only

```bash
rustzap passive --input https://example.com --output passive-report.json
```

### List Plugins

```bash
rustzap plugins
```

---

## Active Scan Plugins

> **Evidence-based, no self-validation.** Active plugins verify that a payload —
> not the page's normal content — caused the observed behavior before reporting.
> They fetch an untouched **baseline**, inject **unique canaries**, and only
> conclude when a DB error / metadata token / evaluated expression is *new
> relative to the baseline* (or a reflection survives **unencoded**). Every
> finding carries a `confidence` (`tentative` / `firm` / `confirmed`) and a
> `poc_validated` flag in JSON, CSV, and HTML output. See `src/verify.rs`.

| Plugin | Vuln | OWASP | CWE |
|---|---|---|---|
| `xss` | Reflected XSS | A03:2021 | CWE-79 |
| `sqli` | SQL Injection (basic error-based) | A03:2021 | CWE-89 |
| `sqli-error` | Error-based SQLi — extended DB coverage (MySQL/PG/MSSQL/Oracle/SQLite) | A03:2021 | CWE-89 |
| `sqli-boolean` | Boolean-blind SQLi — TRUE/FALSE response diff oracle | A03:2021 | CWE-89 |
| `sqli-time` | Time-based blind SQLi — SLEEP/WAITFOR/pg_sleep timing oracle | A03:2021 | CWE-89 |
| `sqli-union` | UNION-based SQLi — column count probe + canary reflection | A03:2021 | CWE-89 |
| `sqli-stacked` | Stacked queries — semicolon-separated secondary statement | A03:2021 | CWE-89 |
| `sqli-oob` | Out-of-band SQLi — dispatches DNS/HTTP callback payloads. **Inert unless `RUSTZAP_OOB_DOMAIN` names a listener** (interactsh/Collaborator); reported `tentative` until you observe a callback | A03:2021 | CWE-89 |
| `sqli-second-order` | Second-order SQLi — stores a payload, then confirms via a DB error that surfaces on retrieval (baseline-differential) | A03:2021 | CWE-89 |
| `sqli-waf-bypass` | WAF bypass SQLi — comment, encoding, case, whitespace tricks | A03:2021 | CWE-89 |
| `nosql` | NoSQL injection — MongoDB $ne/$gt/$where/$regex operator injection | A03:2021 | CWE-943 |
| `sqli-fingerprint` | DB fingerprinting via SQLi — identify MySQL/PG/MSSQL/Oracle/SQLite | A05:2021 | CWE-200 |
| `path-traversal` | Directory Traversal | A01:2021 | CWE-22 |
| `open-redirect` | Open Redirect | A01:2021 | CWE-601 |
| `ssrf` | SSRF (AWS/GCP metadata) | A10:2021 | CWE-918 |
| `xxe` | XML External Entity | A03:2021 | CWE-611 |
| `cmd-injection` | OS Command Injection | A03:2021 | CWE-78 |
| `ssti` | Template Injection | A03:2021 | CWE-94 |
| `graphql-introspection` | GraphQL schema exposure via introspection query | A05:2021 | CWE-200 |
| `http-methods` | OPTIONS probe — flags dangerous methods (PUT/DELETE/TRACE/PATCH) | A05:2021 | CWE-650 |
| `redirect-chain` | Redirect chain analyzer — HTTPS→HTTP downgrade, cross-origin, loops, excessive hops | A02:2021 | CWE-601 |
| `sensitive-paths` ⚠️ | Well-known / backup file probe (`/.git/HEAD`, `/.env`, `/backup.zip`, …) — **opt-in, default OFF** | A05:2021 | CWE-538 |

⚠️ `sensitive-paths` is intentionally excluded from defaults. Enable it only against targets you are explicitly authorized to scan — it issues 25+ HEAD requests against well-known dotfile and backup paths.

Run specific plugins only:

```bash
# Default plugin set (everything except sensitive-paths)
rustzap scan --target https://example.com

# Narrow to a few plugins
rustzap scan --target https://example.com --plugins xss,sqli,ssrf

# Opt in to sensitive-path probing
rustzap scan --target https://example.com \
  --plugins xss,sqli,ssrf,sensitive-paths
```

---

## Passive Check Coverage

| Check | Plugin id | Severity |
|---|---|---|
| Missing HSTS | `passive/missing-headers` | Medium |
| Missing CSP | `passive/missing-headers` | Medium |
| Missing X-Frame-Options | `passive/missing-headers` | Medium |
| Missing X-Content-Type-Options | `passive/missing-headers` | Low |
| Cookie missing HttpOnly / Secure / SameSite | `passive/cookie-flags` | Medium / Medium / Low |
| Server version / X-Powered-By disclosure | `passive/info-disclosure` | Low |
| Stack trace / verbose error in body | `passive/info-disclosure` | Medium |
| Mixed content (HTTP asset on HTTPS page) | `passive/mixed-content` | Medium |
| API keys / passwords / private keys in body | `passive/sensitive-data` | High / Critical |
| Wildcard CORS / CORS + credentials | `passive/cors` | Medium / High |
| Missing cache-control on sensitive pages | `passive/cache-control` | Low |
| Missing charset in Content-Type | `passive/content-type` | Low |
| `security.txt` missing / no Contact / no Expires / expired | `passive/security-txt` | Info / Low / Low / Medium |
| CSP `unsafe-inline`, `unsafe-eval`, wildcard, `object-src` not `'none'` | `passive/csp-unsafe-directives` | Low → High |
| Tech-stack fingerprint (Server, generator meta, framework markers) | `passive/tech-fingerprint` | Info |
| JWT `alg:none`, missing `exp`, lifetime > 1 year | `passive/jwt-heuristic` | High / Medium / Low |

The `security.txt` probe runs **once per origin** (not once per URL). The CSP check inspects both `Content-Security-Policy` and `Content-Security-Policy-Report-Only` — findings on the Report-Only header are downgraded one severity tier.

---

## Spider Enrichment

In addition to recursive HTML link / form / inline-JS extraction, the spider also reads:

- `/robots.txt` — `Allow:` / `Disallow:` paths enqueue as `UrlSource::Robots`; `Sitemap:` lines trigger sitemap fetches.
- XML sitemaps (`urlset` and `sitemapindex`) — `<loc>` URLs enqueue as `UrlSource::Sitemap`.

All of this is bounded: robots up to 256 KB, sitemaps up to 1 MB each, max 5 sitemap fetches, max 500 enriched URLs per scan. Hosts outside the target's are silently dropped.

---

## Transport & Intel

After the active phase, RustZAP runs a per-host **TLS certificate probe** against every unique HTTPS host discovered by the spider. The probe accepts any cert (so it can inspect expired / mismatched chains), then summarises the leaf via `x509-parser`.

| Check | Plugin id | Severity |
|---|---|---|
| Certificate expired | `transport/tls-expired` | Critical |
| Certificate expires in < 30 days | `transport/tls-expiring-soon` | Medium |
| Weak signature algorithm (SHA-1 / MD5) | `transport/tls-weak-signature` | Medium |
| Self-signed (subject == issuer) | `transport/tls-self-signed` | Low |
| Hostname not covered by SANs (exact + 1-label wildcard) | `transport/tls-hostname-mismatch` | Medium |

**Optional intel enrichment** is gated by environment variables — if none are set, the module is a no-op.

| Env var | Provider | Findings |
|---|---|---|
| `SHODAN_API_KEY` | Shodan REST host lookup | `intel/shodan-vulns` (High), `intel/shodan-ports` (Low) |

```bash
SHODAN_API_KEY=xxx rustzap scan --target https://example.com
```

Shodan's `/shodan/host/{ip}` endpoint requires an IP — hostnames return 404 and are silently dropped. Provide IPs as scan targets when intel is the goal. Only call these services for hosts you are authorized to scan.

---

## Report Format

```json
{
  "meta": {
    "scanner": "RustZAP",
    "version": "0.1.0",
    "target": "https://example.com",
    "scan_date": "2026-03-08T12:00:00Z",
    "duration_secs": 42.1
  },
  "summary": {
    "total_urls": 87,
    "total_findings": 12,
    "critical": 1,
    "high": 2,
    "medium": 5,
    "low": 3,
    "info": 1,
    "risk_score": 47
  },
  "findings": [
    {
      "id": "a1b2c3d4-...",
      "title": "SQL Injection",
      "severity": "critical",
      "url": "https://example.com/search?q=test",
      "parameter": "q",
      "evidence": "Payload ''' — Error keyword 'You have an error in your SQL syntax' found",
      "description": "...",
      "solution": "Use parameterized queries...",
      "cwe": 89,
      "owasp_category": "A03:2021 – Injection",
      "plugin": "active/sqli",
      "found_at": "2026-03-08T12:01:23Z"
    }
  ]
}
```

---

## Stress Testing

RustZAP includes a full load/stress testing engine with 5 modes, real-time stats, percentile latency, and a detailed JSON report.

### Modes

| Mode | Description |
|---|---|
| `constant` | N concurrent users hammering the endpoint for D seconds |
| `ramp` | Linearly ramp from `start_users` up to peak, then hold |
| `spike` | Baseline users with a sudden burst at a specific time |
| `soak` | Long-duration constant load — finds memory leaks and degradation |
| `requests` | Fire exactly N requests at a fixed concurrency, then stop |

### Examples

```bash
# Constant: 50 users for 60 seconds
rustzap stress --target https://api.example.com/v1/users \
  --mode constant --users 50 --duration 60

# Ramp: 1 → 100 users over 30s, hold 30s
rustzap stress --target https://api.example.com/search \
  --mode ramp --start-users 1 --users 100 --ramp-secs 30 --duration 60

# Spike: 10 base users, spike to 200 at t=10s for 5s
rustzap stress --target https://api.example.com/checkout \
  --mode spike --users 200 --start-users 10 \
  --spike-at 10 --spike-duration 5 --duration 30

# Soak: 20 users for 10 minutes (find leaks)
rustzap stress --target https://api.example.com/health \
  --mode soak --users 20 --duration 600

# Fixed request count: 10,000 requests at concurrency 100
rustzap stress --target https://api.example.com/ping \
  --mode requests --requests 10000 --users 100

# POST with JSON body + auth
rustzap stress --target https://api.example.com/orders \
  --mode constant --users 20 --duration 30 \
  --method POST \
  --body '{"item":"widget","qty":1}' \
  --header "Content-Type: application/json" \
  --auth "Bearer eyJhbGci..." \
  --expect-status 201

# Assert response body
rustzap stress --target https://api.example.com/health \
  --expect-body '"status":"ok"'
```

### Live Output (during test)

```
⠸ reqs=1,842  rps=184.2  avg=54ms  min=12ms  max=890ms  err=0.0%
```

### Results Summary

```
────────────────────────────────────────────────────────────────
  STRESS TEST RESULTS
────────────────────────────────────────────────────────────────

  Summary
  Total Requests:              10,000
  Successful:                  9,997
  Failed:                      3
  Error Rate:                  0.03%
  Throughput:                  842.1 req/s
  Data Rate:                   1,204.3 KB/s
  Duration:                    11.9s

  Latency
  Average:                     54ms
  Min:                         8ms
  Max:                         1,204ms
  p50 (median):                42ms
  p75:                         68ms
  p90:                         112ms
  p95:                         189ms
  p99:                         412ms
  p99.9:                       988ms

  Latency Distribution
      0-10ms      127   1.3%  █
     10-25ms    2,841  28.4%  ████████████████████████████
     25-50ms    3,912  39.1%  ██████████████████████████████
     50-100ms   2,203  22.0%  ██████████████████████
    100-250ms     743   7.4%  ███████
    250-500ms     132   1.3%  █
   500-1000ms      35   0.4%
      1000ms+       7   0.1%

  Verdict
  ✓ PASS — no errors, p99 latency within 500ms
────────────────────────────────────────────────────────────────
```

### Stress Report JSON

```json
{
  "meta": {
    "scanner": "RustZAP",
    "target": "https://api.example.com/v1/users",
    "mode": "constant",
    "method": "GET",
    "start_time": "2026-03-08T12:00:00Z",
    "end_time": "2026-03-08T12:01:00Z",
    "duration_secs": 60.0
  },
  "summary": {
    "total_requests": 50420,
    "successful": 50418,
    "failed": 2,
    "error_rate_pct": 0.004,
    "throughput_rps": 840.3,
    "avg_latency_ms": 58,
    "min_latency_ms": 9,
    "max_latency_ms": 1840,
    "total_bytes_received": 72604320,
    "throughput_kbps": 1181.2
  },
  "percentiles": {
    "p50_ms": 45,
    "p75_ms": 72,
    "p90_ms": 118,
    "p95_ms": 201,
    "p99_ms": 480,
    "p999_ms": 1102
  },
  "histogram": { "buckets": [...] },
  "timeline": [
    { "elapsed_secs": 1, "rps": 812.0, "avg_latency_ms": 61, "errors": 0 },
    ...
  ],
  "errors": [
    { "message": "Request timeout", "count": 2 }
  ]
}
```

---

## Architecture

```
rustzap/
├── src/
│   ├── main.rs              # CLI (clap) — entry point & subcommands
│   ├── types.rs             # Shared data types (Finding, Severity, UrlSource, …)
│   ├── scanner.rs           # Full-scan orchestrator (Spider→Passive→Active→TLS+Intel→Report)
│   ├── spider.rs            # Recursive crawler + robots.txt / sitemap enrichment
│   ├── passive.rs           # Passive checks (headers, body, security.txt, CSP, tech-fp, JWT)
│   ├── active.rs            # Active scanner core + ScanPlugin registrations (core plugins)
│   ├── sqli_advanced.rs     # Advanced SQLi/NoSQL/stacked/etc. ScanPlugins
│   ├── sensitive_paths.rs   # B2 — opt-in well-known path probe
│   ├── tls.rs               # C1 — rustls-based per-host TLS cert summary
│   ├── intel.rs             # C2 — env-gated Shodan / external intel hook
│   ├── proxy.rs             # Intercepting HTTP proxy (hyper)
│   ├── stress.rs            # Load/stress tester (5 modes, percentiles, timeline)
│   ├── report.rs            # JSON / CSV / HTML report generation
│   ├── events.rs            # ScanEvent / ScanPhase — telemetry for the TUI
│   ├── tools.rs             # External tool detection + streaming runner (Semgrep, Trivy, …)
│   ├── installer.rs         # OS-aware companion-tool installer (`rustzap install`)
│   └── tui.rs               # Multi-tab interactive console (Dashboard / Scan / Findings / Tools / Logs)
├── scripts/
│   └── install-tools.sh     # Canonical shell installer — used by Dockerfile & host
├── Dockerfile               # Multi-stage build with all companion tools pre-installed
├── docker-compose.yml       # Compose service + optional Juice-Shop lab target
└── Cargo.toml
```

---

## Extending with Custom Plugins

Implement the `ScanPlugin` trait:

```rust
use async_trait::async_trait;
use crate::active::ScanPlugin;
use crate::types::{DiscoveredUrl, Finding, Severity};

pub struct MyPlugin;

#[async_trait]
impl ScanPlugin for MyPlugin {
    fn name(&self) -> &str { "my-plugin" }
    fn description(&self) -> &str { "Detects XYZ vulnerability" }

    /// Override to `true` when the plugin targets a path itself (e.g. an
    /// `/admin` endpoint) rather than a query parameter. The default `false`
    /// keeps the plugin behind the URL-must-have-`?param=` gate.
    fn always_run(&self) -> bool { false }

    async fn scan(&self, client: &reqwest::Client, target: &DiscoveredUrl) -> Vec<Finding> {
        // Your detection logic here
        vec![]
    }
}
```

Then register it in `ActiveScanner::new()` and `list_plugins()` inside `active.rs` (both lists must stay in sync — the binary uses one for execution, the other for `rustzap plugins`).

---

## License

MIT — Use responsibly. Never scan systems without authorization.
