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
| 🕷️ **Spider/Crawler** | Recursive link, form, and JS URL discovery |
| 🔍 **Passive Scanner** | Analyzes headers and responses for misconfigurations |
| 💥 **Active Scanner** | Injects attack payloads to find real vulnerabilities |
| 🔀 **Intercepting Proxy** | HTTP(S) proxy for manual browsing + passive analysis |
| 📊 **JSON Reports** | Machine-readable findings with OWASP/CWE references |

---

## Installation

```bash
# Build from source (requires Rust 1.75+)
git clone https://github.com/you/rustzap
cd rustzap
cargo build --release
./target/release/rustzap --help
```

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
```

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

### Interactive Terminal Dashboard (TUI)

RustZAP includes a fast, Ratatui-powered terminal user interface to view and interact with your scan findings.

```bash
# Launch the dashboard (automatically parses report.json or rustzap-report.json)
rustzap tui
```

Use `↑`/`↓` or `j`/`k` to navigate through the list of findings. Press `q` to quit.

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

| Plugin | Vuln | OWASP | CWE |
|---|---|---|---|
| `xss` | Reflected XSS | A03:2021 | CWE-79 |
| `sqli` | SQL Injection (basic error-based) | A03:2021 | CWE-89 |
| `sqli-error` | Error-based SQLi — extended DB coverage (MySQL/PG/MSSQL/Oracle/SQLite) | A03:2021 | CWE-89 |
| `sqli-boolean` | Boolean-blind SQLi — TRUE/FALSE response diff oracle | A03:2021 | CWE-89 |
| `sqli-time` | Time-based blind SQLi — SLEEP/WAITFOR/pg_sleep timing oracle | A03:2021 | CWE-89 |
| `sqli-union` | UNION-based SQLi — column count probe + canary reflection | A03:2021 | CWE-89 |
| `sqli-stacked` | Stacked queries — semicolon-separated secondary statement | A03:2021 | CWE-89 |
| `sqli-oob` | Out-of-band SQLi — DNS/HTTP callback payload (detect only) | A03:2021 | CWE-89 |
| `sqli-second-order` | Second-order SQLi — store payload, detect unsafe retrieval | A03:2021 | CWE-89 |
| `sqli-waf-bypass` | WAF bypass SQLi — comment, encoding, case, whitespace tricks | A03:2021 | CWE-89 |
| `nosql` | NoSQL injection — MongoDB $ne/$gt/$where/$regex operator injection | A03:2021 | CWE-943 |
| `sqli-fingerprint` | DB fingerprinting via SQLi — identify MySQL/PG/MSSQL/Oracle/SQLite | A05:2021 | CWE-200 |
| `path-traversal` | Directory Traversal | A01:2021 | CWE-22 |
| `open-redirect` | Open Redirect | A01:2021 | CWE-601 |
| `ssrf` | SSRF (AWS/GCP metadata) | A10:2021 | CWE-918 |
| `xxe` | XML External Entity | A03:2021 | CWE-611 |
| `cmd-injection` | OS Command Injection | A03:2021 | CWE-78 |
| `ssti` | Template Injection | A03:2021 | CWE-94 |

Run specific plugins only:

```bash
rustzap scan --target https://example.com --plugins xss,sqli,ssrf
```

---

## Passive Check Coverage

| Check | Severity |
|---|---|
| Missing HSTS | Medium |
| Missing CSP | Medium |
| Missing X-Frame-Options | Medium |
| Missing X-Content-Type-Options | Low |
| Cookie missing HttpOnly | Medium |
| Cookie missing Secure | Medium |
| Cookie missing SameSite | Low |
| Server version disclosure | Low |
| X-Powered-By disclosure | Low |
| Stack trace in response | Medium |
| Mixed content (HTTP in HTTPS) | Medium |
| API keys / secrets in response | High/Critical |
| Wildcard CORS | Medium |
| CORS + credentials | High |
| Missing cache-control | Low |
| Missing charset in Content-Type | Low |

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
│   ├── main.rs          # CLI (clap) — entry point & subcommands
│   ├── types.rs         # Shared data types (Finding, Severity, HttpTransaction…)
│   ├── scanner.rs       # Full-scan orchestrator
│   ├── spider.rs        # Recursive crawler (links, forms, JS)
│   ├── passive.rs       # Passive checks (headers, cookies, body analysis)
│   ├── active.rs        # Active scanner + 8 attack plugins
│   ├── proxy.rs         # Intercepting HTTP proxy (hyper)
│   ├── stress.rs        # Load/stress tester (5 modes, percentiles, timeline)
│   └── report.rs        # JSON report generation
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

    async fn scan(&self, client: &reqwest::Client, target: &DiscoveredUrl) -> Vec<Finding> {
        // Your detection logic here
        vec![]
    }
}
```

Then register it in `ActiveScanner::new()` inside `active.rs`.

---

## License

MIT — Use responsibly. Never scan systems without authorization.
