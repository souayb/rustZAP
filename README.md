```
██████╗ ██╗   ██╗███████╗████████╗███████╗ █████╗ ██████╗ 
██╔══██╗██║   ██║██╔════╝╚══██╔══╝╚════██║██╔══██╗██╔══██╗
██████╔╝██║   ██║███████╗   ██║       ██╔╝███████║██████╔╝
██╔══██╗██║   ██║╚════██║   ██║      ██╔╝ ██╔══██║██╔═══╝ 
██║  ██║╚██████╔╝███████║   ██║      ██║  ██║  ██║██║     
╚═╝  ╚═╝ ╚═════╝ ╚══════╝   ╚═╝      ╚═╝  ╚═╝  ╚═╝╚═╝     
```
---
# RustZAP 🦀🔐

**Open-source, local-first security assessment and DevSecOps platform built in Rust.**

RustZAP brings web application security testing, repository analysis, infrastructure scanning, network assessment, AI security testing, evidence collection, and security reporting into one self-hosted workflow.

It is designed for organizations and security teams that want to **inspect, test, and understand their systems without being forced into a centralized proprietary security platform**.

RustZAP is built around five principles:

* **Open source** — the platform and its security workflow remain inspectable and extensible.
* **Local-first** — sensitive source code, findings, credentials, and security evidence can remain inside your environment.
* **Self-hostable** — run natively, in Docker, or inside an isolated security environment.
* **Tool independent** — integrate existing security tools instead of replacing them unnecessarily.
* **Human controlled** — network-touching and intrusive operations are bounded by explicit scope and authorization controls.

> ⚠️ **Authorization required:** Only scan systems, applications, repositories, networks, or infrastructure that you own or have explicit written permission to test. Unauthorized security testing may be illegal.

---

## Why RustZAP?

Modern security programs rarely depend on a single security tool.

A typical assessment may involve:

```text
Source Code
    │
    ├── SAST
    ├── Secret Detection
    ├── Dependency / Container Scanning
    ├── Infrastructure-as-Code Analysis
    │
    ▼
Application
    │
    ├── DAST
    ├── API Testing
    ├── Authentication Testing
    └── Web Security Testing
    │
    ▼
Infrastructure
    │
    ├── Network Discovery
    ├── TLS Analysis
    ├── Configuration Analysis
    └── Active Directory Assessment
    │
    ▼
AI Applications
    │
    ├── Prompt Injection
    ├── System Prompt Disclosure
    ├── Sensitive Information Exposure
    └── LLM Security Testing
```

Each tool can produce its own findings, formats, evidence, and severity model.

RustZAP provides a common security workflow for these capabilities:

```text
                 ┌─────────────────────┐
                 │      RustZAP        │
                 │  Security Workflow  │
                 └──────────┬──────────┘
                            │
       ┌────────────────────┼────────────────────┐
       │                    │                    │
       ▼                    ▼                    ▼
   Web / DAST            Repository           Infrastructure
       │                  Analysis                │
       │                    │                    │
       └────────────────────┼────────────────────┘
                            ▼
                  Finding Correlation
                            │
                            ▼
                     Risk Analysis
                            │
                            ▼
                    Evidence & Report
```

The goal is not to force organizations to abandon the tools they already use.

Instead, RustZAP provides an **open orchestration, analysis, correlation, and evidence layer** around security testing.

---

# What RustZAP provides

| Capability                     | Description                                                                         |
| ------------------------------ | ----------------------------------------------------------------------------------- |
| 🕷️ Web crawling               | Recursive links, forms, JavaScript URLs, `robots.txt`, and sitemap discovery        |
| 🔍 Passive security analysis   | Security headers, CSP, cookies, JWTs, information disclosure, CORS, CSRF and more   |
| 💥 Active web testing          | SQLi, XSS, SSRF, XXE, SSTI, command injection, path traversal and additional checks |
| 🔐 TLS analysis                | Certificate expiry, weak signatures, hostname mismatch and self-signed certificates |
| 🛰️ External intelligence      | Optional Shodan host enrichment                                                     |
| 🔀 Intercepting proxy          | Capture and passively analyze HTTP(S) traffic                                       |
| 📂 Repository analysis         | Native analysis plus Semgrep, Trivy, Gitleaks and Checkov integration               |
| 🧩 Finding correlation         | Correlate signals across different security sources                                 |
| 🏢 Active Directory assessment | LDAP, SPN and NTLM security posture checks                                          |
| 🖥️ Terminal security console  | Multi-tab Ratatui interface for security workflows                                  |
| 🤖 Security agents             | Scope-controlled AI or deterministic security workflows                             |
| 🔌 MCP server                  | Expose RustZAP security capabilities to external AI clients                         |
| 🧠 AI red teaming              | OWASP LLM Top 10-oriented testing                                                   |
| 🔁 HTTP capture/replay         | Auditable HTTP evidence and controlled request replay                               |
| 📋 SARIF                       | Integration with security reporting and code-scanning workflows                     |
| 🚀 Stress testing              | Controlled load testing with latency percentiles and reports                        |
| 📦 Isolated environment        | Reproducible Docker/Kali-based security environment                                 |
| 🧪 Security laboratory         | Deliberately vulnerable local target and regression test infrastructure             |
| 🧱 Extensible plugins          | Rust-based scanner plugin architecture                                              |

---

# Open and local by design

RustZAP does not require a proprietary cloud service to perform its core security workflows.

You can run it:

```text
Developer workstation
        │
        ▼
     RustZAP
        │
        ├── Local source code
        ├── Local security tools
        ├── Local reports
        └── Local AI model
```

Or inside your own infrastructure:

```text
                 Your Infrastructure
                        │
             ┌──────────┴──────────┐
             │                     │
        RustZAP Engine         Local AI
             │                     │
       ┌─────┼─────┐               │
       ▼     ▼     ▼               ▼
     SAST   DAST   IaC        Ollama / vLLM /
                              LM Studio / etc.
```

Compatible OpenAI-style APIs can also be used when an external provider is appropriate.

RustZAP does not require that security data be sent to a particular vendor.

---

# Security by default

Security tooling must be careful about the systems it touches.

RustZAP therefore treats **scope and authorization as part of the security architecture**, rather than as documentation alone.

Network-touching agent operations require an explicit scope file.

The scope defines:

* permitted schemes
* permitted hosts
* forbidden paths
* autonomy level
* actions requiring approval
* request and resource budgets
* model configuration

Example:

```yaml
allowed_schemes:
  - http
  - https

allowed_hosts:
  - localhost
  - 127.0.0.1
  - "*.example.com"

forbidden_paths:
  - "^/admin/delete"
```

Create a starter scope:

```bash
rustzap agent --init-scope scope.yaml
```

A missing or malformed scope is treated as a hard error.

RustZAP does not silently fall back to an unrestricted network scope.

---

# Agent safety model

RustZAP can use an LLM or deterministic scripted workflow to plan and execute security analysis.

The agent does not receive unrestricted access to the system.

The workflow is:

```text
                 Scope
                   │
                   ▼
              Policy Check
                   │
                   ▼
             Agent Decision
                   │
                   ▼
             Tool Permission
                   │
             ┌─────┴─────┐
             │           │
           Recon       Exploit
             │           │
             │       Approval Gate
             │           │
             └─────┬─────┘
                   ▼
                Evidence
                   │
                   ▼
                Report
```

Network-touching tools refuse to run without an applicable scope.

Intrusive operations can require explicit approval depending on the selected autonomy policy.

---

# Privacy-preserving AI workflows

Security assessments can expose highly sensitive information:

* source code
* credentials
* internal hostnames
* IP addresses
* email addresses
* HTTP headers
* application responses
* security findings

RustZAP therefore supports privacy tokenization.

With:

```bash
rustzap agent --scope scope.yaml --privacy
```

sensitive values can be replaced before being passed to the model:

```text
real.example.internal
        ↓
RZ_HOST_1

admin@example.com
        ↓
RZ_EMAIL_1

secret-api-key
        ↓
RZ_SECRET_1
```

The model reasons about the structure while RustZAP restores the values locally when required for tool execution.

Privacy tokenization is disabled by default and can be explicitly enabled for agent runs.

---

# Prompt-injection protection

Security tools routinely process attacker-controlled content.

For example:

```text
HTTP response
     ↓
Web page
     ↓
Attacker-controlled text
     ↓
Security agent
```

An application under assessment could attempt to manipulate the security agent through malicious content.

RustZAP therefore treats tool observations as **untrusted data**.

The agent pipeline includes a prompt-injection shield that detects known instruction-manipulation patterns and frames observations appropriately before they reach the model.

Shield events are recorded in the trace.

Raw evidence remains available in the human-readable security report.

---

# Evidence and auditability

RustZAP records security operations as evidence rather than treating an LLM's statement as proof.

Agent runs can produce:

```text
agent-report.json
agent-report.captures.json
agent-trace.jsonl
OUTPUT.tasks-<run-id>.jsonl
```

The trace can contain:

* tool calls
* tool results
* approvals
* scope rejections
* prompt-injection shield events
* captured HTTP transactions
* evidence references
* execution outcomes

Sensitive headers are redacted where applicable.

Tool-generated findings remain authoritative; an LLM observation is not treated as proof simply because the model claims that a vulnerability exists.

---

# Installation

## Prebuilt releases

Tagged releases provide native installers for:

| Platform | Formats                  |
| -------- | ------------------------ |
| Linux    | `.deb`, `.rpm`, AppImage |
| Windows  | `.exe`                   |
| macOS    | `.dmg`                   |

Linux builds are available for x86_64 and ARM64. macOS releases use universal binaries.

Download a release from the project's GitHub Releases page and verify the checksum before installation.

### Linux

```bash
sudo apt install ./rustzap-<version>-linux-amd64.deb
```

or:

```bash
sudo dnf install ./rustzap-<version>-linux-x86_64.rpm
```

For the portable AppImage:

```bash
chmod +x rustzap-<version>-linux-x86_64.AppImage
./rustzap-<version>-linux-x86_64.AppImage
```

### macOS

```bash
open rustzap-<version>-macos-universal.dmg
```

### Windows

Run:

```text
rustzap-<version>-windows-x64.exe
```

Release artifacts are currently not code-signed, so Windows and macOS may display publisher/trust warnings.

Always verify the SHA-256 checksum before bypassing an operating-system warning.

---

# Verify downloads

Linux and macOS:

```bash
shasum -a 256 -c SHA256SUMS --ignore-missing
```

Windows:

```powershell
Get-FileHash .\rustzap-<version>-windows-x64.exe -Algorithm SHA256
```

If you prefer to build from source, RustZAP can be built directly with Cargo.

---

# Build from source

RustZAP requires Rust 1.91+.

```bash
git clone https://github.com/souayb/rustZAP
cd rustZAP

./scripts/install-hooks.sh
cargo build --release

./target/release/rustzap --help
```

On Windows:

```cmd
scripts\install-hooks.cmd
```

Development checks and contribution requirements are documented in `CONTRIBUTION.md`.

---

# Isolated security environment

RustZAP can build and run a complete security environment using Docker.

First detect the available tools:

```bash
rustzap install --list
```

Preview the setup:

```bash
rustzap install --dry-run
```

Build the isolated environment:

```bash
rustzap install --yes
```

Start the isolated console:

```bash
rustzap isolated
```

Run repository analysis inside the environment:

```bash
rustzap isolated analyze . \
  --yes \
  --tools native,semgrep,trivy,gitleaks,checkov
```

The environment can include:

* Semgrep
* Trivy
* Gitleaks
* Checkov
* Nuclei
* Nmap
* Nikto
* Wapiti
* tshark
* Hashcat
* John
* Hydra
* Medusa
* Aircrack-ng
* Wifite

The isolated environment is designed to reduce host setup requirements and provide a reproducible security-testing environment.

Only the selected workspace is mounted into the container. RustZAP does not mount the Docker socket or host credentials.

For workflows requiring special hardware, kernel monitoring, wireless adapters, packet capture, or GPU cracking, use an appropriately configured security VM or host environment.

---

# Docker

Build the image:

```bash
docker build -t rustzap .
```

Start the interactive console:

```bash
docker run --rm -it \
  -v "$PWD/reports:/workspace" \
  rustzap
```

Run a scan:

```bash
docker run --rm \
  -v "$PWD/reports:/workspace" \
  rustzap \
  scan \
  --target https://example.com \
  --output /workspace/report.json
```

Start the intercepting proxy:

```bash
docker run --rm \
  -p 8080:8080 \
  rustzap \
  proxy \
  --listen 0.0.0.0:8080
```

---

# Docker Compose

Start the interactive console:

```bash
docker compose run --rm rustzap
```

Run a scan:

```bash
docker compose run --rm rustzap \
  scan \
  --target https://example.com \
  -o /workspace/report.json
```

Start the optional Juice Shop laboratory:

```bash
docker compose --profile labs up -d juice-shop
```

Then scan it:

```bash
docker compose run --rm rustzap \
  scan \
  --target http://juice-shop:3000
```

Reports are mounted to:

```text
./reports → /workspace
```

The intercepting proxy is exposed on port `8080`.

---

# Security laboratory

RustZAP includes a deliberately vulnerable local application for testing the scanner.

Start the laboratory:

```bash
scripts/lab.sh up
```

Run a full DAST scan:

```bash
scripts/lab.sh scan
```

Run repository analysis:

```bash
scripts/lab.sh analyze
```

Run the AI red-team battery:

```bash
scripts/lab.sh redteam
```

Stop the laboratory:

```bash
scripts/lab.sh down
```

The laboratory contains intentionally fake credentials and vulnerable endpoints.

**Never reuse laboratory credentials or expose the laboratory to systems you do not control.**

RustZAP also contains a deterministic pure-Rust vulnerability test matrix used by the test suite and CI.

---

# Basic usage

## Full web security scan

```bash
rustzap scan --target https://example.com
```

Deep scan:

```bash
rustzap scan \
  --target https://example.com \
  --depth 10 \
  --concurrency 20 \
  --output report.json
```

Export reports:

```bash
rustzap scan --target https://example.com --output report.json
rustzap scan --target https://example.com --output report.csv
rustzap scan --target https://example.com --output report.html
```

SARIF:

```bash
rustzap scan \
  --target https://example.com \
  --output findings.sarif
```

Or:

```bash
rustzap scan \
  --target https://example.com \
  -o report.json \
  --sarif-out findings.sarif
```

---

# Authenticated testing

RustZAP supports cookies, bearer authentication, API keys and basic authentication.

```bash
rustzap scan \
  --target https://app.example.com \
  --cookies "session=abc123; role=admin" \
  --auth "Bearer eyJhbGciOiJIUzI1NiJ9..." \
  --api-key "X-Api-Key: my-secret-key" \
  --basic-auth "username:password"
```

Use authentication only against systems you are authorized to assess.

---

# Read-only security testing

For safer assessments:

```bash
rustzap scan \
  --target https://example.com \
  --read-only-safe \
  --max-rps 20
```

Passive-only analysis:

```bash
rustzap scan \
  --target https://example.com \
  --passive-only
```

RustZAP also provides named safety profiles.

```bash
rustzap scan \
  --target https://staging.example \
  --profile default
```

For fragile environments:

```bash
rustzap scan \
  --target https://plant-staging.example \
  --profile ot-safe \
  --plugins xss,sqli
```

`ot-safe` is a transport safety profile. It is **not an OT/ICS certification**.

Always obtain asset-owner approval before testing operational technology environments.

---

# Repository analysis

RustZAP can analyze local repositories.

```bash
rustzap analyze ~/src/myapp --tools native
```

For CI:

```bash
rustzap analyze ~/src/myapp \
  --tools native \
  --yes \
  --output native-report.json
```

Multiple tools can be combined:

```bash
rustzap analyze \
  --repo . \
  --tools semgrep,trivy,gitleaks,native \
  --yes
```

Checkov can be enabled explicitly:

```bash
rustzap analyze \
  --repo . \
  --tools native,checkov \
  --yes
```

RustZAP can also parse existing tool output without spawning the external tools:

```bash
rustzap analyze \
  --repo . \
  --semgrep-json tests/fixtures/semgrep_small.json \
  --trivy-json tests/fixtures/trivy_small.json \
  --gitleaks-json tests/fixtures/gitleaks_small.json \
  --checkov-json tests/fixtures/checkov_small.json \
  --yes \
  --output analyze-report.json
```

---

# Finding correlation

Security findings often describe different parts of the same underlying problem.

RustZAP can correlate findings across security sources.

For example:

```text
SAST
 │
 └── SQL-related source finding
          │
          ▼
       Correlation
          │
          ▲
          │
 DAST ─── SQL injection
```

Run correlation with:

```bash
rustzap analyze \
  --repo . \
  --semgrep-json semgrep.json \
  --correlate \
  --yes \
  --output analyze-report.json \
  --sarif-out analyze.sarif
```

Reports can contain:

```text
modules[]
correlations[]
static{}
```

Native analysis can additionally produce:

* inventory
* risk score
* risk breakdown
* detection checks
* attack plan

---

# Audit workflow

`audit` combines repository analysis with optional application assessment.

```bash
rustzap audit ~/src/myapp \
  --target https://lab.example.com \
  --tools native \
  --yes \
  --passive-only \
  --depth 2 \
  --output audit-report.json \
  --sarif-out audit.sarif
```

The native repository walker respects:

* `.gitignore`
* `.rustzapignore`

and skips common generated or dependency directories such as:

* `node_modules`
* `target`
* `.git`
* `vendor`
* `dist`

---

# Active Directory assessment

RustZAP provides a detection-oriented Active Directory assessment workflow.

> ⚠️ `rustzap ad` sends LDAP and NTLM authentication traffic. It is intrusive and requires authorization.

Current native checks include:

* LDAP / LDAPS signing posture
* Ghost SPNs
* NTLMv1 indicators
* NTLM signing negotiation flags
* LDAP domain-computer enumeration

Example:

```bash
rustzap ad \
  --domain corp.local \
  --dc-ip 10.0.0.1 \
  --null-auth \
  --checks spn,ldap \
  --yes
```

Authenticated assessment:

```bash
export RZ_AD_PASS='...'

rustzap ad \
  --domain corp.local \
  --dc-ip 10.0.0.1 \
  -u svc-account \
  --audit \
  -o ad-report.json \
  --sarif-out ad.sarif \
  --yes
```

Pass credentials through an environment variable rather than the command line.

---

# Spider

Run the crawler independently:

```bash
rustzap spider \
  --target https://example.com \
  --depth 5
```

Export discovered URLs:

```bash
rustzap spider \
  --target https://example.com \
  --output urls.json
```

The spider can enrich discovery using:

* HTML links
* forms
* inline JavaScript
* `robots.txt`
* XML sitemaps

Discovery remains bounded by configured limits.

---

# Intercepting proxy

Start the proxy:

```bash
rustzap proxy
```

Custom address:

```bash
rustzap proxy \
  --listen 0.0.0.0:9090 \
  --passive \
  --dump captured.json
```

Configure your browser to use:

```text
127.0.0.1:8080
```

Captured traffic can then be analyzed and replayed through the RustZAP workflow.

---

# Interactive terminal console

RustZAP includes a Ratatui-based multi-tab security console.

Start it with:

```bash
rustzap
```

or:

```bash
rustzap tui
```

The console provides:

* scan configuration
* repository analysis
* findings
* external security tools
* logs
* agent workflows

Typical workflow:

```text
RustZAP
  │
  ├── Scan
  ├── Analyze
  ├── Findings
  ├── Tools
  ├── Logs
  └── Agent
```

Useful controls include:

| Key     | Action           |
| ------- | ---------------- |
| `1`–`6` | Jump to tabs     |
| `Tab`   | Cycle tabs       |
| `a`     | Open Analyze     |
| `x`     | Cancel operation |
| `q`     | Quit             |

The console uses the same underlying RustZAP execution paths as the CLI.

---

# Agentic security testing

RustZAP can operate as a controlled security agent.

```bash
rustzap agent
```

The agent can use:

* DAST
* repository analysis
* attack-plan generation
* HTTP probes
* HTTP capture/replay
* AI red-team tools
* finding export
* bounded sub-tasks

The same tool registry is shared between the native agent and MCP.

```text
                 RustZAP Tool Registry
                         │
             ┌───────────┴───────────┐
             │                       │
        rustzap agent             MCP server
             │                       │
       Native brain          External AI client
```

Start the MCP server:

```bash
rustzap mcp
```

This allows compatible external AI clients to drive RustZAP through the Model Context Protocol.

---

# Supported AI providers

The agent uses a portable OpenAI-compatible API format.

This means it can work with compatible:

* hosted providers
* private gateways
* local inference servers

Examples include:

```text
OpenAI-compatible endpoint
        │
        ├── OpenAI
        ├── OpenRouter / compatible gateways
        ├── Together / compatible gateways
        ├── local Ollama
        ├── vLLM
        ├── LM Studio
        └── llama.cpp
```

Local models are particularly useful when security assessments contain information that should remain inside the organization.

---

# Agent scope

Create a scope:

```bash
rustzap agent --init-scope scope.yaml
```

A scope can define:

```yaml
allowed_schemes:
  - http
  - https

allowed_hosts:
  - localhost
  - 127.0.0.1
  - "*.juice-shop.local"

forbidden_paths:
  - "^/admin/delete"
```

The scope also controls:

* autonomy
* approvals
* request budgets
* model configuration
* execution limits

Network operations without a valid scope are rejected.

---

# Capture and replay

HTTP operations performed by the agent can be captured.

For example:

```text
Agent
  │
  ▼
http_probe
  │
  ▼
HTTP transaction
  │
  ├── request
  ├── response
  └── evidence
```

Captured transactions can later be replayed with controlled mutations.

This supports:

* reproducibility
* evidence collection
* manual investigation
* auditability

Reports can produce an associated capture file:

```text
agent-report.json
agent-report.captures.json
```

---

# Agent sub-tasks

The agent can delegate bounded reconnaissance tasks.

Example:

```json
{
  "tool": "spawn_subtask",
  "args": {
    "goal": "map and scan the /api subtree",
    "steps": [
      {
        "tool": "get_attack_plan",
        "args": {
          "path": "."
        }
      },
      {
        "tool": "scan_target",
        "args": {
          "target": "http://localhost:3000/api"
        }
      }
    ]
  }
}
```

Sub-tasks inherit:

* parent scope
* request budget
* capture store
* trace

Sub-tasks are reconnaissance-only and cannot recursively create more sub-tasks.

Intrusive operations remain controlled by the top-level security policy.

---

# AI red teaming

RustZAP includes an AI security testing workflow based on the OWASP LLM security landscape.

The `ai_redteam` tool can test an in-scope OpenAI-compatible chat endpoint for issues such as:

* prompt injection
* role override
* system prompt disclosure
* sensitive configuration disclosure
* insecure output handling

Example:

```bash
rustzap agent \
  --scope scope.yaml \
  --target http://localhost:3000
```

AI red-team operations are classified as intrusive and therefore remain subject to the approval matrix.

---

# Security findings

RustZAP reports findings using a shared model.

Example:

```json
{
  "id": "a1b2c3d4-...",
  "title": "SQL Injection",
  "severity": "critical",
  "url": "https://example.com/search?q=test",
  "parameter": "q",
  "description": "...",
  "solution": "Use parameterized queries...",
  "cwe": 89,
  "owasp_category": "A03:2021 – Injection",
  "plugin": "active/sqli"
}
```

Reports can include:

* severity
* evidence
* URL
* parameter
* description
* remediation
* CWE
* OWASP category
* plugin
* timestamps
* module summaries
* correlations
* static analysis information

---

# Report formats

RustZAP supports:

```text
JSON
CSV
HTML
SARIF
```

SARIF can be used with code-scanning systems such as GitHub Code Scanning.

Example:

```bash
rustzap analyze \
  --repo . \
  --tools native \
  --yes \
  --sarif-out rustzap.sarif
```

---

# Web security coverage

RustZAP currently includes active checks for areas such as:

| Check                 | OWASP | CWE     |
| --------------------- | ----- | ------- |
| Reflected XSS         | A03   | CWE-79  |
| SQL Injection         | A03   | CWE-89  |
| NoSQL Injection       | A03   | CWE-943 |
| Directory Traversal   | A01   | CWE-22  |
| Open Redirect         | A01   | CWE-601 |
| SSRF                  | A10   | CWE-918 |
| XXE                   | A03   | CWE-611 |
| OS Command Injection  | A03   | CWE-78  |
| SSTI                  | A03   | CWE-94  |
| GraphQL introspection | A05   | CWE-200 |
| HTTP method exposure  | A05   | CWE-650 |
| CRLF injection        | A03   | CWE-93  |
| Host Header Injection | A05   | CWE-20  |
| Redirect-chain issues | A02   | CWE-601 |

Additional higher-risk or higher-false-positive checks are explicitly opt-in.

These include:

* sensitive path discovery
* remote file inclusion
* cache deception
* cache poisoning
* rate-limit detection

For example:

```bash
rustzap scan \
  --target https://example.com \
  --plugins xss,sqli,ssrf
```

Opt into additional checks explicitly:

```bash
rustzap scan \
  --target https://example.com \
  --plugins xss,sqli,ssrf,sensitive-paths,cache-deception,cache-poisoning,rate-limit-missing
```

---

# Passive security checks

RustZAP can identify issues including:

* missing HSTS
* missing CSP
* missing X-Frame-Options
* missing X-Content-Type-Options
* insecure cookie flags
* server version disclosure
* verbose error messages
* mixed content
* exposed API keys and credentials
* insecure CORS
* missing cache controls
* missing `security.txt`
* unsafe CSP directives
* technology fingerprinting
* JWT security heuristics
* missing CSRF tokens

Run passive-only analysis:

```bash
rustzap passive \
  --input https://example.com \
  --output passive-report.json
```

---

# TLS and transport analysis

For discovered HTTPS hosts, RustZAP can inspect TLS certificates.

Checks include:

* expired certificates
* certificates expiring soon
* weak signature algorithms
* self-signed certificates
* hostname mismatch

Example findings:

```text
transport/tls-expired
transport/tls-expiring-soon
transport/tls-weak-signature
transport/tls-self-signed
transport/tls-hostname-mismatch
```

---

# Optional external intelligence

RustZAP can optionally use Shodan host intelligence.

Set:

```bash
SHODAN_API_KEY=xxx
```

Then:

```bash
SHODAN_API_KEY=xxx \
rustzap scan --target https://example.com
```

External intelligence is optional. Without the environment variable, the module is a no-op.

Only use external intelligence against infrastructure you are authorized to assess.

---

# Stress testing

RustZAP includes a controlled load-testing engine.

Five modes are available:

| Mode       | Description                           |
| ---------- | ------------------------------------- |
| `constant` | Fixed concurrent users for a duration |
| `ramp`     | Gradually increases load              |
| `spike`    | Introduces a controlled traffic spike |
| `soak`     | Long-duration testing                 |
| `requests` | Fixed request count                   |

Example:

```bash
rustzap stress \
  --target https://api.example.com/v1/users \
  --mode constant \
  --users 50 \
  --duration 60
```

Ramp testing:

```bash
rustzap stress \
  --target https://api.example.com/search \
  --mode ramp \
  --start-users 1 \
  --users 100 \
  --ramp-secs 30 \
  --duration 60
```

Soak testing:

```bash
rustzap stress \
  --target https://api.example.com/health \
  --mode soak \
  --users 20 \
  --duration 600
```

Stress testing is intended for systems you control or have explicit permission to test.

---

# VS Code integration

RustZAP includes a VS Code extension under:

```text
vscode-extension/
```

The extension currently provides:

* `RustZAP: Analyze Workspace`
* `RustZAP: Scan URL`
* `RustZAP: Scan Active Directory`

Build it with:

```bash
cd vscode-extension
npm ci
npm run compile
```

The extension requires the `rustzap` binary on `PATH`, or an explicit `rustzap.path` setting.

Reports are stored in extension storage rather than written into the repository.

---

# External security tools

RustZAP can detect and orchestrate external tools including:

```text
Semgrep
Trivy
Gitleaks
Checkov
Nuclei
Nmap
Nikto
Wapiti
Falco
tshark
Hashcat
John
Hydra
Medusa
Aircrack-ng
Wifite
```

The goal is not to duplicate every capability of these projects.

Instead, RustZAP provides a common workflow around them.

For example:

```text
Semgrep ─────┐
Trivy ───────┤
Gitleaks ────┤
Checkov ─────┤
              ├── RustZAP ── Correlation ── Report
DAST ────────┤
Nmap ────────┤
AD ──────────┤
AI testing ──┘
```

---

# Tool discovery

RustZAP detects installed tools without relying on a Unix shell.

```bash
rustzap install --list
```

Windows environments are supported through PATH, PATHEXT and common installation locations.

Individual tools can be overridden through environment variables:

```powershell
$env:RUSTZAP_TOOL_TRIVY = 'C:\Tools\Trivy\trivy.exe'
```

Then refresh the tool list from the TUI.

---

# Architecture

The project is organized around a shared security engine rather than independent command implementations.

```text
rustzap/
├── src/
│   ├── main.rs
│   ├── types.rs
│   ├── scanner.rs
│   ├── spider.rs
│   ├── passive.rs
│   ├── active.rs
│   ├── sqli_advanced.rs
│   ├── sensitive_paths.rs
│   ├── tls.rs
│   ├── intel.rs
│   ├── proxy.rs
│   ├── stress.rs
│   ├── report.rs
│   ├── analyze/
│   ├── events.rs
│   ├── tools.rs
│   ├── installer.rs
│   └── tui/
│
├── scripts/
│   └── install-tools.sh
│
├── packaging/
├── tests/
├── vscode-extension/
├── Dockerfile
├── docker-compose.yml
└── Cargo.toml
```

The central execution flow is:

```text
CLI / TUI / MCP / Agent
          │
          ▼
    Shared Rust engine
          │
     ┌────┼────┐
     ▼    ▼    ▼
   DAST  SAST  Tools
     │    │    │
     └────┼────┘
          ▼
     Correlation
          │
          ▼
       Findings
          │
          ▼
     Evidence / Report
```

This architecture allows different interfaces to use the same security primitives without duplicating scanning logic.

---

# Extending RustZAP

RustZAP supports custom active scanner plugins through the `ScanPlugin` trait.

Example:

```rust
use async_trait::async_trait;
use crate::active::ScanPlugin;
use crate::types::{DiscoveredUrl, Finding, Severity};

pub struct MyPlugin;

#[async_trait]
impl ScanPlugin for MyPlugin {
    fn name(&self) -> &str {
        "my-plugin"
    }

    fn description(&self) -> &str {
        "Detects XYZ vulnerability"
    }

    fn always_run(&self) -> bool {
        false
    }

    async fn scan(
        &self,
        client: &reqwest::Client,
        target: &DiscoveredUrl,
    ) -> Vec<Finding> {
        // Detection logic
        vec![]
    }
}
```

Register the plugin in:

```text
ActiveScanner::new()
```

and:

```text
list_plugins()
```

in `active.rs`.

Both lists must remain synchronized.

---

# Testing

RustZAP includes multiple layers of testing:

```text
Unit tests
    │
    ▼
Pure-Rust vulnerability matrix
    │
    ▼
Local vulnerable laboratory
    │
    ▼
Full scanner workflows
    │
    ▼
Agent / AI security workflows
```

The pure-Rust vulnerability matrix provides deterministic regression coverage without requiring Node.js or Docker.

The local laboratory provides broader end-to-end testing for:

* active plugins
* passive checks
* crawling
* complete scan pipelines
* repository analysis
* agent workflows
* AI red-team paths

---

# Development

Install the repository hooks:

```bash
./scripts/install-hooks.sh
```

Build:

```bash
cargo build
```

Run tests:

```bash
cargo test
```

Format:

```bash
cargo fmt --all
```

Lint:

```bash
cargo clippy --all-targets --all-features
```

Before submitting changes, ensure formatting, linting, and tests pass.

See:

```text
CONTRIBUTION.md
```

for the project contribution workflow.

---

# Roadmap

RustZAP is actively evolving.

The project roadmap focuses on strengthening the platform around several areas:

### Security engine

* broader DAST coverage
* additional passive analysis
* stronger vulnerability validation
* improved false-positive reduction

### Unified analysis

* richer SAST / DAST correlation
* infrastructure and dependency correlation
* normalized security findings
* stronger risk prioritization

### Agent security

* stronger policy controls
* more deterministic execution
* improved evidence handling
* additional local-model integrations
* expanded AI application testing

### Interoperability

* SARIF
* OpenAPI
* HAR
* MCP
* additional security-tool integrations

### Platform

* richer API capabilities
* improved reporting
* stronger CI/CD integration
* improved self-hosted deployment workflows

The detailed implementation state is maintained in:

* `FEATURE.md`
* `IMPLEMENTATION_PLAN.md`
* `SOFTWARE_DESIGN_DOCUMENT.md`

Implemented functionality should be distinguished from planned work in those documents.

---

# What RustZAP is not

RustZAP is not intended to:

* replace every specialized security tool
* provide unrestricted autonomous penetration testing
* require a centralized cloud service
* treat an LLM's output as security evidence by itself
* encourage unauthorized scanning
* act as an OT/ICS certification
* guarantee that a system is secure

RustZAP is a security assessment and orchestration platform.

The final interpretation of findings remains the responsibility of the security practitioner and system owner.

---

# Responsible use

RustZAP can perform intrusive security operations.

Use it only where you have authorization.

Examples of appropriate environments include:

* applications you own
* development environments
* staging environments
* dedicated security laboratories
* authorized penetration tests
* authorized enterprise assessments
* controlled educational environments

Do not scan:

* third-party websites without permission
* public infrastructure without authorization
* systems belonging to other organizations
* production environments where testing has not been approved

---

# Open-source security infrastructure

RustZAP is developed as open-source security infrastructure.

The project aims to make security assessment capabilities:

* inspectable
* self-hostable
* extensible
* interoperable
* automation-friendly
* usable without mandatory dependence on a centralized proprietary platform

The long-term goal is not simply another scanner.

It is an **open security workflow in which organizations can combine their own infrastructure, security tools, local data, and AI capabilities while retaining control over the security process and evidence.**

---

# Contributing

Contributions are welcome.

Before implementing a significant feature:

1. Open or review an issue.
2. Explain the problem and proposed approach.
3. Keep security-sensitive behavior explicitly scoped.
4. Add tests for new detection logic.
5. Document new CLI or configuration behavior.
6. Run formatting, linting and tests.
7. Submit a pull request.

See:

```text
CONTRIBUTION.md
```

for the development workflow.

---

# License

RustZAP is released under the **MIT License**.

See [`LICENSE`](LICENSE) for the complete license text.

Use responsibly and only against systems you are authorized to test.

---

## Project status

RustZAP is an actively developed open-source project.

Current functionality includes:

* web application scanning
* passive and active security checks
* repository analysis
* security-tool integration
* finding correlation
* Active Directory assessment
* intercepting proxy
* stress testing
* terminal security console
* agentic security workflows
* MCP integration
* AI red teaming
* privacy tokenization
* prompt-injection protection
* evidence and trace collection
* Docker-based isolated execution
* VS Code integration

For detailed implementation status and planned work, see:

* [`FEATURE.md`](FEATURE.md)
* [`IMPLEMENTATION_PLAN.md`](IMPLEMENTATION_PLAN.md)
* [`SOFTWARE_DESIGN_DOCUMENT.md`](SOFTWARE_DESIGN_DOCUMENT.md)
* [`CONTRIBUTION.md`](CONTRIBUTION.md)
