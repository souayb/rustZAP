# Unified DevSecOps Security Platform: Software Design Document (SDD)

## 1. Introduction

This Software Design Document (SDD) outlines the architecture, design, and implementation strategy for a Unified DevSecOps Security Platform. This platform orchestrates various open-source security tools—including Semgrep, Trivy, Falco, Gitleaks, Checkov, and **RustZAP** (our custom fast Rust-based web scanner)—into a single pane of glass. It provides continuous security scanning, runtime correlation, and automated remediation across the entire SDLC.

## 2. System Architecture

The system follows an event-driven, microservices-based architecture designed for scalability and high throughput.

### 2.1 High-Level Architecture

*   **API Gateway & Ingress**: Routes traffic from the frontend dashboard, CLI tools, and external CI/CD webhooks (GitHub, GitLab, etc.).
*   **Core Orchestrator (Control Plane)**: Manages scan jobs, schedules tool executions, and handles events.
*   **Worker Nodes (Data Plane)**: Kubernetes Jobs or DaemonSets that run the actual security tools (RustZAP, Semgrep, Trivy, etc.) in isolated environments.
*   **Runtime Correlation Engine**: Correlates static findings (e.g., Checkov, Semgrep) with runtime events (Falco) and dynamic scans (RustZAP) to reduce false positives and prioritize real risks.
*   **Data Lake & Storage**: Stores raw scan reports, normalized findings, and audit logs.
*   **Message Broker (Kafka/RabbitMQ)**: Facilitates async communication between the orchestrator, workers, and correlation engine.

## 3. Module Design

### 3.1 Orchestrator Module
Responsible for triggering scans based on CI/CD webhooks or scheduled intervals. It translates platform requests into specific tool configurations.

### 3.2 Tool Integration Modules (Workers)
Each tool runs as an independent worker listening to a specific queue.
*   **SAST Worker**: Runs Semgrep on source code.
*   **SCA/Container Worker**: Runs Trivy on Docker images and dependencies.
*   **DAST Worker**: Runs **RustZAP** (and potentially tools like Wapiti and Nikto) against staging and production web applications for active/passive scanning and stress testing.
*   **Secret Scanner Worker**: Runs Gitleaks on commits and PRs.
*   **IaC Scanner Worker**: Runs Checkov on Terraform/Kubernetes manifests.
*   **Reconnaissance & Network Worker**: Runs Nmap and Wireshark for mapping topologies, port scanning, and deep packet inspection.
*   **Password/Auth Testing Worker**: Runs tools like Hashcat, John The Ripper, Hydra, or Medusa for dictionary, brute-force, and hash-cracking tasks.
*   **Wireless Security Worker**: Integrates Aircrack-ng or Wifite for wireless network auditing and monitoring.

### 3.3 Normalization Module
Takes diverse JSON outputs from different tools (e.g., RustZAP's `rustzap-report.json`, Trivy's JSON) and converts them into a Unified Finding Format (UFF).

## 4. Tool Integration Strategy

Our strategy leverages native containerization and the existing JSON reporting capabilities of each tool.

*   **RustZAP (DAST & Stress)**: Integrated natively. The platform invokes `rustzap scan --target <URL> --output report.json` as a Kubernetes Job. RustZAP's custom plugins (`active.rs`, `passive.rs`) feed directly into the platform's API via its JSON output.
*   **Semgrep (SAST)**: Triggered via CI pipelines. Output is fetched via standard SARIF or JSON formats.
*   **Trivy (SCA/Container)**: Scans container registries and image build pipelines.
*   **Gitleaks (Secrets)**: Runs as a pre-commit hook and on every push event to detect hardcoded secrets.
*   **Checkov (IaC)**: Integrated into the deployment pipeline to block insecure infrastructure before it is provisioned.
*   **Falco (Runtime)**: Runs as a DaemonSet on K8s nodes. Falco alerts are ingested via webhooks into the Runtime Correlation Engine.
*   **Reconnaissance (Nmap / Wireshark)**: Scans infrastructure perimeters to enrich assets and ports mapped to discovered apps.
*   **Authentication Exploitation (Hashcat / John The Ripper)**: Uses known hashed password dumps or brute-forcing mechanisms continuously to identify weak authentication vectors automatically.

## 5. Runtime Correlation Engine

The Runtime Correlation Engine is the brain of the platform. It contextualizes findings across tools.

*   **Mechanism**: If Checkov flags a misconfigured security group (port 8080 open), and RustZAP successfully exploits a vulnerability on port 8080 (e.g., via `sqli` or `xxe` plugins), the engine correlates these two findings.
*   **Risk Scoring**: Findings corroborated by multiple tools (e.g., a vulnerable package found by Trivy is actively exploited by RustZAP and causes a runtime alert in Falco) have their risk score elevated to `CRITICAL`.
*   **Deduplication**: Merges similar vulnerabilities reported by different static analysis tools.

## 6. APIs

The platform exposes a RESTful API and a GraphQL endpoint for the frontend.

### 6.1 Core Endpoints
*   `POST /api/v1/scans`: Trigger a new scan.
    *   Payload: `{"target": "repo_url_or_app_url", "tools": ["rustzap", "semgrep"]}`
*   `GET /api/v1/scans/{id}`: Retrieve scan status.
*   `GET /api/v1/findings`: Retrieve normalized findings with filtering (severity, tool, status).
*   `POST /api/v1/webhooks/falco`: Ingest runtime alerts from Falco.

## 7. Database Schemas

We use PostgreSQL for relational data (Projects, Users, Scan Metadata) and a NoSQL/Document store (MongoDB or Elasticsearch) for raw findings.

### 7.1 PostgreSQL (Metadata & State)
```sql
CREATE TABLE projects (
    id UUID PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    repo_url VARCHAR(255)
);

CREATE TABLE scans (
    id UUID PRIMARY KEY,
    project_id UUID REFERENCES projects(id),
    status VARCHAR(50), -- PENDING, RUNNING, COMPLETED, FAILED
    start_time TIMESTAMP,
    end_time TIMESTAMP
);
```

### 7.2 Document Store (Findings - Unified Finding Format)
```json
{
  "finding_id": "uuid",
  "scan_id": "uuid",
  "tool": "RustZAP",
  "severity": "CRITICAL",
  "title": "SQL Injection",
  "cwe": 89,
  "description": "...",
  "evidence": "...",
  "correlated_with": ["falco_alert_123", "trivy_finding_456"]
}
```

## 8. CI/CD Integration

The platform provides a unified CLI and GitHub Actions/GitLab CI templates.

*   **Pre-Commit**: Local hooks running Gitleaks and Semgrep.
*   **PR/Merge Request**: Triggers Trivy, Checkov, and Semgrep. Blocks merge if `HIGH` or `CRITICAL` findings exist.
*   **Post-Deployment**: Triggers RustZAP against the newly deployed environment.

## 9. Plugin System

The platform adopts an extensible plugin system. It uses a gRPC-based architecture, allowing plugins to be written in any language.

*   **RustZAP Extension**: RustZAP's internal `ScanPlugin` trait (found in `src/active.rs`) serves as the model. New DAST plugins can be added to RustZAP, which the platform automatically consumes through updated JSON reports.
*   **Platform Plugins**: Developers can register new tools by implementing a standard Docker-based interface that consumes a target URL/Repo and outputs the Unified Finding Format.

### 9.1 Module-Centric Findings View (RustZAP Operator Console)

#### Motivation

The scanner now ships **22+ active plugins** plus passive helpers (`security.txt`, deep CSP, JWT, tech-fingerprint), transport probes (`tls-*`), and optional intel (`intel/shodan-*`). A flat findings list is unreadable at that volume. Operators need to:

1. See **which modules executed** in the current scan (including modules that ran but produced zero findings — confirms coverage).
2. **Group findings under their originating module** so noise from one module doesn't drown out another.
3. **Collapse / expand** any module group on demand to focus on what matters.

#### Concepts

| Term | Meaning |
|---|---|
| **Module** | A bounded unit of scanning identified by the `plugin` string on a `Finding` (e.g. `passive/security-txt`, `active/sqli`, `transport/tls-expired`, `intel/shodan-vulns`). |
| **Module group** | A collapsible UI element in the Findings tab that holds all findings produced by a single module. The header shows the module name, run status (✓ Ran / · Quiet / ✗ Skipped), and per-severity counts. |
| **Quiet module** | A module that executed but produced zero findings. Still listed (folded by default) so the operator confirms it ran. |
| **Skipped module** | A module that was disabled via `--plugins`. Not shown in the tree. |

#### Module taxonomy (derived from `Finding::plugin`)

Modules are grouped by the slash-separated prefix on the `plugin` field, then by the full plugin id. The runtime does **not** maintain a hard-coded module list — adding a new plugin with a fresh `plugin` id automatically gets its own group.

```
passive/      header, body, CSP, security.txt, JWT, tech-fingerprint, …
active/       xss, sqli-error, sqli-boolean, …, graphql-introspection, …
transport/    tls-expired, tls-expiring-soon, tls-weak-signature, tls-self-signed,
              tls-hostname-mismatch
intel/        shodan-vulns, shodan-ports
spider/       (reserved — robots/sitemap discovery, currently informational)
sast/         static analysis — planned Semgrep rules → `Finding` (IMPLEMENTATION_PLAN Phase 1)
sca/          supply-chain — planned Trivy → `Finding` (IMPLEMENTATION_PLAN Phase 2)
secrets/      secret scanning — planned Gitleaks → `Finding` (IMPLEMENTATION_PLAN Phase 2)
iac/          infra-as-code — planned Checkov → `Finding` (IMPLEMENTATION_PLAN Phase 2)
agentic/      LLM/agent abuse tests — planned, strictly opt-in (IMPLEMENTATION_PLAN Phase 5)
```

#### Event protocol (scanner → TUI)

A new variant is added to `ScanEvent` in `src/events.rs`:

```rust
pub enum ScanEvent {
    // … existing variants …
    /// Emitted once per module that executed during the scan. `findings` is
    /// the count this module produced; zero means the module ran but was
    /// quiet (still shown in the tree, folded by default).
    ModuleRan { name: String, findings: usize },
}
```

Emission points:

* **Active plugins** — `ActiveScanner::scan_all` emits one `ModuleRan` per plugin after the per-URL loop completes.
* **Passive helpers** — `scanner::run_scan_with_events` buckets passive findings by `plugin` at the end of the passive phase and emits one `ModuleRan` per bucket plus one for each *expected* passive check that produced nothing (so quiet modules are visible).
* **Transport / Intel** — `tls::check_hosts` and `intel::enrich_hosts` emit `ModuleRan` per probe class.

The TUI builds module state from the union of:

1. `Finding` events (their `plugin` field defines the module).
2. `ModuleRan` events (covers modules that ran quietly).

#### TUI rendering (Findings tab)

Default tree:

```
▼ Modules (12 ran · 7 quiet)            [press ? for help]
  ▶ active/sqli                          ●1 CRIT
  ▼ passive/csp-unsafe-directives        ●1 HIGH  ●3 MED
       [HIGH] CSP wildcard '*' in script-src
       [MED]  CSP allows 'unsafe-inline' in script-src
       [MED]  CSP allows 'unsafe-eval' in script-src
       [MED]  CSP object-src is not 'none'
  ▶ passive/security-txt                 ●1 INFO
  ▶ transport/tls-expiring-soon          ●1 MED
  · passive/missing-headers              (quiet)
  · active/xss                           (quiet)
  · active/redirect-chain                (quiet)
```

* `▶` = collapsed group, `▼` = expanded, `·` = quiet (collapsed by default).
* Severity badges use the existing per-severity colour palette from `Severity::color_str`.
* Selecting a finding row reveals the existing detail pane (title, CWE, OWASP, evidence, solution) — unchanged.

Key bindings (within Findings tab):

| Key | Action |
|---|---|
| `j` / `k` (or `↓` / `↑`) | Move focus across the visible tree (module headers and visible findings are both nav nodes) |
| `Enter` / `Space` | Toggle fold on the focused module header |
| `o` | Open-all (expand every module) |
| `O` | Close-all (collapse every module) |
| `f` | Cycle severity filter (existing) |
| `c` | Clear filter (existing) |
| `PgUp` / `PgDn` | Scroll detail pane (existing) |

Module-group ordering: **by max severity descending**, then alphabetical. Quiet modules sink to the bottom. This keeps Critical/High findings glued to the top of the tree.

#### CLI rendering (non-TUI path)

`run_scan` already prints a `SCAN SUMMARY` block. Below it, a new `MODULES` roll-up is added so the same coverage signal is available outside the TUI:

```
─────────────────────────────────────────────────────────
  MODULES
─────────────────────────────────────────────────────────
  ✓ active/sqli                  1 finding   [CRIT]
  ✓ passive/csp-unsafe-directives 4 findings  [HIGH MED]
  ✓ passive/security-txt         1 finding   [INFO]
  ✓ transport/tls-expiring-soon  1 finding   [MED]
  · passive/missing-headers      (quiet)
  · active/xss                   (quiet)
  …
```

#### JSON report extension

The `Report` JSON should include a `modules` array (additive — existing consumers ignore unknown fields). **Current status:** module roll-up is implemented for the CLI `MODULES` block and TUI (`summarize_modules` + `ScanEvent::ModuleRan`); serializing the same structure into JSON is **specified in [`IMPLEMENTATION_PLAN.md`](./IMPLEMENTATION_PLAN.md) Phase 1** (`report.rs`).

```json
"modules": [
  { "name": "active/sqli", "findings": 1, "max_severity": "critical", "quiet": false },
  { "name": "passive/missing-headers", "findings": 0, "max_severity": null, "quiet": true }
]
```

This lets the platform-level dashboard render the same tree the TUI shows without re-deriving it from finding bodies. Later phases add `correlations[]`, SARIF export, and optional `scan_coverage` — see the implementation plan.

#### Non-goals (this iteration)

* No per-module **enable/disable toggle** in the TUI — plugin selection stays on the CLI `--plugins` flag.
* No persistence of fold state across runs.
* No deep-link from a module header into the source file or docs (deferred to platform UI).
* Spider sub-modules (`Robots`, `Sitemap` URL sources) are tracked as crawl provenance, not as finding-producing modules.

### 9.2 RustZAP implementation tracking (in-repo)

The repository carries a **detailed engineering spec** for extending RustZAP beyond DAST: code analysis (`analyze`), unified multi-tool runs (`audit`), correlation, HTTP worker mode (`serve`), and opt-in agentic testing. It maps work to concrete files, CLI flags, JSON fields, tests, and acceptance criteria.

* **Authoritative spec:** [`IMPLEMENTATION_PLAN.md`](./IMPLEMENTATION_PLAN.md)
* **DAST modules (status + backlog):** [`FEATURE.md`](./FEATURE.md)
* **Platform / UFF / correlation context:** this SDD (§3.3, §5, §6)

Contributors should update the implementation plan when a phase ships (mark items Done, adjust schema if the JSON contract changes).

## 10. Kubernetes Deployment

The platform is deployed via Helm charts.

*   **Control Plane**: StatefulSets for databases, Deployments for API/Orchestrator.
*   **Data Plane**: `Jobs` triggered per scan to ensure clean, ephemeral scanning environments.
*   **Falco**: Deployed as a `DaemonSet` on all worker nodes.
*   **Ingress**: NGINX Ingress controller with TLS termination.

## 11. Security Requirements

*   **Authentication**: OIDC/OAuth2 integration (Keycloak, Auth0).
*   **RBAC**: Role-Based Access Control restricting access to projects and sensitive findings.
*   **Encryption**: TLS 1.3 in transit. AES-256 for data at rest (especially for stored Git tokens and credentials).
*   **Self-Scanning**: The platform must scan itself using its own tools (RustZAP, Semgrep, Trivy) in its CI pipeline.


## 12. MVP Roadmap

### Phase 1: Foundation (Months 1-2)
*   Deploy Core Orchestrator and Database schemas.
*   Integrate RustZAP (DAST) and Semgrep (SAST) via worker nodes.
*   Basic API and Findings Normalization.

### Phase 2: Complete Toolchain (Months 3-4)
*   Integrate Trivy, Gitleaks, Checkov.
*   Develop Frontend Dashboard (Overview and Triage views).
*   Implement GitHub Actions / GitLab CI templates.

### Phase 3: Advanced Correlation (Months 5-6)
*   Deploy Falco and the Runtime Correlation Engine.
*   Implement Jira integration for ticketing.
*   Release Plugin SDK for third-party integrations.

### Phase 4: Extended Pentesting Suite (Months 7-8)
*   Integrate network Reconnaissance capabilities (Nmap, Wireshark).
*   Add password security & cracking tools (Hashcat, John The Ripper, Hydra).
*   Incorporate specialized scanning features (Nikto, Wapiti) and WiFi audits (Aircrack-ng).
