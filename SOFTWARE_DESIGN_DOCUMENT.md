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
*   **DAST Worker**: Runs **RustZAP** against staging and production web applications for active/passive scanning and stress testing.
*   **Secret Scanner Worker**: Runs Gitleaks on commits and PRs.
*   **IaC Scanner Worker**: Runs Checkov on Terraform/Kubernetes manifests.

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

## 12. Frontend Dashboard Structure

Built with React/Next.js and Tailwind CSS.

*   **Overview Dashboard**: High-level metrics, risk scores across projects, and recent critical alerts.
*   **Project Detail View**: specific repo/app health, historical trends.
*   **Findings Triage**: A data grid showing all normalized findings. Features: Filtering, grouping by correlation, ignoring false positives, and ticketing (Jira integration).
*   **CI/CD Pipeline View**: Visual representation of the security pipeline for a given build.
*   **Remediation Hub**: Provides actionable advice (e.g., linking Checkov IaC fixes directly to the repo).

## 13. MVP Roadmap

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
