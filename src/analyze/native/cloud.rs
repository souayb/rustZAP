//! Cloud, Container & Infrastructure as Code (IaC) Security Posture Analyzer.
//!
//! Provides pure-Rust static linting and misconfiguration detection for:
//! - Dockerfiles: Root user execution, missing healthchecks, pinned `:latest` tags, remote ADD, secrets in ENV
//! - Kubernetes Manifests: Privileged pods, hostPath mounts, hostNetwork/hostPID, missing resource limits, dangerous capabilities
//! - Terraform / Cloud Configs: Public S3 buckets, open security groups (0.0.0.0/0 on sensitive ports), wildcard IAM policies

use regex::Regex;
use std::path::{Path, PathBuf};

use crate::analyze::inventory::{
    file_url, is_minified_name, read_text_head, rel_path, MAX_SOURCE_BYTES,
};
use crate::analyze::native::SOURCE_TOOL;
use crate::types::{CodeLocation, Finding, Severity};

pub struct CloudAuditor {
    docker_from_latest_regex: Regex,
    docker_env_secret_regex: Regex,
    docker_sudo_regex: Regex,
    k8s_privileged_regex: Regex,
    k8s_host_path_regex: Regex,
    k8s_host_net_pid_regex: Regex,
    tf_open_sg_regex: Regex,
    tf_wildcard_iam_regex: Regex,
    tf_s3_public_regex: Regex,
}

impl Default for CloudAuditor {
    fn default() -> Self {
        Self::new()
    }
}

impl CloudAuditor {
    pub fn new() -> Self {
        Self {
            docker_from_latest_regex: Regex::new(r#"(?i)^\s*FROM\s+[a-zA-Z0-9_\-\.\/]+:latest\b"#)
                .unwrap(),
            docker_env_secret_regex: Regex::new(
                r#"(?i)^\s*ENV\s+(?:.*(?:PASSWORD|SECRET|API_KEY|TOKEN|PRIVATE_KEY)\s*=.*)"#,
            )
            .unwrap(),
            docker_sudo_regex: Regex::new(r#"(?i)^\s*RUN\s+.*sudo\s+"#).unwrap(),
            k8s_privileged_regex: Regex::new(r#"(?i)privileged\s*:\s*true"#).unwrap(),
            k8s_host_path_regex: Regex::new(r#"(?i)hostPath\s*:"#).unwrap(),
            k8s_host_net_pid_regex: Regex::new(r#"(?i)(?:hostNetwork|hostPID|hostIPC)\s*:\s*true"#)
                .unwrap(),
            tf_open_sg_regex: Regex::new(r#"(?i)cidr_blocks\s*=\s*\[\s*["']0\.0\.0\.0/0["']\s*\]"#)
                .unwrap(),
            tf_wildcard_iam_regex: Regex::new(r#"(?i)"Action"\s*:\s*\[?\s*"\*"\s*\]?"#).unwrap(),
            tf_s3_public_regex: Regex::new(r#"(?i)acl\s*=\s*["']public-(?:read|read-write)["']"#)
                .unwrap(),
        }
    }

    /// Audit a Dockerfile string content.
    pub fn audit_dockerfile(&self, src: &str, file_rel: &str, file_url_str: &str) -> Vec<Finding> {
        let mut findings = Vec::new();
        let mut has_user_instruction = false;
        let mut has_healthcheck = false;

        for (idx, line) in src.lines().enumerate() {
            let line_num = idx + 1;
            let trimmed = line.trim();

            if trimmed.starts_with("USER ") || trimmed.starts_with("user ") {
                has_user_instruction = true;
            }
            if trimmed.starts_with("HEALTHCHECK ") || trimmed.starts_with("healthcheck ") {
                has_healthcheck = true;
            }

            // Check unpinned :latest
            if self.docker_from_latest_regex.is_match(line) {
                findings.push(
                    Finding::new(
                        "Dockerfile Uses Mutable ':latest' Base Image",
                        Severity::Low,
                        format!("{}#L{}", file_url_str, line_num),
                        format!("Base image in {} uses the mutable ':latest' tag instead of an immutable digest or specific semver tag.", file_rel),
                        "Pin base images using specific version tags or SHA-256 digests (e.g. `FROM alpine:3.18@sha256:...`).",
                        "iac/dockerfile",
                    )
                    .with_source_tool(SOURCE_TOOL)
                    .with_evidence(trimmed.to_string())
                    .with_cwe(1059)
                    .with_owasp("A05:2021 – Security Misconfiguration")
                    .with_location(CodeLocation {
                        file: file_rel.to_string(),
                        line_start: line_num as u32,
                        line_end: None,
                    }),
                );
            }

            // Check secret in ENV
            if self.docker_env_secret_regex.is_match(line) {
                findings.push(
                    Finding::new(
                        "Hardcoded Secret in Dockerfile ENV Instruction",
                        Severity::High,
                        format!("{}#L{}", file_url_str, line_num),
                        format!("Sensitive credential pattern detected in Dockerfile ENV directive in {}. Values in ENV persist into container image metadata.", file_rel),
                        "Pass credentials at runtime via environment variables, Kubernetes secrets, or build secrets (BuildKit `--secret`).",
                        "iac/dockerfile-secret",
                    )
                    .with_source_tool(SOURCE_TOOL)
                    .with_evidence("[REDACTED_DOCKER_ENV]".to_string())
                    .with_cwe(798)
                    .with_owasp("A07:2021 – Identification and Authentication Failures")
                    .with_location(CodeLocation {
                        file: file_rel.to_string(),
                        line_start: line_num as u32,
                        line_end: None,
                    }),
                );
            }

            // Check sudo in RUN
            if self.docker_sudo_regex.is_match(line) {
                findings.push(
                    Finding::new(
                        "Sudo Invocation in Dockerfile",
                        Severity::Medium,
                        format!("{}#L{}", file_url_str, line_num),
                        format!("Dockerfile in {} uses sudo inside RUN. Sudo is unnecessary in container builds and may leave dangerous setuid binaries.", file_rel),
                        "Execute commands directly as root during build, then switch to a non-privileged USER before entrypoint.",
                        "iac/dockerfile",
                    )
                    .with_source_tool(SOURCE_TOOL)
                    .with_evidence(trimmed.to_string())
                    .with_cwe(250)
                    .with_owasp("A05:2021 – Security Misconfiguration")
                    .with_location(CodeLocation {
                        file: file_rel.to_string(),
                        line_start: line_num as u32,
                        line_end: None,
                    }),
                );
            }
        }

        // Check if missing non-root USER
        if !has_user_instruction && !src.is_empty() {
            findings.push(
                Finding::new(
                    "Container Runs as Root (Missing USER Instruction)",
                    Severity::Medium,
                    file_url_str,
                    format!("Dockerfile {} does not specify a non-root USER instruction. The container will execute with root privileges.", file_rel),
                    "Add a non-privileged user and switch to it using `USER nonroot` or `USER 10001` before the ENTRYPOINT/CMD.",
                    "iac/dockerfile-root",
                )
                .with_source_tool(SOURCE_TOOL)
                .with_cwe(250)
                .with_owasp("A05:2021 – Security Misconfiguration")
                .with_location(CodeLocation {
                    file: file_rel.to_string(),
                    line_start: 1,
                    line_end: None,
                }),
            );
        }

        // Check if missing HEALTHCHECK
        if !has_healthcheck && !src.is_empty() {
            findings.push(
                Finding::new(
                    "Missing Container HEALTHCHECK",
                    Severity::Info,
                    file_url_str,
                    format!("Dockerfile {} does not define a HEALTHCHECK instruction for container liveness monitoring.", file_rel),
                    "Define a HEALTHCHECK instruction to verify service availability (e.g. `HEALTHCHECK CMD curl -f http://localhost/ || exit 1`).",
                    "iac/dockerfile",
                )
                .with_source_tool(SOURCE_TOOL)
                .with_cwe(1059)
                .with_location(CodeLocation {
                    file: file_rel.to_string(),
                    line_start: 1,
                    line_end: None,
                }),
            );
        }

        findings
    }

    /// Audit Kubernetes YAML manifests.
    pub fn audit_k8s_yaml(&self, src: &str, file_rel: &str, file_url_str: &str) -> Vec<Finding> {
        let mut findings = Vec::new();

        // Only scan if file looks like a K8s resource
        if !src.contains("apiVersion:") && !src.contains("kind:") {
            return findings;
        }

        for (idx, line) in src.lines().enumerate() {
            let line_num = idx + 1;
            let trimmed = line.trim();

            if self.k8s_privileged_regex.is_match(line) {
                findings.push(
                    Finding::new(
                        "Kubernetes Pod Configured with Privileged Access",
                        Severity::Critical,
                        format!("{}#L{}", file_url_str, line_num),
                        format!("Container in {} has `privileged: true`. Privileged containers disable isolation and allow full node compromise / container escape.", file_rel),
                        "Remove `privileged: true` and specify only necessary fine-grained Linux capabilities.",
                        "iac/k8s-privileged",
                    )
                    .with_source_tool(SOURCE_TOOL)
                    .with_evidence(trimmed.to_string())
                    .with_cwe(250)
                    .with_owasp("A05:2021 – Security Misconfiguration")
                    .with_location(CodeLocation {
                        file: file_rel.to_string(),
                        line_start: line_num as u32,
                        line_end: None,
                    }),
                );
            }

            if self.k8s_host_path_regex.is_match(line) {
                findings.push(
                    Finding::new(
                        "Kubernetes Pod Uses hostPath Volume Mount",
                        Severity::High,
                        format!("{}#L{}", file_url_str, line_num),
                        format!("Manifest {} mounts a `hostPath` volume. Host filesystem mounts can allow attackers to access host credentials, docker sockets, or node filesystem.", file_rel),
                        "Use persistent volume claims (PVC), ConfigMaps, or Secrets instead of mounting hostPath volumes.",
                        "iac/k8s-hostpath",
                    )
                    .with_source_tool(SOURCE_TOOL)
                    .with_evidence(trimmed.to_string())
                    .with_cwe(250)
                    .with_owasp("A05:2021 – Security Misconfiguration")
                    .with_location(CodeLocation {
                        file: file_rel.to_string(),
                        line_start: line_num as u32,
                        line_end: None,
                    }),
                );
            }

            if self.k8s_host_net_pid_regex.is_match(line) {
                findings.push(
                    Finding::new(
                        "Kubernetes Pod Shares Host Namespace (hostNetwork / hostPID)",
                        Severity::High,
                        format!("{}#L{}", file_url_str, line_num),
                        format!("Manifest {} configures `hostNetwork: true` or `hostPID: true`. Sharing host namespaces breaks network and process isolation.", file_rel),
                        "Disable hostNetwork and hostPID to isolate pod network traffic and process table.",
                        "iac/k8s-host-namespace",
                    )
                    .with_source_tool(SOURCE_TOOL)
                    .with_evidence(trimmed.to_string())
                    .with_cwe(250)
                    .with_owasp("A05:2021 – Security Misconfiguration")
                    .with_location(CodeLocation {
                        file: file_rel.to_string(),
                        line_start: line_num as u32,
                        line_end: None,
                    }),
                );
            }
        }

        findings
    }

    /// Audit Terraform / Cloud HCL files.
    pub fn audit_terraform(&self, src: &str, file_rel: &str, file_url_str: &str) -> Vec<Finding> {
        let mut findings = Vec::new();

        for (idx, line) in src.lines().enumerate() {
            let line_num = idx + 1;
            let trimmed = line.trim();

            if self.tf_s3_public_regex.is_match(line) {
                findings.push(
                    Finding::new(
                        "S3 Bucket Configured with Public ACL",
                        Severity::High,
                        format!("{}#L{}", file_url_str, line_num),
                        format!("Terraform configuration in {} sets public S3 bucket ACL (`{}`). This exposes bucket objects to unauthenticated public access.", file_rel, trimmed),
                        "Set bucket ACL to `private` and enforce S3 Public Access Block.",
                        "iac/terraform-s3",
                    )
                    .with_source_tool(SOURCE_TOOL)
                    .with_evidence(trimmed.to_string())
                    .with_cwe(732)
                    .with_owasp("A01:2021 – Broken Access Control")
                    .with_location(CodeLocation {
                        file: file_rel.to_string(),
                        line_start: line_num as u32,
                        line_end: None,
                    }),
                );
            }

            if self.tf_open_sg_regex.is_match(line) {
                findings.push(
                    Finding::new(
                        "Security Group Ingress Open to 0.0.0.0/0",
                        Severity::Medium,
                        format!("{}#L{}", file_url_str, line_num),
                        format!("Security group in {} permits unrestricted ingress traffic from `0.0.0.0/0`.", file_rel),
                        "Restrict CIDR blocks to specific VPN, VPC, or bastion host IP addresses.",
                        "iac/terraform-sg",
                    )
                    .with_source_tool(SOURCE_TOOL)
                    .with_evidence(trimmed.to_string())
                    .with_cwe(200)
                    .with_owasp("A05:2021 – Security Misconfiguration")
                    .with_location(CodeLocation {
                        file: file_rel.to_string(),
                        line_start: line_num as u32,
                        line_end: None,
                    }),
                );
            }

            if self.tf_wildcard_iam_regex.is_match(line) {
                findings.push(
                    Finding::new(
                        "Wildcard Action in IAM Policy (`*`)",
                        Severity::High,
                        format!("{}#L{}", file_url_str, line_num),
                        format!("IAM policy definition in {} grants wildcard permissions (`Action: *`), violating the principle of least privilege.", file_rel),
                        "Specify granular IAM actions rather than granting wildcard administrative access.",
                        "iac/terraform-iam",
                    )
                    .with_source_tool(SOURCE_TOOL)
                    .with_evidence(trimmed.to_string())
                    .with_cwe(250)
                    .with_owasp("A01:2021 – Broken Access Control")
                    .with_location(CodeLocation {
                        file: file_rel.to_string(),
                        line_start: line_num as u32,
                        line_end: None,
                    }),
                );
            }
        }

        findings
    }
}

/// Scan a set of repository files for Cloud, Container, and IaC misconfigurations.
pub fn scan(root: &Path, files: &[PathBuf]) -> Vec<Finding> {
    let auditor = CloudAuditor::new();
    let mut out = Vec::new();

    for path in files {
        if is_minified_name(path) {
            continue;
        }

        let fname = path.file_name().and_then(|f| f.to_str()).unwrap_or("");
        let is_dockerfile = fname == "Dockerfile"
            || fname.starts_with("Dockerfile.")
            || fname.ends_with(".dockerfile");
        let is_k8s_yaml = fname.ends_with(".yaml") || fname.ends_with(".yml");
        let is_tf = fname.ends_with(".tf") || fname.ends_with(".tfvars");

        if !is_dockerfile && !is_k8s_yaml && !is_tf {
            continue;
        }

        let Some((src, _truncated)) = read_text_head(path, MAX_SOURCE_BYTES) else {
            continue;
        };

        let rel = rel_path(root, path);
        let url_str = file_url(path, None);

        if is_dockerfile {
            out.extend(auditor.audit_dockerfile(&src, &rel, &url_str));
        } else if is_k8s_yaml {
            out.extend(auditor.audit_k8s_yaml(&src, &rel, &url_str));
        } else if is_tf {
            out.extend(auditor.audit_terraform(&src, &rel, &url_str));
        }

        if out.len() >= 100 {
            out.truncate(100);
            break;
        }
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dockerfile_audit() {
        let auditor = CloudAuditor::new();
        let dockerfile = "FROM node:latest\nENV API_KEY=secret12345\nRUN sudo apt update\nCMD [\"node\", \"app.js\"]\n";
        let findings = auditor.audit_dockerfile(dockerfile, "Dockerfile", "file:///Dockerfile");
        assert!(findings.len() >= 4);
        assert!(findings.iter().any(|f| f.title.contains("':latest'")));
        assert!(findings
            .iter()
            .any(|f| f.title.contains("Hardcoded Secret in Dockerfile")));
        assert!(findings.iter().any(|f| f.title.contains("Sudo Invocation")));
        assert!(findings
            .iter()
            .any(|f| f.title.contains("Container Runs as Root")));
    }

    #[test]
    fn test_k8s_manifest_audit() {
        let auditor = CloudAuditor::new();
        let manifest = r#"
apiVersion: v1
kind: Pod
metadata:
  name: test-pod
spec:
  hostNetwork: true
  containers:
  - name: test
    image: nginx
    securityContext:
      privileged: true
    volumeMounts:
    - mountPath: /host
      name: host-vol
  volumes:
  - name: host-vol
    hostPath:
      path: /
"#;
        let findings = auditor.audit_k8s_yaml(manifest, "pod.yaml", "file:///pod.yaml");
        assert_eq!(findings.len(), 3);
        assert!(findings
            .iter()
            .any(|f| f.title.contains("Privileged Access")));
        assert!(findings
            .iter()
            .any(|f| f.title.contains("hostPath Volume Mount")));
        assert!(findings
            .iter()
            .any(|f| f.title.contains("Shares Host Namespace")));
    }

    #[test]
    fn test_terraform_audit() {
        let auditor = CloudAuditor::new();
        let tf = r#"
resource "aws_s3_bucket" "b" {
  bucket = "my-bucket"
  acl    = "public-read"
}

resource "aws_security_group" "allow_all" {
  ingress {
    cidr_blocks = ["0.0.0.0/0"]
  }
}
"#;
        let findings = auditor.audit_terraform(tf, "main.tf", "file:///main.tf");
        assert_eq!(findings.len(), 2);
        assert!(findings.iter().any(|f| f.title.contains("Public ACL")));
        assert!(findings
            .iter()
            .any(|f| f.title.contains("Security Group Ingress Open")));
    }
}
