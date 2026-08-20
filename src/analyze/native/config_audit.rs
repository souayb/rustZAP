//! Lightweight infrastructure/config misconfiguration checks (no subprocess).
//!
//! Complements Checkov/Trivy: covers common Dockerfile, docker-compose,
//! Kubernetes, Terraform, and shell-script foot-guns so a baseline of IaC
//! coverage exists even when those external tools are not installed.

use std::path::{Path, PathBuf};

use regex::Regex;

use crate::analyze::inventory::{
    extension_lower, file_url, line_number, read_text_head, rel_path, MAX_SOURCE_BYTES,
};
use crate::analyze::native::SOURCE_TOOL;
use crate::types::{CodeLocation, Finding, Severity};

const MAX_CONFIG_FINDINGS: usize = 100;

#[derive(Clone, Copy, PartialEq)]
enum ConfigKind {
    Dockerfile,
    Compose,
    Kubernetes,
    Terraform,
    Shell,
}

fn classify(path: &Path) -> Option<ConfigKind> {
    let name = path.file_name()?.to_string_lossy().to_ascii_lowercase();
    let ext = extension_lower(path);
    if name == "dockerfile" || name.starts_with("dockerfile.") || name.ends_with(".dockerfile") {
        return Some(ConfigKind::Dockerfile);
    }
    if name.starts_with("docker-compose") || name == "compose.yml" || name == "compose.yaml" {
        return Some(ConfigKind::Compose);
    }
    if matches!(ext.as_deref(), Some("tf") | Some("tfvars")) {
        return Some(ConfigKind::Terraform);
    }
    if matches!(ext.as_deref(), Some("sh") | Some("bash")) {
        return Some(ConfigKind::Shell);
    }
    // Kubernetes manifests are just YAML; classify by content later.
    if matches!(ext.as_deref(), Some("yml") | Some("yaml")) {
        return Some(ConfigKind::Kubernetes);
    }
    None
}

struct Rule {
    id: &'static str,
    severity: Severity,
    re: Regex,
    title: &'static str,
    remediation: &'static str,
}

fn rules_for(kind: ConfigKind) -> Vec<Rule> {
    fn r(
        id: &'static str,
        severity: Severity,
        pat: &str,
        title: &'static str,
        remediation: &'static str,
    ) -> Rule {
        Rule {
            id,
            severity,
            re: Regex::new(pat).expect("static config_audit regex"),
            title,
            remediation,
        }
    }
    match kind {
        ConfigKind::Dockerfile => vec![
            r(
                "docker-image-latest",
                Severity::Low,
                r"(?im)^\s*FROM\s+\S+:latest\b",
                "Docker base image pinned to :latest",
                "Pin a specific image digest/tag for reproducible, auditable builds.",
            ),
            r(
                "docker-add-remote",
                Severity::Medium,
                r"(?im)^\s*ADD\s+https?://",
                "Dockerfile ADD from remote URL",
                "Use COPY for local files; fetch remote content with verified checksums.",
            ),
            r(
                "docker-curl-pipe-shell",
                Severity::High,
                r"(?i)(?:curl|wget)\b[^\n|]*\|\s*(?:sudo\s+)?(?:sh|bash)\b",
                "Remote script piped into a shell",
                "Download, verify (checksum/signature), then execute — never pipe network content to a shell.",
            ),
            r(
                "docker-secret-in-env",
                Severity::High,
                r#"(?im)^\s*(?:ENV|ARG)\s+\w*(?:password|passwd|secret|api[_-]?key|token)\w*\s*[=\s]\S+"#,
                "Secret baked into image ENV/ARG",
                "Never bake credentials into layers; use build secrets or runtime injection.",
            ),
        ],
        ConfigKind::Compose => vec![
            r(
                "compose-privileged",
                Severity::High,
                r"(?im)^\s*privileged:\s*true\b",
                "Privileged container in docker-compose",
                "Drop privileged mode; grant only the specific capabilities required.",
            ),
            r(
                "compose-docker-sock",
                Severity::High,
                r"/var/run/docker\.sock",
                "Docker socket mounted into a container",
                "Mounting docker.sock grants host root; avoid it or use a rootless proxy.",
            ),
            r(
                "compose-host-network",
                Severity::Medium,
                r#"(?im)^\s*network_mode:\s*['"]?host\b"#,
                "Container uses host network mode",
                "Use a bridge network and publish only required ports.",
            ),
        ],
        ConfigKind::Kubernetes => vec![
            r(
                "k8s-privileged",
                Severity::High,
                r"(?im)^\s*privileged:\s*true\b",
                "Privileged Kubernetes container",
                "Set securityContext.privileged=false and drop unneeded capabilities.",
            ),
            r(
                "k8s-host-network",
                Severity::Medium,
                r"(?im)^\s*hostNetwork:\s*true\b",
                "Pod uses host network",
                "Avoid hostNetwork unless strictly required; it bypasses network policy.",
            ),
            r(
                "k8s-run-as-root",
                Severity::Medium,
                r"(?im)^\s*runAsUser:\s*0\b",
                "Container configured to run as root (UID 0)",
                "Run as a non-root UID and set runAsNonRoot=true.",
            ),
        ],
        ConfigKind::Terraform => vec![
            r(
                "tf-open-ingress",
                Severity::High,
                r#"(?i)cidr_blocks\s*=\s*\[\s*['"]0\.0\.0\.0/0['"]"#,
                "Security group open to 0.0.0.0/0",
                "Restrict ingress CIDRs to known ranges; avoid world-open rules.",
            ),
            r(
                "tf-public-acl",
                Severity::High,
                r#"(?i)acl\s*=\s*['"]public-read(?:-write)?['"]"#,
                "Storage ACL set to public-read",
                "Keep buckets private; use signed URLs or explicit policies for sharing.",
            ),
            r(
                "tf-hardcoded-password",
                Severity::High,
                r#"(?i)(?:password|secret)\s*=\s*['"][^'"\s]{6,}['"]"#,
                "Hardcoded credential in Terraform",
                "Use variables with sensitive=true sourced from a secret manager.",
            ),
        ],
        ConfigKind::Shell => vec![
            r(
                "shell-curl-pipe-shell",
                Severity::High,
                r"(?i)(?:curl|wget)\b[^\n|]*\|\s*(?:sudo\s+)?(?:sh|bash)\b",
                "Remote script piped into a shell",
                "Download, verify, then execute — do not pipe network content to a shell.",
            ),
            r(
                "shell-chmod-777",
                Severity::Medium,
                r"(?i)chmod\s+(?:-[a-z]+\s+)*777\b",
                "World-writable permissions (chmod 777)",
                "Grant least-privilege permissions; 777 lets any user modify the file.",
            ),
            r(
                "shell-rm-rf-root",
                Severity::High,
                r"rm\s+-rf\s+(?:--no-preserve-root\s+)?/(?:\s|$)",
                "Destructive rm -rf on filesystem root",
                "Guard destructive deletes; never target / .",
            ),
        ],
    }
}

pub fn scan(root: &Path, files: &[PathBuf]) -> Vec<Finding> {
    let mut out = Vec::new();
    for path in files {
        let Some(kind) = classify(path) else {
            continue;
        };
        let Some((src, _truncated)) = read_text_head(path, MAX_SOURCE_BYTES) else {
            continue;
        };
        out.extend(scan_source(root, path, kind, &src));
        if out.len() >= MAX_CONFIG_FINDINGS {
            out.truncate(MAX_CONFIG_FINDINGS);
            break;
        }
    }
    out
}

fn scan_source(root: &Path, path: &Path, kind: ConfigKind, src: &str) -> Vec<Finding> {
    let rel = rel_path(root, path);
    let mut out = Vec::new();
    for rule in rules_for(kind) {
        if let Some(m) = rule.re.find(src) {
            let line = line_number(src, m.start());
            out.push(
                Finding::new(
                    rule.title,
                    rule.severity,
                    file_url(path, Some(line)),
                    format!("{} in {rel}.", rule.title),
                    rule.remediation,
                    "iac/native",
                )
                .with_source_tool(SOURCE_TOOL)
                .with_parameter(rule.id)
                .with_evidence(m.as_str().trim().to_string())
                .with_owasp("A05:2021")
                .with_location(CodeLocation {
                    file: rel.clone(),
                    line_start: line,
                    line_end: None,
                })
                .tentative(),
            );
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scan_str(name: &str, src: &str) -> Vec<Finding> {
        let kind = classify(Path::new(name)).expect("classified");
        scan_source(Path::new("."), Path::new(name), kind, src)
    }

    #[test]
    fn dockerfile_flags_latest_and_curl_pipe() {
        let src = "FROM node:latest\nRUN curl https://x.sh | bash\n";
        let f = scan_str("Dockerfile", src);
        assert!(f
            .iter()
            .any(|f| f.parameter.as_deref() == Some("docker-image-latest")));
        assert!(f
            .iter()
            .any(|f| f.parameter.as_deref() == Some("docker-curl-pipe-shell")));
    }

    #[test]
    fn compose_flags_docker_sock_and_privileged() {
        let src = "services:\n  a:\n    privileged: true\n    volumes:\n      - /var/run/docker.sock:/var/run/docker.sock\n";
        let f = scan_str("docker-compose.yml", src);
        assert!(f
            .iter()
            .any(|f| f.parameter.as_deref() == Some("compose-privileged")));
        assert!(f
            .iter()
            .any(|f| f.parameter.as_deref() == Some("compose-docker-sock")));
    }

    #[test]
    fn terraform_flags_open_ingress() {
        let src = "resource \"aws_security_group\" \"x\" {\n  cidr_blocks = [\"0.0.0.0/0\"]\n}\n";
        let f = scan_str("main.tf", src);
        assert!(f
            .iter()
            .any(|f| f.parameter.as_deref() == Some("tf-open-ingress")));
        assert_eq!(f[0].plugin, "iac/native");
    }

    #[test]
    fn shell_flags_chmod_777() {
        let f = scan_str("setup.sh", "#!/bin/bash\nchmod -R 777 /app\n");
        assert!(f
            .iter()
            .any(|f| f.parameter.as_deref() == Some("shell-chmod-777")));
    }

    #[test]
    fn clean_yaml_has_no_findings() {
        let f = scan_str("deploy.yaml", "apiVersion: v1\nkind: Pod\n");
        assert!(f.is_empty());
    }
}
