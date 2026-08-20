//! Trivy filesystem scan JSON → RustZAP findings.

use std::path::Path;

use anyhow::{Context, Result};
use serde::Deserialize;

use crate::types::{Finding, Severity};

#[derive(Debug, Deserialize)]
struct TrivyReport {
    #[serde(default, alias = "Results")]
    results: Vec<TrivyResult>,
}

#[derive(Debug, Deserialize)]
struct TrivyResult {
    #[serde(default, alias = "Target")]
    target: Option<String>,
    #[serde(default, alias = "Vulnerabilities")]
    vulnerabilities: Vec<TrivyVuln>,
}

#[derive(Debug, Deserialize)]
struct TrivyVuln {
    #[serde(default, alias = "VulnerabilityID")]
    vulnerability_id: Option<String>,
    #[serde(default, alias = "PkgName")]
    pkg_name: Option<String>,
    #[serde(default, alias = "InstalledVersion")]
    installed_version: Option<String>,
    #[serde(default, alias = "Severity")]
    severity: Option<String>,
    #[serde(default, alias = "Title")]
    title: Option<String>,
    #[serde(default, alias = "Description")]
    description: Option<String>,
}

pub fn parse_trivy_json_file(json_path: &str) -> Result<Vec<Finding>> {
    let bytes = std::fs::read(json_path).with_context(|| format!("Read {}", json_path))?;
    let s = String::from_utf8(bytes).context("Trivy JSON must be valid UTF-8")?;
    parse_trivy_json_str(&s)
}

pub fn parse_trivy_json_str(json: &str) -> Result<Vec<Finding>> {
    let report: TrivyReport =
        serde_json::from_str(json).context("Trivy JSON parse error (expected Results[])")?;

    let mut out = Vec::new();
    for result in report.results {
        let target = result.target.unwrap_or_else(|| "filesystem".to_string());
        for vuln in result.vulnerabilities {
            out.push(vuln_to_finding(&target, &vuln)?);
        }
    }
    Ok(out)
}

fn vuln_to_finding(target: &str, vuln: &TrivyVuln) -> Result<Finding> {
    let cve = vuln
        .vulnerability_id
        .clone()
        .unwrap_or_else(|| "UNKNOWN-CVE".to_string());
    let title = vuln
        .title
        .clone()
        .unwrap_or_else(|| format!("{} in {}", cve, vuln.pkg_name.as_deref().unwrap_or("pkg")));
    let description = vuln.description.clone().unwrap_or_else(|| title.clone());
    let severity = map_trivy_severity(vuln.severity.as_deref());

    let url = format!("file://{}", target);
    let evidence = format!(
        "{} {}@{}",
        cve,
        vuln.pkg_name.as_deref().unwrap_or("unknown"),
        vuln.installed_version.as_deref().unwrap_or("?")
    );

    Ok(Finding::new(
        title,
        severity,
        url,
        description,
        "Upgrade the affected package or apply vendor patches.",
        "sca/trivy",
    )
    .with_parameter(cve)
    .with_source_tool("trivy")
    .with_evidence(evidence)
    .with_cwe(1395)
    .with_owasp("A06:2021 – Vulnerable and Outdated Components"))
}

fn map_trivy_severity(sev: Option<&str>) -> Severity {
    match sev.map(|s| s.trim().to_ascii_uppercase()).as_deref() {
        Some("CRITICAL") => Severity::Critical,
        Some("HIGH") => Severity::High,
        Some("MEDIUM") => Severity::Medium,
        Some("LOW") => Severity::Low,
        Some("UNKNOWN") | None => Severity::Info,
        _ => Severity::Medium,
    }
}

pub async fn run_trivy_fs(repo_path: &Path) -> Result<String> {
    let output = tokio::process::Command::new("trivy")
        .args(["fs", "--format", "json", "--quiet", "."])
        .current_dir(repo_path)
        .output()
        .await
        .map_err(|e| super::map_spawn_io(e, "trivy"))?;

    if !output.status.success() {
        anyhow::bail!(
            "Trivy exited with {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        );
    }

    Ok(String::from_utf8(output.stdout)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture(name: &str) -> String {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures")
            .join(name);
        std::fs::read_to_string(path).expect("read fixture")
    }

    #[test]
    fn parse_trivy_fixture() {
        let findings = parse_trivy_json_str(&fixture("trivy_small.json")).expect("parse");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].plugin, "sca/trivy");
        assert_eq!(findings[0].severity, Severity::High);
        assert_eq!(findings[0].parameter.as_deref(), Some("CVE-2024-1234"));
        assert_eq!(findings[0].source_tool.as_deref(), Some("trivy"));
    }
}
