//! Checkov IaC JSON → RustZAP findings.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::Deserialize;

use crate::types::{CodeLocation, Finding, Severity};

const PLUGIN: &str = "iac/checkov";
const MAX_FINDINGS: usize = 500;

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum CheckovJson {
    Multi(Vec<CheckovReport>),
    Single(CheckovReport),
}

#[derive(Debug, Deserialize)]
struct CheckovReport {
    #[serde(default)]
    results: Option<CheckovResults>,
    /// Flattened variant: `{ "failed_checks": [ ... ] }`.
    #[serde(default)]
    failed_checks: Vec<CheckovCheck>,
}

#[derive(Debug, Deserialize)]
struct CheckovResults {
    #[serde(default)]
    failed_checks: Vec<CheckovCheck>,
}

#[derive(Debug, Deserialize)]
struct CheckovCheck {
    #[serde(default)]
    check_id: Option<String>,
    #[serde(default)]
    check_name: Option<String>,
    #[serde(default)]
    file_path: Option<String>,
    #[serde(default)]
    file_line_range: Option<Vec<u32>>,
    #[serde(default)]
    severity: Option<String>,
    #[serde(default)]
    bc_severity: Option<String>,
    #[serde(default)]
    guideline: Option<String>,
    #[serde(default)]
    check_class: Option<String>,
    #[serde(default)]
    resource: Option<String>,
    /// Present on `--output json` records; object (`{ "result": "FAILED" }`) or string.
    #[serde(default)]
    #[allow(dead_code)]
    check_result: Option<serde_json::Value>,
}

pub fn parse_checkov_json_file(json_path: &str, repo_root: &Path) -> Result<Vec<Finding>> {
    let bytes = std::fs::read(json_path).with_context(|| format!("Read {}", json_path))?;
    let s = String::from_utf8(bytes).context("Checkov JSON must be valid UTF-8")?;
    parse_checkov_json_str(&s, repo_root)
}

pub fn parse_checkov_json_str(json: &str, repo_root: &Path) -> Result<Vec<Finding>> {
    let payload = extract_json_payload(json);
    if payload.trim().is_empty() {
        return Ok(Vec::new());
    }

    let parsed: CheckovJson = serde_json::from_str(payload)
        .context("Checkov JSON parse error (expected results.failed_checks)")?;

    let mut checks = Vec::new();
    match parsed {
        CheckovJson::Multi(reports) => {
            for report in reports {
                collect_failed_checks(report, &mut checks);
            }
        }
        CheckovJson::Single(report) => collect_failed_checks(report, &mut checks),
    }

    let mut out = Vec::new();
    for check in checks.iter().take(MAX_FINDINGS) {
        out.push(check_to_finding(check, repo_root)?);
    }
    Ok(out)
}

fn collect_failed_checks(report: CheckovReport, out: &mut Vec<CheckovCheck>) {
    if let Some(results) = report.results {
        out.extend(results.failed_checks);
    }
    out.extend(report.failed_checks);
}

fn check_to_finding(check: &CheckovCheck, repo_root: &Path) -> Result<Finding> {
    let check_id = check
        .check_id
        .clone()
        .unwrap_or_else(|| "checkov/unknown".to_string());
    let title = check
        .check_name
        .clone()
        .unwrap_or_else(|| format!("IaC misconfiguration ({check_id})"));

    let rel = check
        .file_path
        .clone()
        .unwrap_or_else(|| "unknown".to_string());
    let full = to_full_path(&rel, repo_root);

    let (line_start, line_end) = line_range(check);
    let url = if line_start > 0 {
        format!("file://{}#L{line_start}", full.display())
    } else {
        format!("file://{}", full.display())
    };

    let severity = map_checkov_severity(check.severity.as_deref().or(check.bc_severity.as_deref()));

    let mut evidence_parts = Vec::new();
    if let Some(resource) = check.resource.as_deref() {
        evidence_parts.push(format!("resource={resource}"));
    }
    if let Some(class) = check.check_class.as_deref() {
        evidence_parts.push(format!("class={class}"));
    }
    evidence_parts.push(format!("id={check_id}"));
    let evidence = evidence_parts.join(" ");

    let solution = check.guideline.clone().unwrap_or_else(|| {
        "Remediate the IaC misconfiguration according to Checkov / provider guidance.".to_string()
    });

    let mut f = Finding::new(title.clone(), severity, url, title, solution, PLUGIN)
        .with_parameter(check_id)
        .with_source_tool("checkov")
        .with_evidence(evidence)
        .with_cwe(16)
        .with_owasp("A05:2021 – Security Misconfiguration");

    if line_start > 0 {
        f = f.with_location(CodeLocation {
            file: full.to_string_lossy().to_string(),
            line_start,
            line_end,
        });
    }

    Ok(f)
}

fn line_range(check: &CheckovCheck) -> (u32, Option<u32>) {
    let Some(range) = check.file_line_range.as_ref() else {
        return (0, None);
    };
    let start = range.first().copied().unwrap_or(0);
    let end = range.get(1).copied().filter(|&e| e > 0);
    (start, end)
}

fn to_full_path(path: &str, repo_root: &Path) -> PathBuf {
    let p = PathBuf::from(path);
    if p.is_absolute() {
        p
    } else {
        repo_root.join(p)
    }
}

/// Checkov may print a banner before JSON; take from the first `{` or `[`.
fn extract_json_payload(raw: &str) -> &str {
    let trimmed = raw.trim();
    let brace = trimmed.find('{');
    let bracket = trimmed.find('[');
    match (brace, bracket) {
        (Some(a), Some(b)) => &trimmed[a.min(b)..],
        (Some(a), None) => &trimmed[a..],
        (None, Some(b)) => &trimmed[b..],
        (None, None) => trimmed,
    }
}

fn map_checkov_severity(sev: Option<&str>) -> Severity {
    // FAILED checks without a severity grade default to Medium.
    let Some(s) = sev else {
        return Severity::Medium;
    };
    match s.trim().to_ascii_uppercase().as_str() {
        "CRITICAL" => Severity::Critical,
        "HIGH" | "ERROR" => Severity::High,
        "MEDIUM" | "WARNING" | "FAILED" => Severity::Medium,
        "LOW" => Severity::Low,
        "INFO" | "INFORMATIONAL" => Severity::Info,
        _ => Severity::Medium,
    }
}

pub async fn run_checkov(repo_path: &Path) -> Result<String> {
    let output = tokio::process::Command::new("checkov")
        .args(["-d", ".", "-o", "json", "--quiet", "--compact"])
        .current_dir(repo_path)
        .output()
        .await
        .map_err(|e| super::map_spawn_io(e, "checkov"))?;

    // Exit 1 = failed checks found (JSON still written to stdout).
    if !output.status.success() && output.status.code() != Some(1) {
        anyhow::bail!(
            "Checkov exited with {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        );
    }

    Ok(String::from_utf8(output.stdout)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    fn fixture(name: &str) -> String {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures")
            .join(name);
        std::fs::read_to_string(path).expect("read fixture")
    }

    #[test]
    fn parse_checkov_fixture() {
        let findings = parse_checkov_json_str(&fixture("checkov_small.json"), Path::new("/repo"))
            .expect("parse");
        assert_eq!(findings.len(), 2);
        assert!(findings.iter().all(|f| f.plugin == PLUGIN));
        assert!(findings
            .iter()
            .all(|f| f.source_tool.as_deref() == Some("checkov")));
        assert_eq!(findings[0].parameter.as_deref(), Some("CKV_AWS_20"));
        assert_eq!(findings[0].severity, Severity::High);
        assert_eq!(findings[1].parameter.as_deref(), Some("CKV_K8S_21"));
        assert_eq!(findings[1].severity, Severity::Medium);
        assert!(findings[0].location.is_some());
        assert_eq!(findings[0].cwe, Some(16));
        assert!(findings[0]
            .owasp_category
            .as_deref()
            .unwrap()
            .contains("A05"));
        assert!(findings[0]
            .evidence
            .as_deref()
            .unwrap()
            .contains("aws_s3_bucket.logs"));
        assert!(findings[1]
            .location
            .as_ref()
            .unwrap()
            .file
            .ends_with("k8s/deployment.yaml"));
    }

    #[test]
    fn parse_checkov_json_file_reads_fixture() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/checkov_small.json");
        let findings = parse_checkov_json_file(path.to_str().unwrap(), Path::new("/repo"))
            .expect("parse file");
        assert_eq!(findings.len(), 2);
    }

    #[test]
    fn missing_severity_defaults_to_medium() {
        let json = r#"
        {
          "results": {
            "failed_checks": [
              {
                "check_id": "CKV_AWS_1",
                "check_name": "Ensure encryption",
                "file_path": "main.tf",
                "file_line_range": [1, 3],
                "resource": "aws_s3_bucket.x",
                "check_class": "checkov.terraform.checks.resource.aws.Encryption",
                "check_result": { "result": "FAILED" }
              }
            ]
          }
        }
        "#;
        let findings = parse_checkov_json_str(json, Path::new("/repo")).expect("parse");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Medium);
        assert_eq!(findings[0].plugin, PLUGIN);
    }

    #[test]
    fn accepts_array_of_framework_reports() {
        let json = r#"
        [
          {
            "check_type": "terraform",
            "results": {
              "failed_checks": [
                {
                  "check_id": "CKV_AWS_20",
                  "check_name": "Public ACL",
                  "file_path": "s3.tf",
                  "file_line_range": [2, 2],
                  "severity": "HIGH",
                  "resource": "aws_s3_bucket.a"
                }
              ]
            }
          },
          {
            "check_type": "kubernetes",
            "failed_checks": [
              {
                "check_id": "CKV_K8S_21",
                "check_name": "Default namespace",
                "file_path": "pod.yaml",
                "file_line_range": [1, 8],
                "severity": "LOW",
                "resource": "Pod.default"
              }
            ]
          }
        ]
        "#;
        let findings = parse_checkov_json_str(json, Path::new("/repo")).expect("parse");
        assert_eq!(findings.len(), 2);
        assert_eq!(findings[0].severity, Severity::High);
        assert_eq!(findings[1].severity, Severity::Low);
    }

    #[test]
    fn strips_banner_before_json() {
        let json = "Checkov banner\n{\n  \"results\": { \"failed_checks\": [\n    {\n      \"check_id\": \"CKV_X\",\n      \"check_name\": \"x\",\n      \"file_path\": \"a.tf\",\n      \"severity\": \"INFO\"\n    }\n  ] }\n}\n";
        let findings = parse_checkov_json_str(json, Path::new("/repo")).expect("parse");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Info);
        assert!(findings[0].url.starts_with("file://"));
    }

    #[test]
    fn caps_findings_at_500() {
        let checks: Vec<String> = (0..520)
            .map(|i| {
                format!(
                    r#"{{"check_id":"CKV_{i}","check_name":"c{i}","file_path":"f.tf","severity":"LOW"}}"#
                )
            })
            .collect();
        let json = format!(
            r#"{{"results":{{"failed_checks":[{}]}}}}"#,
            checks.join(",")
        );
        let findings = parse_checkov_json_str(&json, Path::new("/repo")).expect("parse");
        assert_eq!(findings.len(), MAX_FINDINGS);
    }

    #[test]
    fn empty_payload_yields_no_findings() {
        let findings = parse_checkov_json_str("   ", Path::new("/repo")).expect("parse");
        assert!(findings.is_empty());
    }
}
