//! Gitleaks JSON report → RustZAP findings.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::Deserialize;

use crate::types::{CodeLocation, Finding, Severity};

#[derive(Debug, Deserialize)]
struct GitleaksFinding {
    #[serde(default, alias = "RuleID")]
    rule_id: Option<String>,
    #[serde(default, alias = "Description")]
    description: Option<String>,
    #[serde(default, alias = "File")]
    file: Option<String>,
    #[serde(default, alias = "StartLine")]
    start_line: Option<u32>,
    #[serde(default, alias = "EndLine")]
    end_line: Option<u32>,
    #[serde(default, alias = "Match")]
    match_text: Option<String>,
    #[serde(default, alias = "Secret")]
    secret: Option<String>,
}

pub fn parse_gitleaks_json_file(json_path: &str, repo_root: &Path) -> Result<Vec<Finding>> {
    let bytes = std::fs::read(json_path).with_context(|| format!("Read {}", json_path))?;
    let s = String::from_utf8(bytes).context("Gitleaks JSON must be valid UTF-8")?;
    parse_gitleaks_json_str(&s, repo_root)
}

pub fn parse_gitleaks_json_str(json: &str, repo_root: &Path) -> Result<Vec<Finding>> {
    let items: Vec<GitleaksFinding> =
        serde_json::from_str(json).context("Gitleaks JSON parse error (expected array)")?;

    items
        .iter()
        .map(|item| item_to_finding(item, repo_root))
        .collect()
}

fn item_to_finding(item: &GitleaksFinding, repo_root: &Path) -> Result<Finding> {
    let rule = item
        .rule_id
        .clone()
        .unwrap_or_else(|| "gitleaks/unknown".to_string());
    let title = item
        .description
        .clone()
        .unwrap_or_else(|| format!("Secret detected ({})", rule));

    let rel = item.file.clone().unwrap_or_else(|| "unknown".to_string());
    let full = if Path::new(&rel).is_absolute() {
        PathBuf::from(&rel)
    } else {
        repo_root.join(&rel)
    };

    let line_start = item.start_line.unwrap_or(0);
    let line_end = item.end_line;
    let url = if line_start > 0 {
        format!("file://{}#L{}", full.display(), line_start)
    } else {
        format!("file://{}", full.display())
    };

    let redacted = item
        .secret
        .as_ref()
        .map(|s| {
            if s.len() > 8 {
                format!("{}…[REDACTED]", &s[..4])
            } else {
                "[REDACTED]".to_string()
            }
        })
        .or_else(|| item.match_text.clone());

    let mut f = Finding::new(
        title.clone(),
        Severity::High,
        url,
        "A secret was found in the repository history or working tree.",
        "Rotate the credential, purge it from history, and use a secret manager.",
        "secrets/gitleaks",
    )
    .with_parameter(rule)
    .with_source_tool("gitleaks")
    .with_evidence(redacted.unwrap_or(title))
    .with_cwe(798)
    .with_owasp("A02:2021 – Cryptographic Failures");

    if line_start > 0 {
        f = f.with_location(CodeLocation {
            file: full.to_string_lossy().to_string(),
            line_start,
            line_end,
        });
    }

    Ok(f)
}

pub async fn run_gitleaks(repo_path: &Path) -> Result<String> {
    let report_path = repo_path.join(".rustzap-gitleaks-report.json");
    let _ = tokio::fs::remove_file(&report_path).await;

    let output = tokio::process::Command::new("gitleaks")
        .args([
            "detect",
            "--source",
            repo_path
                .to_str()
                .context("repo path must be valid UTF-8")?,
            "--no-banner",
            "--report-format",
            "json",
            "--report-path",
            report_path
                .to_str()
                .context("report path must be valid UTF-8")?,
        ])
        .output()
        .await
        .map_err(|e| super::map_spawn_io(e, "gitleaks"))?;

    // Exit code 1 = leaks found (still wrote report); other failures are errors.
    if !output.status.success() && output.status.code() != Some(1) {
        anyhow::bail!(
            "Gitleaks exited with {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        );
    }

    let json = tokio::fs::read_to_string(&report_path)
        .await
        .with_context(|| format!("Read Gitleaks report at {}", report_path.display()))?;
    let _ = tokio::fs::remove_file(&report_path).await;
    Ok(json)
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
    fn parse_gitleaks_fixture() {
        let findings = parse_gitleaks_json_str(&fixture("gitleaks_small.json"), Path::new("/repo"))
            .expect("parse");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].plugin, "secrets/gitleaks");
        assert_eq!(findings[0].severity, Severity::High);
        assert!(findings[0].location.is_some());
        assert!(findings[0].evidence.as_ref().unwrap().contains("REDACTED"));
    }
}
