//! Semgrep JSON parsing for Phase 1.
//!
//! Semgrep's JSON schema varies slightly across versions. This parser is
//! intentionally defensive: it only extracts the fields we need to populate
//! a RustZAP `Finding`.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::Deserialize;

use crate::types::{CodeLocation, Finding, Severity};

#[derive(Debug, Deserialize)]
struct SemgrepReport {
    #[serde(default)]
    results: Vec<SemgrepResult>,
}

#[derive(Debug, Deserialize)]
struct SemgrepResult {
    #[serde(default)]
    check_id: Option<String>,
    #[serde(default)]
    path: Option<String>,

    #[serde(default)]
    start: Option<SemgrepLoc>,
    #[serde(default)]
    end: Option<SemgrepLoc>,

    #[serde(default)]
    severity: Option<String>,
    #[serde(default)]
    extra: Option<SemgrepExtra>,
}

#[derive(Debug, Deserialize)]
struct SemgrepLoc {
    #[serde(default)]
    line: Option<u32>,
}

#[derive(Debug, Deserialize)]
struct SemgrepExtra {
    #[serde(default)]
    message: Option<String>,
    #[serde(default)]
    severity: Option<String>,

    // Semgrep often includes code lines near the match.
    #[serde(default)]
    lines: Option<Vec<String>>,
}

pub fn parse_semgrep_json_file(json_path: &str, repo_root: &Path) -> Result<Vec<Finding>> {
    let bytes = std::fs::read(json_path).with_context(|| format!("Read {}", json_path))?;
    let s = String::from_utf8(bytes).context("Semgrep JSON must be valid UTF-8")?;
    parse_semgrep_json_str(&s, repo_root)
}

pub fn parse_semgrep_json_str(json: &str, repo_root: &Path) -> Result<Vec<Finding>> {
    let report: SemgrepReport = serde_json::from_str(json)
        .context("Semgrep JSON parse error (expected top-level object with results[])")?;

    let mut out = Vec::new();
    for r in report.results {
        out.push(result_to_finding(&r, repo_root)?);
    }
    Ok(out)
}

fn result_to_finding(r: &SemgrepResult, repo_root: &Path) -> Result<Finding> {
    let check_id = r
        .check_id
        .clone()
        .unwrap_or_else(|| "semgrep/unknown".to_string());

    let msg = r
        .extra
        .as_ref()
        .and_then(|e| e.message.clone())
        .unwrap_or_else(|| check_id.clone());

    // Semgrep can store severity in multiple places.
    let sev_raw = r
        .severity
        .clone()
        .or_else(|| r.extra.as_ref().and_then(|e| e.severity.clone()));

    let severity = map_semgrep_severity(sev_raw.as_deref());

    let file_path = r
        .path
        .as_ref()
        .map(|p| to_full_path(p, repo_root))
        .unwrap_or_else(|| repo_root.join("unknown"));

    // Prefer start line; end line is optional.
    let line_start = r.start.as_ref().and_then(|l| l.line).unwrap_or(0);
    let line_end = r.end.as_ref().and_then(|l| l.line);

    let evidence = r
        .extra
        .as_ref()
        .and_then(|e| e.lines.clone())
        .map(|lines| lines.join("\n"))
        .or_else(|| Some(msg.clone()));

    let url = format!("file://{}#L{}", file_path.display(), line_start);

    let mut f = Finding::new(
        msg.clone(),
        severity,
        url,
        msg.clone(),
        "Review and remediate according to the Semgrep rule guidelines.",
        "sast/semgrep",
    );

    f = f
        .with_parameter(check_id)
        .with_source_tool("semgrep")
        .with_evidence(evidence.unwrap_or(msg));

    if line_start > 0 {
        f = f.with_location(CodeLocation {
            file: file_path.to_string_lossy().to_string(),
            line_start,
            line_end,
        });
    }

    Ok(f)
}

fn to_full_path(path: &str, repo_root: &Path) -> PathBuf {
    let p = PathBuf::from(path);
    if p.is_absolute() {
        p
    } else {
        repo_root.join(p)
    }
}

pub async fn run_semgrep_scan(repo_path: &Path) -> Result<String> {
    let output = tokio::process::Command::new("semgrep")
        .args(["scan", "--quiet", "--json", "--config", "auto", "."])
        .current_dir(repo_path)
        .output()
        .await
        .context("Failed to spawn semgrep")?;

    if !output.status.success() {
        anyhow::bail!(
            "Semgrep exited with {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        );
    }

    Ok(String::from_utf8(output.stdout)?)
}

fn map_semgrep_severity(sev: Option<&str>) -> Severity {
    let Some(s) = sev else {
        return Severity::Info;
    };
    let s = s.trim().to_ascii_lowercase();
    match s.as_str() {
        "critical" => Severity::Critical,
        "high" => Severity::High,
        "error" => Severity::High,
        "warning" => Severity::Medium,
        "medium" => Severity::Medium,
        "info" | "informational" => Severity::Info,
        "low" => Severity::Low,
        _ => Severity::Info,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    fn parse_with_repo_root(json: &str) -> Vec<Finding> {
        parse_semgrep_json_str(json, Path::new("/repo")).expect("parse should succeed")
    }

    #[test]
    fn maps_severity_error_warning_info() {
        let json = r#"
        {
          "results": [
            {
              "check_id": "python.lang.security.unsafe-sql",
              "path": "src/app.py",
              "start": { "line": 10 },
              "end": { "line": 10 },
              "severity": "ERROR",
              "extra": { "message": "Use parameterized queries", "lines": ["q = '{}'", "cursor.execute(q)"] }
            },
            {
              "check_id": "js.security.audit-trust",
              "path": "api/index.js",
              "start": { "line": 3 },
              "severity": "WARNING",
              "extra": { "message": "Untrusted input used in authz check" }
            }
          ]
        }
        "#;

        let findings = parse_with_repo_root(json);
        assert_eq!(findings.len(), 2);

        assert_eq!(findings[0].plugin, "sast/semgrep");
        assert_eq!(findings[0].severity, Severity::High);
        assert_eq!(
            findings[0].parameter.as_deref(),
            Some("python.lang.security.unsafe-sql")
        );
        assert!(findings[0]
            .evidence
            .as_deref()
            .unwrap()
            .contains("cursor.execute"));
        assert!(findings[0].location.is_some());

        assert_eq!(findings[1].severity, Severity::Medium);
        assert!(findings[1].evidence.is_some());
    }

    #[test]
    fn default_severity_when_missing() {
        let json = r#"
        {
          "results": [
            {
              "check_id": "misc.unknown",
              "path": "main.rs",
              "start": { "line": 1 },
              "extra": { "message": "Something happened" }
            }
          ]
        }
        "#;

        let findings = parse_with_repo_root(json);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Info);
    }

    #[test]
    fn parse_golden_fixture_file() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/semgrep_small.json");
        let findings =
            parse_semgrep_json_file(path.to_str().unwrap(), std::path::Path::new("/repo"))
                .expect("parse golden fixture");
        assert_eq!(findings.len(), 2);
        assert!(findings
            .iter()
            .any(|f| f.parameter.as_deref()
                == Some("python.lang.security.audit.formatted-sql-query")));
    }

    #[test]
    fn file_url_and_location_are_populated() {
        let json = r#"
        {
          "results": [
            {
              "check_id": "python.test.loc",
              "path": "src/lib.py",
              "start": { "line": 42 },
              "end": { "line": 45 },
              "extra": { "message": "Test message", "lines": ["x", "y", "z"] }
            }
          ]
        }
        "#;

        let findings = parse_with_repo_root(json);
        let f = &findings[0];
        assert!(f.url.starts_with("file://"));
        assert!(f.url.contains("#L42"));
        let loc = f.location.as_ref().unwrap();
        assert!(loc.file.ends_with("src/lib.py"));
        assert_eq!(loc.line_start, 42);
        assert_eq!(loc.line_end, Some(45));
    }
}
