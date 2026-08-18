//! Opt-in Nuclei integration (Phase 3).
//!
//! **Must be explicitly enabled** (`--nuclei` or `--nuclei-jsonl`). Never runs
//! by default. Only scan targets you own or have permission to test.

use std::path::Path;

use anyhow::{Context, Result};
use serde::Deserialize;
use tracing::warn;

use crate::types::{Finding, Severity};

const NUCLEI_MAX_FINDINGS: usize = 200;

#[derive(Debug, Deserialize)]
struct NucleiLine {
    #[serde(default)]
    #[serde(alias = "template-id", alias = "templateID")]
    template_id: Option<String>,
    #[serde(default)]
    info: Option<NucleiInfo>,
    #[serde(default)]
    #[serde(alias = "matched-at", alias = "matchedAt")]
    matched_at: Option<String>,
    #[serde(default)]
    host: Option<String>,
    #[serde(default)]
    #[serde(alias = "matcher-name", alias = "matcherName")]
    matcher_name: Option<String>,
    #[serde(default)]
    #[serde(alias = "extracted-results", alias = "extractedResults")]
    extracted_results: Option<Vec<String>>,
    #[serde(default)]
    #[serde(alias = "curl-command", alias = "curlCommand")]
    curl_command: Option<String>,
}

#[derive(Debug, Deserialize)]
struct NucleiInfo {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    severity: Option<String>,
    #[serde(default)]
    description: Option<String>,
}

/// Parse Nuclei `-jsonl` / `-json` line-delimited output into findings.
pub fn parse_nuclei_jsonl(text: &str) -> Result<Vec<Finding>> {
    let mut out = Vec::new();
    for (lineno, raw) in text.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() {
            continue;
        }
        if out.len() >= NUCLEI_MAX_FINDINGS {
            warn!(
                "Nuclei findings capped at {} (truncated remaining lines)",
                NUCLEI_MAX_FINDINGS
            );
            break;
        }
        match serde_json::from_str::<NucleiLine>(line) {
            Ok(row) => {
                if let Some(f) = row_to_finding(row) {
                    out.push(f);
                }
            }
            Err(e) => {
                warn!("Skipping Nuclei JSONL line {}: {}", lineno + 1, e);
            }
        }
    }
    Ok(out)
}

pub fn parse_nuclei_jsonl_file(path: &str) -> Result<Vec<Finding>> {
    let bytes = std::fs::read(path).with_context(|| format!("Read Nuclei JSONL {}", path))?;
    let s = String::from_utf8(bytes).context("Nuclei JSONL must be UTF-8")?;
    parse_nuclei_jsonl(&s)
}

fn row_to_finding(row: NucleiLine) -> Option<Finding> {
    let template = row
        .template_id
        .clone()
        .unwrap_or_else(|| "unknown".to_string());
    let info = row.info.as_ref();
    let title = info
        .and_then(|i| i.name.clone())
        .unwrap_or_else(|| format!("Nuclei: {}", template));
    let severity = map_severity(info.and_then(|i| i.severity.as_deref()));
    let url = row
        .matched_at
        .or(row.host)
        .unwrap_or_else(|| "nuclei://unknown".to_string());
    let description = info
        .and_then(|i| i.description.clone())
        .unwrap_or_else(|| format!("Nuclei template {} matched.", template));
    let evidence = row
        .matcher_name
        .or_else(|| {
            row.extracted_results
                .as_ref()
                .map(|v| v.join(", "))
                .filter(|s| !s.is_empty())
        })
        .or(row.curl_command)
        .unwrap_or_else(|| template.clone());

    let plugin = format!("active/nuclei/{}", sanitize_plugin_segment(&template));

    Some(
        Finding::new(
            title,
            severity,
            url,
            description,
            "Triage the Nuclei match; confirm scope and remediate the underlying issue.",
            plugin,
        )
        .with_parameter(template)
        .with_source_tool("nuclei")
        .with_evidence(evidence),
    )
}

fn sanitize_plugin_segment(s: &str) -> String {
    s.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.' {
                c
            } else {
                '-'
            }
        })
        .collect()
}

fn map_severity(s: Option<&str>) -> Severity {
    match s.map(|x| x.trim().to_ascii_lowercase()).as_deref() {
        Some("critical") => Severity::Critical,
        Some("high") => Severity::High,
        Some("medium") => Severity::Medium,
        Some("low") => Severity::Low,
        Some("info") | Some("unknown") | None => Severity::Info,
        _ => Severity::Medium,
    }
}

/// Spawn `nuclei -u <target> -jsonl` (opt-in). Returns empty Vec if binary missing
/// when `require_binary` is false; errors when required.
pub async fn run_nuclei(target: &str, require_binary: bool) -> Result<Vec<Finding>> {
    if which_nuclei().is_none() {
        if require_binary {
            anyhow::bail!(
                "nuclei binary not found on PATH. Install ProjectDiscovery Nuclei or pass --nuclei-jsonl <file>."
            );
        }
        warn!("nuclei not on PATH; skipping");
        return Ok(vec![]);
    }

    let output = tokio::process::Command::new("nuclei")
        .args(["-u", target, "-jsonl", "-silent"])
        .output()
        .await
        .context("Failed to spawn nuclei")?;

    // Nuclei may exit non-zero when findings exist depending on version/flags;
    // still parse stdout.
    let stdout = String::from_utf8_lossy(&output.stdout);
    if !output.status.success() && stdout.trim().is_empty() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("nuclei exited {}: {}", output.status, stderr);
    }
    parse_nuclei_jsonl(&stdout)
}

fn which_nuclei() -> Option<()> {
    std::env::var_os("PATH").and_then(|paths| {
        for dir in std::env::split_paths(&paths) {
            let candidate = Path::new(&dir).join("nuclei");
            if candidate.is_file() {
                return Some(());
            }
            #[cfg(windows)]
            {
                let exe = Path::new(&dir).join("nuclei.exe");
                if exe.is_file() {
                    return Some(());
                }
            }
        }
        None
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"{"template-id":"http-missing-security-headers","info":{"name":"HTTP Missing Security Headers","severity":"info","description":"Missing headers detected"},"matched-at":"https://app.example.com/","matcher-name":"x-frame-options"}
{"templateID":"cve-2021-44228","info":{"name":"Log4j RCE","severity":"critical"},"matchedAt":"https://app.example.com/api","host":"app.example.com"}
"#;

    #[test]
    fn parses_jsonl_lines() {
        let findings = parse_nuclei_jsonl(SAMPLE).expect("parse");
        assert_eq!(findings.len(), 2);
        assert!(findings[0].plugin.starts_with("active/nuclei/"));
        assert_eq!(findings[0].severity, Severity::Info);
        assert_eq!(findings[1].severity, Severity::Critical);
        assert_eq!(findings[1].source_tool.as_deref(), Some("nuclei"));
    }

    #[test]
    fn empty_input_ok() {
        assert!(parse_nuclei_jsonl("").unwrap().is_empty());
    }
}
