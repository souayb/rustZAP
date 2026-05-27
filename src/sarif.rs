//! SARIF 2.1 export for CI / GitHub Code Scanning integration.

#![allow(non_snake_case)] // SARIF JSON field names are camelCase

use anyhow::Result;
use serde::Serialize;

use crate::report::Report;
use crate::types::{Finding, Severity};

#[derive(Serialize)]
struct SarifLog {
    #[serde(rename = "version")]
    version: String,
    #[serde(rename = "$schema")]
    schema: String,
    runs: Vec<SarifRun>,
}

#[derive(Serialize)]
struct SarifRun {
    tool: SarifTool,
    results: Vec<SarifResult>,
}

#[derive(Serialize)]
struct SarifTool {
    driver: SarifDriver,
}

#[derive(Serialize)]
struct SarifDriver {
    name: String,
    version: String,
}

#[derive(Serialize)]
struct SarifResult {
    ruleId: String,
    level: String,
    message: SarifMessage,
    #[serde(skip_serializing_if = "Option::is_none")]
    locations: Option<Vec<SarifLocation>>,
}

#[derive(Serialize)]
struct SarifMessage {
    text: String,
}

#[derive(Serialize)]
struct SarifLocation {
    physicalLocation: SarifPhysicalLocation,
}

#[derive(Serialize)]
struct SarifPhysicalLocation {
    artifactLocation: SarifArtifactLocation,
    #[serde(skip_serializing_if = "Option::is_none")]
    region: Option<SarifRegion>,
}

#[derive(Serialize)]
struct SarifArtifactLocation {
    uri: String,
}

#[derive(Serialize)]
struct SarifRegion {
    startLine: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    endLine: Option<u32>,
}

pub fn write_sarif(report: &Report, path: &str) -> Result<()> {
    let sarif = build_sarif(report);
    let json = serde_json::to_string_pretty(&sarif)?;
    std::fs::write(path, json)?;
    Ok(())
}

fn build_sarif(report: &Report) -> SarifLog {
    SarifLog {
        version: "2.1.0".to_string(),
        schema: "https://json.schemastore.org/sarif-2.1.0.json".to_string(),
        runs: vec![SarifRun {
            tool: SarifTool {
                driver: SarifDriver {
                    name: report.meta.scanner.clone(),
                    version: report.meta.version.clone(),
                },
            },
            results: report.findings.iter().map(finding_to_result).collect(),
        }],
    }
}

fn finding_to_result(f: &Finding) -> SarifResult {
    let (uri, region) = location_for(f);
    SarifResult {
        ruleId: f.plugin.clone(),
        level: severity_to_level(&f.severity).to_string(),
        message: SarifMessage {
            text: format!("{} — {}", f.title, f.description),
        },
        locations: Some(vec![SarifLocation {
            physicalLocation: SarifPhysicalLocation {
                artifactLocation: SarifArtifactLocation { uri },
                region,
            },
        }]),
    }
}

fn location_for(f: &Finding) -> (String, Option<SarifRegion>) {
    if let Some(loc) = &f.location {
        return (
            loc.file.clone(),
            Some(SarifRegion {
                startLine: loc.line_start,
                endLine: loc.line_end,
            }),
        );
    }
    (f.url.clone(), None)
}

fn severity_to_level(sev: &Severity) -> &'static str {
    match sev {
        Severity::Critical | Severity::High => "error",
        Severity::Medium => "warning",
        Severity::Low => "note",
        Severity::Info => "note",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{Finding, ModuleSummary, Severity};

    #[test]
    fn sarif_contains_results_for_findings() {
        let finding = Finding::new(
            "SQLi",
            Severity::High,
            "https://example.com/a",
            "desc",
            "fix",
            "active/sqli",
        );
        let report = Report::new(
            "https://example.com",
            vec![ModuleSummary {
                name: "active/sqli".to_string(),
                findings: 1,
                max_severity: Some(Severity::High),
                quiet: false,
            }],
            vec![],
            vec![finding],
            std::time::Duration::from_secs(1),
        );
        let sarif = build_sarif(&report);
        assert_eq!(sarif.runs.len(), 1);
        assert_eq!(sarif.runs[0].results.len(), 1);
        assert_eq!(sarif.runs[0].results[0].level, "error");
    }
}
