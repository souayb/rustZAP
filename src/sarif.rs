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
    /// Run property bag: execution coverage (#41), revision and limitations (#49).
    #[serde(skip_serializing_if = "Option::is_none")]
    properties: Option<serde_json::Value>,
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
    /// Stable finding fingerprint shared with JSON/HTML/CSV exports.
    partialFingerprints: serde_json::Value,
    properties: serde_json::Value,
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
            results: report
                .export_findings()
                .iter()
                .map(finding_to_result)
                .collect(),
            properties: run_properties(report),
        }],
    }
}

fn run_properties(report: &Report) -> Option<serde_json::Value> {
    let m = &report.meta;
    let mut p = serde_json::Map::new();
    if let Some(c) = &report.coverage {
        p.insert("coverage".into(), serde_json::json!(c));
    }
    if m.source_revision.is_some() || !m.coverage_limitations.is_empty() {
        p.insert(
            "sourceRevision".into(),
            serde_json::json!(m.source_revision),
        );
        p.insert(
            "coverageLimitations".into(),
            serde_json::json!(m.coverage_limitations),
        );
    }
    (!p.is_empty()).then(|| crate::evidence::redact(&serde_json::Value::Object(p)))
}

/// `f` must already be an exported (fingerprinted + redacted) finding.
fn finding_to_result(f: &Finding) -> SarifResult {
    let mut locs = vec![location_for(f)];
    // Deduped findings: primary location first, then every other instance.
    locs.extend(f.instances.iter().skip(1).map(|i| instance_location(i)));
    SarifResult {
        ruleId: f.plugin.clone(),
        level: severity_to_level(&f.severity).to_string(),
        message: SarifMessage {
            text: format!("{} — {}", f.title, f.description),
        },
        locations: Some(
            locs.into_iter()
                .map(|(uri, region)| SarifLocation {
                    physicalLocation: SarifPhysicalLocation {
                        artifactLocation: SarifArtifactLocation { uri },
                        region,
                    },
                })
                .collect(),
        ),
        partialFingerprints: serde_json::json!({
            "rustzapFindingId/v1": f.fingerprint.as_deref().unwrap_or_default(),
        }),
        properties: serde_json::json!({
            "confidence": f.confidence,
            "validated": f.poc_validated,
            "validationStatus": f.validation_status,
            "method": f.method,
            "parameter": f.parameter,
        }),
    }
}

/// Instance strings are `url` or `url [param]`; `file://…#L<n>` carries a line.
fn instance_location(inst: &str) -> (String, Option<SarifRegion>) {
    let url = inst.split(" [").next().unwrap_or(inst);
    if let Some((file, line)) = url.rsplit_once("#L") {
        if let Ok(n) = line.parse::<u32>() {
            let file = file.strip_prefix("file://").unwrap_or(file);
            return (
                file.to_string(),
                Some(SarifRegion {
                    startLine: n,
                    endLine: None,
                }),
            );
        }
    }
    (url.to_string(), None)
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

    #[test]
    fn sarif_emits_one_location_per_instance() {
        let mk =
            |url: &str| Finding::new("Missing CSP", Severity::Medium, url, "d", "s", "passive/x");
        let report = Report::new(
            "https://example.com",
            vec![],
            vec![],
            vec![
                mk("https://example.com/a"),
                mk("https://example.com/b").with_parameter("q"),
                mk("file:///repo/.env#L3"),
            ],
            std::time::Duration::from_secs(1),
        );
        let sarif = build_sarif(&report);
        assert_eq!(sarif.runs[0].results.len(), 1);
        let locs = sarif.runs[0].results[0].locations.as_ref().unwrap();
        assert_eq!(locs.len(), 3);
        assert_eq!(
            locs[1].physicalLocation.artifactLocation.uri,
            "https://example.com/b"
        );
        assert_eq!(locs[2].physicalLocation.artifactLocation.uri, "/repo/.env");
        assert_eq!(
            locs[2].physicalLocation.region.as_ref().unwrap().startLine,
            3
        );
    }
}
