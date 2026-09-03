use std::time::Duration;

use anyhow::Result;
use chrono::Utc;
use serde::{Deserialize, Serialize};

use crate::types::{DiscoveredUrl, Finding, ModuleSummary, Severity};

/// Cross-tool correlation group (Phase 2).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Correlation {
    pub id: String,
    pub finding_ids: Vec<String>,
    pub reason: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub elevated_severity: Option<Severity>,
}

#[derive(Serialize, Deserialize)]
pub struct Report {
    pub meta: ReportMeta,
    pub summary: ReportSummary,
    pub modules: Vec<ModuleSummary>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub correlations: Vec<Correlation>,
    /// Full-repo static analysis roll-up (Phase 2.5). Omitted on DAST-only reports.
    #[serde(rename = "static", default, skip_serializing_if = "Option::is_none")]
    pub static_analysis: Option<StaticAnalysis>,
    pub urls: Vec<DiscoveredUrl>,
    pub findings: Vec<Finding>,
}

/// Repo inventory + weighted risk from native (and sibling) static tools.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct StaticAnalysis {
    #[serde(default)]
    pub inventory: Inventory,
    pub risk_score: u8,
    pub risk_breakdown: RiskBreakdown,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub detection_checks: Vec<DetectionCheck>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub attack_plan: Vec<AttackPlanEntry>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct Inventory {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub languages: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub frameworks: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub entrypoints: Vec<String>,
}

/// Weighted contributions (0–category cap) that sum into `risk_score`.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct RiskBreakdown {
    pub secrets: u32,
    pub sinks: u32,
    pub config: u32,
    pub sca: u32,
    pub iac: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DetectionCheck {
    pub id: String,
    pub triggered: bool,
    pub severity: Severity,
    pub count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AttackPlanEntry {
    pub url: String,
    pub method: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub params: Vec<String>,
    pub reason: String,
}

#[derive(Serialize, Deserialize)]
pub struct ReportMeta {
    pub scanner: String,
    pub version: String,
    pub target: String,
    pub scan_date: String,
    pub duration_secs: f64,
}

#[derive(Serialize, Deserialize)]
pub struct ReportSummary {
    pub total_urls: usize,
    pub total_findings: usize,
    pub critical: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
    pub info: usize,
    pub risk_score: u8,
}

impl Report {
    pub fn new(
        target: &str,
        modules: Vec<ModuleSummary>,
        urls: Vec<DiscoveredUrl>,
        mut findings: Vec<Finding>,
        elapsed: Duration,
    ) -> Self {
        // Sort findings by severity descending
        findings.sort_by(|a, b| b.severity.cmp(&a.severity));

        let critical = findings
            .iter()
            .filter(|f| f.severity == Severity::Critical)
            .count();
        let high = findings
            .iter()
            .filter(|f| f.severity == Severity::High)
            .count();
        let medium = findings
            .iter()
            .filter(|f| f.severity == Severity::Medium)
            .count();
        let low = findings
            .iter()
            .filter(|f| f.severity == Severity::Low)
            .count();
        let info = findings
            .iter()
            .filter(|f| f.severity == Severity::Info)
            .count();

        // Simple risk score: 0–100
        let risk_score =
            ((critical * 20 + high * 10 + medium * 5 + low * 2 + info) as f64).min(100.0) as u8;

        Report {
            meta: ReportMeta {
                scanner: "RustZAP".to_string(),
                version: env!("CARGO_PKG_VERSION").to_string(),
                target: target.to_string(),
                scan_date: Utc::now().to_rfc3339(),
                duration_secs: elapsed.as_secs_f64(),
            },
            summary: ReportSummary {
                total_urls: urls.len(),
                total_findings: findings.len(),
                critical,
                high,
                medium,
                low,
                info,
                risk_score,
            },
            modules,
            correlations: Vec::new(),
            static_analysis: None,
            urls,
            findings,
        }
    }

    pub fn with_correlations(mut self, correlations: Vec<Correlation>) -> Self {
        self.correlations = correlations;
        self
    }

    pub fn with_static(mut self, static_analysis: StaticAnalysis) -> Self {
        self.static_analysis = Some(static_analysis);
        self
    }

    pub async fn save_json(&self, path: &str) -> Result<()> {
        let json = serde_json::to_string_pretty(self)?;
        tokio::fs::write(path, json).await?;
        Ok(())
    }

    pub async fn save_csv(&self, path: &str) -> Result<()> {
        let mut csv =
            String::from("ID,Title,Severity,Confidence,Validated,URL,Parameter,CWE,Plugin\n");
        for f in &self.findings {
            let row = format!(
                "\"{}\",\"{}\",\"{}\",\"{}\",\"{}\",\"{}\",\"{}\",\"{}\",\"{}\"\n",
                f.id,
                f.title.replace('"', "\"\""),
                f.severity,
                f.confidence,
                f.poc_validated,
                f.url.replace('"', "\"\""),
                f.parameter.as_deref().unwrap_or(""),
                f.cwe.unwrap_or(0),
                f.plugin
            );
            csv.push_str(&row);
        }
        tokio::fs::write(path, csv).await?;
        Ok(())
    }

    pub async fn save_html(&self, path: &str) -> Result<()> {
        let mut html = String::from("<html><head><title>RustZAP Report</title><style>body { font-family: sans-serif; } table { border-collapse: collapse; width: 100%; } th, td { border: 1px solid #ddd; padding: 8px; }</style></head><body>");
        html.push_str(&format!(
            "<h1>RustZAP Scan Report: {}</h1>",
            self.meta.target
        ));
        html.push_str(&format!(
            "<p>Total Findings: {} | Risk Score: {}</p>",
            self.summary.total_findings, self.summary.risk_score
        ));

        html.push_str("<table><tr><th>Severity</th><th>Confidence</th><th>Title</th><th>URL</th><th>Parameter</th><th>Description</th></tr>");
        for f in &self.findings {
            let color = match f.severity {
                Severity::Critical => "magenta",
                Severity::High => "red",
                Severity::Medium => "orange",
                Severity::Low => "blue",
                Severity::Info => "gray",
            };
            let confidence = if f.poc_validated {
                format!("{} ✓", f.confidence)
            } else {
                f.confidence.to_string()
            };
            html.push_str(&format!(
                "<tr><td style='color: {}'><b>{}</b></td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
                color,
                f.severity,
                confidence,
                f.title,
                f.url,
                f.parameter.as_deref().unwrap_or("-"),
                f.description
            ));
        }
        html.push_str("</table></body></html>");

        tokio::fs::write(path, html).await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{CodeLocation, Finding, ModuleSummary, Severity};

    #[test]
    fn report_serializes_modules_array() {
        let modules = vec![ModuleSummary {
            name: "sast/semgrep".to_string(),
            findings: 1,
            max_severity: Some(Severity::High),
            quiet: false,
        }];

        let finding = Finding {
            id: "id-1".to_string(),
            title: "t".to_string(),
            severity: Severity::High,
            url: "file:///tmp/x#L1".to_string(),
            parameter: Some("check".to_string()),
            evidence: Some("e".to_string()),
            description: "d".to_string(),
            solution: "s".to_string(),
            cwe: None,
            owasp_category: None,
            nist_control: None,
            disa_stig_id: None,
            plugin: "sast/semgrep".to_string(),
            source_tool: Some("semgrep".to_string()),
            location: Some(CodeLocation {
                file: "/tmp/x".to_string(),
                line_start: 1,
                line_end: None,
            }),
            correlated_with: vec![],
            poc_validated: false,
            poc: None,
            confidence: crate::types::Confidence::Firm,
            found_at: chrono::Utc::now(),
        };

        let report = Report::new(
            "target",
            modules.clone(),
            vec![],
            vec![finding],
            std::time::Duration::from_secs(1),
        );

        let json = serde_json::to_string(&report).expect("json serialize");
        let decoded: Report = serde_json::from_str(&json).expect("json deserialize");
        assert_eq!(decoded.modules.len(), 1);
        assert_eq!(decoded.modules[0].name, "sast/semgrep");
        assert_eq!(decoded.findings.len(), 1);
    }

    #[test]
    fn report_serializes_quiet_module_with_zero_findings() {
        let modules = vec![ModuleSummary {
            name: "sast/semgrep".to_string(),
            findings: 0,
            max_severity: None,
            quiet: true,
        }];

        let report = Report::new(
            "target",
            modules.clone(),
            vec![],
            vec![],
            std::time::Duration::from_secs(1),
        );

        assert!(report.modules[0].quiet);
        assert_eq!(report.modules[0].findings, 0);

        let json = serde_json::to_string(&report).expect("json serialize");
        assert!(json.contains("\"modules\""));
    }

    #[test]
    fn report_serializes_correlations_when_set() {
        let report = Report::new(
            "target",
            vec![],
            vec![],
            vec![],
            std::time::Duration::from_secs(0),
        )
        .with_correlations(vec![Correlation {
            id: "corr-1".to_string(),
            finding_ids: vec!["a".to_string(), "b".to_string()],
            reason: "test".to_string(),
            elevated_severity: Some(Severity::Critical),
        }]);
        let json = serde_json::to_string(&report).expect("json");
        assert!(json.contains("\"correlations\""));
        assert!(json.contains("corr-1"));
    }

    #[test]
    fn report_omits_static_when_unset() {
        let report = Report::new(
            "target",
            vec![],
            vec![],
            vec![],
            std::time::Duration::from_secs(0),
        );
        let json = serde_json::to_string(&report).expect("json");
        assert!(
            !json.contains("\"static\""),
            "DAST-only reports must stay additive: {json}"
        );
    }

    #[test]
    fn report_serializes_static_block() {
        let report = Report::new(
            "target",
            vec![],
            vec![],
            vec![],
            std::time::Duration::from_secs(0),
        )
        .with_static(StaticAnalysis {
            inventory: Inventory {
                languages: vec!["JavaScript".to_string()],
                frameworks: vec!["express".to_string()],
                entrypoints: vec!["server.js".to_string()],
            },
            risk_score: 12,
            risk_breakdown: RiskBreakdown {
                secrets: 12,
                sinks: 0,
                config: 0,
                sca: 0,
                iac: 0,
            },
            detection_checks: vec![DetectionCheck {
                id: "js-secrets".to_string(),
                triggered: true,
                severity: Severity::High,
                count: 1,
            }],
            attack_plan: vec![AttackPlanEntry {
                url: "/login".to_string(),
                method: "POST".to_string(),
                params: vec!["user".to_string(), "pass".to_string()],
                reason: "form+password".to_string(),
            }],
        });
        let json = serde_json::to_string(&report).expect("json");
        assert!(json.contains("\"static\""));
        assert!(json.contains("js-secrets"));
        assert!(json.contains("/login"));
        let decoded: Report = serde_json::from_str(&json).expect("round-trip");
        assert_eq!(decoded.static_analysis.unwrap().risk_score, 12);
    }
}
