use std::time::Duration;

use anyhow::Result;
use chrono::Utc;
use serde::{Deserialize, Serialize};

use crate::types::{DiscoveredUrl, Finding, Severity};

#[derive(Serialize, Deserialize)]
pub struct Report {
    pub meta: ReportMeta,
    pub summary: ReportSummary,
    pub urls: Vec<DiscoveredUrl>,
    pub findings: Vec<Finding>,
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
                version: "0.1.0".to_string(),
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
            urls,
            findings,
        }
    }

    pub async fn save_json(&self, path: &str) -> Result<()> {
        let json = serde_json::to_string_pretty(self)?;
        tokio::fs::write(path, json).await?;
        Ok(())
    }

    pub async fn save_csv(&self, path: &str) -> Result<()> {
        let mut csv = String::from("ID,Title,Severity,URL,Parameter,CWE,Plugin\n");
        for f in &self.findings {
            let row = format!(
                "\"{}\",\"{}\",\"{}\",\"{}\",\"{}\",\"{}\",\"{}\"\n",
                f.id,
                f.title.replace('"', "\"\""),
                f.severity,
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

        html.push_str("<table><tr><th>Severity</th><th>Title</th><th>URL</th><th>Parameter</th><th>Description</th></tr>");
        for f in &self.findings {
            let color = match f.severity {
                Severity::Critical => "magenta",
                Severity::High => "red",
                Severity::Medium => "orange",
                Severity::Low => "blue",
                Severity::Info => "gray",
            };
            html.push_str(&format!(
                "<tr><td style='color: {}'><b>{}</b></td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
                color,
                f.severity,
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
