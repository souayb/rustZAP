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
    /// Execution coverage (#41); absent in reports written before it existed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub coverage: Option<crate::coverage::Coverage>,
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
    /// Git revision of the analyzed source / deployment, when known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_revision: Option<String>,
    /// What this run could not cover (e.g. active checks disabled).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub coverage_limitations: Vec<String>,
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

/// Risk score 0–100. Low/info contributions are capped so a flood of repeated
/// weak signals cannot saturate the score on its own (max 15 from low+info).
fn risk_score(critical: usize, high: usize, medium: usize, low: usize, info: usize) -> u8 {
    (critical * 20 + high * 10 + medium * 5 + (low * 2).min(10) + info.min(5)).min(100) as u8
}

impl Report {
    pub fn new(
        target: &str,
        modules: Vec<ModuleSummary>,
        urls: Vec<DiscoveredUrl>,
        findings: Vec<Finding>,
        elapsed: Duration,
    ) -> Self {
        let mut findings = crate::finding_dedup::collapse(findings);
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

        let risk_score = risk_score(critical, high, medium, low, info);

        Report {
            meta: ReportMeta {
                scanner: "RustZAP".to_string(),
                version: env!("CARGO_PKG_VERSION").to_string(),
                target: target.to_string(),
                scan_date: Utc::now().to_rfc3339(),
                duration_secs: elapsed.as_secs_f64(),
                source_revision: None,
                coverage_limitations: Vec::new(),
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
            coverage: None,
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

    pub fn with_coverage(mut self, coverage: crate::coverage::Coverage) -> Self {
        self.coverage = Some(coverage);
        self
    }

    /// Findings as exported: stable fingerprint + validation status, redacted.
    pub fn export_findings(&self) -> Vec<Finding> {
        self.findings
            .iter()
            .map(crate::evidence::export_finding)
            .collect()
    }

    /// The JSON export: every string in the report goes through the shared redaction.
    pub fn to_export_json(&self) -> Result<String> {
        let mut v = serde_json::to_value(self)?;
        v["findings"] = serde_json::to_value(self.export_findings())?;
        Ok(serde_json::to_string_pretty(&crate::evidence::redact(&v))?)
    }

    pub async fn save_json(&self, path: &str) -> Result<()> {
        tokio::fs::write(path, self.to_export_json()?).await?;
        Ok(())
    }

    pub async fn save_csv(&self, path: &str) -> Result<()> {
        tokio::fs::write(path, self.to_csv()).await?;
        Ok(())
    }

    pub fn to_csv(&self) -> String {
        let mut csv = String::from(
            "ID,Title,Severity,Confidence,Validated,URL,Parameter,CWE,Plugin,Instances,Fingerprint,ValidationStatus\n",
        );
        for f in &self.export_findings() {
            let row = format!(
                "{},{},\"{}\",\"{}\",\"{}\",{},{},\"{}\",{},{},{},{}\n",
                csv_cell(&f.id),
                csv_cell(&f.title),
                f.severity,
                f.confidence,
                f.poc_validated,
                csv_cell(&f.url),
                csv_cell(f.parameter.as_deref().unwrap_or("")),
                f.cwe.unwrap_or(0),
                csv_cell(&f.plugin),
                csv_cell(&f.instances.join("; ")),
                csv_cell(f.fingerprint.as_deref().unwrap_or("")),
                csv_cell(f.validation_status.as_deref().unwrap_or("")),
            );
            csv.push_str(&row);
        }
        csv
    }

    pub async fn save_html(&self, path: &str) -> Result<()> {
        tokio::fs::write(path, self.to_html()).await?;
        Ok(())
    }

    pub fn to_html(&self) -> String {
        let redact = crate::evidence::redact_string;
        let mut html = String::from(
            "<!DOCTYPE html><html><head><meta charset=\"utf-8\"><meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; style-src 'unsafe-inline';\"><title>RustZAP Report</title><style>body { font-family: sans-serif; } table { border-collapse: collapse; width: 100%; } th, td { border: 1px solid #ddd; padding: 8px; }</style></head><body>"
        );
        html.push_str(&format!(
            "<h1>RustZAP Scan Report: {}</h1>",
            html_escape(&redact(&self.meta.target))
        ));
        html.push_str(&format!(
            "<p>Total Findings: {} | Risk Score: {} | {} {}{}</p>",
            self.summary.total_findings,
            self.summary.risk_score,
            html_escape(&self.meta.scanner),
            html_escape(&self.meta.version),
            self.meta
                .source_revision
                .as_deref()
                .map(|r| format!(" | Revision: {}", html_escape(r)))
                .unwrap_or_default()
        ));
        if !self.meta.coverage_limitations.is_empty() {
            html.push_str("<p>Coverage limitations:</p><ul>");
            for l in &self.meta.coverage_limitations {
                html.push_str(&format!("<li>{}</li>", html_escape(&redact(l))));
            }
            html.push_str("</ul>");
        }

        html.push_str("<table><tr><th>ID</th><th>Severity</th><th>Confidence</th><th>Validation</th><th>Title</th><th>Method</th><th>URL</th><th>Parameter</th><th>Description</th><th>Evidence</th></tr>");
        for f in &self.export_findings() {
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
            // Evidence column: observed evidence, expected/actual, then the PoC request.
            let evidence = [
                f.evidence.clone(),
                f.expected.as_ref().map(|e| format!("expected: {e}")),
                f.actual.as_ref().map(|a| format!("actual: {a}")),
                f.identity_role.as_ref().map(|r| format!("role: {r}")),
                f.poc.as_ref().map(|p| p.raw_request.clone()),
            ]
            .into_iter()
            .flatten()
            .collect::<Vec<_>>()
            .join("\n");
            let fp = html_escape(f.fingerprint.as_deref().unwrap_or(""));
            html.push_str(&format!(
                "<tr id='{fp}'><td><code>{fp}</code></td><td style='color: {}'><b>{}</b></td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td><pre>{}</pre></td></tr>",
                color,
                html_escape(&f.severity.to_string()),
                html_escape(&confidence),
                html_escape(f.validation_status.as_deref().unwrap_or("")),
                html_escape(&f.title),
                html_escape(f.method.as_deref().unwrap_or("-")),
                html_url_cell(f),
                html_escape(f.parameter.as_deref().unwrap_or("-")),
                html_escape(&f.description),
                html_escape(&evidence)
            ));
        }
        html.push_str("</table>");
        if let Some(c) = &self.coverage {
            html.push_str(&redact(&coverage_html(c)));
        }
        html.push_str("</body></html>");
        html
    }
}

/// HTML coverage section: status line, then only the checks that did not
/// complete cleanly (completed/finding rows would drown the gaps).
fn coverage_html(c: &crate::coverage::Coverage) -> String {
    use crate::coverage::Outcome;
    let mut s = format!("<h2>Coverage</h2><p>{}</p>", html_escape(&c.summary_line()));
    let gaps: Vec<_> = c
        .records
        .iter()
        .filter(|r| !matches!(r.outcome, Outcome::CompletedNoFinding | Outcome::Finding))
        .collect();
    if !gaps.is_empty() {
        s.push_str("<table><tr><th>Outcome</th><th>Method</th><th>Endpoint</th><th>Plugin</th><th>Requests</th><th>Reason</th></tr>");
        for r in gaps {
            s.push_str(&format!(
                "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}/{}</td><td>{}</td></tr>",
                r.outcome,
                html_escape(&r.method),
                html_escape(&r.endpoint),
                html_escape(&r.plugin),
                r.requests_completed,
                r.requests_attempted,
                html_escape(&r.reason)
            ));
        }
        s.push_str("</table>");
    }
    if !c.omitted.is_empty() {
        s.push_str("<h3>Analysis limits reached</h3><ul>");
        for o in &c.omitted {
            s.push_str(&format!(
                "<li>{} (limit {}): {}</li>",
                html_escape(&o.source),
                o.limit,
                html_escape(&o.reason)
            ));
        }
        s.push_str("</ul>");
    }
    s
}

/// URL cell: the primary URL, plus a collapsible list when deduped into instances.
fn html_url_cell(f: &Finding) -> String {
    if f.instances.is_empty() {
        return html_escape(&f.url);
    }
    let items: String = f
        .instances
        .iter()
        .map(|i| format!("<li>{}</li>", html_escape(i)))
        .collect();
    format!(
        "{}<details><summary>{} instances</summary><ul>{}</ul></details>",
        html_escape(&f.url),
        f.instances.len(),
        items
    )
}

/// Escape text for safe embedding in HTML documents.
pub fn html_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#x27;"),
            other => out.push(other),
        }
    }
    out
}

/// Sanitize and format a CSV cell value, preventing formula injection (DDE).
pub fn csv_cell(s: &str) -> String {
    let mut text = s.replace('"', "\"\"");
    // Neutralize formula characters if present at the start
    if text.starts_with('=')
        || text.starts_with('+')
        || text.starts_with('-')
        || text.starts_with('@')
        || text.starts_with('\t')
        || text.starts_with('\r')
    {
        text.insert(0, '\'');
    }
    format!("\"{text}\"")
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
            instances: vec![],
            fingerprint: None,
            validation_status: None,
            method: None,
            identity_role: None,
            expected: None,
            actual: None,
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

    #[test]
    fn risk_score_not_saturated_by_repeated_weak_signals() {
        assert_eq!(risk_score(0, 0, 0, 0, 500), 5);
        assert_eq!(risk_score(0, 0, 0, 200, 200), 15);
        assert_eq!(risk_score(1, 1, 1, 1, 1), 38);
        assert_eq!(risk_score(5, 5, 0, 0, 0), 100);
    }

    #[test]
    fn html_escape_neutralizes_script_and_markup() {
        let raw = "<script>alert('xss')</script>&\"test\"";
        let escaped = html_escape(raw);
        assert_eq!(
            escaped,
            "&lt;script&gt;alert(&#x27;xss&#x27;)&lt;/script&gt;&amp;&quot;test&quot;"
        );
        assert!(!escaped.contains('<'));
        assert!(!escaped.contains('>'));
    }

    #[test]
    fn csv_cell_neutralizes_formula_injection() {
        assert_eq!(csv_cell("=1+1"), "\"'=1+1\"");
        assert_eq!(csv_cell("+cmd|' /C calc'!A0"), "\"'+cmd|' /C calc'!A0\"");
        assert_eq!(csv_cell("-5"), "\"'-5\"");
        assert_eq!(csv_cell("@SUM(A1:A10)"), "\"'@SUM(A1:A10)\"");
        assert_eq!(csv_cell("normal text"), "\"normal text\"");
        assert_eq!(csv_cell("quote \"test\""), "\"quote \"\"test\"\"\"");
    }
}
