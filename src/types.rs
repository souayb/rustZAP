use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Truncate a string to at most `max_chars` characters safely on UTF-8 character boundaries.
pub fn safe_truncate(s: &str, max_chars: usize) -> &str {
    match s.char_indices().nth(max_chars) {
        Some((idx, _)) => &s[..idx],
        None => s,
    }
}

/// Severity levels for findings
#[derive(Debug, Clone, Hash, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl std::str::FromStr for Severity {
    type Err = &'static str;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_lowercase().as_str() {
            "info" | "informational" => Ok(Severity::Info),
            "low" => Ok(Severity::Low),
            "medium" | "med" => Ok(Severity::Medium),
            "high" => Ok(Severity::High),
            "critical" | "crit" => Ok(Severity::Critical),
            _ => Err("unknown severity: must be info, low, medium, high, or critical"),
        }
    }
}

/// How much trust to place in a finding. This is what stops the scanner from
/// "self-validating": active checks only claim `Confirmed` when a payload's
/// effect was verified against a baseline (see `crate::verify`). Weaker
/// heuristics report `Tentative` so triagers know to hand-verify.
#[derive(
    Debug, Clone, Copy, Hash, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Default,
)]
#[serde(rename_all = "lowercase")]
pub enum Confidence {
    /// Requires manual verification; emitted on a weak/heuristic signal.
    Tentative,
    /// Strong signal but not independently reproduced.
    #[default]
    Firm,
    /// Verified against a baseline differential / unique canary.
    Confirmed,
}

impl std::fmt::Display for Confidence {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Confidence::Tentative => write!(f, "TENTATIVE"),
            Confidence::Firm => write!(f, "FIRM"),
            Confidence::Confirmed => write!(f, "CONFIRMED"),
        }
    }
}

/// Optional code location for static-analysis findings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CodeLocation {
    pub file: String,
    pub line_start: u32,
    pub line_end: Option<u32>,
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Severity::Info => write!(f, "INFO"),
            Severity::Low => write!(f, "LOW"),
            Severity::Medium => write!(f, "MEDIUM"),
            Severity::High => write!(f, "HIGH"),
            Severity::Critical => write!(f, "CRITICAL"),
        }
    }
}

impl Severity {
    pub fn color_str(&self) -> colored::ColoredString {
        use colored::*;
        match self {
            Severity::Info => format!("[{}]", self).bright_blue(),
            Severity::Low => format!("[{}]", self).bright_cyan(),
            Severity::Medium => format!("[{}]", self).bright_yellow(),
            Severity::High => format!("[{}]", self).bright_red(),
            Severity::Critical => format!("[{}]", self).on_red().white(),
        }
    }
}

/// Proof-of-concept evidence for confirmed findings (Strix-style reproducible PoC).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PocProof {
    pub script_type: String, // "curl" | "python"
    pub script_content: String,
    pub canary_sent: String,
    pub canary_received: String,
    pub raw_request: String,
    pub raw_response: String,
    pub execution_time_ms: u64,
}

/// A security finding
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub id: String,
    pub title: String,
    pub severity: Severity,
    pub url: String,
    pub parameter: Option<String>,
    pub evidence: Option<String>,
    pub description: String,
    pub solution: String,
    pub cwe: Option<u32>,
    pub owasp_category: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nist_control: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub disa_stig_id: Option<String>,
    pub plugin: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_tool: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub location: Option<CodeLocation>,
    #[serde(default)]
    pub correlated_with: Vec<String>,
    #[serde(default)]
    pub poc_validated: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub poc: Option<PocProof>,
    /// Trust level for this finding. See `Confidence`.
    #[serde(default)]
    pub confidence: Confidence,
    pub found_at: DateTime<Utc>,
}

impl Finding {
    pub fn new(
        title: impl Into<String>,
        severity: Severity,
        url: impl Into<String>,
        description: impl Into<String>,
        solution: impl Into<String>,
        plugin: impl Into<String>,
    ) -> Self {
        Finding {
            id: uuid_v4(),
            title: title.into(),
            severity,
            url: url.into(),
            parameter: None,
            evidence: None,
            description: description.into(),
            solution: solution.into(),
            cwe: None,
            owasp_category: None,
            nist_control: None,
            disa_stig_id: None,
            plugin: plugin.into(),
            source_tool: None,
            location: None,
            correlated_with: vec![],
            poc_validated: false,
            poc: None,
            confidence: Confidence::Firm,
            found_at: Utc::now(),
        }
    }

    pub fn with_nist(mut self, control: impl Into<String>) -> Self {
        self.nist_control = Some(control.into());
        self
    }

    pub fn with_disa_stig(mut self, stig_id: impl Into<String>) -> Self {
        self.disa_stig_id = Some(stig_id.into());
        self
    }

    pub fn with_source_tool(mut self, tool: impl Into<String>) -> Self {
        self.source_tool = Some(tool.into());
        self
    }

    pub fn with_location(mut self, location: CodeLocation) -> Self {
        self.location = Some(location);
        self
    }

    pub fn with_parameter(mut self, param: impl Into<String>) -> Self {
        self.parameter = Some(param.into());
        self
    }

    pub fn with_evidence(mut self, evidence: impl Into<String>) -> Self {
        self.evidence = Some(evidence.into());
        self
    }

    pub fn with_cwe(mut self, cwe: u32) -> Self {
        self.cwe = Some(cwe);
        self
    }

    pub fn with_owasp(mut self, category: impl Into<String>) -> Self {
        self.owasp_category = Some(category.into());
        self
    }

    pub fn with_confidence(mut self, confidence: Confidence) -> Self {
        self.confidence = confidence;
        self
    }

    pub fn with_poc(mut self, poc: PocProof) -> Self {
        self.poc = Some(poc);
        self.poc_validated = true;
        self.confidence = Confidence::Confirmed;
        self
    }

    /// Mark a finding as verified against a baseline / unique canary. Sets both
    /// the machine flag (`poc_validated`) and `Confidence::Confirmed`.
    pub fn confirmed(mut self) -> Self {
        self.poc_validated = true;
        self.confidence = Confidence::Confirmed;
        self
    }

    /// Mark a finding as a heuristic that needs manual verification.
    pub fn tentative(mut self) -> Self {
        self.poc_validated = false;
        self.confidence = Confidence::Tentative;
        self
    }
}

/// An HTTP request/response pair captured during scanning
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpTransaction {
    pub id: String,
    pub request: HttpRequest,
    pub response: Option<HttpResponse>,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpRequest {
    pub method: String,
    pub url: String,
    pub headers: Vec<(String, String)>,
    pub body: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: String,
    pub elapsed_ms: u64,
}

/// Cached response representation for zero-network passive scanning.
#[derive(Debug, Clone)]
pub struct CachedResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: String,
}

/// In-memory response cache populated during spidering.
#[derive(Debug, Default, Clone)]
pub struct HttpResponseCache {
    responses:
        std::sync::Arc<tokio::sync::RwLock<std::collections::HashMap<String, CachedResponse>>>,
}

impl HttpResponseCache {
    pub fn new() -> Self {
        Self::default()
    }

    pub async fn insert(
        &self,
        url: String,
        status: u16,
        headers: Vec<(String, String)>,
        body: String,
    ) {
        let mut map = self.responses.write().await;
        map.insert(
            url,
            CachedResponse {
                status,
                headers,
                body,
            },
        );
    }

    pub async fn get(&self, url: &str) -> Option<CachedResponse> {
        let map = self.responses.read().await;
        map.get(url).cloned()
    }

    pub async fn len(&self) -> usize {
        let map = self.responses.read().await;
        map.len()
    }

    pub async fn is_empty(&self) -> bool {
        let map = self.responses.read().await;
        map.is_empty()
    }
}

/// Discovered URL with metadata
#[derive(Debug, Clone, Serialize, Deserialize, Hash, PartialEq, Eq)]
pub struct DiscoveredUrl {
    pub url: String,
    pub method: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub headers: Vec<(String, String)>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub body: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content_type: Option<String>,
    #[serde(default)]
    pub parameters: Vec<String>,
    pub source: UrlSource,
}

impl DiscoveredUrl {
    pub fn new(url: impl Into<String>, method: impl Into<String>, source: UrlSource) -> Self {
        let url_str = url.into();
        let params = if let Ok(u) = url::Url::parse(&url_str) {
            u.query_pairs().map(|(k, _)| k.to_string()).collect()
        } else {
            vec![]
        };
        DiscoveredUrl {
            url: url_str,
            method: method.into(),
            headers: Vec::new(),
            body: None,
            content_type: None,
            parameters: params,
            source,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Hash, PartialEq, Eq)]
pub enum UrlSource {
    Seed,
    Link,
    Form,
    Script,
    Redirect,
    Robots,
    Sitemap,
    OpenApi,
    Har,
}

/// Roll-up of one module's contribution to the scan. See SDD §9.1.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModuleSummary {
    /// Plugin id, e.g. `passive/security-txt` or `active/sqli`.
    pub name: String,
    /// Number of findings this module produced.
    pub findings: usize,
    /// Highest severity in this module's findings (None when quiet).
    pub max_severity: Option<Severity>,
    /// True when the module ran but produced zero findings.
    pub quiet: bool,
}

/// Bucket findings by their `plugin` field and union with `known_modules`
/// (so modules that ran quietly still appear in the result). Returns one
/// `ModuleSummary` per distinct module name, sorted: non-quiet first (by
/// max severity descending), then quiet (alphabetical).
pub fn summarize_modules(findings: &[Finding], known_modules: &[&str]) -> Vec<ModuleSummary> {
    use std::collections::BTreeMap;
    let mut buckets: BTreeMap<String, (usize, Option<Severity>)> = BTreeMap::new();
    for k in known_modules {
        buckets.entry((*k).to_string()).or_insert((0, None));
    }
    for f in findings {
        let entry = buckets.entry(f.plugin.clone()).or_insert((0, None));
        entry.0 += 1;
        entry.1 = Some(match entry.1.as_ref() {
            Some(prev) if prev > &f.severity => prev.clone(),
            _ => f.severity.clone(),
        });
    }
    let mut out: Vec<ModuleSummary> = buckets
        .into_iter()
        .map(|(name, (count, sev))| ModuleSummary {
            quiet: count == 0,
            findings: count,
            max_severity: sev,
            name,
        })
        .collect();
    out.sort_by(|a, b| match (a.quiet, b.quiet) {
        (false, true) => std::cmp::Ordering::Less,
        (true, false) => std::cmp::Ordering::Greater,
        _ => b
            .max_severity
            .cmp(&a.max_severity)
            .then_with(|| a.name.cmp(&b.name)),
    });
    out
}

/// Generate a simple UUID-like identifier
pub fn uuid_v4() -> String {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    format!(
        "{:08x}-{:04x}-4{:03x}-{:04x}-{:012x}",
        rng.gen::<u32>(),
        rng.gen::<u16>(),
        rng.gen::<u16>() & 0x0fff,
        (rng.gen::<u16>() & 0x3fff) | 0x8000,
        rng.gen::<u64>() & 0xffffffffffff,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mk(plugin: &str, sev: Severity) -> Finding {
        Finding::new("t", sev, "https://x", "d", "s", plugin)
    }

    #[test]
    fn summarize_modules_buckets_by_plugin() {
        let findings = vec![
            mk("active/sqli", Severity::Critical),
            mk("active/xss", Severity::High),
            mk("active/xss", Severity::Medium),
            mk("passive/security-txt", Severity::Info),
        ];
        let known: &[&str] = &["active/sqli", "active/xss", "passive/security-txt"];
        let summaries = summarize_modules(&findings, known);
        let by_name: std::collections::HashMap<_, _> =
            summaries.iter().map(|s| (s.name.clone(), s)).collect();
        assert_eq!(by_name["active/sqli"].findings, 1);
        assert_eq!(by_name["active/xss"].findings, 2);
        // Max severity within active/xss is High (not Medium).
        assert_eq!(by_name["active/xss"].max_severity, Some(Severity::High));
    }

    #[test]
    fn summarize_modules_surfaces_quiet_modules() {
        let findings: Vec<Finding> = vec![];
        let known: &[&str] = &["passive/missing-headers", "active/xss"];
        let summaries = summarize_modules(&findings, known);
        assert_eq!(summaries.len(), 2);
        assert!(summaries.iter().all(|s| s.quiet));
        assert!(summaries.iter().all(|s| s.max_severity.is_none()));
    }

    #[test]
    fn summarize_modules_sorts_non_quiet_first_by_severity() {
        let findings = vec![
            mk("active/a", Severity::Low),
            mk("active/b", Severity::Critical),
            mk("active/c", Severity::Medium),
        ];
        let known: &[&str] = &["active/quiet-one", "active/a", "active/b", "active/c"];
        let summaries = summarize_modules(&findings, known);
        // Order: Critical (b), Medium (c), Low (a), then quiet.
        assert_eq!(summaries[0].name, "active/b");
        assert_eq!(summaries[1].name, "active/c");
        assert_eq!(summaries[2].name, "active/a");
        assert_eq!(summaries[3].name, "active/quiet-one");
        assert!(summaries[3].quiet);
    }

    #[test]
    fn summarize_modules_picks_up_unknown_plugins() {
        // A plugin not in `known_modules` but present in findings still
        // appears in the result.
        let findings = vec![mk("custom/special", Severity::Medium)];
        let known: &[&str] = &["passive/security-txt"];
        let summaries = summarize_modules(&findings, known);
        assert!(summaries.iter().any(|s| s.name == "custom/special"));
    }
}
