use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};

/// Severity levels for findings
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
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
    pub plugin: String,
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
            plugin: plugin.into(),
            found_at: Utc::now(),
        }
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

/// Discovered URL with metadata
#[derive(Debug, Clone, Serialize, Deserialize, Hash, PartialEq, Eq)]
pub struct DiscoveredUrl {
    pub url: String,
    pub method: String,
    pub parameters: Vec<String>,
    pub source: UrlSource,
}

#[derive(Debug, Clone, Serialize, Deserialize, Hash, PartialEq, Eq)]
pub enum UrlSource {
    Seed,
    Link,
    Form,
    Script,
    Redirect,
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
