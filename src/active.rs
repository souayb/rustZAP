use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use async_trait::async_trait;
use colored::*;
use indicatif::ProgressBar;
use tokio::sync::Semaphore;
use tracing::{debug, warn};

use crate::types::{DiscoveredUrl, Finding, Severity};

// ─────────────────────────────────────────────────────────────────────────────
// Plugin trait
// ─────────────────────────────────────────────────────────────────────────────

#[async_trait]
pub trait ScanPlugin: Send + Sync {
    fn name(&self) -> &str;
    fn description(&self) -> &str;
    async fn scan(&self, client: &reqwest::Client, target: &DiscoveredUrl) -> Vec<Finding>;
}

// ─────────────────────────────────────────────────────────────────────────────
// Active Scanner
// ─────────────────────────────────────────────────────────────────────────────

pub struct ActiveScanner {
    client: Arc<reqwest::Client>,
    plugins: Vec<Box<dyn ScanPlugin>>,
    semaphore: Arc<Semaphore>,
}

impl ActiveScanner {
    pub fn new(
        client: Arc<reqwest::Client>,
        enabled: Vec<String>,
        concurrency: usize,
    ) -> Self {
        let all_plugins: Vec<Box<dyn ScanPlugin>> = vec![
            Box::new(XssPlugin),
            Box::new(SqlInjectionPlugin),
            Box::new(PathTraversalPlugin),
            Box::new(OpenRedirectPlugin),
            Box::new(SsrfPlugin),
            Box::new(XxePlugin),
            Box::new(CmdInjectionPlugin),
            Box::new(SstiPlugin),
        ];

        let plugins = all_plugins
            .into_iter()
            .filter(|p| {
                let name = p.name().to_lowercase();
                enabled.iter().any(|e| name.contains(&e.to_lowercase()) || e == "all")
            })
            .collect();

        ActiveScanner {
            client,
            plugins,
            semaphore: Arc::new(Semaphore::new(concurrency)),
        }
    }

    pub async fn scan_all(
        &self,
        urls: &[DiscoveredUrl],
        pb: &ProgressBar,
    ) -> Result<Vec<Finding>> {
        let mut all_findings = Vec::new();

        for du in urls {
            pb.inc(1);
            pb.set_message(format!("Scanning {}", &du.url[..du.url.len().min(50)]));

            // Skip URLs with no parameters for active scanning
            if du.parameters.is_empty() && !du.url.contains('?') {
                continue;
            }

            let _permit = self.semaphore.acquire().await?;

            for plugin in &self.plugins {
                debug!("Running {} on {}", plugin.name(), du.url);
                let findings = plugin.scan(&self.client, du).await;
                if !findings.is_empty() {
                    for f in &findings {
                        println!(
                            "  {} {} — {}",
                            f.severity.color_str(),
                            f.title.bright_white().bold(),
                            f.url.dimmed()
                        );
                    }
                    all_findings.extend(findings);
                }
            }
        }

        Ok(all_findings)
    }
}

pub fn list_plugins() {
    let plugins: Vec<Box<dyn ScanPlugin>> = vec![
        Box::new(XssPlugin),
        Box::new(SqlInjectionPlugin),
        Box::new(PathTraversalPlugin),
        Box::new(OpenRedirectPlugin),
        Box::new(SsrfPlugin),
        Box::new(XxePlugin),
        Box::new(CmdInjectionPlugin),
        Box::new(SstiPlugin),
    ];

    println!("{}", "Available Active Scan Plugins".bright_white().bold());
    println!("{}", "─".repeat(50).dimmed());
    for p in &plugins {
        println!("  {:25} {}", p.name().bright_cyan(), p.description().dimmed());
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Build variants of a URL with a given parameter value injected
pub fn build_injection_urls_adv(target: &DiscoveredUrl, payload: &str) -> Vec<(String, String)> {
    let mut variants = Vec::new();

    // Inject into query string params
    if let Ok(mut parsed) = url::Url::parse(&target.url) {
        let params: Vec<(String, String)> = parsed.query_pairs().map(|(k, v)| (k.to_string(), v.to_string())).collect();
        for (key, _) in &params {
            let mut modified = parsed.clone();
            let new_pairs: Vec<(String, String)> = params
                .iter()
                .map(|(k, v)| {
                    if k == key {
                        (k.clone(), payload.to_string())
                    } else {
                        (k.clone(), v.clone())
                    }
                })
                .collect();
            {
                let mut qp = modified.query_pairs_mut();
                qp.clear();
                for (k, v) in &new_pairs {
                    qp.append_pair(k, v);
                }
            }
            variants.push((key.clone(), modified.to_string()));
        }
    }

    variants
}

pub async fn get_body(client: &reqwest::Client, url: &str) -> Option<(u16, String)> {
    get_response_body(client, url).await
}

pub async fn timed_get(client: &reqwest::Client, url: &str) -> (u64, bool) {
    let t = std::time::Instant::now();
    let ok = client.get(url).send().await.map(|r| r.status().as_u16() < 600).unwrap_or(false);
    (t.elapsed().as_millis() as u64, ok)
}

async fn get_response_body(client: &reqwest::Client, url: &str) -> Option<(u16, String)> {
    match client
        .get(url)
        .timeout(Duration::from_secs(8))
        .send()
        .await
    {
        Ok(r) => {
            let status = r.status().as_u16();
            let body = r.text().await.unwrap_or_default();
            Some((status, body))
        }
        Err(_) => None,
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// XSS Plugin
// ─────────────────────────────────────────────────────────────────────────────

pub struct XssPlugin;

#[async_trait]
impl ScanPlugin for XssPlugin {
    fn name(&self) -> &str { "xss" }
    fn description(&self) -> &str { "Reflected XSS — inject script payloads into URL parameters" }

    async fn scan(&self, client: &reqwest::Client, target: &DiscoveredUrl) -> Vec<Finding> {
        let mut findings = Vec::new();

        let payloads = vec![
            r#"<script>alert('XSS')</script>"#,
            r#""><img src=x onerror=alert(1)>"#,
            r#"javascript:alert(1)"#,
            r#"'><svg/onload=alert(1)>"#,
        ];

        for payload in payloads {
            let variants = build_injection_urls_adv(target, payload);
            for (param, url) in variants {
                if let Some((_, body)) = get_response_body(client, &url).await {
                    if body.contains(payload) || body.contains("alert(1)") {
                        findings.push(
                            Finding::new(
                                "Reflected Cross-Site Scripting (XSS)",
                                Severity::High,
                                &target.url,
                                "User-supplied input is reflected in the response without encoding, enabling script injection.",
                                "Encode all user input in HTML context. Implement a Content-Security-Policy.",
                                "active/xss",
                            )
                            .with_parameter(&param)
                            .with_evidence(format!("Payload '{}' reflected in response", payload))
                            .with_cwe(79)
                            .with_owasp("A03:2021 – Injection"),
                        );
                        return findings; // one confirmed is enough
                    }
                }
            }
        }

        findings
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// SQL Injection Plugin
// ─────────────────────────────────────────────────────────────────────────────

pub struct SqlInjectionPlugin;

#[async_trait]
impl ScanPlugin for SqlInjectionPlugin {
    fn name(&self) -> &str { "sqli" }
    fn description(&self) -> &str { "SQL Injection — error-based, boolean-based detection" }

    async fn scan(&self, client: &reqwest::Client, target: &DiscoveredUrl) -> Vec<Finding> {
        let mut findings = Vec::new();

        let error_payloads = vec![
            ("'", vec![
                "You have an error in your SQL syntax",
                "ORA-00907",
                "Microsoft OLE DB Provider",
                "Unclosed quotation mark",
                "SQLSTATE",
                "pg_query",
                "SQLite3::query",
                "mysql_num_rows",
            ]),
            ("'--", vec!["error", "syntax"]),
            ("1 AND 1=2", vec!["error", "syntax"]),
            ("1' OR '1'='1", vec!["error", "syntax", "warning"]),
        ];

        for (payload, error_strings) in error_payloads {
            let variants = build_injection_urls_adv(target, payload);
            for (param, url) in variants {
                if let Some((_, body)) = get_response_body(client, &url).await {
                    let body_lower = body.to_lowercase();
                    for err in &error_strings {
                        if body_lower.contains(*err) {
                            findings.push(
                                Finding::new(
                                    "SQL Injection",
                                    Severity::Critical,
                                    &target.url,
                                    "A SQL injection vulnerability was detected. An attacker could read, modify, or delete database contents.",
                                    "Use parameterized queries or prepared statements. Never interpolate user input into SQL.",
                                    "active/sqli",
                                )
                                .with_parameter(&param)
                                .with_evidence(format!("Payload: {} — Error keyword '{}' found in response", payload, err))
                                .with_cwe(89)
                                .with_owasp("A03:2021 – Injection"),
                            );
                            return findings;
                        }
                    }
                }
            }
        }

        findings
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Path Traversal Plugin
// ─────────────────────────────────────────────────────────────────────────────

pub struct PathTraversalPlugin;

#[async_trait]
impl ScanPlugin for PathTraversalPlugin {
    fn name(&self) -> &str { "path-traversal" }
    fn description(&self) -> &str { "Path/Directory Traversal — attempt to read /etc/passwd" }

    async fn scan(&self, client: &reqwest::Client, target: &DiscoveredUrl) -> Vec<Finding> {
        let mut findings = Vec::new();

        let payloads = vec![
            "../../../../etc/passwd",
            "..%2F..%2F..%2F..%2Fetc%2Fpasswd",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
            "....//....//etc/passwd",
        ];

        let signatures = ["root:x:0:0", "daemon:x:", "bin:x:", "/bin/bash"];

        for payload in payloads {
            let variants = build_injection_urls_adv(target, payload);
            for (param, url) in variants {
                if let Some((_, body)) = get_response_body(client, &url).await {
                    for sig in &signatures {
                        if body.contains(sig) {
                            findings.push(
                                Finding::new(
                                    "Path Traversal — /etc/passwd Readable",
                                    Severity::Critical,
                                    &target.url,
                                    "The application is vulnerable to path traversal, allowing access to arbitrary files on the server filesystem.",
                                    "Validate and sanitize file path inputs. Use an allowlist of permitted paths.",
                                    "active/path-traversal",
                                )
                                .with_parameter(&param)
                                .with_evidence(format!("Payload: {} — Response contains '{}'", payload, sig))
                                .with_cwe(22)
                                .with_owasp("A01:2021 – Broken Access Control"),
                            );
                            return findings;
                        }
                    }
                }
            }
        }

        findings
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Open Redirect Plugin
// ─────────────────────────────────────────────────────────────────────────────

pub struct OpenRedirectPlugin;

#[async_trait]
impl ScanPlugin for OpenRedirectPlugin {
    fn name(&self) -> &str { "open-redirect" }
    fn description(&self) -> &str { "Open Redirect — detect unvalidated redirects to external URLs" }

    async fn scan(&self, client: &reqwest::Client, target: &DiscoveredUrl) -> Vec<Finding> {
        let mut findings = Vec::new();
        let canary = "https://rustzap-canary.example.com/redirect-test";

        let payloads = vec![
            canary,
            "//rustzap-canary.example.com",
            "/\\rustzap-canary.example.com",
        ];

        for payload in payloads {
            let variants = build_injection_urls_adv(target, payload);
            for (param, url) in variants {
                // Use no-redirect policy to catch the 3xx
                match client
                    .get(&url)
                    .timeout(Duration::from_secs(8))
                    .send()
                    .await
                {
                    Ok(resp) => {
                        let status = resp.status().as_u16();
                        if (300..=399).contains(&status) {
                            if let Some(loc) = resp.headers().get("location") {
                                let loc_str = loc.to_str().unwrap_or("");
                                if loc_str.contains("rustzap-canary") || loc_str.starts_with("//") {
                                    findings.push(
                                        Finding::new(
                                            "Open Redirect",
                                            Severity::Medium,
                                            &target.url,
                                            "The application redirects to a user-supplied URL without validation, enabling phishing attacks.",
                                            "Validate redirect targets against an allowlist of permitted domains.",
                                            "active/open-redirect",
                                        )
                                        .with_parameter(&param)
                                        .with_evidence(format!("HTTP {} Location: {}", status, loc_str))
                                        .with_cwe(601)
                                        .with_owasp("A01:2021 – Broken Access Control"),
                                    );
                                    return findings;
                                }
                            }
                        }
                    }
                    Err(_) => {}
                }
            }
        }

        findings
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// SSRF Plugin
// ─────────────────────────────────────────────────────────────────────────────

pub struct SsrfPlugin;

#[async_trait]
impl ScanPlugin for SsrfPlugin {
    fn name(&self) -> &str { "ssrf" }
    fn description(&self) -> &str { "SSRF — probe internal metadata endpoints and localhost" }

    async fn scan(&self, client: &reqwest::Client, target: &DiscoveredUrl) -> Vec<Finding> {
        let mut findings = Vec::new();

        let ssrf_payloads = vec![
            "http://169.254.169.254/latest/meta-data/",      // AWS IMDS
            "http://metadata.google.internal/computeMetadata/v1/",  // GCP
            "http://localhost/",
            "http://127.0.0.1/",
            "http://[::1]/",
        ];

        let ssrf_indicators = [
            "ami-id",
            "instance-id",
            "computeMetadata",
            "iam/security-credentials",
            "localhost",
            "127.0.0.1",
        ];

        for payload in ssrf_payloads {
            let variants = build_injection_urls_adv(target, payload);
            for (param, url) in variants {
                if let Some((status, body)) = get_response_body(client, &url).await {
                    if status == 200 {
                        for indicator in &ssrf_indicators {
                            if body.contains(indicator) {
                                findings.push(
                                    Finding::new(
                                        "Server-Side Request Forgery (SSRF)",
                                        Severity::Critical,
                                        &target.url,
                                        "The server fetches user-supplied URLs, enabling access to internal services and cloud metadata endpoints.",
                                        "Validate and sanitize all URL inputs. Implement a server-side allowlist for outbound requests.",
                                        "active/ssrf",
                                    )
                                    .with_parameter(&param)
                                    .with_evidence(format!("Payload: {} — Response contains '{}'", payload, indicator))
                                    .with_cwe(918)
                                    .with_owasp("A10:2021 – Server-Side Request Forgery"),
                                );
                                return findings;
                            }
                        }
                    }
                }
            }
        }

        findings
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// XXE Plugin
// ─────────────────────────────────────────────────────────────────────────────

pub struct XxePlugin;

#[async_trait]
impl ScanPlugin for XxePlugin {
    fn name(&self) -> &str { "xxe" }
    fn description(&self) -> &str { "XXE — XML External Entity injection via POST bodies" }

    async fn scan(&self, client: &reqwest::Client, target: &DiscoveredUrl) -> Vec<Finding> {
        let mut findings = Vec::new();

        // Only probe POST endpoints (forms)
        if target.method != "POST" {
            return findings;
        }

        let xxe_payload = r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<root><param>&xxe;</param></root>"#;

        match client
            .post(&target.url)
            .header("Content-Type", "application/xml")
            .body(xxe_payload)
            .timeout(Duration::from_secs(8))
            .send()
            .await
        {
            Ok(resp) => {
                let body = resp.text().await.unwrap_or_default();
                if body.contains("root:x:0:0") || body.contains("/bin/bash") {
                    findings.push(
                        Finding::new(
                            "XML External Entity (XXE) Injection",
                            Severity::Critical,
                            &target.url,
                            "The XML parser processes external entity declarations, enabling file read, SSRF, and denial of service.",
                            "Disable external entity processing in your XML parser. Use a JSON API where possible.",
                            "active/xxe",
                        )
                        .with_evidence("XXE payload successfully read /etc/passwd".to_string())
                        .with_cwe(611)
                        .with_owasp("A03:2021 – Injection"),
                    );
                }
            }
            Err(_) => {}
        }

        findings
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Command Injection Plugin
// ─────────────────────────────────────────────────────────────────────────────

pub struct CmdInjectionPlugin;

#[async_trait]
impl ScanPlugin for CmdInjectionPlugin {
    fn name(&self) -> &str { "cmd-injection" }
    fn description(&self) -> &str { "OS Command Injection — shell metacharacter injection" }

    async fn scan(&self, client: &reqwest::Client, target: &DiscoveredUrl) -> Vec<Finding> {
        let mut findings = Vec::new();

        let payloads_and_sigs: Vec<(&str, Vec<&str>)> = vec![
            ("; id", vec!["uid=", "gid=", "groups="]),
            ("| id", vec!["uid=", "gid="]),
            ("`id`", vec!["uid=", "gid="]),
            ("$(id)", vec!["uid=", "gid="]),
            ("; cat /etc/passwd", vec!["root:x:0:0"]),
            ("| cat /etc/passwd", vec!["root:x:0:0"]),
        ];

        for (payload, sigs) in payloads_and_sigs {
            let variants = build_injection_urls_adv(target, payload);
            for (param, url) in variants {
                if let Some((_, body)) = get_response_body(client, &url).await {
                    for sig in &sigs {
                        if body.contains(sig) {
                            findings.push(
                                Finding::new(
                                    "OS Command Injection",
                                    Severity::Critical,
                                    &target.url,
                                    "User input is passed directly to a system shell, allowing arbitrary command execution.",
                                    "Never pass user input to shell commands. Use language APIs instead of shell exec. Apply strict input validation.",
                                    "active/cmd-injection",
                                )
                                .with_parameter(&param)
                                .with_evidence(format!("Payload '{}' — Response contains '{}'", payload, sig))
                                .with_cwe(78)
                                .with_owasp("A03:2021 – Injection"),
                            );
                            return findings;
                        }
                    }
                }
            }
        }

        findings
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// SSTI Plugin
// ─────────────────────────────────────────────────────────────────────────────

pub struct SstiPlugin;

#[async_trait]
impl ScanPlugin for SstiPlugin {
    fn name(&self) -> &str { "ssti" }
    fn description(&self) -> &str { "Server-Side Template Injection — math expression evaluation" }

    async fn scan(&self, client: &reqwest::Client, target: &DiscoveredUrl) -> Vec<Finding> {
        let mut findings = Vec::new();

        // We inject math expressions that different template engines evaluate
        let probes: Vec<(&str, &str)> = vec![
            ("{{7*7}}", "49"),
            ("${7*7}", "49"),
            ("<%= 7*7 %>", "49"),
            ("#{7*7}", "49"),
            ("*{7*7}", "49"),
        ];

        for (payload, expected) in probes {
            let variants = build_injection_urls_adv(target, payload);
            for (param, url) in variants {
                if let Some((_, body)) = get_response_body(client, &url).await {
                    if body.contains(expected) && !body.contains(payload) {
                        findings.push(
                            Finding::new(
                                "Server-Side Template Injection (SSTI)",
                                Severity::Critical,
                                &target.url,
                                "User input is embedded directly into a template, allowing expression evaluation and potentially remote code execution.",
                                "Never pass user input directly into template strings. Use template sandboxing or a logic-less template engine.",
                                "active/ssti",
                            )
                            .with_parameter(&param)
                            .with_evidence(format!("Payload '{}' evaluated to '{}'", payload, expected))
                            .with_cwe(94)
                            .with_owasp("A03:2021 – Injection"),
                        );
                        return findings;
                    }
                }
            }
        }

        findings
    }
}
