use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use async_trait::async_trait;
use colored::*;
use indicatif::ProgressBar;
use tokio::sync::{Mutex, Semaphore};
use tracing::debug;
use url::Url;

use crate::types::{DiscoveredUrl, Finding, Severity};

// ─────────────────────────────────────────────────────────────────────────────
// Plugin trait
// ─────────────────────────────────────────────────────────────────────────────

#[async_trait]
pub trait ScanPlugin: Send + Sync {
    fn name(&self) -> &str;
    fn description(&self) -> &str;
    async fn scan(&self, client: &reqwest::Client, target: &DiscoveredUrl) -> Vec<Finding>;

    /// When `true`, the plugin is exempted from the URL-must-have-params
    /// gating in `ActiveScanner::scan_all`. Used by probes that target a
    /// path itself (GraphQL endpoint, HTTP method enumeration) rather than
    /// a query parameter.
    fn always_run(&self) -> bool {
        false
    }
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
    pub fn new(client: Arc<reqwest::Client>, enabled: Vec<String>, concurrency: usize) -> Self {
        let mut all_plugins: Vec<Box<dyn ScanPlugin>> = vec![
            Box::new(XssPlugin),
            Box::new(SqlInjectionPlugin),
            Box::new(PathTraversalPlugin),
            Box::new(OpenRedirectPlugin),
            Box::new(SsrfPlugin),
            Box::new(XxePlugin),
            Box::new(CmdInjectionPlugin),
            Box::new(SstiPlugin),
            Box::new(GraphqlIntrospectionPlugin),
            Box::new(HttpMethodsPlugin::new()),
            Box::new(RedirectChainPlugin::new()),
            Box::new(crate::sensitive_paths::SensitivePathsPlugin::new()),
        ];
        all_plugins.extend(crate::sqli_advanced::plugins());

        let plugins = all_plugins
            .into_iter()
            .filter(|p| {
                let name = p.name().to_lowercase();
                enabled
                    .iter()
                    .any(|e| name.contains(&e.to_lowercase()) || e == "all")
            })
            .collect();

        ActiveScanner {
            client,
            plugins,
            semaphore: Arc::new(Semaphore::new(concurrency)),
        }
    }

    /// Plugin ids (as they appear on `Finding::plugin`) for every plugin
    /// this scanner instance will run. Used to surface quiet modules in
    /// the post-scan tree view (SDD §9.1). Maps `name()` → `active/<name>`.
    pub fn enabled_module_names(&self) -> Vec<String> {
        self.plugins
            .iter()
            .map(|p| format!("active/{}", p.name()))
            .collect()
    }

    pub async fn scan_all(&self, urls: &[DiscoveredUrl], pb: &ProgressBar) -> Result<Vec<Finding>> {
        let mut all_findings = Vec::new();

        for du in urls {
            pb.inc(1);
            pb.set_message(format!("Scanning {}", &du.url[..du.url.len().min(50)]));

            let has_params = !du.parameters.is_empty() || du.url.contains('?');
            let any_always_run = self.plugins.iter().any(|p| p.always_run());

            // Skip URLs with no parameters for active scanning, unless at
            // least one selected plugin opts to run on any URL.
            if !has_params && !any_always_run {
                continue;
            }

            let _permit = self.semaphore.acquire().await?;

            for plugin in &self.plugins {
                if !has_params && !plugin.always_run() {
                    continue;
                }
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
    let mut plugins: Vec<Box<dyn ScanPlugin>> = vec![
        Box::new(XssPlugin),
        Box::new(SqlInjectionPlugin),
        Box::new(PathTraversalPlugin),
        Box::new(OpenRedirectPlugin),
        Box::new(SsrfPlugin),
        Box::new(XxePlugin),
        Box::new(CmdInjectionPlugin),
        Box::new(SstiPlugin),
        Box::new(GraphqlIntrospectionPlugin),
        Box::new(HttpMethodsPlugin::new()),
        Box::new(RedirectChainPlugin::new()),
        Box::new(crate::sensitive_paths::SensitivePathsPlugin::new()),
    ];
    plugins.extend(crate::sqli_advanced::plugins());

    println!("{}", "Available Active Scan Plugins".bright_white().bold());
    println!("{}", "─".repeat(50).dimmed());
    for p in &plugins {
        println!(
            "  {:25} {}",
            p.name().bright_cyan(),
            p.description().dimmed()
        );
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Build variants of a URL with a given parameter value injected
pub fn build_injection_urls_adv(target: &DiscoveredUrl, payload: &str) -> Vec<(String, String)> {
    let mut variants = Vec::new();

    // Inject into query string params
    if let Ok(parsed) = url::Url::parse(&target.url) {
        let params: Vec<(String, String)> = parsed
            .query_pairs()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
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
    let ok = client
        .get(url)
        .send()
        .await
        .map(|r| r.status().as_u16() < 600)
        .unwrap_or(false);
    (t.elapsed().as_millis() as u64, ok)
}

async fn get_response_body(client: &reqwest::Client, url: &str) -> Option<(u16, String)> {
    match client.get(url).timeout(Duration::from_secs(8)).send().await {
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
    fn name(&self) -> &str {
        "xss"
    }
    fn description(&self) -> &str {
        "Reflected XSS — inject script payloads into URL parameters"
    }

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
    fn name(&self) -> &str {
        "sqli"
    }
    fn description(&self) -> &str {
        "SQL Injection — error-based, boolean-based detection"
    }

    async fn scan(&self, client: &reqwest::Client, target: &DiscoveredUrl) -> Vec<Finding> {
        let mut findings = Vec::new();

        let error_payloads = vec![
            (
                "'",
                vec![
                    "You have an error in your SQL syntax",
                    "ORA-00907",
                    "Microsoft OLE DB Provider",
                    "Unclosed quotation mark",
                    "SQLSTATE",
                    "pg_query",
                    "SQLite3::query",
                    "mysql_num_rows",
                ],
            ),
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
    fn name(&self) -> &str {
        "path-traversal"
    }
    fn description(&self) -> &str {
        "Path/Directory Traversal — attempt to read /etc/passwd"
    }

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
    fn name(&self) -> &str {
        "open-redirect"
    }
    fn description(&self) -> &str {
        "Open Redirect — detect unvalidated redirects to external URLs"
    }

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
                if let Ok(resp) = client
                    .get(&url)
                    .timeout(Duration::from_secs(8))
                    .send()
                    .await
                {
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
    fn name(&self) -> &str {
        "ssrf"
    }
    fn description(&self) -> &str {
        "SSRF — probe internal metadata endpoints and localhost"
    }

    async fn scan(&self, client: &reqwest::Client, target: &DiscoveredUrl) -> Vec<Finding> {
        let mut findings = Vec::new();

        let ssrf_payloads = vec![
            "http://169.254.169.254/latest/meta-data/", // AWS IMDS
            "http://metadata.google.internal/computeMetadata/v1/", // GCP
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
    fn name(&self) -> &str {
        "xxe"
    }
    fn description(&self) -> &str {
        "XXE — XML External Entity injection via POST bodies"
    }

    async fn scan(&self, client: &reqwest::Client, target: &DiscoveredUrl) -> Vec<Finding> {
        let mut findings = Vec::new();

        // Only probe POST endpoints (forms)
        if target.method != "POST" {
            return findings;
        }

        let xxe_payload = r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<root><param>&xxe;</param></root>"#;

        if let Ok(resp) = client
            .post(&target.url)
            .header("Content-Type", "application/xml")
            .body(xxe_payload)
            .timeout(Duration::from_secs(8))
            .send()
            .await
        {
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

        findings
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Command Injection Plugin
// ─────────────────────────────────────────────────────────────────────────────

pub struct CmdInjectionPlugin;

#[async_trait]
impl ScanPlugin for CmdInjectionPlugin {
    fn name(&self) -> &str {
        "cmd-injection"
    }
    fn description(&self) -> &str {
        "OS Command Injection — shell metacharacter injection"
    }

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
    fn name(&self) -> &str {
        "ssti"
    }
    fn description(&self) -> &str {
        "Server-Side Template Injection — math expression evaluation"
    }

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

// ─────────────────────────────────────────────────────────────────────────────
// A3. GraphQL introspection plugin
// ─────────────────────────────────────────────────────────────────────────────

pub struct GraphqlIntrospectionPlugin;

const GRAPHQL_INTROSPECTION_QUERY: &str = r#"{"query":"{__schema{queryType{name} types{name}}}"}"#;

/// Returns true when the URL path or Content-Type suggests a GraphQL endpoint.
pub fn looks_like_graphql(url: &str, content_type: Option<&str>) -> bool {
    let lower_path = Url::parse(url)
        .ok()
        .map(|u| u.path().to_lowercase())
        .unwrap_or_default();
    if lower_path.contains("graphql") || lower_path.contains("graphiql") {
        return true;
    }
    matches!(
        content_type.map(|c| c.to_lowercase()),
        Some(ref c) if c.contains("application/graphql") || c.contains("application/graphql+json")
    )
}

/// Returns true when the JSON-ish body exposes a GraphQL schema via
/// introspection. We check for both `__schema` and `queryType` so we don't
/// trip on unrelated keys.
pub fn looks_like_introspection_response(body: &str) -> bool {
    body.contains("__schema") && body.contains("queryType")
}

#[async_trait]
impl ScanPlugin for GraphqlIntrospectionPlugin {
    fn name(&self) -> &str {
        "graphql-introspection"
    }
    fn description(&self) -> &str {
        "GraphQL Introspection — detect schema exposure on GraphQL endpoints"
    }

    fn always_run(&self) -> bool {
        true
    }

    async fn scan(&self, client: &reqwest::Client, target: &DiscoveredUrl) -> Vec<Finding> {
        let mut findings = Vec::new();

        // Gate by path/content-type so we don't POST to arbitrary endpoints.
        let probe_ct = match client
            .get(&target.url)
            .timeout(Duration::from_secs(6))
            .send()
            .await
        {
            Ok(r) => r
                .headers()
                .get("content-type")
                .and_then(|v| v.to_str().ok())
                .map(|s| s.to_string()),
            Err(_) => None,
        };

        if !looks_like_graphql(&target.url, probe_ct.as_deref()) {
            return findings;
        }

        let resp = match client
            .post(&target.url)
            .header("Content-Type", "application/json")
            .body(GRAPHQL_INTROSPECTION_QUERY)
            .timeout(Duration::from_secs(8))
            .send()
            .await
        {
            Ok(r) => r,
            Err(_) => return findings,
        };

        let status = resp.status().as_u16();
        let body = resp.text().await.unwrap_or_default();

        if status == 200 && looks_like_introspection_response(&body) {
            let snippet = body[..body.len().min(120)].to_string();
            findings.push(
                Finding::new(
                    "GraphQL Introspection Enabled",
                    Severity::Medium,
                    &target.url,
                    "The GraphQL endpoint answers introspection queries, exposing the full schema. Attackers can enumerate types, fields, and arguments.",
                    "Disable introspection in production (e.g. set introspection: false in Apollo Server) or require authentication for the /graphql endpoint.",
                    "active/graphql-introspection",
                )
                .with_evidence(snippet)
                .with_cwe(200)
                .with_owasp("A05:2021 – Security Misconfiguration"),
            );
        }

        findings
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// A4. HTTP method enumeration
// ─────────────────────────────────────────────────────────────────────────────

pub struct HttpMethodsPlugin {
    /// Per-scanner-run dedupe of seen paths to keep traffic low. Multiple
    /// query variants of the same path probe OPTIONS only once.
    seen_paths: Mutex<HashSet<String>>,
}

impl HttpMethodsPlugin {
    pub fn new() -> Self {
        Self {
            seen_paths: Mutex::new(HashSet::new()),
        }
    }
}

impl Default for HttpMethodsPlugin {
    fn default() -> Self {
        Self::new()
    }
}

/// Parse an HTTP `Allow` header into a deduplicated, uppercased method list.
pub fn parse_allow_header(value: &str) -> Vec<String> {
    let mut seen: HashSet<String> = HashSet::new();
    let mut out = Vec::new();
    for tok in value.split(',') {
        let m = tok.trim().to_uppercase();
        if !m.is_empty() && seen.insert(m.clone()) {
            out.push(m);
        }
    }
    out
}

/// Return the subset of `methods` that are considered dangerous to expose
/// without authentication.
pub fn dangerous_methods(methods: &[String]) -> Vec<String> {
    let dangerous = ["PUT", "DELETE", "PATCH", "TRACE", "CONNECT"];
    methods
        .iter()
        .filter(|m| dangerous.contains(&m.as_str()))
        .cloned()
        .collect()
}

#[async_trait]
impl ScanPlugin for HttpMethodsPlugin {
    fn name(&self) -> &str {
        "http-methods"
    }
    fn description(&self) -> &str {
        "HTTP method enumeration — OPTIONS probe, flags dangerous combos (PUT/DELETE/TRACE)"
    }

    fn always_run(&self) -> bool {
        true
    }

    async fn scan(&self, client: &reqwest::Client, target: &DiscoveredUrl) -> Vec<Finding> {
        let mut findings = Vec::new();

        // Dedupe by path so /foo?a=1 and /foo?a=2 only probe OPTIONS once.
        let path_key = match Url::parse(&target.url) {
            Ok(u) => format!(
                "{}://{}{}",
                u.scheme(),
                u.host_str().unwrap_or(""),
                u.path()
            ),
            Err(_) => return findings,
        };
        {
            let mut seen = self.seen_paths.lock().await;
            if !seen.insert(path_key.clone()) {
                return findings;
            }
        }

        let resp = match client
            .request(reqwest::Method::OPTIONS, &target.url)
            .timeout(Duration::from_secs(6))
            .send()
            .await
        {
            Ok(r) => r,
            Err(_) => return findings,
        };

        let allow = resp
            .headers()
            .get("allow")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());

        let Some(allow_value) = allow else {
            return findings;
        };

        let methods = parse_allow_header(&allow_value);
        let bad = dangerous_methods(&methods);

        if !bad.is_empty() {
            findings.push(
                Finding::new(
                    "Dangerous HTTP Methods Allowed",
                    Severity::Medium,
                    &target.url,
                    format!(
                        "The endpoint advertises methods that are often unnecessary and risky: {}.",
                        bad.join(", ")
                    ),
                    "Restrict allowed methods at the web server / framework layer. Disable TRACE, and require auth for PUT/DELETE/PATCH.",
                    "active/http-methods",
                )
                .with_evidence(format!("Allow: {}", allow_value))
                .with_cwe(650)
                .with_owasp("A05:2021 – Security Misconfiguration"),
            );
        }

        findings
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// A5. Redirect chain analyzer
// ─────────────────────────────────────────────────────────────────────────────

pub struct RedirectChainPlugin {
    nofollow: std::sync::OnceLock<reqwest::Client>,
}

impl RedirectChainPlugin {
    pub fn new() -> Self {
        Self {
            nofollow: std::sync::OnceLock::new(),
        }
    }

    fn client(&self) -> &reqwest::Client {
        self.nofollow.get_or_init(|| {
            reqwest::Client::builder()
                .timeout(Duration::from_secs(8))
                .redirect(reqwest::redirect::Policy::none())
                .danger_accept_invalid_certs(true)
                .user_agent("RustZAP/0.1 RedirectChain")
                .build()
                .expect("redirect-chain client")
        })
    }
}

impl Default for RedirectChainPlugin {
    fn default() -> Self {
        Self::new()
    }
}

/// One hop in a redirect chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RedirectHop {
    pub url: String,
    pub status: u16,
    pub location: Option<String>,
}

/// Findings derived purely from a sequence of hops. Split out for unit
/// testing — the network logic just collects hops and feeds them in.
pub fn analyze_redirect_chain(hops: &[RedirectHop], max_hops: usize) -> Vec<Finding> {
    let mut findings = Vec::new();
    if hops.is_empty() {
        return findings;
    }
    let origin_url = &hops[0].url;
    let origin_host = Url::parse(origin_url)
        .ok()
        .and_then(|u| u.host_str().map(|s| s.to_string()));
    let origin_scheme = Url::parse(origin_url).ok().map(|u| u.scheme().to_string());

    let mut visited: HashSet<String> = HashSet::new();
    for hop in hops {
        if !visited.insert(hop.url.clone()) {
            findings.push(
                Finding::new(
                    "Redirect Loop Detected",
                    Severity::Medium,
                    origin_url,
                    "The redirect chain revisits a URL, forming a loop. Clients will eventually error out.",
                    "Fix the redirect logic so each hop progresses toward a terminal response.",
                    "active/redirect-chain",
                )
                .with_evidence(format!("Looped at: {}", hop.url))
                .with_cwe(835),
            );
            break;
        }

        let Some(loc) = hop.location.as_ref() else {
            continue;
        };
        let resolved = Url::parse(&hop.url)
            .ok()
            .and_then(|base| base.join(loc).ok());
        let Some(target) = resolved else { continue };

        // Scheme downgrade (HTTPS → HTTP).
        if origin_scheme.as_deref() == Some("https") && target.scheme() == "http" {
            findings.push(
                Finding::new(
                    "Redirect Downgrades HTTPS to HTTP",
                    Severity::Medium,
                    origin_url,
                    "A redirect points from an HTTPS URL to an HTTP URL, exposing the user to MITM attacks during the next request.",
                    "Redirect to HTTPS targets only; enforce HSTS at the origin.",
                    "active/redirect-chain",
                )
                .with_evidence(format!("{} → {}", hop.url, target))
                .with_cwe(319)
                .with_owasp("A02:2021 – Cryptographic Failures"),
            );
        }

        // Cross-origin redirect (potential open redirect / phishing surface).
        if let (Some(origin), Some(dest)) = (origin_host.as_deref(), target.host_str()) {
            if !same_or_subdomain(origin, dest) {
                findings.push(
                    Finding::new(
                        "Redirect Crosses Origin",
                        Severity::Low,
                        origin_url,
                        format!(
                            "A redirect leaves the original host. Target: {}. Verify this is intentional and not a reflected user input.",
                            dest
                        ),
                        "Validate redirect targets against an allowlist. Avoid using user input as a redirect destination.",
                        "active/redirect-chain",
                    )
                    .with_evidence(format!("{} → {}", hop.url, target))
                    .with_cwe(601),
                );
            }
        }
    }

    if hops.len() > max_hops {
        findings.push(
            Finding::new(
                "Excessive Redirect Chain",
                Severity::Low,
                origin_url,
                format!("The redirect chain exceeded {} hops.", max_hops),
                "Collapse redirect chains. Each extra hop adds latency and an opportunity for downgrade attacks.",
                "active/redirect-chain",
            )
            .with_evidence(format!("Observed {} hops", hops.len())),
        );
    }

    findings
}

fn same_or_subdomain(origin: &str, candidate: &str) -> bool {
    let o = origin.trim_start_matches("www.");
    let c = candidate.trim_start_matches("www.");
    c == o || c.ends_with(&format!(".{}", o))
}

#[async_trait]
impl ScanPlugin for RedirectChainPlugin {
    fn name(&self) -> &str {
        "redirect-chain"
    }
    fn description(&self) -> &str {
        "Redirect chain analyzer — downgrade, cross-origin, loop, excessive hops"
    }

    async fn scan(&self, _client: &reqwest::Client, target: &DiscoveredUrl) -> Vec<Finding> {
        let mut hops: Vec<RedirectHop> = Vec::new();
        let mut current = target.url.clone();
        const MAX_HOPS: usize = 10;
        let nf = self.client();

        for _ in 0..MAX_HOPS {
            let resp = match nf.get(&current).send().await {
                Ok(r) => r,
                Err(_) => break,
            };
            let status = resp.status().as_u16();
            let location = resp
                .headers()
                .get("location")
                .and_then(|v| v.to_str().ok())
                .map(|s| s.to_string());

            hops.push(RedirectHop {
                url: current.clone(),
                status,
                location: location.clone(),
            });

            if !(300..400).contains(&status) {
                break;
            }
            let Some(loc) = location else { break };
            let next = match Url::parse(&current).ok().and_then(|b| b.join(&loc).ok()) {
                Some(u) => u.to_string(),
                None => break,
            };
            current = next;
        }

        analyze_redirect_chain(&hops, MAX_HOPS - 1)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── A3 GraphQL ─────────────────────────────────────────────────────

    #[test]
    fn graphql_path_detected_via_substring() {
        assert!(looks_like_graphql("https://api.example.com/graphql", None));
        assert!(looks_like_graphql(
            "https://api.example.com/v1/graphql",
            None
        ));
        assert!(looks_like_graphql(
            "https://api.example.com/admin/graphiql",
            None
        ));
        assert!(!looks_like_graphql("https://api.example.com/users", None));
    }

    #[test]
    fn graphql_detected_via_content_type() {
        assert!(looks_like_graphql(
            "https://api.example.com/q",
            Some("application/graphql+json; charset=utf-8")
        ));
        assert!(!looks_like_graphql(
            "https://api.example.com/q",
            Some("application/json")
        ));
    }

    #[test]
    fn introspection_response_requires_both_markers() {
        assert!(looks_like_introspection_response(
            r#"{"data":{"__schema":{"queryType":{"name":"Query"}}}}"#
        ));
        // Only __schema → not enough on its own
        assert!(!looks_like_introspection_response(
            r#"{"data":{"__schema":null}}"#
        ));
        // Only queryType → not enough
        assert!(!looks_like_introspection_response(
            r#"{"data":{"queryType":"Query"}}"#
        ));
    }

    // ── A4 HTTP methods ────────────────────────────────────────────────

    #[test]
    fn parse_allow_normalizes_and_dedups() {
        assert_eq!(
            parse_allow_header("GET, post ,  GET ,OPTIONS"),
            vec!["GET", "POST", "OPTIONS"]
        );
        assert!(parse_allow_header("").is_empty());
    }

    #[test]
    fn dangerous_methods_flags_destructive_verbs() {
        let methods: Vec<String> = ["GET", "POST", "PUT", "TRACE"]
            .into_iter()
            .map(String::from)
            .collect();
        let bad = dangerous_methods(&methods);
        assert_eq!(bad, vec!["PUT".to_string(), "TRACE".to_string()]);
    }

    #[test]
    fn dangerous_methods_silent_on_safe_set() {
        let methods: Vec<String> = ["GET", "HEAD", "OPTIONS"]
            .into_iter()
            .map(String::from)
            .collect();
        assert!(dangerous_methods(&methods).is_empty());
    }

    // ── A5 Redirect chain ──────────────────────────────────────────────

    fn hop(url: &str, status: u16, loc: Option<&str>) -> RedirectHop {
        RedirectHop {
            url: url.to_string(),
            status,
            location: loc.map(String::from),
        }
    }

    #[test]
    fn redirect_chain_detects_https_to_http_downgrade() {
        let hops = vec![
            hop(
                "https://example.com/",
                302,
                Some("http://example.com/insecure"),
            ),
            hop("http://example.com/insecure", 200, None),
        ];
        let findings = analyze_redirect_chain(&hops, 9);
        assert!(findings
            .iter()
            .any(|f| f.title.contains("Downgrades HTTPS")));
    }

    #[test]
    fn redirect_chain_detects_cross_origin() {
        let hops = vec![
            hop(
                "https://example.com/",
                302,
                Some("https://evil.example.org/x"),
            ),
            hop("https://evil.example.org/x", 200, None),
        ];
        let findings = analyze_redirect_chain(&hops, 9);
        assert!(findings.iter().any(|f| f.title.contains("Crosses Origin")));
    }

    #[test]
    fn redirect_chain_subdomain_is_not_cross_origin() {
        let hops = vec![
            hop(
                "https://example.com/",
                302,
                Some("https://api.example.com/x"),
            ),
            hop("https://api.example.com/x", 200, None),
        ];
        let findings = analyze_redirect_chain(&hops, 9);
        assert!(findings.iter().all(|f| !f.title.contains("Crosses Origin")));
    }

    #[test]
    fn redirect_chain_detects_loop() {
        let hops = vec![
            hop("https://example.com/a", 302, Some("/b")),
            hop("https://example.com/b", 302, Some("/a")),
            hop("https://example.com/a", 302, Some("/b")),
        ];
        let findings = analyze_redirect_chain(&hops, 9);
        assert!(findings.iter().any(|f| f.title.contains("Loop")));
    }

    #[test]
    fn redirect_chain_flags_excessive_hops() {
        let mut hops: Vec<RedirectHop> = (0..6)
            .map(|i| {
                hop(
                    &format!("https://example.com/{}", i),
                    302,
                    Some(&format!("/{}", i + 1)),
                )
            })
            .collect();
        hops.push(hop("https://example.com/6", 200, None));
        let findings = analyze_redirect_chain(&hops, 5);
        assert!(findings.iter().any(|f| f.title.contains("Excessive")));
    }
}
