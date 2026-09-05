use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use colored::*;
use indicatif::ProgressBar;
use tokio::sync::Mutex;
use tracing::debug;
use url::Url;

use crate::types::{DiscoveredUrl, Finding, Severity};

pub struct PassiveScanner {
    client: Arc<reqwest::Client>,
    seen_origins: Mutex<HashSet<String>>,
    /// When true, passive checks also run on non-GET discovered requests.
    all_methods: bool,
}

impl PassiveScanner {
    pub fn new(client: Arc<reqwest::Client>) -> Self {
        PassiveScanner {
            client,
            seen_origins: Mutex::new(HashSet::new()),
            all_methods: false,
        }
    }

    /// Enable passive checks on non-GET requests (`--passive-all-methods`).
    pub fn with_all_methods(mut self, all_methods: bool) -> Self {
        self.all_methods = all_methods;
        self
    }

    /// Run all passive checks against discovered URLs
    pub async fn scan_all(&self, urls: &[DiscoveredUrl], pb: &ProgressBar) -> Result<Vec<Finding>> {
        self.scan_all_with_cache(urls, pb, None).await
    }

    /// Run all passive checks, utilizing cached responses from spidering when available.
    pub async fn scan_all_with_cache(
        &self,
        urls: &[DiscoveredUrl],
        pb: &ProgressBar,
        cache: Option<&crate::types::HttpResponseCache>,
    ) -> Result<Vec<Finding>> {
        let mut all_findings = Vec::new();

        for du in urls {
            pb.inc(1);
            pb.set_message(format!(
                "Checking {}",
                crate::types::safe_truncate(&du.url, 50)
            ));

            // Only check GET URLs for passive scanning, unless all methods opted in.
            if !self.all_methods && du.method != "GET" {
                continue;
            }

            let findings = if let Some(c) = cache {
                if let Some(cached) = c.get(&du.url).await {
                    let mut hmap = reqwest::header::HeaderMap::new();
                    for (k, v) in &cached.headers {
                        if let (Ok(name), Ok(val)) = (
                            reqwest::header::HeaderName::from_bytes(k.as_bytes()),
                            reqwest::header::HeaderValue::from_str(v),
                        ) {
                            hmap.insert(name, val);
                        }
                    }
                    check_response_passive(&du.url, cached.status, &hmap, &cached.body)
                } else {
                    self.check_url(&du.url).await
                }
            } else {
                self.check_url(&du.url).await
            };

            if !findings.is_empty() {
                debug!("Passive findings at {}: {}", du.url, findings.len());
                all_findings.extend(findings);
            }

            // Per-origin checks (security.txt) — fire once per unique origin.
            if let Some(origin_findings) = self.check_origin_once(&du.url).await {
                all_findings.extend(origin_findings);
            }
        }

        Ok(all_findings)
    }

    /// Run origin-scoped probes once per unique origin (scheme://host[:port]).
    /// Returns `None` when the origin has already been visited.
    async fn check_origin_once(&self, url: &str) -> Option<Vec<Finding>> {
        let parsed = Url::parse(url).ok()?;
        if !matches!(parsed.scheme(), "http" | "https") {
            return None;
        }
        let origin = match parsed.port() {
            Some(p) => format!("{}://{}:{}", parsed.scheme(), parsed.host_str()?, p),
            None => format!("{}://{}", parsed.scheme(), parsed.host_str()?),
        };

        {
            let mut seen = self.seen_origins.lock().await;
            if !seen.insert(origin.clone()) {
                return None;
            }
        }

        Some(check_security_txt(&self.client, &origin).await)
    }

    async fn check_url(&self, url: &str) -> Vec<Finding> {
        let response = match self.client.get(url).send().await {
            Ok(r) => r,
            Err(_) => return vec![],
        };

        let status = response.status().as_u16();
        let headers = response.headers().clone();
        let body = response.text().await.unwrap_or_default();

        let mut findings = Vec::new();

        // Run all passive checks
        findings.extend(check_missing_security_headers(url, &headers));
        findings.extend(check_insecure_cookies(url, &headers));
        findings.extend(check_information_disclosure(url, &headers, &body));
        findings.extend(check_content_type(url, &headers));
        findings.extend(check_mixed_content(url, &body));
        findings.extend(check_sensitive_data_exposure(url, &body));
        findings.extend(check_error_messages(url, status, &body));
        findings.extend(check_cache_control(url, &headers));
        findings.extend(check_cors(url, &headers));
        findings.extend(check_csp_policy(url, &headers));
        findings.extend(check_tech_fingerprint(url, &headers, &body));
        findings.extend(check_jwt_surface(url, &body));

        findings
    }
}

/// Run all per-URL passive checks on a captured HTTP response (no network I/O).
///
/// Used by golden/integration tests (`tests/passive_golden.rs`) and mirrors
/// `PassiveScanner::check_url` without fetching the URL.
pub fn check_response_passive(
    url: &str,
    status: u16,
    headers: &reqwest::header::HeaderMap,
    body: &str,
) -> Vec<Finding> {
    let mut findings = Vec::new();
    findings.extend(check_missing_security_headers(url, headers));
    findings.extend(check_insecure_cookies(url, headers));
    findings.extend(check_information_disclosure(url, headers, body));
    findings.extend(check_content_type(url, headers));
    findings.extend(check_mixed_content(url, body));
    findings.extend(check_sensitive_data_exposure(url, body));
    findings.extend(check_error_messages(url, status, body));
    findings.extend(check_cache_control(url, headers));
    findings.extend(check_cors(url, headers));
    findings.extend(check_csp_policy(url, headers));
    findings.extend(check_tech_fingerprint(url, headers, body));
    findings.extend(check_jwt_surface(url, body));
    findings
}

/// Check for missing HTTP security headers
fn check_missing_security_headers(url: &str, headers: &reqwest::header::HeaderMap) -> Vec<Finding> {
    let mut findings = Vec::new();

    let required = vec![
        (
            "Strict-Transport-Security",
            "Missing HSTS Header",
            "The server is not enforcing HTTPS via HSTS. Browsers may allow HTTP connections.",
            "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains",
            Severity::Medium,
            16,
        ),
        (
            "X-Content-Type-Options",
            "Missing X-Content-Type-Options Header",
            "Without nosniff, browsers may MIME-sniff responses, enabling XSS attacks.",
            "Add: X-Content-Type-Options: nosniff",
            Severity::Low,
            693,
        ),
        (
            "X-Frame-Options",
            "Missing X-Frame-Options Header",
            "The page can be embedded in iframes, enabling clickjacking attacks.",
            "Add: X-Frame-Options: DENY or SAMEORIGIN",
            Severity::Medium,
            1021,
        ),
        (
            "Content-Security-Policy",
            "Missing Content-Security-Policy Header",
            "No CSP header found. XSS attacks may be more impactful.",
            "Implement a Content-Security-Policy header to restrict resource loading.",
            Severity::Medium,
            1021,
        ),
        (
            "X-XSS-Protection",
            "Missing X-XSS-Protection Header",
            "Legacy XSS filter header not present (affects older browsers).",
            "Add: X-XSS-Protection: 1; mode=block",
            Severity::Info,
            693,
        ),
        (
            "Referrer-Policy",
            "Missing Referrer-Policy Header",
            "Without a Referrer-Policy, sensitive URLs may be leaked via the Referer header.",
            "Add: Referrer-Policy: no-referrer or strict-origin-when-cross-origin",
            Severity::Low,
            116,
        ),
        (
            "Permissions-Policy",
            "Missing Permissions-Policy Header",
            "No Permissions-Policy header restricting browser feature access.",
            "Add a Permissions-Policy header to restrict access to camera, microphone, etc.",
            Severity::Info,
            693,
        ),
    ];

    for (header_name, title, desc, solution, severity, cwe) in required {
        let key = header_name.to_lowercase();
        let present = headers
            .iter()
            .any(|(k, _)| k.as_str().to_lowercase() == key);

        if !present {
            findings.push(
                Finding::new(
                    title,
                    severity,
                    url,
                    desc,
                    solution,
                    "passive/missing-headers",
                )
                .with_cwe(cwe)
                .with_owasp("A05:2021 – Security Misconfiguration"),
            );
        }
    }

    findings
}

/// Check for insecure cookie attributes
fn check_insecure_cookies(url: &str, headers: &reqwest::header::HeaderMap) -> Vec<Finding> {
    let mut findings = Vec::new();

    for (name, value) in headers.iter() {
        if name.as_str().to_lowercase() != "set-cookie" {
            continue;
        }

        let cookie_str = match value.to_str() {
            Ok(v) => v.to_lowercase(),
            Err(_) => continue,
        };

        let cookie_name: &str = value
            .to_str()
            .unwrap_or("?")
            .split('=')
            .next()
            .unwrap_or("?");

        if !cookie_str.contains("httponly") {
            findings.push(
                Finding::new(
                    "Cookie Missing HttpOnly Flag",
                    Severity::Medium,
                    url,
                    "A cookie is set without the HttpOnly flag, making it accessible via JavaScript and vulnerable to XSS-based theft.",
                    "Set the HttpOnly flag on all session cookies.",
                    "passive/cookie-flags",
                )
                .with_parameter(cookie_name)
                .with_evidence(format!("Cookie: {}", &value.to_str().unwrap_or("")[..value.to_str().unwrap_or("").len().min(100)]))
                .with_cwe(1004)
                .with_owasp("A02:2021 – Cryptographic Failures"),
            );
        }

        if !cookie_str.contains("secure") && url.starts_with("https://") {
            findings.push(
                Finding::new(
                    "Cookie Missing Secure Flag",
                    Severity::Medium,
                    url,
                    "A cookie is set without the Secure flag on an HTTPS page. It may be transmitted over HTTP.",
                    "Set the Secure flag on all session cookies when serving HTTPS.",
                    "passive/cookie-flags",
                )
                .with_parameter(cookie_name)
                .with_cwe(614)
                .with_owasp("A02:2021 – Cryptographic Failures"),
            );
        }

        if !cookie_str.contains("samesite") {
            findings.push(
                Finding::new(
                    "Cookie Missing SameSite Attribute",
                    Severity::Low,
                    url,
                    "A cookie is set without a SameSite attribute, potentially enabling CSRF attacks.",
                    "Set SameSite=Strict or SameSite=Lax on cookies.",
                    "passive/cookie-flags",
                )
                .with_parameter(cookie_name)
                .with_cwe(352)
                .with_owasp("A01:2021 – Broken Access Control"),
            );
        }
    }

    findings
}

/// Check for information disclosure in headers and body
fn check_information_disclosure(
    url: &str,
    headers: &reqwest::header::HeaderMap,
    body: &str,
) -> Vec<Finding> {
    let mut findings = Vec::new();

    // Server header disclosure
    if let Some(server) = headers.get("server") {
        if let Ok(v) = server.to_str() {
            // Check if version is disclosed
            let has_version = v.chars().any(|c| c.is_ascii_digit());
            if has_version
                || v.to_lowercase().contains("apache")
                || v.to_lowercase().contains("nginx")
                || v.to_lowercase().contains("iis")
            {
                findings.push(
                    Finding::new(
                        "Server Version Disclosed",
                        Severity::Low,
                        url,
                        "The Server header reveals version information that could aid attackers in targeting known vulnerabilities.",
                        "Configure the server to return a generic or no Server header.",
                        "passive/info-disclosure",
                    )
                    .with_evidence(format!("Server: {}", v))
                    .with_cwe(200)
                    .with_owasp("A05:2021 – Security Misconfiguration"),
                );
            }
        }
    }

    // X-Powered-By disclosure
    if let Some(xpb) = headers.get("x-powered-by") {
        if let Ok(v) = xpb.to_str() {
            findings.push(
                Finding::new(
                    "Technology Stack Disclosed via X-Powered-By",
                    Severity::Low,
                    url,
                    "The X-Powered-By header reveals the backend technology stack.",
                    "Remove the X-Powered-By header from all responses.",
                    "passive/info-disclosure",
                )
                .with_evidence(format!("X-Powered-By: {}", v))
                .with_cwe(200)
                .with_owasp("A05:2021 – Security Misconfiguration"),
            );
        }
    }

    // Stack traces / error messages in body
    let stack_indicators = [
        (
            "\tat ",
            "Stack trace detected",
            "Java/Node.js stack trace may leak internal paths",
        ),
        (
            "    at ",
            "Stack trace detected",
            "Java/Node.js stack trace may leak internal paths",
        ),
        (
            "Traceback (most recent call",
            "Python Traceback Detected",
            "Python exception traceback exposed",
        ),
        (
            "System.Exception",
            ".NET Exception Disclosed",
            ".NET exception details exposed",
        ),
        (
            "Fatal error:",
            "PHP Fatal Error",
            "PHP error message exposed",
        ),
        (
            "Warning: ",
            "PHP Warning Disclosed",
            "PHP warning message may expose internal info",
        ),
    ];

    for (pattern, title, desc) in &stack_indicators {
        if let Some(idx) = body.find(pattern) {
            let snippet = crate::types::safe_truncate(&body[idx..], 200);
            findings.push(
                Finding::new(
                    *title,
                    Severity::Medium,
                    url,
                    *desc,
                    "Disable verbose error output in production. Configure a custom error page.",
                    "passive/info-disclosure",
                )
                .with_evidence(snippet.to_string())
                .with_cwe(209)
                .with_owasp("A05:2021 – Security Misconfiguration"),
            );
            break;
        }
    }

    findings
}

/// Check Content-Type header
fn check_content_type(url: &str, headers: &reqwest::header::HeaderMap) -> Vec<Finding> {
    let mut findings = Vec::new();

    if let Some(ct) = headers.get("content-type") {
        if let Ok(v) = ct.to_str() {
            if v.contains("text/html") && !v.contains("charset") {
                findings.push(
                    Finding::new(
                        "Content-Type Missing Charset",
                        Severity::Low,
                        url,
                        "The Content-Type header for HTML does not specify a charset, which can lead to XSS via character encoding attacks.",
                        "Add charset=UTF-8 to the Content-Type header: text/html; charset=UTF-8",
                        "passive/content-type",
                    )
                    .with_evidence(format!("Content-Type: {}", v))
                    .with_cwe(116),
                );
            }
        }
    }

    findings
}

/// Check for mixed HTTP/HTTPS content
fn check_mixed_content(url: &str, body: &str) -> Vec<Finding> {
    let mut findings = Vec::new();

    if !url.starts_with("https://") {
        return findings;
    }

    let patterns = [
        r#"src\s*=\s*['"]http://"#,
        r#"href\s*=\s*['"]http://"#,
        r#"action\s*=\s*['"]http://"#,
    ];

    for pattern in &patterns {
        if let Ok(re) = regex::Regex::new(pattern) {
            if let Some(m) = re.find(body) {
                let snippet = &body[m.start()..body.len().min(m.start() + 80)];
                findings.push(
                    Finding::new(
                        "Mixed Active Content",
                        Severity::Medium,
                        url,
                        "An HTTPS page loads resources over HTTP. This enables man-in-the-middle attacks.",
                        "Update all resource URLs to use HTTPS.",
                        "passive/mixed-content",
                    )
                    .with_evidence(snippet.to_string())
                    .with_cwe(311)
                    .with_owasp("A02:2021 – Cryptographic Failures"),
                );
                break;
            }
        }
    }

    findings
}

/// Check for sensitive data in body (API keys, tokens, passwords)
fn check_sensitive_data_exposure(url: &str, body: &str) -> Vec<Finding> {
    let mut findings = Vec::new();

    let patterns: Vec<(&str, &str, Severity)> = vec![
        (
            r#"(?i)api[_-]?key\s*[=:]\s*['"]?[a-zA-Z0-9_\-]{16,}"#,
            "API Key Exposed in Response",
            Severity::High,
        ),
        (
            r#"(?i)password\s*[=:]\s*['"][^'"]{4,}"#,
            "Password Exposed in Response",
            Severity::Critical,
        ),
        (
            r#"(?i)secret[_-]?key\s*[=:]\s*['"]?[a-zA-Z0-9_\-]{16,}"#,
            "Secret Key Exposed",
            Severity::High,
        ),
        (
            r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----",
            "Private Key Exposed",
            Severity::Critical,
        ),
        (
            r#"(?i)aws_secret_access_key\s*=\s*[a-zA-Z0-9/+]{40}"#,
            "AWS Secret Key Exposed",
            Severity::Critical,
        ),
        (
            r#"(?i)Authorization:\s*Bearer\s+[a-zA-Z0-9\-_.]+\.[a-zA-Z0-9\-_.]+"#,
            "JWT Token Exposed in Body",
            Severity::High,
        ),
        (
            r#"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b"#,
            "Email Address Disclosed",
            Severity::Info,
        ),
    ];

    for (pattern, title, severity) in patterns {
        if let Ok(re) = regex::Regex::new(pattern) {
            if let Some(m) = re.find(body) {
                let snippet = &body[m.start()..body.len().min(m.start() + 60)];
                // Redact most of it
                let redacted = if snippet.len() > 20 {
                    format!("{}...[REDACTED]", &snippet[..20])
                } else {
                    snippet.to_string()
                };

                findings.push(
                    Finding::new(
                        title,
                        severity,
                        url,
                        format!("Sensitive data pattern detected in response body: {}", title),
                        "Remove sensitive data from responses. Use environment variables for secrets.",
                        "passive/sensitive-data",
                    )
                    .with_evidence(redacted)
                    .with_cwe(200)
                    .with_owasp("A02:2021 – Cryptographic Failures"),
                );
            }
        }
    }

    findings
}

/// Check for verbose error messages
fn check_error_messages(url: &str, status: u16, body: &str) -> Vec<Finding> {
    let mut findings = Vec::new();

    if status >= 500 {
        let has_stack =
            body.contains("Exception") || body.contains("Traceback") || body.contains("Error:");
        if has_stack {
            findings.push(
                Finding::new(
                    "Verbose Server Error Message",
                    Severity::Medium,
                    url,
                    format!("Server returned HTTP {} with a verbose error message that may disclose internal information.", status),
                    "Return generic error pages in production. Log detailed errors server-side only.",
                    "passive/error-disclosure",
                )
                .with_cwe(209)
                .with_owasp("A05:2021 – Security Misconfiguration"),
            );
        }
    }

    findings
}

/// Check cache control headers
fn check_cache_control(url: &str, headers: &reqwest::header::HeaderMap) -> Vec<Finding> {
    let mut findings = Vec::new();

    let cc = headers
        .get("cache-control")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_lowercase();
    let pragma = headers
        .get("pragma")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_lowercase();

    if !cc.contains("no-store") && !cc.contains("private") && !pragma.contains("no-cache") {
        // Only flag HTML/JSON pages, not static assets
        let ct = headers
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        if ct.contains("text/html") || ct.contains("application/json") {
            findings.push(
                Finding::new(
                    "Sensitive Page May Be Cached",
                    Severity::Low,
                    url,
                    "The response does not set cache-control: no-store, meaning sensitive content could be cached by proxies or browsers.",
                    "Set Cache-Control: no-store, private for pages with sensitive content.",
                    "passive/cache-control",
                )
                .with_cwe(525)
                .with_owasp("A02:2021 – Cryptographic Failures"),
            );
        }
    }

    findings
}

/// Check for CORS misconfigurations
fn check_cors(url: &str, headers: &reqwest::header::HeaderMap) -> Vec<Finding> {
    let mut findings = Vec::new();

    if let Some(acao) = headers.get("access-control-allow-origin") {
        if let Ok(v) = acao.to_str() {
            if v == "*" {
                findings.push(
                    Finding::new(
                        "Wildcard CORS Policy",
                        Severity::Medium,
                        url,
                        "The server returns Access-Control-Allow-Origin: * which allows any origin to make cross-origin requests.",
                        "Restrict CORS to known, trusted origins. Avoid wildcard for authenticated endpoints.",
                        "passive/cors",
                    )
                    .with_evidence("Access-Control-Allow-Origin: *")
                    .with_cwe(942)
                    .with_owasp("A05:2021 – Security Misconfiguration"),
                );
            }

            // Check if credentials are allowed with wildcard
            if v == "*" {
                if let Some(creds) = headers.get("access-control-allow-credentials") {
                    if creds.to_str().unwrap_or("") == "true" {
                        findings.push(
                            Finding::new(
                                "CORS Wildcard with Credentials",
                                Severity::High,
                                url,
                                "The server allows credentials with a wildcard CORS policy. This is a browser security violation but can be exploited.",
                                "Never use wildcard ACAO with credentials. Specify exact trusted origins.",
                                "passive/cors",
                            )
                            .with_cwe(942)
                            .with_owasp("A01:2021 – Broken Access Control"),
                        );
                    }
                }
            }
        }
    }

    findings
}

// ─────────────────────────────────────────────────────────────────────────────
// A1. security.txt probe (RFC 9116)
// ─────────────────────────────────────────────────────────────────────────────

/// Parsed view of a security.txt file. Only the fields we care about.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct SecurityTxtInfo {
    pub contacts: Vec<String>,
    pub expires: Option<String>,
    pub canonical: Vec<String>,
    pub policy: Option<String>,
}

/// Parse a security.txt body into a structured form. Comments (`#`) and blank
/// lines are ignored. Field names are case-insensitive per RFC 9116 §2.2.
pub fn parse_security_txt(body: &str) -> SecurityTxtInfo {
    let mut info = SecurityTxtInfo::default();
    for raw in body.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let key = name.trim().to_lowercase();
        let val = value.trim().to_string();
        if val.is_empty() {
            continue;
        }
        match key.as_str() {
            "contact" => info.contacts.push(val),
            "expires" => info.expires = Some(val),
            "canonical" => info.canonical.push(val),
            "policy" => info.policy = Some(val),
            _ => {}
        }
    }
    info
}

/// Returns true when `expires` is in the past relative to `now_rfc3339`.
/// Best-effort parse — if the value is malformed we conservatively return
/// `false` and surface a separate finding via the caller.
pub fn security_txt_expires_in_past(expires: &str, now: chrono::DateTime<chrono::Utc>) -> bool {
    chrono::DateTime::parse_from_rfc3339(expires)
        .map(|dt| dt.with_timezone(&chrono::Utc) < now)
        .unwrap_or(false)
}

/// Fetch `/.well-known/security.txt` (with a fallback to `/security.txt`) and
/// produce findings about presence / freshness / contact info.
pub async fn check_security_txt(client: &reqwest::Client, origin: &str) -> Vec<Finding> {
    let primary = format!("{}/.well-known/security.txt", origin.trim_end_matches('/'));
    let fallback = format!("{}/security.txt", origin.trim_end_matches('/'));

    let (status, body, url_used) = match fetch_text(client, &primary).await {
        Some((200, body)) => (200u16, body, primary),
        Some((status, _)) => {
            // Try root-level fallback only when the well-known path is missing.
            if status == 404 {
                match fetch_text(client, &fallback).await {
                    Some((200, body)) => (200, body, fallback),
                    Some((s, _)) => (s, String::new(), primary),
                    None => return vec![],
                }
            } else {
                (status, String::new(), primary)
            }
        }
        None => return vec![],
    };

    evaluate_security_txt(&url_used, status, &body, chrono::Utc::now())
}

/// Pure evaluator — takes the response we already fetched and returns the
/// findings list. Split out so it is unit-testable without HTTP.
pub fn evaluate_security_txt(
    url: &str,
    status: u16,
    body: &str,
    now: chrono::DateTime<chrono::Utc>,
) -> Vec<Finding> {
    let mut findings = Vec::new();

    if status == 404 {
        findings.push(
            Finding::new(
                "security.txt Missing",
                Severity::Info,
                url,
                "No security.txt file was found at /.well-known/security.txt. RFC 9116 recommends publishing one so researchers can reach the security team.",
                "Publish a security.txt at /.well-known/security.txt with at least a Contact field and an Expires date.",
                "passive/security-txt",
            )
            .with_owasp("A05:2021 – Security Misconfiguration"),
        );
        return findings;
    }

    if status != 200 {
        return findings;
    }

    let info = parse_security_txt(body);

    if info.contacts.is_empty() {
        findings.push(
            Finding::new(
                "security.txt Missing Contact Field",
                Severity::Low,
                url,
                "A security.txt file is served but contains no Contact field. RFC 9116 requires at least one Contact entry.",
                "Add one or more Contact lines (mailto:, tel:, or https: URI) to security.txt.",
                "passive/security-txt",
            )
            .with_owasp("A05:2021 – Security Misconfiguration"),
        );
    }

    match info.expires.as_deref() {
        None => findings.push(
            Finding::new(
                "security.txt Missing Expires",
                Severity::Low,
                url,
                "A security.txt file is served but has no Expires field. RFC 9116 §2.5.5 requires this field to bound the file's validity.",
                "Add an Expires line with an RFC 3339 timestamp (e.g. 2026-12-31T00:00:00Z).",
                "passive/security-txt",
            )
            .with_owasp("A05:2021 – Security Misconfiguration"),
        ),
        Some(expires) if security_txt_expires_in_past(expires, now) => findings.push(
            Finding::new(
                "security.txt Expired",
                Severity::Medium,
                url,
                "The Expires field in security.txt is in the past. Researchers may treat the contact information as stale.",
                "Update the Expires field and rotate the document at least annually.",
                "passive/security-txt",
            )
            .with_evidence(format!("Expires: {}", expires))
            .with_owasp("A05:2021 – Security Misconfiguration"),
        ),
        _ => {}
    }

    findings
}

async fn fetch_text(client: &reqwest::Client, url: &str) -> Option<(u16, String)> {
    let resp = client
        .get(url)
        .timeout(Duration::from_secs(6))
        .send()
        .await
        .ok()?;
    let status = resp.status().as_u16();
    let body = resp.text().await.unwrap_or_default();
    Some((status, body))
}

// ─────────────────────────────────────────────────────────────────────────────
// A6. Deep CSP review
// ─────────────────────────────────────────────────────────────────────────────

/// Parse a CSP header value into `(directive, [source...])` tuples.
/// Directive names are lowercased; values are returned verbatim (trimmed).
pub fn parse_csp_directives(value: &str) -> Vec<(String, Vec<String>)> {
    value
        .split(';')
        .filter_map(|part| {
            let part = part.trim();
            if part.is_empty() {
                return None;
            }
            let mut tokens = part.split_whitespace();
            let directive = tokens.next()?.to_lowercase();
            let sources: Vec<String> = tokens.map(|t| t.to_string()).collect();
            Some((directive, sources))
        })
        .collect()
}

/// Inspect each `Content-Security-Policy` / `Content-Security-Policy-Report-Only`
/// header for risky tokens (`unsafe-inline`, `unsafe-eval`, wildcard sources,
/// `data:` in script-src). Returns one finding per (directive, issue) pair.
pub fn check_csp_policy(url: &str, headers: &reqwest::header::HeaderMap) -> Vec<Finding> {
    let mut findings = Vec::new();

    for header_name in &[
        "content-security-policy",
        "content-security-policy-report-only",
    ] {
        let report_only = header_name.ends_with("report-only");
        let values: Vec<_> = headers.get_all(*header_name).iter().collect();
        for value in values {
            let Ok(text) = value.to_str() else { continue };
            for (directive, sources) in parse_csp_directives(text) {
                findings.extend(evaluate_csp_directive(
                    url,
                    &directive,
                    &sources,
                    report_only,
                ));
            }
        }
    }

    findings
}

fn evaluate_csp_directive(
    url: &str,
    directive: &str,
    sources: &[String],
    report_only: bool,
) -> Vec<Finding> {
    let mut findings = Vec::new();
    let suffix = if report_only { " (Report-Only)" } else { "" };

    let is_script_like = matches!(
        directive,
        "script-src" | "script-src-elem" | "script-src-attr" | "default-src"
    );
    let is_style_like = matches!(directive, "style-src" | "style-src-elem" | "style-src-attr");
    let is_fetch_like = is_script_like
        || is_style_like
        || matches!(
            directive,
            "img-src"
                | "media-src"
                | "object-src"
                | "frame-src"
                | "connect-src"
                | "font-src"
                | "worker-src"
                | "manifest-src"
        );

    for src in sources {
        let lower = src.to_lowercase();
        let lower = lower.trim_matches('\'').to_string();
        match lower.as_str() {
            "unsafe-inline" if is_script_like => findings.push(
                Finding::new(
                    format!("CSP allows 'unsafe-inline' in {}{}", directive, suffix),
                    if report_only { Severity::Low } else { Severity::Medium },
                    url,
                    "The CSP directive permits inline scripts, defeating most of CSP's XSS mitigation.",
                    "Remove 'unsafe-inline'. Use nonces or hashes to allow specific inline blocks.",
                    "passive/csp-unsafe-directives",
                )
                .with_evidence(format!("{} {}", directive, src))
                .with_cwe(693)
                .with_owasp("A05:2021 – Security Misconfiguration"),
            ),
            "unsafe-inline" if is_style_like => findings.push(
                Finding::new(
                    format!("CSP allows 'unsafe-inline' in {}{}", directive, suffix),
                    Severity::Low,
                    url,
                    "Inline styles are permitted. Limited XSS impact but still relaxes CSP guarantees.",
                    "Avoid inline styles or use a nonce.",
                    "passive/csp-unsafe-directives",
                )
                .with_evidence(format!("{} {}", directive, src)),
            ),
            "unsafe-eval" if is_script_like => findings.push(
                Finding::new(
                    format!("CSP allows 'unsafe-eval' in {}{}", directive, suffix),
                    if report_only { Severity::Low } else { Severity::Medium },
                    url,
                    "The CSP directive permits eval() and similar dynamic code evaluation, expanding the XSS attack surface.",
                    "Remove 'unsafe-eval'. Refactor any runtime code generation.",
                    "passive/csp-unsafe-directives",
                )
                .with_evidence(format!("{} {}", directive, src))
                .with_cwe(95)
                .with_owasp("A05:2021 – Security Misconfiguration"),
            ),
            "*" if is_fetch_like => findings.push(
                Finding::new(
                    format!("CSP wildcard '*' in {}{}", directive, suffix),
                    if is_script_like {
                        Severity::High
                    } else {
                        Severity::Low
                    },
                    url,
                    "A wildcard source allows resources from any origin, neutralising the directive.",
                    "Pin allowed origins explicitly. Avoid '*' in fetch directives.",
                    "passive/csp-unsafe-directives",
                )
                .with_evidence(format!("{} {}", directive, src))
                .with_owasp("A05:2021 – Security Misconfiguration"),
            ),
            _ if is_script_like && lower == "data:" => findings.push(
                Finding::new(
                    format!("CSP allows 'data:' in {}{}", directive, suffix),
                    Severity::Medium,
                    url,
                    "Allowing data: URIs as a script source enables attackers to craft payloads inline.",
                    "Remove data: from script source lists; serve scripts from trusted origins only.",
                    "passive/csp-unsafe-directives",
                )
                .with_evidence(format!("{} {}", directive, src))
                .with_owasp("A05:2021 – Security Misconfiguration"),
            ),
            _ => {}
        }
    }

    if directive == "object-src" && sources.iter().all(|s| s.trim_matches('\'') != "none") {
        findings.push(
            Finding::new(
                format!("CSP object-src is not 'none'{}", suffix),
                Severity::Low,
                url,
                "object-src allows plugins (Flash, Java) to load, which can be abused for XSS or content injection.",
                "Set object-src 'none' unless plugins are required.",
                "passive/csp-unsafe-directives",
            )
            .with_owasp("A05:2021 – Security Misconfiguration"),
        );
    }

    findings
}

// ─────────────────────────────────────────────────────────────────────────────
// B1. Tech-stack fingerprint
// ─────────────────────────────────────────────────────────────────────────────

/// Collect tech-stack signals from headers and body markers and emit a single
/// informational finding so platform-side correlation has a stable shape.
pub fn check_tech_fingerprint(
    url: &str,
    headers: &reqwest::header::HeaderMap,
    body: &str,
) -> Vec<Finding> {
    let signals = collect_tech_signals(headers, body);
    if signals.is_empty() {
        return vec![];
    }

    // Truncate evidence — some sites stuff X-Powered-By with long banners.
    let evidence: Vec<String> = signals.iter().take(20).cloned().collect();
    let evidence_str = evidence.join(", ");

    vec![
        Finding::new(
            "Technology Stack Fingerprint",
            Severity::Info,
            url,
            "The response leaks information about the underlying technology stack via headers, generators, or script paths. By itself this is informational; combined with known CVEs it accelerates exploitation.",
            "Strip Server, X-Powered-By, X-AspNet-Version and similar headers; remove generator meta tags; avoid versioned asset paths.",
            "passive/tech-fingerprint",
        )
        .with_evidence(evidence_str)
        .with_cwe(200)
        .with_owasp("A05:2021 – Security Misconfiguration"),
    ]
}

/// Pure collector — testable without a real HTTP response.
pub fn collect_tech_signals(headers: &reqwest::header::HeaderMap, body: &str) -> Vec<String> {
    let mut signals: Vec<String> = Vec::new();
    let mut push = |s: String| {
        if !signals.contains(&s) {
            signals.push(s);
        }
    };

    let header_signals = [
        "server",
        "x-powered-by",
        "x-aspnet-version",
        "x-aspnetmvc-version",
        "x-generator",
        "x-drupal-cache",
        "x-runtime",
        "x-rails-version",
        "x-shopify-stage",
        "via",
    ];
    for h in header_signals {
        if let Some(v) = headers.get(h).and_then(|v| v.to_str().ok()) {
            push(format!("{}: {}", h, v.trim()));
        }
    }

    // Body markers — kept tight so we don't false-positive on user content.
    let body_markers: &[(&str, &str)] = &[
        (
            "<meta name=\"generator\" content=\"WordPress",
            "WordPress (generator meta)",
        ),
        ("/wp-content/", "WordPress (asset path)"),
        (
            "<meta name=\"generator\" content=\"Drupal",
            "Drupal (generator meta)",
        ),
        ("/sites/default/files/", "Drupal (asset path)"),
        (
            "<meta name=\"generator\" content=\"Joomla",
            "Joomla (generator meta)",
        ),
        ("__NEXT_DATA__", "Next.js"),
        ("data-reactroot", "React (legacy SSR marker)"),
        ("ng-version=", "Angular"),
        ("__NUXT__", "Nuxt.js"),
        ("data-vue-meta", "Vue.js"),
        ("Powered by Discourse", "Discourse"),
        ("var Shopify =", "Shopify"),
        ("/_next/static/", "Next.js (build asset)"),
    ];
    for (needle, label) in body_markers {
        if body.contains(needle) {
            push((*label).to_string());
        }
    }

    signals
}

// ─────────────────────────────────────────────────────────────────────────────
// B3. JWT surface inspection
// ─────────────────────────────────────────────────────────────────────────────

/// Heuristic JWT detection in response bodies. Emits one finding per distinct
/// JWT shape (`header.payload.signature` base64url segments), with the
/// signature redacted in evidence.
pub fn check_jwt_surface(url: &str, body: &str) -> Vec<Finding> {
    let mut findings = Vec::new();
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();

    // Tight pattern: header starts with eyJ, three base64url segments separated by `.`.
    let re = match regex::Regex::new(r"eyJ[a-zA-Z0-9_-]{8,}\.[a-zA-Z0-9_-]{8,}\.[a-zA-Z0-9_-]{8,}")
    {
        Ok(r) => r,
        Err(_) => return findings,
    };

    for m in re.find_iter(body) {
        let token = m.as_str();
        if !seen.insert(token.to_string()) {
            continue;
        }
        let issues = analyze_jwt(token);
        if issues.is_empty() {
            continue;
        }

        let redacted = redact_jwt(token);
        for issue in issues {
            findings.push(
                Finding::new(
                    format!("JWT Issue: {}", issue.label),
                    issue.severity,
                    url,
                    issue.description,
                    issue.solution,
                    "passive/jwt-heuristic",
                )
                .with_evidence(redacted.clone())
                .with_cwe(347)
                .with_owasp("A02:2021 – Cryptographic Failures"),
            );
        }
        if findings.len() >= 5 {
            break; // Cap output even if many tokens are present.
        }
    }

    findings
}

pub struct JwtIssue {
    pub label: &'static str,
    pub severity: Severity,
    pub description: &'static str,
    pub solution: &'static str,
}

/// Decode the header + payload (best-effort base64url) and produce a list of
/// issues. Pure / testable.
pub fn analyze_jwt(token: &str) -> Vec<JwtIssue> {
    let mut issues = Vec::new();
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return issues;
    }
    let header_json = decode_jwt_segment(parts[0]).unwrap_or_default();
    let payload_json = decode_jwt_segment(parts[1]).unwrap_or_default();

    let header_lower = header_json.to_lowercase();
    if header_lower.contains("\"alg\":\"none\"") || header_lower.contains("\"alg\": \"none\"") {
        issues.push(JwtIssue {
            label: "alg=none",
            severity: Severity::High,
            description: "A JWT in the response advertises 'alg':'none', meaning no signature is required. If accepted server-side, anyone can forge tokens.",
            solution: "Reject 'alg':'none'. Pin acceptable algorithms (e.g. RS256/ES256) and validate them server-side.",
        });
    }
    if header_lower.contains("\"alg\":\"hs256\"") && payload_json.to_lowercase().contains("admin") {
        issues.push(JwtIssue {
            label: "HS256 admin token in body",
            severity: Severity::Medium,
            description: "An HS256-signed JWT containing 'admin' claim is present in a response body. HS256 keys are easier to brute-force than asymmetric algorithms.",
            solution: "Move privileged tokens out of response bodies. Consider RS256/ES256 for admin tokens.",
        });
    }

    // Expiry checks on payload.
    let exp = parse_jwt_number_claim(&payload_json, "exp");
    let iat = parse_jwt_number_claim(&payload_json, "iat");

    match exp {
        None => issues.push(JwtIssue {
            label: "missing 'exp'",
            severity: Severity::Medium,
            description: "The JWT carries no expiration claim. Tokens without 'exp' are valid forever once issued.",
            solution: "Add an 'exp' claim and reject tokens missing it.",
        }),
        Some(e) => {
            // 1 year = 31_536_000 seconds.
            if let Some(i) = iat {
                if e.saturating_sub(i) > 31_536_000 {
                    issues.push(JwtIssue {
                        label: "lifetime > 1 year",
                        severity: Severity::Low,
                        description: "The JWT lifetime exceeds one year. Long-lived tokens magnify the blast radius of any leak.",
                        solution: "Reduce token lifetime. Use refresh tokens for long sessions.",
                    });
                }
            }
        }
    }

    issues
}

fn decode_jwt_segment(seg: &str) -> Option<String> {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
    // Some encoders include padding; try both variants.
    let cleaned = seg.trim_end_matches('=');
    let bytes = URL_SAFE_NO_PAD
        .decode(cleaned)
        .or_else(|_| base64::engine::general_purpose::URL_SAFE.decode(seg))
        .ok()?;
    String::from_utf8(bytes).ok()
}

fn parse_jwt_number_claim(json: &str, key: &str) -> Option<i64> {
    // Minimal extractor: looks for `"key":<digits>` and parses the digits.
    // Avoids pulling in serde_json for body that is already untrusted noise.
    let needle = format!("\"{}\":", key);
    let idx = json.find(&needle)?;
    let after = &json[idx + needle.len()..];
    let trimmed = after.trim_start();
    let digits: String = trimmed.chars().take_while(|c| c.is_ascii_digit()).collect();
    digits.parse().ok()
}

fn redact_jwt(token: &str) -> String {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return "[REDACTED]".into();
    }
    let head = &parts[0][..parts[0].len().min(12)];
    let pay = &parts[1][..parts[1].len().min(12)];
    format!("{}…—{}…—[signature REDACTED]", head, pay)
}

/// Canonical list of plugin ids the passive scanner can emit. Used by the
/// scanner to surface modules that ran quietly (see SDD §9.1).
pub fn known_plugin_names() -> &'static [&'static str] {
    &[
        "passive/missing-headers",
        "passive/cookie-flags",
        "passive/info-disclosure",
        "passive/content-type",
        "passive/mixed-content",
        "passive/sensitive-data",
        "passive/error-disclosure",
        "passive/cache-control",
        "passive/cors",
        "passive/csp-unsafe-directives",
        "passive/tech-fingerprint",
        "passive/jwt-heuristic",
        "passive/security-txt",
    ]
}

/// CLI entry point for passive-only scan
pub async fn run_passive_cli(input: &str, output: &str) -> Result<()> {
    use indicatif::{ProgressBar, ProgressStyle};

    println!(
        "{} {}",
        "▶ Passive scan:".bright_white().bold(),
        input.bright_cyan()
    );

    let client = Arc::new(
        reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .user_agent("RustZAP/0.1 Passive Scanner")
            .build()?,
    );

    let urls = vec![crate::types::DiscoveredUrl {
        url: input.to_string(),
        method: "GET".to_string(),
        headers: Vec::new(),
        body: None,
        content_type: None,
        parameters: vec![],
        source: crate::types::UrlSource::Seed,
    }];

    let pb = ProgressBar::new(1);
    pb.set_style(
        ProgressStyle::default_bar()
            .template("{prefix:.bold} [{bar:40.green}] {pos}/{len}")
            .unwrap(),
    );
    pb.set_prefix("PASSIVE");

    let scanner = PassiveScanner::new(client);
    let findings = scanner.scan_all(&urls, &pb).await?;
    pb.finish();

    for f in &findings {
        println!("  {} {}", f.severity.color_str(), f.title.bright_white());
    }

    let json = serde_json::to_string_pretty(&findings)?;
    tokio::fs::write(output, json).await?;
    println!("\n{} {}", "✓ Saved to:".bright_green(), output);

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{TimeZone, Utc};
    use reqwest::header::{HeaderMap, HeaderName, HeaderValue};

    fn headers_from(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut h = HeaderMap::new();
        for (k, v) in pairs {
            h.append(
                HeaderName::from_bytes(k.as_bytes()).unwrap(),
                HeaderValue::from_str(v).unwrap(),
            );
        }
        h
    }

    // ── A1 security.txt ────────────────────────────────────────────────

    #[test]
    fn parse_security_txt_extracts_required_fields() {
        let body = "# Our security.txt\n\
Contact: mailto:security@example.com\n\
Contact: https://example.com/security\n\
Expires: 2030-01-01T00:00:00Z\n\
Canonical: https://example.com/.well-known/security.txt\n\
Policy: https://example.com/policy\n";
        let info = parse_security_txt(body);
        assert_eq!(info.contacts.len(), 2);
        assert_eq!(info.contacts[0], "mailto:security@example.com");
        assert_eq!(info.expires.as_deref(), Some("2030-01-01T00:00:00Z"));
        assert_eq!(
            info.canonical,
            vec!["https://example.com/.well-known/security.txt"]
        );
        assert_eq!(info.policy.as_deref(), Some("https://example.com/policy"));
    }

    #[test]
    fn parse_security_txt_handles_case_and_blank_lines() {
        let body = "\n\nCONTACT:  mailto:a@example.com  \n\n";
        let info = parse_security_txt(body);
        assert_eq!(info.contacts, vec!["mailto:a@example.com"]);
    }

    #[test]
    fn security_txt_expires_in_past_detects_stale() {
        let now = Utc.with_ymd_and_hms(2026, 5, 1, 0, 0, 0).unwrap();
        assert!(security_txt_expires_in_past("2025-01-01T00:00:00Z", now));
        assert!(!security_txt_expires_in_past("2099-01-01T00:00:00Z", now));
        // Malformed → conservatively false; the caller emits a separate finding.
        assert!(!security_txt_expires_in_past("not-a-date", now));
    }

    #[test]
    fn evaluate_security_txt_flags_404() {
        let now = Utc::now();
        let findings =
            evaluate_security_txt("https://example.com/.well-known/security.txt", 404, "", now);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].plugin, "passive/security-txt");
        assert_eq!(findings[0].severity, Severity::Info);
    }

    #[test]
    fn evaluate_security_txt_flags_missing_expires() {
        let now = Utc::now();
        let body = "Contact: mailto:security@example.com\n";
        let findings = evaluate_security_txt(
            "https://example.com/.well-known/security.txt",
            200,
            body,
            now,
        );
        assert!(findings.iter().any(|f| f.title.contains("Missing Expires")));
    }

    #[test]
    fn evaluate_security_txt_flags_expired_and_missing_contact() {
        let now = Utc.with_ymd_and_hms(2026, 5, 1, 0, 0, 0).unwrap();
        let body = "Expires: 2024-01-01T00:00:00Z\n";
        let findings = evaluate_security_txt(
            "https://example.com/.well-known/security.txt",
            200,
            body,
            now,
        );
        assert!(findings.iter().any(|f| f.title.contains("Expired")));
        assert!(findings
            .iter()
            .any(|f| f.title.contains("Missing Contact Field")));
    }

    #[test]
    fn evaluate_security_txt_quiet_when_healthy() {
        let now = Utc.with_ymd_and_hms(2026, 5, 1, 0, 0, 0).unwrap();
        let body = "Contact: mailto:sec@example.com\nExpires: 2099-01-01T00:00:00Z\n";
        let findings = evaluate_security_txt(
            "https://example.com/.well-known/security.txt",
            200,
            body,
            now,
        );
        assert!(findings.is_empty(), "got: {:?}", findings);
    }

    // ── A6 CSP ─────────────────────────────────────────────────────────

    #[test]
    fn parse_csp_handles_multiple_directives() {
        let parsed =
            parse_csp_directives("default-src 'self'; script-src 'self' 'unsafe-inline'; ");
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].0, "default-src");
        assert_eq!(parsed[0].1, vec!["'self'"]);
        assert_eq!(parsed[1].0, "script-src");
        assert_eq!(parsed[1].1, vec!["'self'", "'unsafe-inline'"]);
    }

    #[test]
    fn csp_flags_unsafe_inline_and_eval() {
        let headers = headers_from(&[(
            "content-security-policy",
            "script-src 'self' 'unsafe-inline' 'unsafe-eval'",
        )]);
        let findings = check_csp_policy("https://example.com", &headers);
        assert!(findings.iter().any(|f| f.title.contains("'unsafe-inline'")));
        assert!(findings.iter().any(|f| f.title.contains("'unsafe-eval'")));
    }

    #[test]
    fn csp_flags_wildcard_in_script_src_as_high() {
        let headers = headers_from(&[("content-security-policy", "script-src *")]);
        let findings = check_csp_policy("https://example.com", &headers);
        let wildcard = findings
            .iter()
            .find(|f| f.title.contains("wildcard"))
            .expect("expected wildcard finding");
        assert_eq!(wildcard.severity, Severity::High);
    }

    #[test]
    fn csp_report_only_downgrades_severity() {
        let headers = headers_from(&[(
            "content-security-policy-report-only",
            "script-src 'unsafe-inline'",
        )]);
        let findings = check_csp_policy("https://example.com", &headers);
        let f = findings
            .iter()
            .find(|f| f.title.contains("'unsafe-inline'"))
            .expect("expected unsafe-inline finding");
        assert!(f.title.contains("(Report-Only)"));
        assert_eq!(f.severity, Severity::Low);
    }

    #[test]
    fn csp_flags_non_none_object_src() {
        let headers = headers_from(&[("content-security-policy", "object-src 'self'")]);
        let findings = check_csp_policy("https://example.com", &headers);
        assert!(findings
            .iter()
            .any(|f| f.title.starts_with("CSP object-src is not 'none'")));
    }

    #[test]
    fn csp_quiet_when_strict() {
        let headers = headers_from(&[(
            "content-security-policy",
            "default-src 'self'; object-src 'none'; script-src 'self'",
        )]);
        let findings = check_csp_policy("https://example.com", &headers);
        assert!(findings.is_empty(), "got: {:?}", findings);
    }

    // ── B1 tech fingerprint ────────────────────────────────────────────

    #[test]
    fn tech_fingerprint_picks_up_header_signals() {
        let headers = headers_from(&[("server", "nginx/1.21.0"), ("x-powered-by", "PHP/8.1.2")]);
        let signals = collect_tech_signals(&headers, "");
        assert!(signals.iter().any(|s| s.contains("nginx/1.21.0")));
        assert!(signals.iter().any(|s| s.contains("PHP/8.1.2")));
    }

    #[test]
    fn tech_fingerprint_picks_up_body_markers() {
        let body = r#"<html><head><meta name="generator" content="WordPress 6.4"></head>
<body><script src="/wp-content/plugins/foo.js"></script></body></html>"#;
        let signals = collect_tech_signals(&HeaderMap::new(), body);
        assert!(signals.iter().any(|s| s.contains("WordPress")));
    }

    #[test]
    fn tech_fingerprint_returns_nothing_when_clean() {
        let signals = collect_tech_signals(&HeaderMap::new(), "<html><body>hello</body></html>");
        assert!(signals.is_empty());
    }

    #[test]
    fn check_tech_fingerprint_emits_one_finding() {
        let headers = headers_from(&[("server", "nginx/1.21.0")]);
        let findings = check_tech_fingerprint("https://example.com", &headers, "");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Info);
    }

    // ── B3 JWT ─────────────────────────────────────────────────────────

    #[test]
    fn jwt_detects_alg_none() {
        // alg=none, no signature meaning, payload trivial.
        // header: {"alg":"none","typ":"JWT"}
        // payload: {"sub":"user","exp":1700000000}
        let token = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJ1c2VyIiwiZXhwIjoxNzAwMDAwMDAwfQ.signaturevalue123";
        let issues = analyze_jwt(token);
        assert!(issues.iter().any(|i| i.label == "alg=none"));
    }

    #[test]
    fn jwt_detects_missing_exp() {
        // header: {"alg":"HS256","typ":"JWT"}
        // payload: {"sub":"user"}
        let token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyIn0.signaturepart12345";
        let issues = analyze_jwt(token);
        assert!(issues.iter().any(|i| i.label == "missing 'exp'"));
    }

    #[test]
    fn jwt_detects_long_lifetime() {
        // iat = 1_700_000_000, exp = iat + 2 years
        // payload: {"iat":1700000000,"exp":1763072000}
        let token = "eyJhbGciOiJIUzI1NiJ9.eyJpYXQiOjE3MDAwMDAwMDAsImV4cCI6MTc2MzA3MjAwMH0.sig123";
        let issues = analyze_jwt(token);
        assert!(issues.iter().any(|i| i.label == "lifetime > 1 year"));
    }

    #[test]
    fn jwt_quiet_for_well_formed_short_lived() {
        // iat = 1_700_000_000, exp = iat + 1 hour. HS256, no admin.
        // payload: {"iat":1700000000,"exp":1700003600}
        let token = "eyJhbGciOiJIUzI1NiJ9.eyJpYXQiOjE3MDAwMDAwMDAsImV4cCI6MTcwMDAwMzYwMH0.sig123";
        let issues = analyze_jwt(token);
        assert!(
            issues.is_empty(),
            "expected no issues, got: {:?}",
            issues.iter().map(|i| i.label).collect::<Vec<_>>()
        );
    }

    #[test]
    fn jwt_surface_redacts_signature() {
        let body =
            r#"{"token":"eyJhbGciOiJub25lIn0.eyJzdWIiOiJ1c2VyIn0.somesignatureGoesHere1234"}"#;
        let findings = check_jwt_surface("https://example.com", body);
        assert!(!findings.is_empty());
        for f in &findings {
            let ev = f.evidence.as_deref().unwrap_or("");
            assert!(!ev.contains("somesignatureGoesHere1234"));
            assert!(ev.contains("REDACTED"));
        }
    }
}
