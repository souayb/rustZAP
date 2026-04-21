use std::sync::Arc;

use anyhow::Result;
use colored::*;
use indicatif::ProgressBar;
use tracing::debug;

use crate::types::{DiscoveredUrl, Finding, Severity};

pub struct PassiveScanner {
    client: Arc<reqwest::Client>,
}

impl PassiveScanner {
    pub fn new(client: Arc<reqwest::Client>) -> Self {
        PassiveScanner { client }
    }

    /// Run all passive checks against discovered URLs
    pub async fn scan_all(
        &self,
        urls: &[DiscoveredUrl],
        pb: &ProgressBar,
    ) -> Result<Vec<Finding>> {
        let mut all_findings = Vec::new();

        for du in urls {
            pb.inc(1);
            pb.set_message(format!("Checking {}", &du.url[..du.url.len().min(50)]));

            // Only check GET URLs for passive scanning
            if du.method != "GET" {
                continue;
            }

            let findings = self.check_url(&du.url).await;
            if !findings.is_empty() {
                debug!("Passive findings at {}: {}", du.url, findings.len());
                all_findings.extend(findings);
            }
        }

        Ok(all_findings)
    }

    async fn check_url(&self, url: &str) -> Vec<Finding> {
        let response = match self.client.get(url).send().await {
            Ok(r) => r,
            Err(_) => return vec![],
        };

        let status = response.status().as_u16();
        let headers = response.headers().clone();
        let body = match response.text().await {
            Ok(b) => b,
            Err(_) => String::new(),
        };

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

        findings
    }
}

/// Check for missing HTTP security headers
fn check_missing_security_headers(
    url: &str,
    headers: &reqwest::header::HeaderMap,
) -> Vec<Finding> {
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
                Finding::new(title, severity, url, desc, solution, "passive/missing-headers")
                    .with_cwe(cwe)
                    .with_owasp("A05:2021 – Security Misconfiguration"),
            );
        }
    }

    findings
}

/// Check for insecure cookie attributes
fn check_insecure_cookies(
    url: &str,
    headers: &reqwest::header::HeaderMap,
) -> Vec<Finding> {
    let mut findings = Vec::new();

    for (name, value) in headers.iter() {
        if name.as_str().to_lowercase() != "set-cookie" {
            continue;
        }

        let cookie_str = match value.to_str() {
            Ok(v) => v.to_lowercase(),
            Err(_) => continue,
        };

        let cookie_name: &str = value.to_str().unwrap_or("?").split('=').next().unwrap_or("?");

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
            if has_version || v.to_lowercase().contains("apache") || v.to_lowercase().contains("nginx") || v.to_lowercase().contains("iis") {
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
        ("at ", "Stack trace detected", "Java/Node.js stack trace may leak internal paths"),
        ("Traceback (most recent call", "Python Traceback Detected", "Python exception traceback exposed"),
        ("System.Exception", ".NET Exception Disclosed", ".NET exception details exposed"),
        ("Fatal error:", "PHP Fatal Error", "PHP error message exposed"),
        ("Warning: ", "PHP Warning Disclosed", "PHP warning message may expose internal info"),
    ];

    for (pattern, title, desc) in &stack_indicators {
        if body.contains(pattern) {
            let idx = body.find(pattern).unwrap_or(0);
            let snippet = &body[idx..body.len().min(idx + 200)];
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
        (r#"(?i)api[_-]?key\s*[=:]\s*['"]?[a-zA-Z0-9_\-]{16,}"#, "API Key Exposed in Response", Severity::High),
        (r#"(?i)password\s*[=:]\s*['"][^'"]{4,}"#, "Password Exposed in Response", Severity::Critical),
        (r#"(?i)secret[_-]?key\s*[=:]\s*['"]?[a-zA-Z0-9_\-]{16,}"#, "Secret Key Exposed", Severity::High),
        (r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----", "Private Key Exposed", Severity::Critical),
        (r#"(?i)aws_secret_access_key\s*=\s*[a-zA-Z0-9/+]{40}"#, "AWS Secret Key Exposed", Severity::Critical),
        (r#"(?i)Authorization:\s*Bearer\s+[a-zA-Z0-9\-_.]+\.[a-zA-Z0-9\-_.]+"#, "JWT Token Exposed in Body", Severity::High),
        (r#"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b"#, "Email Address Disclosed", Severity::Info),
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
                        &format!("Sensitive data pattern detected in response body: {}", title),
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
        let has_stack = body.contains("Exception") || body.contains("Traceback") || body.contains("Error:");
        if has_stack {
            findings.push(
                Finding::new(
                    "Verbose Server Error Message",
                    Severity::Medium,
                    url,
                    &format!("Server returned HTTP {} with a verbose error message that may disclose internal information.", status),
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

    let cc = headers.get("cache-control").and_then(|v| v.to_str().ok()).unwrap_or("").to_lowercase();
    let pragma = headers.get("pragma").and_then(|v| v.to_str().ok()).unwrap_or("").to_lowercase();

    if !cc.contains("no-store") && !cc.contains("private") && !pragma.contains("no-cache") {
        // Only flag HTML/JSON pages, not static assets
        let ct = headers.get("content-type").and_then(|v| v.to_str().ok()).unwrap_or("");
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

/// CLI entry point for passive-only scan
pub async fn run_passive_cli(input: &str, output: &str) -> Result<()> {
    use indicatif::{ProgressBar, ProgressStyle};

    println!("{} {}", "▶ Passive scan:".bright_white().bold(), input.bright_cyan());

    let client = Arc::new(
        reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .user_agent("RustZAP/0.1 Passive Scanner")
            .build()?,
    );

    let urls = vec![crate::types::DiscoveredUrl {
        url: input.to_string(),
        method: "GET".to_string(),
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
