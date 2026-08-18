//! Golden matrix for passive checks — deterministic HTTP fixtures, no network.
//!
//! Complements unit tests in `src/passive.rs` by exercising the full
//! `check_response_passive` pipeline and `evaluate_security_txt`.

use std::collections::HashSet;

use chrono::{TimeZone, Utc};
use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
use rustzap::passive::{check_response_passive, evaluate_security_txt, known_plugin_names};
use rustzap::types::Severity;

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

fn plugins(findings: &[rustzap::types::Finding]) -> HashSet<&str> {
    findings.iter().map(|f| f.plugin.as_str()).collect()
}

fn assert_has_plugin(findings: &[rustzap::types::Finding], plugin: &str) {
    assert!(
        findings.iter().any(|f| f.plugin == plugin),
        "expected plugin {plugin:?}, got: {:?}",
        findings.iter().map(|f| &f.plugin).collect::<Vec<_>>()
    );
}

fn assert_finding_json_roundtrip(findings: &[rustzap::types::Finding]) {
    for f in findings {
        let json = serde_json::to_string(f).expect("finding serializes");
        assert!(json.contains("\"plugin\""));
        assert!(json.contains(&f.plugin));
        assert!(json.contains("\"severity\""));
    }
}

/// Every known passive plugin id should be reachable from at least one fixture.
#[test]
fn golden_matrix_covers_all_known_passive_plugins() {
    let mut covered: HashSet<&str> = HashSet::new();

    // Bare minimum response — mostly missing-headers
    let bare = check_response_passive(
        "https://example.com/",
        200,
        &HeaderMap::new(),
        "<html></html>",
    );
    covered.extend(bare.iter().map(|f| f.plugin.as_str()));

    // Cookie flags
    let cookie = check_response_passive(
        "https://example.com/login",
        200,
        &headers_from(&[("set-cookie", "session=abc123")]),
        "",
    );
    covered.extend(cookie.iter().map(|f| f.plugin.as_str()));

    // Info disclosure (server version)
    let info = check_response_passive(
        "https://example.com/",
        200,
        &headers_from(&[("server", "nginx/1.21.0")]),
        "",
    );
    covered.extend(info.iter().map(|f| f.plugin.as_str()));

    // Content-Type charset
    let ctype = check_response_passive(
        "https://example.com/",
        200,
        &headers_from(&[("content-type", "text/html")]),
        "<html></html>",
    );
    covered.extend(ctype.iter().map(|f| f.plugin.as_str()));

    // Mixed content
    let mixed = check_response_passive(
        "https://example.com/secure",
        200,
        &HeaderMap::new(),
        r#"<img src="http://cdn.example.com/a.png">"#,
    );
    covered.extend(mixed.iter().map(|f| f.plugin.as_str()));

    // Sensitive data
    let secret = check_response_passive(
        "https://example.com/config.js",
        200,
        &HeaderMap::new(),
        r#"var x = { api_key: "abcdefghijklmnopqrst" };"#,
    );
    covered.extend(secret.iter().map(|f| f.plugin.as_str()));

    // Error disclosure
    let err = check_response_passive(
        "https://example.com/broken",
        500,
        &HeaderMap::new(),
        "Exception: something broke at line 42",
    );
    covered.extend(err.iter().map(|f| f.plugin.as_str()));

    // Cache control on HTML
    let cache = check_response_passive(
        "https://example.com/dashboard",
        200,
        &headers_from(&[("content-type", "text/html; charset=utf-8")]),
        "<html>account</html>",
    );
    covered.extend(cache.iter().map(|f| f.plugin.as_str()));

    // CORS wildcard + credentials
    let cors = check_response_passive(
        "https://example.com/api",
        200,
        &headers_from(&[
            ("access-control-allow-origin", "*"),
            ("access-control-allow-credentials", "true"),
        ]),
        "{}",
    );
    covered.extend(cors.iter().map(|f| f.plugin.as_str()));

    // CSP unsafe directives
    let csp = check_response_passive(
        "https://example.com/",
        200,
        &headers_from(&[(
            "content-security-policy",
            "script-src 'self' 'unsafe-inline'",
        )]),
        "",
    );
    covered.extend(csp.iter().map(|f| f.plugin.as_str()));

    // Tech fingerprint
    let tech = check_response_passive(
        "https://example.com/",
        200,
        &headers_from(&[("x-powered-by", "Express")]),
        "",
    );
    covered.extend(tech.iter().map(|f| f.plugin.as_str()));

    // JWT heuristic — alg:none (signature segment must be ≥8 chars per regex)
    let jwt_body = r#"{"token":"eyJhbGciOiJub25lIn0.eyJzdWIiOiIxIn0.somesignatureGoesHere1234"}"#;
    let jwt = check_response_passive("https://example.com/app", 200, &HeaderMap::new(), jwt_body);
    covered.extend(jwt.iter().map(|f| f.plugin.as_str()));

    // security.txt (origin probe — evaluated separately from check_response_passive)
    let now = Utc.with_ymd_and_hms(2026, 5, 1, 0, 0, 0).unwrap();
    let stxt = evaluate_security_txt("https://example.com/.well-known/security.txt", 404, "", now);
    covered.extend(stxt.iter().map(|f| f.plugin.as_str()));

    for plugin in known_plugin_names() {
        assert!(
            covered.contains(plugin),
            "golden matrix missing coverage for passive plugin {plugin}"
        );
    }
}

#[test]
fn golden_bare_response_flags_missing_security_headers() {
    let findings = check_response_passive(
        "https://example.com/",
        200,
        &HeaderMap::new(),
        "<html></html>",
    );
    assert_has_plugin(&findings, "passive/missing-headers");
    assert!(findings.iter().any(|f| f.title.contains("HSTS")));
    assert_finding_json_roundtrip(&findings);
}

#[test]
fn golden_hardened_headers_reduce_missing_header_noise() {
    let headers = headers_from(&[
        ("strict-transport-security", "max-age=31536000"),
        ("x-content-type-options", "nosniff"),
        ("x-frame-options", "DENY"),
        ("content-security-policy", "default-src 'self'"),
        ("x-xss-protection", "1; mode=block"),
        ("referrer-policy", "no-referrer"),
        ("permissions-policy", "geolocation=()"),
        ("content-type", "text/html; charset=utf-8"),
    ]);
    let findings = check_response_passive("https://example.com/", 200, &headers, "<html></html>");
    assert!(
        !findings
            .iter()
            .any(|f| f.plugin == "passive/missing-headers"),
        "expected no missing-header findings, got {:?}",
        findings
    );
}

#[test]
fn golden_insecure_session_cookie_emits_cookie_flags() {
    let findings = check_response_passive(
        "https://example.com/",
        200,
        &headers_from(&[("set-cookie", "sid=deadbeef")]),
        "",
    );
    let cookie_findings: Vec<_> = findings
        .iter()
        .filter(|f| f.plugin == "passive/cookie-flags")
        .collect();
    assert!(
        cookie_findings.len() >= 2,
        "expected HttpOnly + Secure + SameSite issues"
    );
}

#[test]
fn golden_cors_wildcard_with_credentials_is_high() {
    let findings = check_response_passive(
        "https://example.com/api",
        200,
        &headers_from(&[
            ("access-control-allow-origin", "*"),
            ("access-control-allow-credentials", "true"),
        ]),
        "",
    );
    let high = findings
        .iter()
        .find(|f| f.plugin == "passive/cors" && f.severity == Severity::High)
        .expect("CORS wildcard+credentials high finding");
    assert!(high.title.contains("Credentials"));
}

#[test]
fn golden_csp_unsafe_inline_is_medium() {
    let findings = check_response_passive(
        "https://example.com/",
        200,
        &headers_from(&[(
            "content-security-policy",
            "script-src 'self' 'unsafe-inline'",
        )]),
        "",
    );
    let csp = findings
        .iter()
        .find(|f| f.plugin == "passive/csp-unsafe-directives")
        .expect("csp finding");
    assert_eq!(csp.severity, Severity::Medium);
}

#[test]
fn golden_mixed_content_on_https_page() {
    let findings = check_response_passive(
        "https://example.com/page",
        200,
        &HeaderMap::new(),
        r#"<script src="http://evil.example/x.js"></script>"#,
    );
    assert_has_plugin(&findings, "passive/mixed-content");
}

#[test]
fn golden_api_key_pattern_in_body() {
    let findings = check_response_passive(
        "https://example.com/env.js",
        200,
        &HeaderMap::new(),
        r#"export const api_key = "sk_live_abcdefghijklmnop";"#,
    );
    assert_has_plugin(&findings, "passive/sensitive-data");
    let f = findings
        .iter()
        .find(|f| f.plugin == "passive/sensitive-data")
        .unwrap();
    assert_eq!(f.severity, Severity::High);
}

#[test]
fn golden_500_with_exception_is_error_disclosure() {
    let findings = check_response_passive(
        "https://example.com/fail",
        500,
        &HeaderMap::new(),
        "Traceback (most recent call last):\n  File ...",
    );
    assert_has_plugin(&findings, "passive/error-disclosure");
}

#[test]
fn golden_security_txt_healthy_is_quiet() {
    let now = Utc.with_ymd_and_hms(2026, 5, 1, 0, 0, 0).unwrap();
    let body = "Contact: mailto:sec@example.com\nExpires: 2099-01-01T00:00:00Z\n";
    let findings = evaluate_security_txt(
        "https://example.com/.well-known/security.txt",
        200,
        body,
        now,
    );
    assert!(findings.is_empty());
}

#[test]
fn golden_security_txt_missing_is_info() {
    let now = Utc::now();
    let findings =
        evaluate_security_txt("https://example.com/.well-known/security.txt", 404, "", now);
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].plugin, "passive/security-txt");
    assert_eq!(findings[0].severity, Severity::Info);
}

#[test]
fn golden_tech_fingerprint_dedupes_signals() {
    let findings = check_response_passive(
        "https://example.com/",
        200,
        &headers_from(&[("server", "nginx/1.21"), ("x-powered-by", "PHP/8.2")]),
        r#"<html><script src="/wp-includes/js/jquery.js"></script></html>"#,
    );
    let tech: Vec<_> = findings
        .iter()
        .filter(|f| f.plugin == "passive/tech-fingerprint")
        .collect();
    assert_eq!(tech.len(), 1, "tech fingerprint collapses to one finding");
    assert!(tech[0].evidence.as_deref().unwrap_or("").contains("nginx"));
}

#[test]
fn golden_jwt_alg_none_is_high() {
    let body = r#"var t = "eyJhbGciOiJub25lIn0.eyJzdWIiOiIxIn0.somesignatureGoesHere1234";"#;
    let findings = check_response_passive("https://example.com/", 200, &HeaderMap::new(), body);
    let jwt = findings
        .iter()
        .find(|f| f.plugin == "passive/jwt-heuristic")
        .expect("jwt finding");
    assert_eq!(jwt.severity, Severity::High);
    assert!(jwt.evidence.as_deref().unwrap_or("").contains("REDACTED"));
}

#[test]
fn golden_plugin_ids_are_stable_prefixes() {
    let findings = check_response_passive(
        "https://example.com/",
        200,
        &headers_from(&[("server", "Apache/2.4")]),
        "",
    );
    for f in &findings {
        assert!(
            f.plugin.starts_with("passive/"),
            "unexpected plugin id: {}",
            f.plugin
        );
    }
}

#[test]
fn golden_combined_fixture_plugin_set() {
    let findings = check_response_passive(
        "https://example.com/dashboard",
        200,
        &headers_from(&[
            ("set-cookie", "session=x"),
            ("access-control-allow-origin", "*"),
            ("content-type", "text/html"),
            ("content-security-policy", "script-src *"),
        ]),
        r#"<img src="http://insecure.example/x.png">"#,
    );
    let got = plugins(&findings);
    for expected in [
        "passive/missing-headers",
        "passive/cookie-flags",
        "passive/content-type",
        "passive/mixed-content",
        "passive/cache-control",
        "passive/cors",
        "passive/csp-unsafe-directives",
    ] {
        assert!(got.contains(expected), "missing {expected} in {got:?}");
    }
}
