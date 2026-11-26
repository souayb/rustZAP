//! Passive DLP / PII inspection plugin.
//!
//! Scans HTTP response bodies and headers for exposed credit card numbers (Luhn checked),
//! SSNs, IBANs, and private keys.

use crate::analyze::native::dlp::{DlpScanner, DlpType};
use crate::types::{Finding, Severity};

/// True for a textual (or unlabelled) response; binary bodies are never scanned.
fn is_text_content(headers: &reqwest::header::HeaderMap) -> bool {
    let Some(ct) = headers
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
    else {
        return true;
    };
    let ct = ct.to_ascii_lowercase();
    ct.starts_with("text/")
        || ["json", "xml", "javascript", "form"]
            .iter()
            .any(|t| ct.contains(t))
}

/// Static bundles/assets: long digit literals there are code constants, not cardholder data.
fn is_static_asset(url: &str) -> bool {
    let path = url
        .split(['?', '#'])
        .next()
        .unwrap_or(url)
        .to_ascii_lowercase();
    [".js", ".mjs", ".css", ".map", ".wasm"]
        .iter()
        .any(|ext| path.ends_with(ext))
}

/// Check response for exposed DLP/PII data.
pub fn check_dlp_exposure(
    url: &str,
    headers: &reqwest::header::HeaderMap,
    body: &str,
) -> Vec<Finding> {
    if !is_text_content(headers) {
        return Vec::new();
    }
    let skip_cards = is_static_asset(url);
    let scanner = DlpScanner::new();
    let matches = scanner.scan_text(body);
    let mut findings = Vec::new();

    for m in matches {
        if skip_cards && matches!(m.dlp_type, DlpType::CreditCard(_)) {
            continue;
        }
        let (title, severity, desc, solution) = match m.dlp_type {
            DlpType::CreditCard(brand) => (
                format!("Payment Card Disclosed ({})", brand.name()),
                Severity::Critical,
                format!("A valid {} number with verified Luhn checksum was detected in the HTTP response body.", brand.name()),
                "Ensure PANs (Primary Account Numbers) are never returned in plaintext. Mask numbers showing at most the last 4 digits (PCI-DSS Requirement 3.3).",
            ),
            DlpType::SocialSecurityNumber => (
                "US Social Security Number (SSN) Disclosed".to_string(),
                Severity::Critical,
                "A formatted US Social Security Number (SSN) passing area/group validation was found in the HTTP response body.".to_string(),
                "Remove Social Security Numbers from client responses or mask all but the last four digits.",
            ),
            DlpType::Iban(ref country) => (
                format!("Bank Account Number (IBAN - {}) Disclosed", country),
                Severity::High,
                format!("A valid International Bank Account Number (IBAN) for country {} with valid ISO 7064 Mod 97-10 checksum was detected.", country),
                "Restrict bank account information exposure to authorized sessions and mask account numbers.",
            ),
            DlpType::PrivateKey(ref key_type) => (
                "Cryptographic Private Key Disclosed".to_string(),
                Severity::Critical,
                format!("A private cryptographic key header ({}) was exposed in the response body.", key_type),
                "Immediately revoke the compromised key and remove private keys from public/web-accessible assets.",
            ),
            DlpType::ApiSecret(ref name) => (
                format!("Cloud/API Credential Exposed ({})", name),
                Severity::Critical,
                format!("An API secret ({}) was detected in the response body.", name),
                "Revoke and rotate the exposed secret immediately. Store credentials securely in server environment variables or secret managers.",
            ),
            DlpType::HighEntropySecret => (
                "High-Entropy Secret Disclosed".to_string(),
                Severity::High,
                "A high-entropy string resembling a cryptographic key or secret was found in the response.".to_string(),
                "Verify if this string is a confidential secret and remove it from HTTP responses.",
            ),
        };

        findings.push(super::regex_only(
            Finding::new(title, severity, url, desc, solution, "passive/dlp-pii")
                .with_evidence(m.redacted)
                .with_cwe(200) // CWE-200: Exposure of Sensitive Information
                .with_owasp("A02:2021 – Cryptographic Failures"),
        ));
    }

    findings
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::Confidence;
    use reqwest::header::{HeaderMap, HeaderValue, CONTENT_TYPE};

    fn ct(v: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert(CONTENT_TYPE, HeaderValue::from_str(v).unwrap());
        h
    }

    #[test]
    fn test_passive_dlp_exposure() {
        let body = "Customer order confirmation: CC 4539 1488 0343 6467 and SSN 219-45-7890.";
        let findings = check_dlp_exposure("https://example.com/checkout", &HeaderMap::new(), body);
        assert_eq!(findings.len(), 2);
        assert!(findings
            .iter()
            .any(|f| f.title.contains("Payment Card Disclosed")));
        assert!(findings
            .iter()
            .any(|f| f.title.contains("Social Security Number")));
        // Regex-only passive hits: tentative and never critical.
        assert!(findings
            .iter()
            .all(|f| f.confidence == Confidence::Tentative && f.severity != Severity::Critical));
    }

    #[test]
    fn dlp_skips_assets_binaries_and_metrics() {
        let card = "payment card 4539 1488 0343 6467";
        assert!(
            check_dlp_exposure("https://e.com/app.min.js?v=3", &HeaderMap::new(), card).is_empty()
        );
        assert!(check_dlp_exposure("https://e.com/app.css", &HeaderMap::new(), card).is_empty());
        assert!(check_dlp_exposure("https://e.com/x", &ct("image/png"), card).is_empty());
        assert_eq!(
            check_dlp_exposure("https://e.com/x", &ct("application/json"), card).len(),
            1
        );
        let metrics = "# TYPE http_request_duration_seconds histogram\n\
            http_request_duration_seconds_sum{route=\"/payment\"} 19148762699999997\n\
            http_request_duration_seconds_sum 1.9148762699999997e+16\n";
        assert!(check_dlp_exposure(
            "https://e.com/metrics",
            &ct("text/plain; version=0.0.4"),
            metrics
        )
        .is_empty());
    }
}
