//! Passive Cryptographic Posture Auditor.
//!
//! Inspects HTTP response bodies, cookies, and headers for exposed MD5/SHA1 hashes,
//! NTLM dumps, and weak cryptography patterns.

use crate::analyze::native::hashes::{audit_crypto_posture, CryptoAuditor};
use crate::types::{Finding, Severity};

/// Check response body and sensitive headers for weak crypto and hash disclosures.
pub fn check_crypto_posture_passive(
    url: &str,
    headers: &reqwest::header::HeaderMap,
    body: &str,
) -> Vec<Finding> {
    let mut findings = Vec::new();

    // 1. Inspect response body
    findings.extend(audit_crypto_posture(url, body));

    // 2. Check Set-Cookie headers for legacy hash values (e.g. 32-char MD5 session IDs)
    for (name, val) in headers.iter() {
        if name.as_str().eq_ignore_ascii_case("set-cookie") {
            if let Ok(cookie_val) = val.to_str() {
                let auditor = CryptoAuditor::new();
                let matches = auditor.audit_text(cookie_val);
                for m in matches {
                    findings.push(
                        Finding::new(
                            "Weak Cryptographic Token in Cookie",
                            Severity::Medium,
                            url,
                            format!("Cookie contains potentially weak cryptographic hash or parameter: {}", m.snippet),
                            "Use cryptographically secure pseudo-random number generators (CSPRNG) with at least 128 bits of entropy for session tokens.",
                            "passive/crypto-cookie",
                        )
                        .with_evidence(m.snippet)
                        .with_cwe(330) // CWE-330: Use of Insufficiently Random Values
                        .with_owasp("A02:2021 – Cryptographic Failures"),
                    );
                }
            }
        }
    }

    findings
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_passive_crypto_posture() {
        let headers = reqwest::header::HeaderMap::new();
        let body = "DEBUG: api_secret_md5 = '098f6bcd4621d373cade4e832627b4f6';";
        let findings = check_crypto_posture_passive("https://example.com/api", &headers, body);
        assert_eq!(findings.len(), 1);
        assert!(findings[0].title.contains("Weak Cryptographic Hash (MD5)"));
    }
}
