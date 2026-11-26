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

    findings.into_iter().map(super::regex_only).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::Confidence;

    #[test]
    fn test_passive_crypto_posture() {
        let headers = reqwest::header::HeaderMap::new();
        let body = "DEBUG: api_secret_md5 = '098f6bcd4621d373cade4e832627b4f6';";
        let findings = check_crypto_posture_passive("https://example.com/api", &headers, body);
        assert_eq!(findings.len(), 1);
        assert!(findings[0].title.contains("Weak Cryptographic Hash (MD5)"));
        assert_eq!(findings[0].confidence, Confidence::Tentative);
    }

    #[test]
    fn des_prose_and_skus_are_quiet_but_real_des_fires() {
        let headers = reqwest::header::HeaderMap::new();
        let quiet = "<p>La liste des produits et des services</p><span>Réf. DES-005</span>\
                     <script>const r=window.indexedDB.open(\"des\")</script>";
        assert!(check_crypto_posture_passive("https://e.com/fr", &headers, quiet).is_empty());

        let bundle = "!function(){var c=CryptoJS.DES.encrypt(m,k)}();";
        let f = check_crypto_posture_passive("https://e.com/app.js", &headers, bundle);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].severity, Severity::High);
        assert_eq!(f[0].confidence, Confidence::Tentative);

        // NTLM dump is Critical natively, but a regex-only passive hit caps at High.
        let ntlm = "admin:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::";
        let f = check_crypto_posture_passive("https://e.com/dump", &headers, ntlm);
        assert!(!f.is_empty());
        assert!(f.iter().all(|x| x.severity != Severity::Critical));
    }
}
