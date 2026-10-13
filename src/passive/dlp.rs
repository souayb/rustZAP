//! Passive DLP / PII inspection plugin.
//!
//! Scans HTTP response bodies and headers for exposed credit card numbers (Luhn checked),
//! SSNs, IBANs, and private keys.

use crate::analyze::native::dlp::{DlpScanner, DlpType};
use crate::types::{Finding, Severity};

/// Check response for exposed DLP/PII data.
pub fn check_dlp_exposure(url: &str, body: &str) -> Vec<Finding> {
    let scanner = DlpScanner::new();
    let matches = scanner.scan_text(body);
    let mut findings = Vec::new();

    for m in matches {
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

        findings.push(
            Finding::new(title, severity, url, desc, solution, "passive/dlp-pii")
                .with_evidence(m.redacted)
                .with_cwe(200) // CWE-200: Exposure of Sensitive Information
                .with_owasp("A02:2021 – Cryptographic Failures"),
        );
    }

    findings
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_passive_dlp_exposure() {
        let body = "Customer order confirmation: CC 4111 1111 1111 1111 and SSN 219-45-7890.";
        let findings = check_dlp_exposure("https://example.com/checkout", body);
        assert_eq!(findings.len(), 2);
        assert!(findings
            .iter()
            .any(|f| f.title.contains("Payment Card Disclosed")));
        assert!(findings
            .iter()
            .any(|f| f.title.contains("Social Security Number")));
    }
}
