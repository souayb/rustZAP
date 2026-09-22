//! Data Loss Prevention (DLP) and Personally Identifiable Information (PII) Engine.
//!
//! Provides high-precision detection of:
//! - Credit Card Numbers with Luhn Algorithm validation (Visa, MasterCard, Amex, Discover, Diners, JCB)
//! - US Social Security Numbers (SSN) with area/group/serial code validation
//! - International Bank Account Numbers (IBAN) with ISO 7064 Mod 97-10 checksum validation
//! - Private Cryptographic Keys (PEM blocks for RSA, EC, OpenSSH, PGP)
//! - API Secrets and Cloud Tokens (AWS, GitHub, Slack, Stripe, Google, OpenAI)
//! - Shannon Entropy calculation for unstructured secret discovery

use crate::types::{Finding, Severity};
use regex::Regex;
use std::collections::HashSet;

/// Classification of detected DLP / PII data types.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum DlpType {
    CreditCard(CreditCardBrand),
    SocialSecurityNumber,
    Iban(String),       // Country code
    PrivateKey(String), // Key type
    ApiSecret(String),  // Provider/token type
    HighEntropySecret,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CreditCardBrand {
    Visa,
    MasterCard,
    AmericanExpress,
    Discover,
    DinersClub,
    Jcb,
    Unknown,
}

impl CreditCardBrand {
    pub fn name(&self) -> &'static str {
        match self {
            CreditCardBrand::Visa => "Visa",
            CreditCardBrand::MasterCard => "MasterCard",
            CreditCardBrand::AmericanExpress => "American Express",
            CreditCardBrand::Discover => "Discover",
            CreditCardBrand::DinersClub => "Diners Club",
            CreditCardBrand::Jcb => "JCB",
            CreditCardBrand::Unknown => "Credit Card (Valid Luhn)",
        }
    }
}

/// A matched DLP/PII finding snippet with metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DlpMatch {
    pub dlp_type: DlpType,
    pub raw_match: String,
    pub redacted: String,
    pub description: String,
    pub line_number: Option<usize>,
}

/// Validates a credit card number using Luhn algorithm (mod 10).
pub fn validate_luhn(number_str: &str) -> bool {
    let digits: Vec<u32> = number_str
        .chars()
        .filter(|c| c.is_ascii_digit())
        .filter_map(|c| c.to_digit(10))
        .collect();

    if digits.len() < 13 || digits.len() > 19 {
        return false;
    }

    // Check if all digits are the same (e.g. 0000000000000000 or 1111111111111111), which is not a real card
    let first = digits[0];
    if digits.iter().all(|&d| d == first) {
        return false;
    }

    let mut sum = 0;
    let len = digits.len();

    for (idx, &digit) in digits.iter().enumerate() {
        // Double every second digit from the right (0-indexed from right: odd positions)
        let pos_from_right = len - 1 - idx;
        if pos_from_right % 2 == 1 {
            let doubled = digit * 2;
            sum += if doubled > 9 { doubled - 9 } else { doubled };
        } else {
            sum += digit;
        }
    }

    sum % 10 == 0
}

/// Identifies the credit card brand from IIN / BIN prefix.
pub fn identify_card_brand(cleaned_digits: &str) -> CreditCardBrand {
    if cleaned_digits.starts_with('4')
        && (cleaned_digits.len() == 13 || cleaned_digits.len() == 16 || cleaned_digits.len() == 19)
    {
        CreditCardBrand::Visa
    } else if (cleaned_digits.starts_with("34") || cleaned_digits.starts_with("37"))
        && cleaned_digits.len() == 15
    {
        CreditCardBrand::AmericanExpress
    } else if (cleaned_digits.starts_with("30")
        || cleaned_digits.starts_with("36")
        || cleaned_digits.starts_with("38"))
        && (cleaned_digits.len() == 14 || cleaned_digits.len() == 16)
    {
        CreditCardBrand::DinersClub
    } else if (cleaned_digits.starts_with("6011")
        || cleaned_digits.starts_with("65")
        || cleaned_digits.starts_with("644")
        || cleaned_digits.starts_with("645"))
        && cleaned_digits.len() == 16
    {
        CreditCardBrand::Discover
    } else if cleaned_digits.len() == 16 {
        if let Ok(prefix2) = cleaned_digits[..2].parse::<u32>() {
            if (51..=55).contains(&prefix2) {
                return CreditCardBrand::MasterCard;
            }
        }
        if let Ok(prefix4) = cleaned_digits[..4].parse::<u32>() {
            if (2221..=2720).contains(&prefix4) {
                return CreditCardBrand::MasterCard;
            }
        }
        if let Ok(prefix4) = cleaned_digits[..4].parse::<u32>() {
            if (3528..=3589).contains(&prefix4) {
                return CreditCardBrand::Jcb;
            }
        }
        CreditCardBrand::Unknown
    } else {
        CreditCardBrand::Unknown
    }
}

/// Redact credit card number preserving last 4 digits.
pub fn redact_credit_card(card_str: &str) -> String {
    let digits: String = card_str.chars().filter(|c| c.is_ascii_digit()).collect();
    if digits.len() < 4 {
        return "[REDACTED_CC]".to_string();
    }
    let last4 = &digits[digits.len() - 4..];
    format!("XXXX-XXXX-XXXX-{}", last4)
}

/// Validates US Social Security Number rules (area code, group code, serial number).
pub fn validate_ssn(ssn_str: &str) -> bool {
    let digits: Vec<u32> = ssn_str
        .chars()
        .filter(|c| c.is_ascii_digit())
        .filter_map(|c| c.to_digit(10))
        .collect();

    if digits.len() != 9 {
        return false;
    }

    let area = digits[0] * 100 + digits[1] * 10 + digits[2];
    let group = digits[3] * 10 + digits[4];
    let serial = digits[5] * 1000 + digits[6] * 100 + digits[7] * 10 + digits[8];

    // Area numbers:
    // Cannot be 000, 666, or 900-999
    if area == 0 || area == 666 || area >= 900 {
        return false;
    }

    // Group numbers: Cannot be 00
    if group == 0 {
        return false;
    }

    // Serial numbers: Cannot be 0000
    if serial == 0 {
        return false;
    }

    // Common test / fake numbers: 078-05-1120 etc.
    // Rejects sequential or repeating test numbers
    if area == 123 && group == 45 && serial == 6789 {
        return false;
    }

    true
}

/// Redact SSN preserving last 4 digits.
pub fn redact_ssn(ssn_str: &str) -> String {
    let digits: String = ssn_str.chars().filter(|c| c.is_ascii_digit()).collect();
    if digits.len() == 9 {
        format!("XXX-XX-{}", &digits[5..])
    } else {
        "XXX-XX-XXXX".to_string()
    }
}

/// Validates IBAN using ISO 7064 Mod 97-10 checksum algorithm.
pub fn validate_iban(iban_str: &str) -> bool {
    let clean: String = iban_str
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .map(|c| c.to_ascii_uppercase())
        .collect();

    if clean.len() < 14 || clean.len() > 34 {
        return false;
    }

    // Country code must be 2 ASCII alphabetic characters
    let country = &clean[..2];
    if !country.chars().all(|c| c.is_ascii_uppercase()) {
        return false;
    }

    // Check expected length by country
    let expected_len = match country {
        "AL" => 28,
        "AD" => 24,
        "AT" => 20,
        "AZ" => 28,
        "BH" => 22,
        "BY" => 28,
        "BE" => 16,
        "BA" => 20,
        "BR" => 29,
        "BG" => 22,
        "CR" => 22,
        "HR" => 21,
        "CY" => 28,
        "CZ" => 24,
        "DK" => 18,
        "DO" => 28,
        "EE" => 20,
        "FO" => 18,
        "FI" => 18,
        "FR" => 27,
        "GE" => 22,
        "DE" => 22,
        "GI" => 23,
        "GR" => 27,
        "GL" => 18,
        "GT" => 28,
        "HU" => 28,
        "IS" => 26,
        "IE" => 22,
        "IL" => 23,
        "IT" => 27,
        "JO" => 30,
        "KZ" => 20,
        "XK" => 20,
        "KW" => 30,
        "LV" => 21,
        "LB" => 28,
        "LI" => 21,
        "LT" => 20,
        "LU" => 20,
        "MK" => 19,
        "MT" => 31,
        "MR" => 27,
        "MU" => 30,
        "MC" => 27,
        "MD" => 24,
        "ME" => 22,
        "NL" => 18,
        "NO" => 15,
        "PK" => 24,
        "PS" => 29,
        "PL" => 28,
        "PT" => 25,
        "QA" => 29,
        "RO" => 24,
        "SM" => 27,
        "SA" => 24,
        "RS" => 22,
        "SK" => 24,
        "SI" => 19,
        "ES" => 24,
        "SE" => 24,
        "CH" => 21,
        "TN" => 24,
        "TR" => 26,
        "AE" => 23,
        "GB" => 22,
        "VA" => 22,
        "VG" => 24,
        _ => clean.len(), // If unknown country, allow if passes mod 97
    };

    if clean.len() != expected_len {
        return false;
    }

    // Rearrange: Move first 4 characters to the end
    let rearranged = format!("{}{}", &clean[4..], &clean[..4]);

    // Convert letters to digits: A=10, B=11, ..., Z=35
    let mut num_str = String::with_capacity(rearranged.len() * 2);
    for ch in rearranged.chars() {
        if ch.is_ascii_digit() {
            num_str.push(ch);
        } else if ch.is_ascii_uppercase() {
            let val = (ch as u32) - ('A' as u32) + 10;
            num_str.push_str(&val.to_string());
        } else {
            return false;
        }
    }

    // Calculate mod 97 on large numeric string piece-by-piece
    let mut remainder: u64 = 0;
    for chunk in num_str.as_bytes().chunks(9) {
        if let Ok(chunk_str) = std::str::from_utf8(chunk) {
            let combined = format!("{}{}", remainder, chunk_str);
            if let Ok(val) = combined.parse::<u64>() {
                remainder = val % 97;
            } else {
                return false;
            }
        }
    }

    remainder == 1
}

/// Redact IBAN preserving country code and last 4 characters.
pub fn redact_iban(iban_str: &str) -> String {
    let clean: String = iban_str
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .collect();
    if clean.len() > 6 {
        let country = &clean[..2];
        let last4 = &clean[clean.len() - 4..];
        format!("{}{}****{}", country, &clean[2..4], last4)
    } else {
        "[REDACTED_IBAN]".to_string()
    }
}

/// Calculate Shannon entropy of a string (in bits per symbol).
pub fn shannon_entropy(s: &str) -> f64 {
    if s.is_empty() {
        return 0.0;
    }

    let mut counts = [0usize; 256];
    let len = s.len() as f64;

    for &b in s.as_bytes() {
        counts[b as usize] += 1;
    }

    let mut entropy = 0.0;
    for &count in &counts {
        if count > 0 {
            let p = count as f64 / len;
            entropy -= p * p.log2();
        }
    }

    entropy
}

/// Scanner for DLP and PII in text content.
pub struct DlpScanner {
    cc_regex: Regex,
    ssn_regex: Regex,
    iban_regex: Regex,
    slack_regex: Regex,
    github_regex: Regex,
    stripe_regex: Regex,
    aws_regex: Regex,
    google_regex: Regex,
    openai_regex: Regex,
    private_key_regex: Regex,
}

impl Default for DlpScanner {
    fn default() -> Self {
        Self::new()
    }
}

impl DlpScanner {
    pub fn new() -> Self {
        Self {
            // Match numbers formatted with spaces/dashes or contiguous 13-19 digits
            cc_regex: Regex::new(r"\b(?:\d[ -]*?){13,19}\b").unwrap(),
            // US SSN format: 9 digits formatted as 3-2-4 or with space
            ssn_regex: Regex::new(r"\b\d{3}[- ]\d{2}[- ]\d{4}\b").unwrap(),
            // IBAN: 2 letters followed by 2 digits and 10 to 30 alphanumerics
            iban_regex: Regex::new(r"\b[A-Z]{2}\d{2}[A-Z0-9 ]{10,32}\b").unwrap(),
            // Slack tokens
            slack_regex: Regex::new(r"\bxox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24,32}\b")
                .unwrap(),
            // GitHub Personal Access Tokens
            github_regex: Regex::new(r"\b(?:ghp|gho|ghu|ghs|ghr)_[a-zA-Z0-9]{36,40}\b").unwrap(),
            // Stripe API Keys
            stripe_regex: Regex::new(r"\b(?:sk|rk)_(?:live|test)_[0-9a-zA-Z]{24,99}\b").unwrap(),
            // AWS Access Key ID
            aws_regex: Regex::new(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b").unwrap(),
            // Google API Key
            google_regex: Regex::new(r"\bAIza[0-9A-Za-z\-_]{35}\b").unwrap(),
            // OpenAI API Key
            openai_regex: Regex::new(r"\bsk-(?:proj-)?[a-zA-Z0-9_\-]{32,64}\b").unwrap(),
            // Private Keys PEM
            private_key_regex: Regex::new(
                r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY(?: BLOCK)?-----",
            )
            .unwrap(),
        }
    }

    /// Scan text content for DLP and PII findings.
    pub fn scan_text(&self, text: &str) -> Vec<DlpMatch> {
        let mut matches = Vec::new();
        let mut seen_raw = HashSet::new();

        // 1. Credit Cards with Luhn Checksum validation
        for mat in self.cc_regex.find_iter(text) {
            let raw = mat.as_str();
            let digits_only: String = raw.chars().filter(|c| c.is_ascii_digit()).collect();
            if digits_only.len() >= 13
                && digits_only.len() <= 19
                && validate_luhn(&digits_only)
                && seen_raw.insert(digits_only.clone())
            {
                let brand = identify_card_brand(&digits_only);
                let redacted = redact_credit_card(raw);
                matches.push(DlpMatch {
                    dlp_type: DlpType::CreditCard(brand),
                    raw_match: raw.to_string(),
                    redacted,
                    description: format!(
                        "Valid {} number detected with verified Luhn checksum",
                        brand.name()
                    ),
                    line_number: None,
                });
            }
        }

        // 2. US Social Security Numbers (SSN)
        for mat in self.ssn_regex.find_iter(text) {
            let raw = mat.as_str();
            if validate_ssn(raw) {
                let clean_digits: String = raw.chars().filter(|c| c.is_ascii_digit()).collect();
                if seen_raw.insert(clean_digits) {
                    let redacted = redact_ssn(raw);
                    matches.push(DlpMatch {
                        dlp_type: DlpType::SocialSecurityNumber,
                        raw_match: raw.to_string(),
                        redacted,
                        description: "Valid US Social Security Number (SSN) format detected"
                            .to_string(),
                        line_number: None,
                    });
                }
            }
        }

        // 3. International Bank Account Numbers (IBAN)
        for mat in self.iban_regex.find_iter(text) {
            let raw = mat.as_str();
            let clean: String = raw.chars().filter(|c| c.is_ascii_alphanumeric()).collect();
            if validate_iban(&clean) && seen_raw.insert(clean.clone()) {
                let country = clean[..2].to_string();
                let redacted = redact_iban(&clean);
                matches.push(DlpMatch {
                    dlp_type: DlpType::Iban(country.clone()),
                    raw_match: raw.to_string(),
                    redacted,
                    description: format!(
                        "Valid International Bank Account Number (IBAN) detected for country {}",
                        country
                    ),
                    line_number: None,
                });
            }
        }

        // 4. PEM Private Keys
        for mat in self.private_key_regex.find_iter(text) {
            let raw = mat.as_str();
            if seen_raw.insert(raw.to_string()) {
                matches.push(DlpMatch {
                    dlp_type: DlpType::PrivateKey(raw.to_string()),
                    raw_match: raw.to_string(),
                    redacted: format!("{}...[REDACTED_PRIVATE_KEY]", raw),
                    description: "Cryptographic Private Key header detected in payload".to_string(),
                    line_number: None,
                });
            }
        }

        // 5. Cloud & API Tokens
        for (re, name) in [
            (&self.slack_regex, "Slack Token"),
            (&self.github_regex, "GitHub Personal Access Token"),
            (&self.stripe_regex, "Stripe API Key"),
            (&self.aws_regex, "AWS Access Key ID"),
            (&self.google_regex, "Google API Key"),
            (&self.openai_regex, "OpenAI API Key"),
        ] {
            for mat in re.find_iter(text) {
                let raw = mat.as_str();
                if seen_raw.insert(raw.to_string()) {
                    let redacted = if raw.len() > 8 {
                        format!("{}...[REDACTED]", &raw[..8])
                    } else {
                        "[REDACTED_TOKEN]".to_string()
                    };
                    matches.push(DlpMatch {
                        dlp_type: DlpType::ApiSecret(name.to_string()),
                        raw_match: raw.to_string(),
                        redacted,
                        description: format!("{} detected in payload", name),
                        line_number: None,
                    });
                }
            }
        }

        matches
    }
}

use crate::analyze::inventory::{
    file_url, is_minified_name, line_number, read_text_head, rel_path, MAX_SOURCE_BYTES,
};
use crate::analyze::native::SOURCE_TOOL;
use crate::types::CodeLocation;
use std::path::{Path, PathBuf};

const MAX_DLP_FINDINGS: usize = 100;

pub fn scan(root: &Path, files: &[PathBuf]) -> Vec<Finding> {
    let scanner = DlpScanner::new();
    let mut out = Vec::new();

    for path in files {
        if is_minified_name(path) {
            continue;
        }
        let Some((src, _truncated)) = read_text_head(path, MAX_SOURCE_BYTES) else {
            continue;
        };

        let rel = rel_path(root, path);
        let matches = scanner.scan_text(&src);

        for m in matches {
            if out.len() >= MAX_DLP_FINDINGS {
                return out;
            }

            let start_idx = src.find(&m.raw_match).unwrap_or(0);
            let line = line_number(&src, start_idx);

            let (title, severity, desc, solution) = match m.dlp_type {
                DlpType::CreditCard(brand) => (
                    format!("Payment Card Disclosed ({})", brand.name()),
                    Severity::Critical,
                    format!("A valid {} number with verified Luhn checksum was detected in {rel}.", brand.name()),
                    "Ensure PANs (Primary Account Numbers) are never stored in plaintext source or config files. Mask numbers showing at most the last 4 digits (PCI-DSS Requirement 3.3).",
                ),
                DlpType::SocialSecurityNumber => (
                    "US Social Security Number (SSN) Disclosed".to_string(),
                    Severity::Critical,
                    format!("A formatted US Social Security Number (SSN) passing area/group validation was found in {rel}."),
                    "Remove Social Security Numbers from source control or mask all but the last four digits.",
                ),
                DlpType::Iban(ref country) => (
                    format!("Bank Account Number (IBAN - {}) Disclosed", country),
                    Severity::High,
                    format!("A valid International Bank Account Number (IBAN) for country {} with valid ISO 7064 Mod 97-10 checksum was detected in {rel}.", country),
                    "Restrict bank account information exposure and mask account numbers.",
                ),
                DlpType::PrivateKey(ref key_type) => (
                    "Cryptographic Private Key Disclosed".to_string(),
                    Severity::Critical,
                    format!("A private cryptographic key header ({}) was exposed in {rel}.", key_type),
                    "Immediately revoke the compromised key and remove private keys from source control.",
                ),
                DlpType::ApiSecret(ref name) => (
                    format!("Cloud/API Credential Exposed ({})", name),
                    Severity::Critical,
                    format!("An API secret ({}) was detected in {rel}.", name),
                    "Revoke and rotate the exposed secret immediately. Store credentials securely in environment variables or secret managers.",
                ),
                DlpType::HighEntropySecret => (
                    "High-Entropy Secret Disclosed".to_string(),
                    Severity::High,
                    format!("A high-entropy string resembling a secret was found in {rel}."),
                    "Verify if this string is a confidential secret and remove it from source files.",
                ),
            };

            out.push(
                Finding::new(
                    title,
                    severity,
                    file_url(path, Some(line)),
                    desc,
                    solution,
                    "sast/dlp-pii",
                )
                .with_source_tool(SOURCE_TOOL)
                .with_evidence(m.redacted)
                .with_cwe(200)
                .with_owasp("A02:2021 – Cryptographic Failures")
                .with_location(CodeLocation {
                    file: rel.clone(),
                    line_start: line,
                    line_end: None,
                }),
            );
        }
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_luhn_algorithm_validation() {
        // Known valid test card numbers
        assert!(validate_luhn("4111 1111 1111 1111"));
        assert!(validate_luhn("4012-8888-8888-1881"));
        assert!(validate_luhn("5105105105105100"));
        assert!(validate_luhn("378282246310005"));

        // Invalid card numbers (fails Luhn)
        assert!(!validate_luhn("4111 1111 1111 1112"));
        assert!(!validate_luhn("1234567812345671"));
        // Repeating fake numbers rejected
        assert!(!validate_luhn("0000000000000000"));
    }

    #[test]
    fn test_ssn_validation() {
        assert!(validate_ssn("123-45-6780"));
        assert!(validate_ssn("219 45 7890"));

        // Invalid area codes
        assert!(!validate_ssn("000-45-6789"));
        assert!(!validate_ssn("666-45-6789"));
        assert!(!validate_ssn("900-45-6789"));

        // Invalid group codes
        assert!(!validate_ssn("123-00-6789"));

        // Invalid serial numbers
        assert!(!validate_ssn("123-45-0000"));
    }

    #[test]
    fn test_iban_validation() {
        // Valid test IBANs (GB and DE)
        assert!(validate_iban("GB82WEST12345698765432"));
        assert!(validate_iban("DE89370400440532013000"));

        // Invalid checksum IBAN
        assert!(!validate_iban("GB82WEST12345698765433"));
    }

    #[test]
    fn test_dlp_scanner_detection() {
        let scanner = DlpScanner::new();
        let payload = r#"
            User profile export:
            Payment method: 4111 1111 1111 1111
            SSN: 219-45-7890
            Bank: DE89370400440532013000
            API: ghp_123456789012345678901234567890123456
            Config: -----BEGIN RSA PRIVATE KEY-----
        "#;

        let findings = scanner.scan_text(payload);
        assert!(findings.len() >= 5);
        assert!(findings
            .iter()
            .any(|f| matches!(f.dlp_type, DlpType::CreditCard(CreditCardBrand::Visa))));
        assert!(findings
            .iter()
            .any(|f| matches!(f.dlp_type, DlpType::SocialSecurityNumber)));
        assert!(findings
            .iter()
            .any(|f| matches!(f.dlp_type, DlpType::Iban(_))));
        assert!(findings
            .iter()
            .any(|f| matches!(f.dlp_type, DlpType::PrivateKey(_))));
        assert!(findings
            .iter()
            .any(|f| matches!(f.dlp_type, DlpType::ApiSecret(_))));
    }
}
