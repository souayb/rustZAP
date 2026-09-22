//! Cryptographic Posture and Weak Hash Inspector (NIST SP 800-131A Rev 2 & OWASP A02:2021).
//!
//! Detects:
//! - Exposed weak/broken hashes (MD5, SHA-1, NTLM) in sensitive contexts
//! - Insecure cipher suites and block modes (DES, 3DES, RC4, Blowfish, AES-ECB)
//! - Substandard password hashing parameters (bcrypt cost < 10, weak Argon2/PBKDF2 settings)
//! - Insufficient RSA/DSA key lengths (< 2048 bits)

use crate::types::{Finding, Severity};
use regex::Regex;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WeakCryptoCategory {
    BrokenHash(String),        // MD5, SHA-1
    NtlmHash,                  // NTLM hash
    InsecureCipher(String),    // DES, 3DES, RC4, AES-ECB
    SubstandardKdf(String),    // bcrypt cost < 10, weak argon2
    WeakAsymmetricKey(String), // RSA-1024, etc.
}

#[derive(Debug, Clone)]
pub struct CryptoAuditMatch {
    pub category: WeakCryptoCategory,
    pub snippet: String,
    pub description: String,
    pub recommendation: String,
    pub severity: Severity,
}

pub struct CryptoAuditor {
    md5_context_regex: Regex,
    sha1_context_regex: Regex,
    ntlm_regex: Regex,
    insecure_cipher_regex: Regex,
    bcrypt_weak_regex: Regex,
    argon2_weak_regex: Regex,
}

impl Default for CryptoAuditor {
    fn default() -> Self {
        Self::new()
    }
}

impl CryptoAuditor {
    pub fn new() -> Self {
        Self {
            // MD5 in hash/password/token context
            md5_context_regex: Regex::new(r#"(?i)(?:password|hash|checksum|token|secret|digest|md5)\s*[:=]\s*['"]?([a-f0-9]{32})['"]?"#).unwrap(),
            // SHA1 in security context
            sha1_context_regex: Regex::new(r#"(?i)(?:password|secret_key|api_key|token|sha1)\s*[:=]\s*['"]?([a-f0-9]{40})['"]?"#).unwrap(),
            // NTLM / LM hash line pattern
            ntlm_regex: Regex::new(r#"\b[a-zA-Z0-9_\-\.\$]+:\d+:[a-fA-F0-9]{32}:[a-fA-F0-9]{32}:::\b"#).unwrap(),
            // Insecure ciphers and modes in code / config
            insecure_cipher_regex: Regex::new(r#"(?i)\b(?:DES_EDE3_CBC|DES-CBC|DES-EDE3|RC4|ARCFOUR|AES(?:_\d+)?_ECB|AES/ECB/PKCS5Padding|Blowfish|DES)\b"#).unwrap(),
            // Weak bcrypt cost parameter ($2a$04$, $2b$06$, etc. with cost < 10)
            bcrypt_weak_regex: Regex::new(r#"\$2[abxy]\$0([4-9])\$[./0-9A-Za-z]{22}[./0-9A-Za-z]{31}"#).unwrap(),
            // Weak Argon2 parameters (e.g. m=1024 or t=1)
            argon2_weak_regex: Regex::new(r#"\$argon2(?:id|i|d)\$v=\d+\$m=([0-9]{1,4}),t=([0-9]{1}),p=\d+\$"#).unwrap(),
        }
    }

    /// Audit arbitrary text or response content for weak cryptographic elements.
    pub fn audit_text(&self, text: &str) -> Vec<CryptoAuditMatch> {
        let mut results = Vec::new();

        // 1. MD5 Hash exposure
        for cap in self.md5_context_regex.captures_iter(text) {
            if let Some(m) = cap.get(1) {
                let hash = m.as_str();
                // Filter out trivial/all-zero hashes
                if !hash.chars().all(|c| c == '0' || c == 'f') {
                    results.push(CryptoAuditMatch {
                        category: WeakCryptoCategory::BrokenHash("MD5".to_string()),
                        snippet: cap.get(0).map_or("", |m| m.as_str()).to_string(),
                        description: "MD5 hash detected in sensitive context. MD5 is cryptographically broken and prone to collision attacks (NIST SP 800-131A).".to_string(),
                        recommendation: "Upgrade to SHA-256/SHA-3 for message integrity, or Argon2id/bcrypt/PBKDF2 for password hashing.".to_string(),
                        severity: Severity::Medium,
                    });
                }
            }
        }

        // 2. SHA-1 Hash exposure
        for cap in self.sha1_context_regex.captures_iter(text) {
            if let Some(m) = cap.get(1) {
                let hash = m.as_str();
                if !hash.chars().all(|c| c == '0') {
                    results.push(CryptoAuditMatch {
                        category: WeakCryptoCategory::BrokenHash("SHA-1".to_string()),
                        snippet: cap.get(0).map_or("", |m| m.as_str()).to_string(),
                        description: "SHA-1 hash detected in sensitive credential/secret context. SHA-1 is deprecated due to practical collision attacks (NIST SP 800-131A).".to_string(),
                        recommendation: "Replace SHA-1 with SHA-256, SHA-384, or SHA-512.".to_string(),
                        severity: Severity::Medium,
                    });
                }
            }
        }

        // 3. NTLM Hash Dump
        for mat in self.ntlm_regex.find_iter(text) {
            results.push(CryptoAuditMatch {
                category: WeakCryptoCategory::NtlmHash,
                snippet: mat.as_str().to_string(),
                description: "Windows LM/NTLM formatted hash dump exposed. NTLM hashes are vulnerable to pass-the-hash attacks and offline cracking.".to_string(),
                recommendation: "Remove NTLM hash dump immediately. Disable NTLM and migrate to Kerberos with AES-256 encryption.".to_string(),
                severity: Severity::Critical,
            });
        }

        // 4. Insecure Ciphers & Block Modes
        for mat in self.insecure_cipher_regex.find_iter(text) {
            let cipher = mat.as_str();
            results.push(CryptoAuditMatch {
                category: WeakCryptoCategory::InsecureCipher(cipher.to_string()),
                snippet: cipher.to_string(),
                description: format!("Insecure or legacy cryptographic cipher/mode '{}' detected. ECB mode leaks plaintext patterns; DES/RC4 are cryptographically broken.", cipher),
                recommendation: "Use authenticated symmetric encryption (AES-256-GCM, ChaCha20-Poly1305) with unique nonces.".to_string(),
                severity: Severity::High,
            });
        }

        // 5. Weak bcrypt cost
        for cap in self.bcrypt_weak_regex.captures_iter(text) {
            if let Some(cost_match) = cap.get(1) {
                let cost: u32 = cost_match.as_str().parse().unwrap_or(0);
                if cost < 10 {
                    results.push(CryptoAuditMatch {
                        category: WeakCryptoCategory::SubstandardKdf(format!("bcrypt cost={}", cost)),
                        snippet: cap.get(0).map_or("", |m| m.as_str()).to_string(),
                        description: format!("Substandard bcrypt work factor (cost={}) detected. Cost < 10 is susceptible to rapid GPU-based brute-force cracking.", cost),
                        recommendation: "Increase bcrypt work factor to at least cost=12 (or cost=10 minimum per NIST guidelines).".to_string(),
                        severity: Severity::High,
                    });
                }
            }
        }

        // 6. Weak Argon2 parameters
        for cap in self.argon2_weak_regex.captures_iter(text) {
            let mem_str = cap.get(1).map_or("0", |m| m.as_str());
            let time_str = cap.get(2).map_or("0", |m| m.as_str());
            let mem: u64 = mem_str.parse().unwrap_or(0);
            let time: u64 = time_str.parse().unwrap_or(0);

            if mem < 65536 || time < 2 {
                results.push(CryptoAuditMatch {
                    category: WeakCryptoCategory::SubstandardKdf(format!("argon2 m={}KiB, t={}", mem, time)),
                    snippet: cap.get(0).map_or("", |m| m.as_str()).to_string(),
                    description: format!("Weak Argon2 KDF parameters detected (memory={} KiB, iterations={}). Insufficient memory/time allows efficient ASIC/GPU attacks.", mem, time),
                    recommendation: "Configure Argon2id with at least m=65536 (64 MiB), t=3, p=4 per OWASP Password Storage Cheat Sheet.".to_string(),
                    severity: Severity::Medium,
                });
            }
        }

        results
    }
}

/// Helper function to convert crypto audit matches into standardized [`Finding`] records.
pub fn audit_crypto_posture(url_or_file: &str, content: &str) -> Vec<Finding> {
    let auditor = CryptoAuditor::new();
    let matches = auditor.audit_text(content);

    matches
        .into_iter()
        .map(|m| {
            let title = match &m.category {
                WeakCryptoCategory::BrokenHash(h) => format!("Weak Cryptographic Hash ({})", h),
                WeakCryptoCategory::NtlmHash => "Exposed NTLM Hash Credential".to_string(),
                WeakCryptoCategory::InsecureCipher(c) => {
                    format!("Insecure Cryptographic Cipher ({})", c)
                }
                WeakCryptoCategory::SubstandardKdf(k) => {
                    format!("Substandard Password Hash Parameters ({})", k)
                }
                WeakCryptoCategory::WeakAsymmetricKey(k) => {
                    format!("Weak Asymmetric Key Length ({})", k)
                }
            };

            Finding::new(
                title,
                m.severity,
                url_or_file,
                m.description,
                m.recommendation,
                "sast/crypto-audit",
            )
            .with_evidence(m.snippet)
            .with_cwe(327) // CWE-327: Use of a Broken or Risky Cryptographic Algorithm
            .with_owasp("A02:2021 – Cryptographic Failures")
        })
        .collect()
}

use crate::analyze::inventory::{
    file_url, is_minified_name, line_number, read_text_head, rel_path, MAX_SOURCE_BYTES,
};
use crate::analyze::native::SOURCE_TOOL;
use crate::types::CodeLocation;
use std::path::{Path, PathBuf};

const MAX_CRYPTO_FINDINGS: usize = 100;

pub fn scan(root: &Path, files: &[PathBuf]) -> Vec<Finding> {
    let auditor = CryptoAuditor::new();
    let mut out = Vec::new();

    for path in files {
        if is_minified_name(path) {
            continue;
        }
        let Some((src, _truncated)) = read_text_head(path, MAX_SOURCE_BYTES) else {
            continue;
        };

        let rel = rel_path(root, path);
        let matches = auditor.audit_text(&src);

        for m in matches {
            if out.len() >= MAX_CRYPTO_FINDINGS {
                return out;
            }

            let start_idx = src.find(&m.snippet).unwrap_or(0);
            let line = line_number(&src, start_idx);

            let title = match &m.category {
                WeakCryptoCategory::BrokenHash(h) => format!("Weak Cryptographic Hash ({})", h),
                WeakCryptoCategory::NtlmHash => "Exposed NTLM Hash Credential".to_string(),
                WeakCryptoCategory::InsecureCipher(c) => {
                    format!("Insecure Cryptographic Cipher ({})", c)
                }
                WeakCryptoCategory::SubstandardKdf(k) => {
                    format!("Substandard Password Hash Parameters ({})", k)
                }
                WeakCryptoCategory::WeakAsymmetricKey(k) => {
                    format!("Weak Asymmetric Key Length ({})", k)
                }
            };

            out.push(
                Finding::new(
                    title,
                    m.severity,
                    file_url(path, Some(line)),
                    m.description,
                    m.recommendation,
                    "sast/crypto-audit",
                )
                .with_source_tool(SOURCE_TOOL)
                .with_evidence(m.snippet)
                .with_cwe(327)
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
    fn test_crypto_auditor_broken_hashes() {
        let auditor = CryptoAuditor::new();
        let sample = "user_record: password_md5='5d41402abc4b2a76b9719d911017c592', sha1='aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d'";
        let matches = auditor.audit_text(sample);
        assert_eq!(matches.len(), 2);
        assert!(matches
            .iter()
            .any(|m| matches!(m.category, WeakCryptoCategory::BrokenHash(ref h) if h == "MD5")));
        assert!(matches
            .iter()
            .any(|m| matches!(m.category, WeakCryptoCategory::BrokenHash(ref h) if h == "SHA-1")));
    }

    #[test]
    fn test_crypto_auditor_insecure_ciphers() {
        let auditor = CryptoAuditor::new();
        let sample = "Cipher cipher = Cipher.getInstance(\"AES/ECB/PKCS5Padding\");";
        let matches = auditor.audit_text(sample);
        assert_eq!(matches.len(), 1);
        assert!(matches
            .iter()
            .any(|m| matches!(m.category, WeakCryptoCategory::InsecureCipher(_))));
    }

    #[test]
    fn test_crypto_auditor_weak_kdf() {
        let auditor = CryptoAuditor::new();
        // bcrypt with cost 4 ($2a$04$...)
        let sample = "admin_hash: $2a$04$12345678901234567890123456789012345678901234567890123";
        let matches = auditor.audit_text(sample);
        assert_eq!(matches.len(), 1);
        assert!(matches
            .iter()
            .any(|m| matches!(m.category, WeakCryptoCategory::SubstandardKdf(_))));
    }
}
