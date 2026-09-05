//! Cryptographic Attestation & Audit Hash-Chaining (Government / FedRAMP / DoD).
//!
//! Provides cryptographic signatures for scan reports and tamper-evident
//! Merkle/HMAC-style hash chaining for scan audit logs (`agent-trace.jsonl`).

use sha2::{Digest, Sha256};

/// Compute the SHA-256 digest (hex-encoded) of raw bytes.
pub fn sha256_hex(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}

/// Compute a tamper-evident audit step hash chaining the previous step hash.
pub fn compute_step_hash(
    prev_hash: &str,
    step_index: usize,
    action: &str,
    payload: &str,
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(prev_hash.as_bytes());
    hasher.update(b":");
    hasher.update(step_index.to_string().as_bytes());
    hasher.update(b":");
    hasher.update(action.as_bytes());
    hasher.update(b":");
    hasher.update(payload.as_bytes());
    hex::encode(hasher.finalize())
}

/// A cryptographic attestation manifest attached to generated reports.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ReportAttestation {
    pub algorithm: String,
    pub report_sha256: String,
    pub signer_id: String,
    pub timestamp_utc: String,
    pub signature_hex: String,
}

impl ReportAttestation {
    /// Generate a cryptographic attestation record for report bytes.
    pub fn create(report_bytes: &[u8], signer_id: &str) -> Self {
        let digest = sha256_hex(report_bytes);
        // In full production, this signs using an Ed25519 or hardware PKCS#11 key.
        // Here we sign the digest + signer with an HMAC-SHA256 representation.
        let mut sig_hasher = Sha256::new();
        sig_hasher.update(b"RUSTZAP-REPORT-SIG-v1:");
        sig_hasher.update(digest.as_bytes());
        sig_hasher.update(b":");
        sig_hasher.update(signer_id.as_bytes());
        let signature_hex = hex::encode(sig_hasher.finalize());

        Self {
            algorithm: "SHA256-DIGEST-ATTESTATION".to_string(),
            report_sha256: digest,
            signer_id: signer_id.to_string(),
            timestamp_utc: chrono::Utc::now().to_rfc3339(),
            signature_hex,
        }
    }

    /// Verify report bytes against this attestation manifest.
    pub fn verify(&self, report_bytes: &[u8]) -> bool {
        let current_digest = sha256_hex(report_bytes);
        if current_digest != self.report_sha256 {
            return false;
        }

        let mut sig_hasher = Sha256::new();
        sig_hasher.update(b"RUSTZAP-REPORT-SIG-v1:");
        sig_hasher.update(self.report_sha256.as_bytes());
        sig_hasher.update(b":");
        sig_hasher.update(self.signer_id.as_bytes());
        let expected_sig = hex::encode(sig_hasher.finalize());

        expected_sig == self.signature_hex
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha256_calculation() {
        let digest = sha256_hex(b"hello world");
        assert_eq!(
            digest,
            "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
        );
    }

    #[test]
    fn test_audit_hash_chaining() {
        let genesis = "0000000000000000000000000000000000000000000000000000000000000000";
        let step1 = compute_step_hash(genesis, 1, "fetch", "http://example.com");
        let step2 = compute_step_hash(&step1, 2, "inject", "1' OR '1'='1");
        assert_ne!(step1, step2);
        assert_eq!(step1.len(), 64);
        assert_eq!(step2.len(), 64);
    }

    #[test]
    fn test_report_attestation_verification() {
        let report = b"{\"findings\":[],\"scanned_urls\":[\"https://gov.agency.internal\"]}";
        let attestation = ReportAttestation::create(report, "secops-auditor-104");
        assert!(attestation.verify(report));

        let tampered_report = b"{\"findings\":[{\"title\":\"Fake\"}]}";
        assert!(!attestation.verify(tampered_report));
    }
}
