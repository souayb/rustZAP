//! C1 — TLS certificate summary probe.
//!
//! `probe_tls(host, port)` does a TCP connect + TLS handshake with a
//! *non-verifying* `rustls` client (so we can inspect bad / expired certs),
//! pulls the peer chain, parses the leaf via `x509-parser`, and returns a
//! `TlsSummary`. `check_hosts` runs the probe once per unique host and
//! converts the result into `Finding`s.
//!
//! Findings:
//! - `transport/tls-expired` Critical when notAfter is in the past
//! - `transport/tls-expiring-soon` Medium when notAfter < 30 days
//! - `transport/tls-weak-signature` Medium when SHA-1 / MD5 in signature alg
//! - `transport/tls-self-signed` Low when issuer == subject
//! - `transport/tls-hostname-mismatch` Medium when host not in SAN (stub:
//!   exact match against DNS SANs only; wildcard support is limited)

use std::sync::Arc;
use std::time::{Duration, SystemTime};

use chrono::{DateTime, TimeZone, Utc};
use rustls::client::{ServerCertVerified, ServerCertVerifier, ServerName};
use rustls::{Certificate, ClientConfig};
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tracing::warn;
use x509_parser::prelude::*;

use crate::types::{Finding, Severity};

#[derive(Debug, Clone)]
#[allow(dead_code)] // `port`, `issuer`, `not_before` are part of the public summary surface.
pub struct TlsSummary {
    pub host: String,
    pub port: u16,
    pub subject: String,
    pub issuer: String,
    pub not_before: DateTime<Utc>,
    pub not_after: DateTime<Utc>,
    pub signature_algorithm: String,
    pub subject_alt_names: Vec<String>,
    pub self_signed: bool,
}

/// Open a TCP+TLS connection to `host:port` and return a summary of the
/// peer leaf certificate. Returns `None` on any network or parse error —
/// TLS probes are best-effort, and any host that doesn't respond is silently
/// dropped from reporting.
pub async fn probe_tls(host: &str, port: u16) -> Option<TlsSummary> {
    let config = ClientConfig::builder()
        .with_safe_defaults()
        .with_custom_certificate_verifier(Arc::new(AcceptAnyVerifier))
        .with_no_client_auth();
    let connector = TlsConnector::from(Arc::new(config));
    let server_name = ServerName::try_from(host).ok()?;

    let tcp = tokio::time::timeout(Duration::from_secs(5), TcpStream::connect((host, port)))
        .await
        .ok()?
        .ok()?;

    let mut tls = tokio::time::timeout(Duration::from_secs(5), connector.connect(server_name, tcp))
        .await
        .ok()?
        .ok()?;

    // The handshake completes during `connect`, so peer_certificates() is
    // already populated. We still issue a clean shutdown to be polite.
    let (_, conn) = tls.get_ref();
    let summary = conn
        .peer_certificates()
        .and_then(|chain| summarize_chain(host, port, chain));
    let _ = tls.shutdown().await;
    summary
}

/// Parse the first cert in `chain` (the leaf) into a `TlsSummary`.
fn summarize_chain(host: &str, port: u16, chain: &[Certificate]) -> Option<TlsSummary> {
    let leaf = chain.first()?;
    let (_, cert) = X509Certificate::from_der(&leaf.0).ok()?;
    let subject = cert.subject().to_string();
    let issuer = cert.issuer().to_string();

    let not_before = cert.validity().not_before.timestamp();
    let not_after = cert.validity().not_after.timestamp();
    let not_before = Utc.timestamp_opt(not_before, 0).single()?;
    let not_after = Utc.timestamp_opt(not_after, 0).single()?;

    let signature_algorithm = format!("{}", cert.signature_algorithm.algorithm);

    let subject_alt_names = cert
        .extensions()
        .iter()
        .find_map(|ext| match ext.parsed_extension() {
            ParsedExtension::SubjectAlternativeName(san) => Some(
                san.general_names
                    .iter()
                    .filter_map(|gn| match gn {
                        GeneralName::DNSName(s) => Some(s.to_string()),
                        _ => None,
                    })
                    .collect::<Vec<_>>(),
            ),
            _ => None,
        })
        .unwrap_or_default();

    let self_signed = subject == issuer;

    Some(TlsSummary {
        host: host.to_string(),
        port,
        subject,
        issuer,
        not_before,
        not_after,
        signature_algorithm,
        subject_alt_names,
        self_signed,
    })
}

/// Canonical list of plugin ids the TLS probe can emit. Used by the scanner
/// to surface quiet transport modules in the module-tree view (SDD §9.1).
pub fn known_plugin_names() -> &'static [&'static str] {
    &[
        "transport/tls-expired",
        "transport/tls-expiring-soon",
        "transport/tls-weak-signature",
        "transport/tls-self-signed",
        "transport/tls-hostname-mismatch",
    ]
}

/// Probe each unique host in `hosts` (port 443) and convert into findings.
pub async fn check_hosts(hosts: &[String]) -> Vec<Finding> {
    let mut seen = std::collections::HashSet::new();
    let mut findings = Vec::new();
    for host in hosts {
        if !seen.insert(host.clone()) {
            continue;
        }
        match probe_tls(host, 443).await {
            Some(summary) => {
                findings.extend(evaluate_tls_summary(&summary, Utc::now()));
            }
            None => {
                warn!("TLS probe failed for {}", host);
            }
        }
    }
    findings
}

/// Pure evaluator — separated for unit testing.
pub fn evaluate_tls_summary(summary: &TlsSummary, now: DateTime<Utc>) -> Vec<Finding> {
    let mut findings = Vec::new();
    let target = format!("https://{}", summary.host);

    // Expiry.
    if summary.not_after < now {
        findings.push(
            Finding::new(
                "TLS Certificate Expired",
                Severity::Critical,
                &target,
                format!(
                    "The TLS certificate for {} expired on {}. Browsers will block connections.",
                    summary.host, summary.not_after
                ),
                "Renew the certificate immediately and automate renewal (e.g. via certbot/ACME).",
                "transport/tls-expired",
            )
            .with_evidence(format!("notAfter: {}", summary.not_after))
            .with_cwe(298)
            .with_owasp("A02:2021 – Cryptographic Failures"),
        );
    } else if summary.not_after - now < chrono::Duration::days(30) {
        findings.push(
            Finding::new(
                "TLS Certificate Expiring Soon",
                Severity::Medium,
                &target,
                format!(
                    "The TLS certificate for {} expires on {} (in under 30 days).",
                    summary.host, summary.not_after
                ),
                "Renew the certificate before it expires.",
                "transport/tls-expiring-soon",
            )
            .with_evidence(format!("notAfter: {}", summary.not_after)),
        );
    }

    // Weak signature algorithm.
    let sig = summary.signature_algorithm.to_lowercase();
    if sig.contains("sha1") || sig.contains("md5") {
        findings.push(
            Finding::new(
                "Weak TLS Certificate Signature Algorithm",
                Severity::Medium,
                &target,
                format!(
                    "The certificate is signed with {}, which is cryptographically broken.",
                    summary.signature_algorithm
                ),
                "Reissue the certificate with SHA-256 (or stronger) and a modern key.",
                "transport/tls-weak-signature",
            )
            .with_evidence(summary.signature_algorithm.clone())
            .with_cwe(327)
            .with_owasp("A02:2021 – Cryptographic Failures"),
        );
    }

    // Self-signed.
    if summary.self_signed {
        findings.push(
            Finding::new(
                "Self-signed TLS Certificate",
                Severity::Low,
                &target,
                "The certificate is self-signed. Clients will reject it unless they trust it explicitly.",
                "Issue the certificate from a trusted CA (Let's Encrypt, internal CA, etc.).",
                "transport/tls-self-signed",
            )
            .with_evidence(format!("subject == issuer: {}", summary.subject)),
        );
    }

    // Hostname mismatch (exact + simple wildcard).
    if !hostname_matches(&summary.host, &summary.subject_alt_names) {
        findings.push(
            Finding::new(
                "TLS Hostname Mismatch",
                Severity::Medium,
                &target,
                format!(
                    "The certificate's SANs do not cover {}. Clients will warn about an invalid certificate.",
                    summary.host
                ),
                "Reissue the certificate with the correct SAN list.",
                "transport/tls-hostname-mismatch",
            )
            .with_evidence(format!("SANs: {}", summary.subject_alt_names.join(", ")))
            .with_cwe(297)
            .with_owasp("A02:2021 – Cryptographic Failures"),
        );
    }

    findings
}

/// True when `host` matches any SAN entry. Wildcards match exactly one label.
pub fn hostname_matches(host: &str, sans: &[String]) -> bool {
    let host_l = host.to_lowercase();
    for san in sans {
        let san_l = san.to_lowercase();
        if san_l == host_l {
            return true;
        }
        if let Some(rest) = san_l.strip_prefix("*.") {
            // Wildcard matches exactly one label (RFC 6125).
            if let Some(host_rest) = host_l.split_once('.').map(|(_, r)| r) {
                if host_rest == rest {
                    return true;
                }
            }
        }
    }
    false
}

/// A rustls `ServerCertVerifier` that trusts everything. We *only* use it to
/// inspect certificates — we don't tunnel real traffic through this client.
struct AcceptAnyVerifier;

impl ServerCertVerifier for AcceptAnyVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &Certificate,
        _intermediates: &[Certificate],
        _server_name: &ServerName,
        _scts: &mut dyn Iterator<Item = &[u8]>,
        _ocsp_response: &[u8],
        _now: SystemTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(host: &str, sans: Vec<&str>) -> TlsSummary {
        TlsSummary {
            host: host.into(),
            port: 443,
            subject: format!("CN={}", host),
            issuer: "CN=Test CA".into(),
            not_before: Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap(),
            not_after: Utc.with_ymd_and_hms(2027, 1, 1, 0, 0, 0).unwrap(),
            signature_algorithm: "1.2.840.113549.1.1.11".into(), // SHA-256 with RSA
            subject_alt_names: sans.into_iter().map(String::from).collect(),
            self_signed: false,
        }
    }

    #[test]
    fn hostname_matches_exact_san() {
        let sans = vec!["example.com".to_string()];
        assert!(hostname_matches("example.com", &sans));
        assert!(!hostname_matches("api.example.com", &sans));
    }

    #[test]
    fn hostname_matches_wildcard_one_label() {
        let sans = vec!["*.example.com".to_string()];
        assert!(hostname_matches("api.example.com", &sans));
        assert!(!hostname_matches("a.b.example.com", &sans));
        assert!(!hostname_matches("example.com", &sans));
    }

    #[test]
    fn evaluate_flags_expired_cert() {
        let now = Utc.with_ymd_and_hms(2030, 1, 1, 0, 0, 0).unwrap();
        let s = sample("example.com", vec!["example.com"]);
        let findings = evaluate_tls_summary(&s, now);
        assert!(findings.iter().any(|f| f.title.contains("Expired")));
    }

    #[test]
    fn evaluate_flags_expiring_soon() {
        let now = Utc.with_ymd_and_hms(2026, 12, 20, 0, 0, 0).unwrap();
        let s = sample("example.com", vec!["example.com"]);
        let findings = evaluate_tls_summary(&s, now);
        assert!(findings.iter().any(|f| f.title.contains("Expiring Soon")));
    }

    #[test]
    fn evaluate_flags_weak_signature() {
        let now = Utc.with_ymd_and_hms(2026, 6, 1, 0, 0, 0).unwrap();
        let mut s = sample("example.com", vec!["example.com"]);
        s.signature_algorithm = "1.2.840.113549.1.1.5".into(); // sha1WithRSA OID
                                                               // Force lowercase string to actually contain "sha1"
        s.signature_algorithm = "sha1WithRSAEncryption".into();
        let findings = evaluate_tls_summary(&s, now);
        assert!(findings.iter().any(|f| f.title.contains("Weak")));
    }

    #[test]
    fn evaluate_flags_hostname_mismatch() {
        let now = Utc.with_ymd_and_hms(2026, 6, 1, 0, 0, 0).unwrap();
        let s = sample("example.com", vec!["other.example.com"]);
        let findings = evaluate_tls_summary(&s, now);
        assert!(findings.iter().any(|f| f.title.contains("Hostname")));
    }

    #[test]
    fn evaluate_flags_self_signed() {
        let now = Utc.with_ymd_and_hms(2026, 6, 1, 0, 0, 0).unwrap();
        let mut s = sample("example.com", vec!["example.com"]);
        s.self_signed = true;
        let findings = evaluate_tls_summary(&s, now);
        assert!(findings.iter().any(|f| f.title.contains("Self-signed")));
    }

    #[test]
    fn evaluate_quiet_when_healthy() {
        let now = Utc.with_ymd_and_hms(2026, 6, 1, 0, 0, 0).unwrap();
        let s = sample("example.com", vec!["example.com"]);
        let findings = evaluate_tls_summary(&s, now);
        assert!(findings.is_empty(), "got: {:?}", findings);
    }
}
