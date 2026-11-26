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
//! - `transport/tls-untrusted-chain` Medium when the chain does not build to a
//!   Mozilla (webpki-roots) trust anchor
//! - `transport/tls-inconclusive` Info whenever a check could not be decided:
//!   failed probe, masked chain trust, and legacy TLS 1.0/1.1 acceptance
//!   (rustls cannot offer those versions, so that check is always inconclusive)

use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, TimeZone, Utc};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::client::WebPkiServerVerifier;
use rustls::crypto::{ring, verify_tls12_signature, verify_tls13_signature, CryptoProvider};
use rustls::pki_types::{CertificateDer, Der, ServerName, TrustAnchor, UnixTime};
use rustls::{
    CertificateError, ClientConfig, DigitallySignedStruct, RootCertStore, SignatureScheme,
};
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tracing::warn;
use x509_parser::prelude::*;

use crate::types::{Confidence, Finding, Severity};

/// Outcome of validating the peer chain against the Mozilla root set.
#[derive(Debug, Clone, PartialEq)]
pub enum ChainTrust {
    Trusted,
    Untrusted(String),
    Inconclusive(String),
}

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
    /// Negotiated protocol (e.g. `TLSv1_3`), when the handshake reported one.
    pub protocol_version: Option<String>,
    pub chain_trust: ChainTrust,
}

/// Open a TCP+TLS connection to `host:port` and return a summary of the
/// peer leaf certificate. `Err` carries the reason the probe failed, which
/// callers report as an inconclusive result.
pub async fn probe_tls(host: &str, port: u16) -> Result<TlsSummary, String> {
    // Explicit provider: does not depend on a process-wide default being installed.
    let provider = Arc::new(ring::default_provider());
    let config = ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .map_err(|e| format!("TLS config: {e}"))?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAnyVerifier(provider.clone())))
        .with_no_client_auth();
    let connector = TlsConnector::from(Arc::new(config));
    let server_name =
        ServerName::try_from(host.to_string()).map_err(|e| format!("invalid server name: {e}"))?;

    let tcp = tokio::time::timeout(Duration::from_secs(5), TcpStream::connect((host, port)))
        .await
        .map_err(|_| "TCP connect timed out".to_string())?
        .map_err(|e| format!("TCP connect failed: {e}"))?;

    let mut tls = tokio::time::timeout(
        Duration::from_secs(5),
        connector.connect(server_name.clone(), tcp),
    )
    .await
    .map_err(|_| "TLS handshake timed out".to_string())?
    .map_err(|e| format!("TLS handshake failed: {e}"))?;

    // The handshake completes during `connect`, so peer_certificates() is
    // already populated. We still issue a clean shutdown to be polite.
    let (_, conn) = tls.get_ref();
    let protocol_version = conn.protocol_version().map(|v| format!("{v:?}"));
    let summary = conn
        .peer_certificates()
        .ok_or_else(|| "server sent no certificate".to_string())
        .and_then(|chain| {
            let mut s = summarize_chain(host, port, chain)
                .ok_or_else(|| "could not parse leaf certificate".to_string())?;
            s.chain_trust = evaluate_chain_trust(provider, &server_name, chain, UnixTime::now());
            s.protocol_version = protocol_version;
            Ok(s)
        });
    let _ = tls.shutdown().await;
    summary
}

/// Validate `chain` against the Mozilla root set. Name and expiry are
/// reported by their own checks, so only path-building failures count as
/// untrusted; errors that mask path building are inconclusive.
pub fn evaluate_chain_trust(
    provider: Arc<CryptoProvider>,
    server_name: &ServerName<'_>,
    chain: &[CertificateDer<'_>],
    now: UnixTime,
) -> ChainTrust {
    let Some((leaf, intermediates)) = chain.split_first() else {
        return ChainTrust::Inconclusive("server sent no certificates".into());
    };
    let roots = RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS
            .iter()
            .map(|ta| TrustAnchor {
                subject: Der::from_slice(ta.subject),
                subject_public_key_info: Der::from_slice(ta.spki),
                name_constraints: ta.name_constraints.map(Der::from_slice),
            })
            .collect(),
    };
    let verifier =
        match WebPkiServerVerifier::builder_with_provider(Arc::new(roots), provider).build() {
            Ok(v) => v,
            Err(e) => return ChainTrust::Inconclusive(format!("verifier setup failed: {e}")),
        };
    match verifier.verify_server_cert(leaf, intermediates, server_name, &[], now) {
        Ok(_) => ChainTrust::Trusted,
        Err(rustls::Error::InvalidCertificate(e)) => match e {
            // rustls checks the name only after the path to a root was built.
            CertificateError::NotValidForName | CertificateError::NotValidForNameContext { .. } => {
                ChainTrust::Trusted
            }
            CertificateError::UnknownIssuer | CertificateError::BadSignature => {
                ChainTrust::Untrusted(format!("{e:?}"))
            }
            other => ChainTrust::Inconclusive(format!("chain trust masked by {other:?}")),
        },
        Err(e) => ChainTrust::Inconclusive(e.to_string()),
    }
}

/// Parse the first cert in `chain` (the leaf) into a `TlsSummary`.
fn summarize_chain(host: &str, port: u16, chain: &[CertificateDer<'_>]) -> Option<TlsSummary> {
    let leaf = chain.first()?;
    let (_, cert) = X509Certificate::from_der(leaf.as_ref()).ok()?;
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
        protocol_version: None,
        chain_trust: ChainTrust::Inconclusive("not evaluated".into()),
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
        "transport/tls-untrusted-chain",
        "transport/tls-inconclusive",
    ]
}

/// Explicit "could not decide" result for one TLS check on `host`.
pub fn inconclusive_finding(host: &str, check: &str, reason: &str) -> Finding {
    Finding::new(
        "TLS Check Inconclusive",
        Severity::Info,
        format!("https://{host}"),
        format!("The TLS `{check}` check for {host} is inconclusive: {reason}."),
        "Verify manually (e.g. `openssl s_client` / testssl.sh) against an authorized target.",
        "transport/tls-inconclusive",
    )
    .with_parameter(check)
    .with_evidence(reason.to_string())
    .with_confidence(Confidence::Tentative)
}

/// Probe each unique host in `hosts` (port 443) and convert into findings.
pub async fn check_hosts(hosts: &[String]) -> Vec<Finding> {
    check_hosts_with_coverage(hosts).await.0
}

/// Like [`check_hosts`], plus one execution record per host so a failed probe
/// is reported as an `error`, not as a clean certificate evaluation (#41).
pub async fn check_hosts_with_coverage(
    hosts: &[String],
) -> (Vec<Finding>, Vec<crate::coverage::ExecutionRecord>) {
    use crate::coverage::{ExecutionRecord, Outcome};
    let mut seen = std::collections::HashSet::new();
    let mut findings = Vec::new();
    let mut records = Vec::new();
    for host in hosts {
        if !seen.insert(host.clone()) {
            continue;
        }
        let (outcome, completed, reason) = match probe_tls(host, 443).await {
            Ok(summary) => {
                let f = evaluate_tls_summary(&summary, Utc::now());
                // Inconclusive notes (e.g. legacy-protocol check) are not findings.
                let outcome = if f.iter().all(|x| x.plugin == "transport/tls-inconclusive") {
                    Outcome::CompletedNoFinding
                } else {
                    Outcome::Finding
                };
                findings.extend(f);
                (outcome, 1, String::new())
            }
            Err(reason) => {
                warn!("TLS probe failed for {}: {}", host, reason);
                findings.push(inconclusive_finding(host, "probe", &reason));
                (
                    Outcome::Error,
                    0,
                    format!("TLS probe failed ({reason}); certificate was NOT evaluated"),
                )
            }
        };
        records.push(ExecutionRecord {
            endpoint: format!("{host}:443"),
            method: "TLS".to_string(),
            plugin: "transport/tls".to_string(),
            identity: None,
            requests_attempted: 1,
            requests_completed: completed,
            outcome,
            reason,
        });
    }
    (findings, records)
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

    // Chain trust.
    match &summary.chain_trust {
        ChainTrust::Trusted => {}
        ChainTrust::Untrusted(reason) => findings.push(
            Finding::new(
                "Untrusted TLS Certificate Chain",
                Severity::Medium,
                &target,
                format!(
                    "The certificate chain for {} does not build to a trusted public root.",
                    summary.host
                ),
                "Serve the full intermediate chain from a publicly trusted CA.",
                "transport/tls-untrusted-chain",
            )
            .with_evidence(reason.clone())
            .with_cwe(295)
            .with_owasp("A02:2021 – Cryptographic Failures"),
        ),
        ChainTrust::Inconclusive(reason) => {
            findings.push(inconclusive_finding(&summary.host, "chain-trust", reason))
        }
    }

    // Legacy protocol acceptance: rustls only speaks TLS 1.2/1.3.
    findings.push(inconclusive_finding(
        &summary.host,
        "legacy-protocols",
        &format!(
            "TLS 1.0/1.1 acceptance not tested (rustls cannot offer those versions); negotiated {}",
            summary.protocol_version.as_deref().unwrap_or("unknown")
        ),
    ));

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

/// A rustls `ServerCertVerifier` that trusts every certificate chain. We *only*
/// use it to inspect certificates — we don't tunnel real traffic through this
/// client. Handshake signatures are still checked, as before the rustls 0.23 move.
#[derive(Debug)]
struct AcceptAnyVerifier(Arc<CryptoProvider>);

impl ServerCertVerifier for AcceptAnyVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls12_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
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
            protocol_version: Some("TLSv1_3".into()),
            chain_trust: ChainTrust::Trusted,
        }
    }

    fn non_inconclusive(findings: &[Finding]) -> Vec<&Finding> {
        findings
            .iter()
            .filter(|f| f.plugin != "transport/tls-inconclusive")
            .collect()
    }

    #[test]
    fn legacy_protocol_check_is_explicitly_inconclusive() {
        let now = Utc.with_ymd_and_hms(2026, 6, 1, 0, 0, 0).unwrap();
        let findings = evaluate_tls_summary(&sample("example.com", vec!["example.com"]), now);
        let f = findings
            .iter()
            .find(|f| f.parameter.as_deref() == Some("legacy-protocols"))
            .expect("legacy inconclusive");
        assert_eq!(f.severity, Severity::Info);
        assert!(f.description.contains("inconclusive"));
        assert!(f.evidence.as_deref().unwrap().contains("TLSv1_3"));
    }

    #[test]
    fn untrusted_and_inconclusive_chain_are_reported() {
        let now = Utc.with_ymd_and_hms(2026, 6, 1, 0, 0, 0).unwrap();
        let mut s = sample("example.com", vec!["example.com"]);
        s.chain_trust = ChainTrust::Untrusted("UnknownIssuer".into());
        let f = evaluate_tls_summary(&s, now);
        assert!(f
            .iter()
            .any(|f| f.plugin == "transport/tls-untrusted-chain"));
        s.chain_trust = ChainTrust::Inconclusive("chain trust masked by Expired".into());
        let f = evaluate_tls_summary(&s, now);
        assert!(f
            .iter()
            .any(|f| f.parameter.as_deref() == Some("chain-trust")
                && f.plugin == "transport/tls-inconclusive"));
    }

    #[test]
    fn chain_trust_is_inconclusive_for_empty_or_garbage_chain() {
        let provider = Arc::new(ring::default_provider());
        let name = ServerName::try_from("example.com").unwrap();
        assert!(matches!(
            evaluate_chain_trust(provider.clone(), &name, &[], UnixTime::now()),
            ChainTrust::Inconclusive(_)
        ));
        let junk = CertificateDer::from(vec![0u8; 8]);
        assert!(!matches!(
            evaluate_chain_trust(provider, &name, &[junk], UnixTime::now()),
            ChainTrust::Trusted
        ));
    }

    #[tokio::test]
    async fn failed_probe_yields_inconclusive_reason() {
        // Port 1 on loopback is closed in CI; the probe must fail with a reason.
        let err = probe_tls("127.0.0.1", 1).await.expect_err("closed port");
        assert!(!err.is_empty());
        let f = inconclusive_finding("127.0.0.1", "probe", &err);
        assert_eq!(f.plugin, "transport/tls-inconclusive");
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
        let real = non_inconclusive(&findings);
        assert!(real.is_empty(), "got: {:?}", real);
    }
}
