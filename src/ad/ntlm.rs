//! NTLM negotiate-flag inspection.
//!
//! We send an NTLMSSP type-1 (NEGOTIATE) to a target that speaks NTLM over HTTP
//! (WinRM `5985/5986`, or IIS `80/443`) and read the flags the server sets in its
//! type-2 (CHALLENGE) reply. Two relay-relevant signals fall out:
//!   * no `NEGOTIATE_EXTENDED_SESSIONSECURITY` ⇒ NTLMv1-compatible session security
//!   * no `NEGOTIATE_SIGN` ⇒ message signing not negotiated
//!
//! The wire transport is best-effort (any failure ⇒ no finding); the flag
//! decoding is pure and unit-tested against a fixed CHALLENGE buffer.

use anyhow::Result;
use async_trait::async_trait;
use base64::Engine;

use crate::types::{Confidence, Finding, Severity};

use super::probe::{NtlmFlags, NtlmProbe};
use super::{host_url, OWASP_AUTH};

const NEGOTIATE_SIGN: u32 = 0x0000_0010;
const NEGOTIATE_SEAL: u32 = 0x0000_0020;
const NEGOTIATE_EXTENDED_SESSIONSECURITY: u32 = 0x0008_0000;

// Type-1 request flags: Unicode + OEM + RequestTarget + NTLM + AlwaysSign +
// ExtendedSessionSecurity. We advertise strong session security so a server that
// still negotiates *down* is genuinely NTLMv1-tolerant.
const TYPE1_FLAGS: u32 = 0x0000_0001
    | 0x0000_0002
    | 0x0000_0004
    | 0x0000_0200
    | 0x0000_8000
    | NEGOTIATE_EXTENDED_SESSIONSECURITY;

/// Build a minimal NTLMSSP type-1 (NEGOTIATE) message (32 bytes).
pub fn build_type1() -> Vec<u8> {
    let mut m = Vec::with_capacity(32);
    m.extend_from_slice(b"NTLMSSP\0");
    m.extend_from_slice(&1u32.to_le_bytes()); // MessageType = 1
    m.extend_from_slice(&TYPE1_FLAGS.to_le_bytes());
    m.extend_from_slice(&[0u8; 8]); // DomainNameFields (empty)
    m.extend_from_slice(&[0u8; 8]); // WorkstationFields (empty)
    m
}

/// Parse the NegotiateFlags out of an NTLMSSP type-2 (CHALLENGE) message.
///
/// Layout: signature(8) + MessageType(4) + TargetNameFields(8) + NegotiateFlags(4).
pub fn parse_type2_flags(buf: &[u8]) -> Option<NtlmFlags> {
    if buf.len() < 24 || &buf[0..8] != b"NTLMSSP\0" {
        return None;
    }
    if u32::from_le_bytes([buf[8], buf[9], buf[10], buf[11]]) != 2 {
        return None;
    }
    let flags = u32::from_le_bytes([buf[20], buf[21], buf[22], buf[23]]);
    Some(NtlmFlags {
        sign: flags & NEGOTIATE_SIGN != 0,
        seal: flags & NEGOTIATE_SEAL != 0,
        extended_session_security: flags & NEGOTIATE_EXTENDED_SESSIONSECURITY != 0,
    })
}

/// Extract the base64 NTLM token from a `WWW-Authenticate` header value.
pub fn ntlm_token_from_header(value: &str) -> Option<Vec<u8>> {
    for part in value.split(',') {
        let part = part.trim();
        if let Some(b64) = part
            .strip_prefix("NTLM ")
            .or_else(|| part.strip_prefix("Negotiate "))
        {
            if let Ok(bytes) = base64::engine::general_purpose::STANDARD.decode(b64.trim()) {
                if bytes.starts_with(b"NTLMSSP\0") {
                    return Some(bytes);
                }
            }
        }
    }
    None
}

/// NTLM negotiate-flag verdicts for `host`. Heuristic ⇒ `Tentative`.
pub fn ntlm_findings(host: &str, flags: &NtlmFlags) -> Vec<Finding> {
    let mut out = Vec::new();
    let url = host_url(host);

    if !flags.extended_session_security {
        out.push(
            Finding::new(
                format!("NTLMv1 / weak session security on {host}"),
                Severity::High,
                url.clone(),
                "The target negotiated NTLM without extended session security, indicating NTLMv1 \
                 is accepted. NTLMv1 responses can be cracked or relayed and materially widen \
                 relay attack surface.",
                "Set \"Network security: LAN Manager authentication level\" to \"Send NTLMv2 \
                 response only. Refuse LM & NTLM\" and disable NTLMv1 across the domain.",
                "ad/ntlmv1",
            )
            .with_source_tool("rustzap-ad")
            .with_confidence(Confidence::Tentative)
            .with_cwe(326)
            .with_owasp(OWASP_AUTH),
        );
    }

    if !flags.sign {
        out.push(
            Finding::new(
                format!("NTLM message signing not negotiated on {host}"),
                Severity::Medium,
                url,
                "The target did not set the NTLM signing flag in its CHALLENGE, so relayed \
                 authentication to this service would not be integrity-protected.",
                "Require SMB/LDAP signing and Extended Protection for Authentication (EPA) on \
                 the affected services.",
                "ad/ntlm-signing",
            )
            .with_source_tool("rustzap-ad")
            .with_confidence(Confidence::Tentative)
            .with_cwe(294)
            .with_owasp(OWASP_AUTH),
        );
    }

    out
}

/// Live NTLM probe over HTTP (WinRM / IIS). Best-effort: unreachable or
/// non-NTLM targets yield `Ok(None)`.
pub struct HttpNtlmProbe {
    client: reqwest::Client,
}

impl HttpNtlmProbe {
    pub fn new(insecure: bool) -> Result<Self> {
        let client = reqwest::Client::builder()
            .danger_accept_invalid_certs(insecure)
            .timeout(std::time::Duration::from_secs(8))
            .build()?;
        Ok(HttpNtlmProbe { client })
    }

    fn endpoint(host: &str, port: u16) -> String {
        match port {
            5985 => format!("http://{host}:5985/wsman"),
            5986 => format!("https://{host}:5986/wsman"),
            443 => format!("https://{host}/"),
            _ => format!("http://{host}:{port}/"),
        }
    }
}

#[async_trait]
impl NtlmProbe for HttpNtlmProbe {
    async fn challenge_flags(&self, host: &str, port: u16) -> Result<Option<NtlmFlags>> {
        let token = base64::engine::general_purpose::STANDARD.encode(build_type1());
        let url = Self::endpoint(host, port);
        let resp = match self
            .client
            .get(&url)
            .header(reqwest::header::AUTHORIZATION, format!("NTLM {token}"))
            .send()
            .await
        {
            Ok(r) => r,
            Err(_) => return Ok(None),
        };
        for value in resp.headers().get_all(reqwest::header::WWW_AUTHENTICATE) {
            if let Ok(s) = value.to_str() {
                if let Some(bytes) = ntlm_token_from_header(s) {
                    return Ok(parse_type2_flags(&bytes));
                }
            }
        }
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn type2(flags: u32) -> Vec<u8> {
        let mut m = Vec::new();
        m.extend_from_slice(b"NTLMSSP\0");
        m.extend_from_slice(&2u32.to_le_bytes());
        m.extend_from_slice(&[0u8; 8]); // TargetNameFields
        m.extend_from_slice(&flags.to_le_bytes());
        m.extend_from_slice(&[0u8; 16]); // challenge + reserved
        m
    }

    #[test]
    fn type1_is_well_formed() {
        let t1 = build_type1();
        assert_eq!(&t1[0..8], b"NTLMSSP\0");
        assert_eq!(u32::from_le_bytes([t1[8], t1[9], t1[10], t1[11]]), 1);
        assert_eq!(t1.len(), 32);
    }

    #[test]
    fn parses_strong_and_weak_flags() {
        let strong =
            parse_type2_flags(&type2(NEGOTIATE_SIGN | NEGOTIATE_EXTENDED_SESSIONSECURITY)).unwrap();
        assert!(strong.sign && strong.extended_session_security);
        let weak = parse_type2_flags(&type2(0)).unwrap();
        assert!(!weak.sign && !weak.extended_session_security);
    }

    #[test]
    fn rejects_non_type2() {
        assert!(parse_type2_flags(b"NTLMSSP\0\x01\x00\x00\x00").is_none());
        assert!(parse_type2_flags(b"garbage").is_none());
    }

    #[test]
    fn weak_flags_emit_ntlmv1_and_signing() {
        let f = ntlm_findings(
            "SRV01",
            &NtlmFlags {
                sign: false,
                seal: false,
                extended_session_security: false,
            },
        );
        assert_eq!(f.len(), 2);
        assert!(f
            .iter()
            .any(|x| x.plugin == "ad/ntlmv1" && x.severity == Severity::High));
        assert!(f.iter().all(|x| x.confidence == Confidence::Tentative));
    }

    #[test]
    fn strong_flags_are_silent() {
        let f = ntlm_findings(
            "SRV01",
            &NtlmFlags {
                sign: true,
                seal: true,
                extended_session_security: true,
            },
        );
        assert!(f.is_empty());
    }

    #[test]
    fn header_token_extraction() {
        let b64 = base64::engine::general_purpose::STANDARD.encode(type2(NEGOTIATE_SIGN));
        let hdr = format!("Negotiate, NTLM {b64}");
        let bytes = ntlm_token_from_header(&hdr).expect("token");
        assert!(parse_type2_flags(&bytes).unwrap().sign);
        assert!(ntlm_token_from_header("Basic realm=x").is_none());
    }
}
