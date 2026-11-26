//! JWT analysis pass (`passive/jwt`).
//!
//! Decodes bearer tokens observed via `--auth` and in Authorization / Set-Cookie
//! response headers, and flags common weaknesses:
//! - `alg: none` (unsigned token accepted),
//! - missing `exp` (no expiry),
//! - HS256 signed with a weak secret — **only** when `crack` is set (the
//!   `--jwt-crack` opt-in). The crack is a fully offline dictionary check: no
//!   network, a small built-in word list, no external files.
//!
//! The full token is never emitted; evidence redacts the signature segment.

use base64::Engine;
use regex::Regex;
use sha2::{Digest, Sha256};

use crate::types::{Finding, Severity};

/// Small built-in HS256 secret dictionary (offline only). Expand deliberately —
/// a large list turns a detection probe into a slow brute force.
const WEAK_SECRETS: &[&str] = &[
    "secret",
    "password",
    "changeme",
    "admin",
    "123456",
    "jwt",
    "token",
    "key",
    "test",
    "secretkey",
    "your-256-bit-secret",
    "supersecret",
    "s3cr3t",
    "qwerty",
    "letmein",
];

fn token_re() -> Regex {
    // header.payload.signature — base64url segments; signature may be empty (alg:none).
    Regex::new(r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*").unwrap()
}

fn b64url(seg: &str) -> Option<Vec<u8>> {
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(seg)
        .ok()
}

/// Redact a token to `eyJhbG…[REDACTED-SIG]` — enough to correlate, never the whole thing.
fn redact(token: &str) -> String {
    let head = crate::types::safe_truncate(token, 12);
    format!("{head}….[REDACTED-SIG]")
}

/// Hand-rolled HMAC-SHA256 (avoids pulling in the `hmac` crate for one call site).
fn hmac_sha256(key: &[u8], msg: &[u8]) -> [u8; 32] {
    const BLOCK: usize = 64;
    let mut k = [0u8; BLOCK];
    if key.len() > BLOCK {
        let d = Sha256::digest(key);
        k[..32].copy_from_slice(&d);
    } else {
        k[..key.len()].copy_from_slice(key);
    }
    let mut ipad = [0x36u8; BLOCK];
    let mut opad = [0x5cu8; BLOCK];
    for i in 0..BLOCK {
        ipad[i] ^= k[i];
        opad[i] ^= k[i];
    }
    let mut inner = Sha256::new();
    inner.update(ipad);
    inner.update(msg);
    let inner = inner.finalize();
    let mut outer = Sha256::new();
    outer.update(opad);
    outer.update(inner);
    outer.finalize().into()
}

/// Analyze every JWT found in the given header strings plus an optional
/// `--auth` value. `source` is a label for the finding URL (e.g. the target).
pub fn scan(
    auth_header: Option<&str>,
    header_values: &[String],
    crack: bool,
    source: &str,
) -> Vec<Finding> {
    let re = token_re();
    let mut seen = std::collections::HashSet::new();
    let mut out = Vec::new();
    let candidates = auth_header
        .into_iter()
        .map(|s| s.to_string())
        .chain(header_values.iter().cloned());
    for value in candidates {
        for m in re.find_iter(&value) {
            let token = m.as_str();
            if !seen.insert(token.to_string()) {
                continue;
            }
            out.extend(analyze_token(token, crack, source));
        }
    }
    out
}

/// Analyze a single token. Public for unit testing.
pub fn analyze_token(token: &str, crack: bool, source: &str) -> Vec<Finding> {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return vec![];
    }
    let header_json =
        match b64url(parts[0]).and_then(|b| serde_json::from_slice::<serde_json::Value>(&b).ok()) {
            Some(v) => v,
            None => return vec![],
        };
    let payload_json = b64url(parts[1])
        .and_then(|b| serde_json::from_slice::<serde_json::Value>(&b).ok())
        .unwrap_or(serde_json::Value::Null);

    let alg = header_json
        .get("alg")
        .and_then(|a| a.as_str())
        .unwrap_or("")
        .to_string();
    let redacted = redact(token);
    let mut findings = Vec::new();

    let mk = |title: &str, sev: Severity, desc: String, sol: &str| -> Finding {
        Finding::new(title, sev, source, desc, sol, "passive/jwt")
            .with_evidence(redacted.clone())
            .with_cwe(347)
            .with_owasp("A02:2021 – Cryptographic Failures")
    };

    if alg.eq_ignore_ascii_case("none") {
        findings.push(mk(
            "JWT accepts alg:none (unsigned)",
            Severity::High,
            "The token header declares `alg: none`, meaning it carries no signature and can be forged.".to_string(),
            "Reject `none` as an algorithm server-side; require a signed algorithm (e.g. RS256).",
        ));
    }

    if payload_json.get("exp").is_none() {
        findings.push(mk(
            "JWT missing exp (no expiry)",
            Severity::Medium,
            "The token payload has no `exp` claim, so it never expires and a leaked token stays valid indefinitely.".to_string(),
            "Issue short-lived tokens with an `exp` claim and validate it on every request.",
        ));
    }

    if crack && alg.eq_ignore_ascii_case("HS256") {
        if let Some(secret) = crack_hs256(token, parts) {
            findings.push(
                mk(
                    "JWT HS256 signed with weak secret",
                    Severity::Critical,
                    format!(
                        "The HS256 signature was recovered offline with a dictionary secret ({secret:?}); tokens can be forged."
                    ),
                    "Use a long, random signing key (>=256 bits) from a secret manager and rotate the compromised key.",
                )
                .confirmed(),
            );
        }
    }

    findings
}

/// Returns the weak secret if the HS256 signature verifies against one, else None.
fn crack_hs256(token: &str, parts: Vec<&str>) -> Option<String> {
    let signature = b64url(parts[2])?;
    let signing_input = &token[..parts[0].len() + 1 + parts[1].len()];
    for secret in WEAK_SECRETS {
        let mac = hmac_sha256(secret.as_bytes(), signing_input.as_bytes());
        if mac.as_slice() == signature.as_slice() {
            return Some((*secret).to_string());
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn enc(bytes: &[u8]) -> String {
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
    }

    /// Build an HS256 token signed with `secret`.
    fn hs256_token(header: &str, payload: &str, secret: &str) -> String {
        let signing = format!("{}.{}", enc(header.as_bytes()), enc(payload.as_bytes()));
        let sig = hmac_sha256(secret.as_bytes(), signing.as_bytes());
        format!("{}.{}", signing, enc(&sig))
    }

    #[test]
    fn flags_alg_none() {
        let token = format!(
            "{}.{}.",
            enc(br#"{"alg":"none","typ":"JWT"}"#),
            enc(br#"{"sub":"1","exp":9999999999}"#)
        );
        let f = analyze_token(&token, false, "t");
        assert_eq!(f.len(), 1);
        assert!(f[0].title.contains("alg:none"));
        assert_eq!(f[0].severity, Severity::High);
        // Evidence must not contain the full token.
        assert!(!f[0]
            .evidence
            .as_ref()
            .unwrap()
            .contains(token.split('.').nth(1).unwrap()));
    }

    #[test]
    fn flags_missing_exp() {
        let token = hs256_token(r#"{"alg":"HS256"}"#, r#"{"sub":"1"}"#, "whatever");
        let f = analyze_token(&token, false, "t");
        assert!(f.iter().any(|x| x.title.contains("missing exp")));
    }

    #[test]
    fn crack_only_when_enabled() {
        let token = hs256_token(r#"{"alg":"HS256"}"#, r#"{"sub":"1","exp":1}"#, "secret");
        assert!(analyze_token(&token, false, "t")
            .iter()
            .all(|f| !f.title.contains("weak secret")));
        let cracked = analyze_token(&token, true, "t");
        let hit = cracked
            .iter()
            .find(|f| f.title.contains("weak secret"))
            .unwrap();
        assert_eq!(hit.severity, Severity::Critical);
    }

    #[test]
    fn strong_secret_not_cracked() {
        let token = hs256_token(
            r#"{"alg":"HS256"}"#,
            r#"{"sub":"1","exp":1}"#,
            "a-very-long-random-key-not-in-the-dictionary-xyz",
        );
        assert!(analyze_token(&token, true, "t")
            .iter()
            .all(|f| !f.title.contains("weak secret")));
    }

    #[test]
    fn hmac_matches_known_vector() {
        // RFC 4231 test case 1.
        let mac = hmac_sha256(&[0x0b; 20], b"Hi There");
        assert_eq!(
            hex::encode(mac),
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
        );
    }

    #[test]
    fn scan_extracts_bearer_and_dedups() {
        let token = hs256_token(r#"{"alg":"none"}"#, r#"{"sub":"1"}"#, "x");
        // alg:none token has a signature segment but header says none -> still flagged.
        let bearer = format!("Bearer {token}");
        let f = scan(Some(&bearer), &[format!("session={token}")], false, "t");
        // Same token seen twice -> analyzed once (2 findings: none + missing exp).
        assert_eq!(f.len(), 2);
    }
}
