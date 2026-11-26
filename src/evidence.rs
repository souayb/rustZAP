//! Shared evidence contract: the single redaction pass applied at export time
//! to every evidence-bearing artifact (JSON/CSV/HTML/SARIF reports, agent
//! captures, autofix prompts, audit traces), plus the stable finding identifier
//! that links reproduction templates to their evidence across formats.

use std::sync::OnceLock;

use regex::Regex;
use serde_json::Value;

use crate::types::{Confidence, Finding, HttpTransaction};

/// Header names whose values must never be exported.
const SENSITIVE_HEADERS: &[&str] = &[
    "authorization",
    "proxy-authorization",
    "cookie",
    "set-cookie",
    "x-api-key",
    "x-auth-token",
    "x-csrf-token",
];

pub const REDACTED: &str = "[REDACTED]";

fn is_sensitive_header(name: &str) -> bool {
    SENSITIVE_HEADERS
        .iter()
        .any(|h| name.trim().eq_ignore_ascii_case(h))
}

/// Ordered (pattern, replacement) rules applied to free text: headers, URLs,
/// query strings, request bodies, response excerpts, logs, exception text.
fn rules() -> &'static [(Regex, &'static str)] {
    static RULES: OnceLock<Vec<(Regex, &'static str)>> = OnceLock::new();
    RULES.get_or_init(|| {
        let r = |p: &str| Regex::new(p).expect("static redaction regex");
        vec![
            // `Authorization: ...`, `Cookie: ...`, `Set-Cookie: ...` header lines (raw or in curl -H).
            (
                r(r"(?i)\b(proxy-authorization|authorization|set-cookie|cookie|x-api-key|x-auth-token|x-csrf-token)(\s*:\s*)[^\r\n'`]*"),
                "${1}${2}[REDACTED]",
            ),
            // Bearer / Basic credentials anywhere in text.
            (
                r(r"(?i)\b(bearer|basic)\s+[A-Za-z0-9._~+/=-]+"),
                "${1} [REDACTED]",
            ),
            // URL userinfo: scheme://user:pass@host
            (r(r"(?i)\b([a-z][a-z0-9+.-]*://)[^/\s:@]+:[^/\s@]+@"), "${1}[REDACTED]@"),
            // key=value / "key":"value" secrets in query strings, form and JSON bodies.
            (
                r(r#"(?i)(^|[?&;\s"'{,(])((?:access_|refresh_|id_|auth_|csrf_|xsrf_)?token|api[_-]?key|apikey|key|password|passwd|pwd|secret|client_secret|session(?:_?id)?|sessid|sid|jsessionid|phpsessid|signature|sig)(["']?\s*[=:]\s*["']?)([^&\s"',;}<]+)"#),
                "${1}${2}${3}[REDACTED]",
            ),
            // JWTs.
            (
                r(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*"),
                "[REDACTED_JWT]",
            ),
            // Personal data: email addresses and US SSN-shaped numbers.
            (
                r(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}"),
                "[REDACTED_EMAIL]",
            ),
            (r(r"\b\d{3}-\d{2}-\d{4}\b"), "[REDACTED_SSN]"),
        ]
    })
}

/// Redact credentials and personal data embedded in arbitrary text.
pub fn redact_string(s: &str) -> String {
    let mut out = s.to_string();
    for (re, rep) in rules() {
        if re.is_match(&out) {
            out = re.replace_all(&out, *rep).into_owned();
        }
    }
    out
}

/// Redact a JSON value: sensitive object keys and `[name, value]` header pairs
/// lose their value; every other string goes through [`redact_string`].
pub fn redact(v: &Value) -> Value {
    match v {
        Value::Object(map) => Value::Object(
            map.iter()
                .map(|(k, val)| {
                    let val = if is_sensitive_header(k) {
                        Value::String(REDACTED.into())
                    } else {
                        redact(val)
                    };
                    (k.clone(), val)
                })
                .collect(),
        ),
        Value::Array(arr) => match arr.as_slice() {
            [Value::String(k), Value::String(_)] if is_sensitive_header(k) => Value::Array(vec![
                Value::String(k.clone()),
                Value::String(REDACTED.into()),
            ]),
            _ => Value::Array(arr.iter().map(redact).collect()),
        },
        Value::String(s) => Value::String(redact_string(s)),
        other => other.clone(),
    }
}

/// Stable identifier for a finding: hash of plugin + location + parameter + title.
/// The query string is ignored so payload/token values don't change the id.
pub fn finding_fingerprint(f: &Finding) -> String {
    let location = match &f.location {
        Some(loc) => format!("{}:{}", loc.file, loc.line_start),
        None => f.url.split(['?', '#']).next().unwrap_or("").to_string(),
    };
    let key = format!(
        "{}\n{}\n{}\n{}",
        f.plugin,
        location,
        f.parameter.as_deref().unwrap_or(""),
        f.title
    );
    crate::crypto_sig::sha256_hex(key.as_bytes())[..32].to_string()
}

/// Single validation vocabulary shared by every export format.
pub fn validation_status(f: &Finding) -> &'static str {
    if f.poc_validated || f.confidence == Confidence::Confirmed {
        "confirmed"
    } else if f.confidence == Confidence::Tentative {
        "tentative"
    } else {
        "unconfirmed"
    }
}

/// The exported form of a finding: evidence contract fields filled in, then
/// every evidence-bearing string redacted.
pub fn export_finding(f: &Finding) -> Finding {
    let mut f = f.clone();
    f.fingerprint = Some(finding_fingerprint(&f));
    f.validation_status = Some(validation_status(&f).to_string());
    if f.method.is_none() {
        f.method = f
            .poc
            .as_ref()
            .and_then(|p| p.raw_request.split_whitespace().next())
            .map(str::to_uppercase);
    }
    let v = serde_json::to_value(&f).expect("Finding serializes");
    serde_json::from_value(redact(&v)).expect("redaction preserves Finding shape")
}

/// Redacted copy of a captured HTTP transaction (replay artifact).
pub fn redact_transaction(t: &HttpTransaction) -> HttpTransaction {
    let v = serde_json::to_value(t).expect("HttpTransaction serializes");
    serde_json::from_value(redact(&v)).expect("redaction preserves transaction shape")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::Severity;

    #[test]
    fn redacts_each_location_kind() {
        let cases = [
            ("Authorization: Bearer abc.def", "abc.def"),
            ("curl -H 'Cookie: sid=zzz' http://x", "zzz"),
            ("Set-Cookie: SESSION=qqq; HttpOnly", "qqq"),
            ("GET /a?access_token=t0k&x=1", "t0k"),
            (r#"{"password":"hunter2"}"#, "hunter2"),
            ("user=a&passwd=p4ss", "p4ss"),
            ("mail jane.doe@example.test now", "jane.doe"),
            ("https://bob:pw123@host/", "pw123"),
            ("ssn 123-45-6789", "123-45-6789"),
        ];
        for (input, secret) in cases {
            let out = redact_string(input);
            assert!(!out.contains(secret), "{input} -> {out}");
        }
        // Idempotent and leaves ordinary text alone.
        let once = redact_string("GET /a?token=abc");
        assert_eq!(redact_string(&once), once);
        assert_eq!(
            redact_string("X-Frame-Options missing"),
            "X-Frame-Options missing"
        );
    }

    #[test]
    fn fingerprint_is_stable_and_ignores_query_values() {
        let a = Finding::new("XSS", Severity::High, "http://h/p?q=1", "d", "s", "xss");
        let b = Finding::new("XSS", Severity::High, "http://h/p?q=2", "d", "s", "xss");
        assert_ne!(a.id, b.id);
        assert_eq!(finding_fingerprint(&a), finding_fingerprint(&b));
        let c = Finding::new("XSS", Severity::High, "http://h/other", "d", "s", "xss");
        assert_ne!(finding_fingerprint(&a), finding_fingerprint(&c));
    }
}
