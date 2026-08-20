//! JS/TS secret-lite, hardcoded URLs, and source map hints (Argus-inspired).

use std::path::{Path, PathBuf};

use regex::Regex;

use crate::analyze::inventory::{
    file_url, is_js_like, is_minified_name, line_number, read_text_head, rel_path, MAX_SOURCE_BYTES,
};
use crate::analyze::native::SOURCE_TOOL;
use crate::types::{CodeLocation, Confidence, Finding, Severity};

const MAX_SECRET_FINDINGS: usize = 50;
const MAX_URL_FINDINGS: usize = 30;

struct JsPatterns {
    secrets: Vec<(&'static str, Regex)>,
    urls: Regex,
    source_map: Regex,
}

impl JsPatterns {
    fn new() -> Self {
        Self {
            secrets: vec![
                ("aws-access-key", re(r"AKIA[0-9A-Z]{16}")),
                ("google-api-key", re(r"AIza[0-9A-Za-z\-_]{35}")),
                ("slack-token", re(r"xox[baprs]-[0-9A-Za-z-]{10,}")),
                ("stripe-live", re(r"sk_live_[0-9A-Za-z]{16,}")),
                ("github-pat", re(r"ghp_[A-Za-z0-9]{20,}")),
                (
                    "generic-secret",
                    re(r#"(?i)(?:api[_-]?key|secret|token)\s*[:=]\s*['"][^'"]{8,}['"]"#),
                ),
            ],
            urls: re(r#"https?://[^\s"'<>)\\]+"#),
            source_map: re(r"(?://[#@]\s*sourceMappingURL=)\S+"),
        }
    }
}

fn re(pat: &str) -> Regex {
    Regex::new(pat).expect("static js_surface regex")
}

pub fn scan(root: &Path, files: &[PathBuf]) -> Vec<Finding> {
    let patterns = JsPatterns::new();
    let mut out = Vec::new();
    for path in files {
        if !is_js_like(path) || is_minified_name(path) {
            continue;
        }
        let Some((src, _truncated)) = read_text_head(path, MAX_SOURCE_BYTES) else {
            continue;
        };
        out.extend(scan_js_source(root, path, &src, &patterns));
        if out.len() >= MAX_SECRET_FINDINGS + MAX_URL_FINDINGS + 20 {
            break;
        }
    }
    out
}

fn scan_js_source(root: &Path, path: &Path, src: &str, patterns: &JsPatterns) -> Vec<Finding> {
    let mut out = Vec::new();
    let rel = rel_path(root, path);

    let mut secret_count = 0usize;
    for (kind, re) in &patterns.secrets {
        for m in re.find_iter(src) {
            if secret_count >= MAX_SECRET_FINDINGS {
                break;
            }
            secret_count += 1;
            let line = line_number(src, m.start());
            let redacted = redact(m.as_str());
            out.push(
                Finding::new(
                    format!("Possible secret in JS ({kind})"),
                    Severity::High,
                    file_url(path, Some(line)),
                    format!("Heuristic secret pattern `{kind}` in {rel}."),
                    "Rotate the credential, remove it from source, and use a secret manager.",
                    "sast/js-secrets",
                )
                .with_source_tool(SOURCE_TOOL)
                .with_parameter(*kind)
                .with_evidence(redacted)
                .with_cwe(798)
                .with_owasp("A07:2021")
                .with_location(CodeLocation {
                    file: rel.clone(),
                    line_start: line,
                    line_end: None,
                })
                .tentative(),
            );
        }
    }

    let mut url_count = 0usize;
    let mut seen_urls = std::collections::BTreeSet::new();
    for m in patterns.urls.find_iter(src) {
        if url_count >= MAX_URL_FINDINGS {
            break;
        }
        let raw = m.as_str().trim_end_matches(['.', ',', ';', ')']);
        if raw.len() < 10 || !seen_urls.insert(raw.to_string()) {
            continue;
        }
        url_count += 1;
        let line = line_number(src, m.start());
        out.push(
            Finding::new(
                "Hardcoded URL in JavaScript",
                Severity::Info,
                file_url(path, Some(line)),
                format!("URL `{raw}` embedded in {rel}."),
                "Confirm the endpoint is expected and not an internal or staging host.",
                "sast/js-urls",
            )
            .with_source_tool(SOURCE_TOOL)
            .with_evidence(raw.to_string())
            .with_location(CodeLocation {
                file: rel.clone(),
                line_start: line,
                line_end: None,
            })
            .with_confidence(Confidence::Firm),
        );
    }

    if let Some(m) = patterns.source_map.find(src) {
        let line = line_number(src, m.start());
        out.push(
            Finding::new(
                "JavaScript source map reference",
                Severity::Info,
                file_url(path, Some(line)),
                format!("sourceMappingURL present in {rel} (may expose original sources)."),
                "Avoid shipping source maps to production if they reveal unpublished code.",
                "sast/js-urls",
            )
            .with_source_tool(SOURCE_TOOL)
            .with_evidence(m.as_str().to_string())
            .with_location(CodeLocation {
                file: rel,
                line_start: line,
                line_end: None,
            })
            .with_confidence(Confidence::Firm),
        );
    }

    out
}

fn redact(s: &str) -> String {
    let trimmed = s.trim_matches(|c| c == '\'' || c == '"');
    if trimmed.len() <= 8 {
        "[REDACTED]".to_string()
    } else {
        format!("{}…[REDACTED]", &trimmed[..4.min(trimmed.len())])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_generic_api_key_and_redacts() {
        let src = r#"const api_key = "test_key_not_a_real_secret_zz";"#;
        let path = Path::new("static/app.js");
        let findings = scan_js_source(Path::new("."), path, src, &JsPatterns::new());
        let secrets: Vec<_> = findings
            .iter()
            .filter(|f| f.plugin == "sast/js-secrets")
            .collect();
        assert!(!secrets.is_empty());
        let ev = secrets[0].evidence.as_deref().unwrap_or("");
        assert!(ev.contains("REDACTED"));
        assert!(!ev.contains("test_key_not_a_real_secret_zz"));
    }

    #[test]
    fn detects_aws_example_and_url_and_sourcemap() {
        let src = r#"
            const k = "AKIAEXAMPLEKEYFAKE00";
            fetch("https://example.invalid/api");
            //# sourceMappingURL=app.js.map
        "#;
        let findings = scan_js_source(Path::new("."), Path::new("app.js"), src, &JsPatterns::new());
        assert!(findings
            .iter()
            .any(|f| f.parameter.as_deref() == Some("aws-access-key")));
        assert!(findings
            .iter()
            .any(|f| f.plugin == "sast/js-urls" && f.title.contains("URL")));
        assert!(findings.iter().any(|f| f.title.contains("source map")));
    }

    #[test]
    fn redact_short_is_placeholder() {
        assert_eq!(redact("abcd"), "[REDACTED]");
        assert!(redact("abcdefghij").contains("REDACTED"));
    }
}
