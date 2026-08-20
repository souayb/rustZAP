//! Repo-wide secret scanning over every text file (not just JS).
//!
//! Complements `js_surface` (which owns `.js`/`.ts`): this analyzer covers
//! `.env`, YAML, Python, Go, SQL, shell, config, and anything else textual so
//! a hardcoded credential is caught regardless of file type — and without
//! requiring Gitleaks to be installed.

use std::path::{Path, PathBuf};

use regex::Regex;

use crate::analyze::inventory::{
    file_url, is_js_like, is_minified_name, line_number, read_text_head, rel_path, MAX_SOURCE_BYTES,
};
use crate::analyze::native::SOURCE_TOOL;
use crate::types::{CodeLocation, Finding, Severity};

const MAX_SECRET_FINDINGS: usize = 100;

struct SecretPatterns {
    rules: Vec<(&'static str, Regex)>,
}

impl SecretPatterns {
    fn new() -> Self {
        Self {
            rules: vec![
                ("aws-access-key", re(r"AKIA[0-9A-Z]{16}")),
                ("google-api-key", re(r"AIza[0-9A-Za-z\-_]{35}")),
                ("slack-token", re(r"xox[baprs]-[0-9A-Za-z-]{10,}")),
                (
                    "slack-webhook",
                    re(r"https://hooks\.slack\.com/services/[A-Za-z0-9/]+"),
                ),
                ("stripe-live", re(r"sk_live_[0-9A-Za-z]{16,}")),
                ("github-token", re(r"gh[pousr]_[A-Za-z0-9]{20,}")),
                (
                    "github-fine-grained-pat",
                    re(r"github_pat_[A-Za-z0-9_]{22,}"),
                ),
                ("gitlab-pat", re(r"glpat-[0-9A-Za-z\-_]{20}")),
                ("npm-token", re(r"npm_[A-Za-z0-9]{36}")),
                (
                    "private-key",
                    re(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP |ENCRYPTED )?PRIVATE KEY-----"),
                ),
                (
                    "jwt",
                    re(r"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}"),
                ),
                (
                    "db-connection-string",
                    re(
                        r"(?i)(?:postgres|postgresql|mysql|mongodb(?:\+srv)?|redis|amqp)://[^:@\s/]+:[^@\s/]+@",
                    ),
                ),
                (
                    "generic-secret-assignment",
                    re(
                        r#"(?i)(?:api[_-]?key|secret|token|password|passwd|pwd|access[_-]?key)\w*\s*[:=]\s*['"][^'"\s]{8,}['"]"#,
                    ),
                ),
            ],
        }
    }
}

fn re(pat: &str) -> Regex {
    Regex::new(pat).expect("static secrets regex")
}

pub fn scan(root: &Path, files: &[PathBuf]) -> Vec<Finding> {
    let patterns = SecretPatterns::new();
    let mut out = Vec::new();
    for path in files {
        // JS/TS are handled by `js_surface` to avoid duplicate findings.
        if is_js_like(path) || is_minified_name(path) {
            continue;
        }
        let Some((src, _truncated)) = read_text_head(path, MAX_SOURCE_BYTES) else {
            continue;
        };
        out.extend(scan_source(root, path, &src, &patterns));
        if out.len() >= MAX_SECRET_FINDINGS {
            out.truncate(MAX_SECRET_FINDINGS);
            break;
        }
    }
    out
}

fn scan_source(root: &Path, path: &Path, src: &str, patterns: &SecretPatterns) -> Vec<Finding> {
    let rel = rel_path(root, path);
    let mut out = Vec::new();
    for (kind, re) in &patterns.rules {
        for m in re.find_iter(src) {
            if out.len() >= MAX_SECRET_FINDINGS {
                return out;
            }
            let line = line_number(src, m.start());
            out.push(
                Finding::new(
                    format!("Possible secret ({kind})"),
                    Severity::High,
                    file_url(path, Some(line)),
                    format!("Heuristic secret pattern `{kind}` detected in {rel}."),
                    "Rotate the credential, remove it from source control, and load it from a secret manager or environment at runtime.",
                    "sast/secrets",
                )
                .with_source_tool(SOURCE_TOOL)
                .with_parameter(*kind)
                .with_evidence(redact(m.as_str()))
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
    out
}

/// Show a short non-reversible hint so reviewers can locate the value without
/// the report leaking the full secret.
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

    fn scan_str(name: &str, src: &str) -> Vec<Finding> {
        scan_source(Path::new("."), Path::new(name), src, &SecretPatterns::new())
    }

    #[test]
    fn detects_aws_key_in_env_file() {
        let f = scan_str(".env", "AWS_ACCESS_KEY_ID=AKIAEXAMPLEKEYFAKE00\n");
        assert!(f
            .iter()
            .any(|f| f.parameter.as_deref() == Some("aws-access-key")));
        assert!(f[0].evidence.as_deref().unwrap().contains("REDACTED"));
    }

    #[test]
    fn detects_private_key_and_db_url_in_yaml() {
        let src = "key: |\n  -----BEGIN RSA PRIVATE KEY-----\ndb: postgres://admin:s3cr3tpw@db:5432/app\n";
        let f = scan_str("config.yaml", src);
        assert!(f
            .iter()
            .any(|f| f.parameter.as_deref() == Some("private-key")));
        assert!(f
            .iter()
            .any(|f| f.parameter.as_deref() == Some("db-connection-string")));
    }

    #[test]
    fn detects_generic_assignment_in_python() {
        let f = scan_str(
            "settings.py",
            r#"SECRET_KEY = "not-a-real-secret-abcdefgh""#,
        );
        assert!(f
            .iter()
            .any(|f| f.parameter.as_deref() == Some("generic-secret-assignment")));
    }

    #[test]
    fn skips_js_files_here() {
        // JS is owned by js_surface; this analyzer must skip it.
        let out = scan(Path::new("."), &[PathBuf::from("app.js")]);
        assert!(out.is_empty());
    }

    #[test]
    fn plugin_id_is_sast_secrets() {
        let f = scan_str(".env", "GITHUB_TOKEN=ghp_abcdefghijklmnopqrstuvwxyz0123\n");
        assert_eq!(f[0].plugin, "sast/secrets");
    }
}
