//! B2 — Well-known and backup path probe.
//!
//! Opt-in: not present in the default `--plugins` list. The user must pass
//! `--plugins sensitive-paths,...` to enable it. This module performs a
//! curated set of HEAD requests against the target's origin and reports any
//! 200/2xx hits as Medium-severity exposure findings.
//!
//! Design constraints (per FEATURE.md B2 + CLAUDE.md legal/safety):
//! - HEAD requests only — never body-fetch potentially sensitive content.
//! - Per-origin dedupe — every parametrized URL discovers the same paths.
//! - Curated allowlist — no aggressive wordlist; pulls common offenders.
//! - Per-scan concurrency cap built into the loop (sequential by default).

use std::collections::HashSet;
use std::time::Duration;

use async_trait::async_trait;
use tokio::sync::Mutex;
use url::Url;

use crate::active::ScanPlugin;
use crate::types::{DiscoveredUrl, Finding, Severity};

/// Curated allowlist. Keep the list tight — the goal is to flag clear
/// misconfigurations, not to broad-scan the filesystem.
pub const SENSITIVE_PATHS: &[&str] = &[
    "/.git/HEAD",
    "/.git/config",
    "/.env",
    "/.env.local",
    "/.env.production",
    "/.DS_Store",
    "/.svn/entries",
    "/.hg/store/00manifest.i",
    "/backup.zip",
    "/backup.tar.gz",
    "/db.sql",
    "/dump.sql",
    "/wp-config.php.bak",
    "/config.php.bak",
    "/composer.json",
    "/composer.lock",
    "/package.json.bak",
    "/Dockerfile",
    "/docker-compose.yml",
    "/server-status",
    "/server-info",
    "/phpinfo.php",
    "/.aws/credentials",
    "/id_rsa",
    "/.ssh/id_rsa",
];

pub struct SensitivePathsPlugin {
    seen_origins: Mutex<HashSet<String>>,
}

impl SensitivePathsPlugin {
    pub fn new() -> Self {
        Self {
            seen_origins: Mutex::new(HashSet::new()),
        }
    }
}

impl Default for SensitivePathsPlugin {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl ScanPlugin for SensitivePathsPlugin {
    fn name(&self) -> &str {
        "sensitive-paths"
    }

    fn description(&self) -> &str {
        "Well-known / backup file probe — HEAD-only check for /.git/HEAD, /.env, /backup.zip, … (OPT-IN; default OFF)"
    }

    /// Probes are path-based, not param-based.
    fn always_run(&self) -> bool {
        true
    }

    async fn scan(&self, client: &reqwest::Client, target: &DiscoveredUrl) -> Vec<Finding> {
        let Some(origin) = origin_of(&target.url) else {
            return vec![];
        };

        {
            let mut seen = self.seen_origins.lock().await;
            if !seen.insert(origin.clone()) {
                return vec![];
            }
        }

        let mut findings = Vec::new();
        for path in SENSITIVE_PATHS {
            let url = format!("{}{}", origin.trim_end_matches('/'), path);
            let resp = match client
                .head(&url)
                .timeout(Duration::from_secs(5))
                .send()
                .await
            {
                Ok(r) => r,
                Err(_) => continue,
            };
            let status = resp.status().as_u16();
            if !(200..300).contains(&status) {
                continue;
            }

            // Content-Length helps avoid flagging large 200 HTML "soft 404" pages.
            let content_length = resp
                .headers()
                .get("content-length")
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.parse::<u64>().ok());

            if let Some(len) = content_length {
                // Heuristic: very large responses for `/.git/HEAD` etc. are
                // almost certainly an SPA catch-all returning index.html.
                if len > 4096 && !path.ends_with(".zip") && !path.ends_with(".tar.gz") {
                    continue;
                }
            }

            findings.push(
                Finding::new(
                    format!("Sensitive Path Exposed: {}", path),
                    Severity::Medium,
                    &url,
                    format!(
                        "The server returned a {} for {}. This file may expose source code, credentials, or infrastructure details.",
                        status, path
                    ),
                    "Remove the file from the web root or block requests to dotfile / backup paths at the web server layer.",
                    "active/sensitive-paths",
                )
                .with_evidence(format!("HTTP {} — Content-Length: {:?}", status, content_length))
                .with_cwe(538)
                .with_owasp("A05:2021 – Security Misconfiguration"),
            );
        }

        findings
    }
}

fn origin_of(url: &str) -> Option<String> {
    let parsed = Url::parse(url).ok()?;
    if !matches!(parsed.scheme(), "http" | "https") {
        return None;
    }
    let host = parsed.host_str()?;
    Some(match parsed.port() {
        Some(p) => format!("{}://{}:{}", parsed.scheme(), host, p),
        None => format!("{}://{}", parsed.scheme(), host),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn origin_strips_path_and_query() {
        assert_eq!(
            origin_of("https://example.com/foo/bar?x=1").as_deref(),
            Some("https://example.com")
        );
        assert_eq!(
            origin_of("http://example.com:8080/foo").as_deref(),
            Some("http://example.com:8080")
        );
        assert_eq!(origin_of("ftp://example.com"), None);
        assert_eq!(origin_of("not a url"), None);
    }

    #[test]
    fn wordlist_only_has_leading_slashes() {
        for p in SENSITIVE_PATHS {
            assert!(p.starts_with('/'), "path missing leading slash: {}", p);
            assert!(
                !p.contains(".."),
                "path traversal not allowed in wordlist: {}",
                p
            );
        }
    }
}
