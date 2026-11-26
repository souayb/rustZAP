//! B2 — Well-known and backup path probe + management-surface recognition.
//!
//! Opt-in: not present in the default `--plugins` list. The user must pass
//! `--plugins sensitive-paths,...` to enable it.
//!
//! Design constraints (per FEATURE.md B2 + CLAUDE.md legal/safety):
//! - Per-origin dedupe — every parametrized URL discovers the same paths.
//! - Curated allowlist — no aggressive wordlist; pulls common offenders.
//! - Bounded budget: `BASELINE_PROBES + SENSITIVE_PATHS + MANAGEMENT_SURFACES`
//!   sequential GETs per origin, each body read capped at `BODY_CAP`, all
//!   through the active `HttpSafetyGate`.
//! - SPA / soft-404 resistant: a random missing-path baseline is fingerprinted
//!   once per origin; a candidate matching it is never a finding, and every
//!   file finding must also match a per-path content signature.
//! - Evidence carries one redacted line at most — never the captured body.

use std::collections::hash_map::DefaultHasher;
use std::collections::HashSet;
use std::hash::{Hash, Hasher};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use tokio::sync::Mutex;
use url::Url;

use crate::active::ScanPlugin;
use crate::agent::trace::redact_string;
use crate::types::{safe_truncate, DiscoveredUrl, Finding, Severity};

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
    "/.git/index",
    "/.npmrc",
    "/.htpasswd",
    "/web.config.bak",
    "/settings.py.bak",
    "/application.properties.bak",
    "/credentials.json",
    "/secrets.yml",
    "/secrets.yaml",
    "/terraform.tfstate",
    "/.terraform/terraform.tfstate",
    "/docker-compose.override.yml",
    "/.idea/workspace.xml",
    "/index.php.bak",
    "/index.html.bak",
    "/.vscode/sftp.json",
];

/// Random missing paths requested once per origin to learn its "not found"
/// behaviour (SPA catch-all, custom error page, dotfile deny rule).
const BASELINE_PROBES: usize = 3;

/// Max bytes read from any probe body — enough for signatures and a stable
/// fingerprint of a large SPA shell, never a full dump/backup download.
const BODY_CAP: usize = 16 * 1024;

#[derive(Clone, Copy)]
enum Surface {
    /// Prometheus text exposition (`# HELP` / `# TYPE`).
    Metrics,
    /// HTML sign-in / console page recognized by a lowercase marker.
    SignIn(&'static str),
    /// JSON management API recognized by a lowercase marker.
    Api(&'static str),
}

/// Management surfaces: (product, path, how to recognize exposed content).
const MANAGEMENT_SURFACES: &[(&str, &str, Surface)] = &[
    ("Prometheus metrics", "/metrics", Surface::Metrics),
    (
        "Prometheus metrics",
        "/actuator/prometheus",
        Surface::Metrics,
    ),
    (
        "Keycloak admin console",
        "/admin/master/console/",
        Surface::SignIn("keycloak"),
    ),
    (
        "Keycloak admin API",
        "/admin/realms",
        Surface::Api("\"realm\""),
    ),
    (
        "Argo CD",
        "/login",
        Surface::SignIn("<title>argo cd</title>"),
    ),
    (
        "Argo CD API",
        "/api/v1/applications",
        Surface::Api("\"items\""),
    ),
];

/// A bounded GET result.
struct Probe {
    status: u16,
    /// Redirect target (path only, query dropped — it often echoes the probe).
    location: String,
    /// Lowercased media type without parameters.
    media: String,
    body: Vec<u8>,
}

/// What a "missing" response looks like, so candidates can be compared to it.
#[derive(Debug, PartialEq)]
struct Fingerprint {
    status: u16,
    location: String,
    media: String,
    len_bucket: usize,
    hash: u64,
}

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
        "Well-known / backup file + management-surface probe — bounded GETs validated against a random-path baseline and content signatures (/.git/config, /.env, /metrics, Keycloak, Argo CD, …) (OPT-IN; default OFF)"
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
        let base = origin.trim_end_matches('/');

        let mut baseline = Vec::with_capacity(BASELINE_PROBES);
        for i in 0..BASELINE_PROBES {
            let token = format!("rz{:016x}", rand::random::<u64>());
            // Plain, dotfile and backup-extension shapes: servers often treat them differently.
            let path = match i {
                0 => format!("/{token}"),
                1 => format!("/.{token}"),
                _ => format!("/{token}.bak"),
            };
            if let Some(p) = probe(client, &format!("{base}{path}")).await {
                baseline.push(fingerprint(&p, &path));
            }
        }

        let mut findings = Vec::new();
        for path in SENSITIVE_PATHS {
            let url = format!("{base}{path}");
            let Some(p) = probe(client, &url).await else {
                continue;
            };
            if !(200..300).contains(&p.status) || matches_baseline(&baseline, &p, path) {
                continue;
            }
            let Some(sig) = file_signature(path, &p.body) else {
                continue;
            };
            findings.push(
                Finding::new(
                    format!("Sensitive Path Exposed: {}", path),
                    Severity::Medium,
                    &url,
                    format!(
                        "The server returned a {} for {} and the content matches the expected file format ({}). This file may expose source code, credentials, or infrastructure details.",
                        p.status, path, sig
                    ),
                    "Remove the file from the web root or block requests to dotfile / backup paths at the web server layer.",
                    "active/sensitive-paths",
                )
                .with_evidence(evidence(&p, sig))
                .with_cwe(538)
                .with_owasp("A05:2021 – Security Misconfiguration")
                .confirmed(),
            );
        }

        for (product, path, surface) in MANAGEMENT_SURFACES {
            let url = format!("{base}{path}");
            let Some(p) = probe(client, &url).await else {
                continue;
            };
            if let Some(f) = classify_surface(product, path, *surface, &p, &baseline, &url) {
                findings.push(f);
            }
        }

        findings
    }
}

/// Bounded GET through the active safety gate. Reads at most `BODY_CAP` bytes.
async fn probe(client: &reqwest::Client, url: &str) -> Option<Probe> {
    let gate = crate::active::active_gate();
    if let Some(g) = &gate {
        if g.before_url_request("GET", url, None).await.is_err() {
            return None;
        }
    }
    let start = Instant::now();
    let mut resp = client
        .get(url)
        .timeout(Duration::from_secs(5))
        .send()
        .await
        .ok()?;
    let status = resp.status().as_u16();
    let header = |name: &str| {
        resp.headers()
            .get(name)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string()
    };
    // A followed redirect shows up as a changed final URL instead of a Location header.
    let location = if resp.url().as_str() != url {
        resp.url().path().to_string()
    } else {
        header("location")
    };
    let location = location.split(['?', '#']).next().unwrap_or("").to_string();
    let media = header("content-type")
        .split(';')
        .next()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    let mut body = Vec::new();
    while body.len() < BODY_CAP {
        match resp.chunk().await {
            Ok(Some(c)) => body.extend_from_slice(&c),
            _ => break,
        }
    }
    body.truncate(BODY_CAP);
    if let Some(g) = &gate {
        let _ = g.after_response(status, start.elapsed().as_millis() as u64);
    }
    Some(Probe {
        status,
        location,
        media,
        body,
    })
}

/// Fingerprint a response. The body is normalized (requested path removed —
/// custom error pages echo it — lowercased, digits and whitespace dropped) so
/// nonces/timestamps and the probe path itself do not defeat the comparison.
fn fingerprint(p: &Probe, path: &str) -> Fingerprint {
    let text = String::from_utf8_lossy(&p.body).to_ascii_lowercase();
    let path = path.to_ascii_lowercase();
    let text = text
        .replace(&path, "")
        .replace(path.trim_start_matches('/'), "");
    let normalized: String = text
        .chars()
        .filter(|c| !c.is_ascii_digit() && !c.is_whitespace())
        .collect();
    let mut h = DefaultHasher::new();
    normalized.hash(&mut h);
    Fingerprint {
        status: p.status,
        location: p.location.clone(),
        media: p.media.clone(),
        len_bucket: p.body.len() / 512,
        hash: h.finish(),
    }
}

/// True when the response is indistinguishable from the origin's "missing" response.
fn matches_baseline(baseline: &[Fingerprint], p: &Probe, path: &str) -> bool {
    let fp = fingerprint(p, path);
    baseline.iter().any(|b| {
        b.status == fp.status
            && b.location == fp.location
            && b.media == fp.media
            && (b.hash == fp.hash || b.len_bucket == fp.len_bucket)
    })
}

fn looks_html(lower: &str) -> bool {
    lower.contains("<html") || lower.contains("<!doctype html")
}

/// Any `KEY=VALUE` line (dotenv / Java properties shape).
fn has_kv_line(text: &str) -> bool {
    text.lines().any(|l| {
        let l = l.trim().trim_start_matches("export ");
        !l.starts_with('#')
            && l.split_once('=').is_some_and(|(k, _)| {
                !k.is_empty()
                    && k.chars()
                        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-'))
            })
    })
}

/// Per-path content signature. Returns a short description of what matched,
/// or `None` when the body does not look like the requested file.
fn file_signature(path: &str, body: &[u8]) -> Option<&'static str> {
    let text = String::from_utf8_lossy(body);
    let lower = text.to_ascii_lowercase();
    let html = looks_html(&lower);
    let any = |needles: &[&str]| needles.iter().any(|n| lower.contains(n));
    let (ok, sig) = match path {
        "/.git/HEAD" => {
            let t = text.trim();
            (
                t.starts_with("ref: ")
                    || (t.len() == 40 && t.chars().all(|c| c.is_ascii_hexdigit())),
                "git HEAD reference",
            )
        }
        "/.git/config" => (lower.contains("[core]"), "git config [core] section"),
        "/.git/index" => (body.starts_with(b"DIRC"), "git index DIRC magic"),
        "/.DS_Store" => (body.get(4..8) == Some(&b"Bud1"[..]), "DS_Store Bud1 magic"),
        "/.svn/entries" => (
            !html && text.trim_start().starts_with(|c: char| c.is_ascii_digit()),
            "svn entries format number",
        ),
        "/.hg/store/00manifest.i" => (!html && body.contains(&0), "binary hg revlog"),
        "/.aws/credentials" => (lower.contains("aws_access_key_id"), "aws_access_key_id"),
        "/id_rsa" | "/.ssh/id_rsa" => (lower.contains("private key-----"), "PEM private key"),
        "/.npmrc" => (
            !html && any(&["registry", "_authtoken", "_auth=", "always-auth"]),
            "npm config keys",
        ),
        "/.htpasswd" => (
            !html
                && text.lines().any(|l| {
                    l.split_once(':')
                        .is_some_and(|(u, h)| !u.is_empty() && !h.is_empty() && !l.contains(' '))
                }),
            "user:hash lines",
        ),
        "/composer.lock" => (lower.contains("\"packages\""), "composer lock packages"),
        "/Dockerfile" => (
            text.lines()
                .any(|l| l.trim_start().to_ascii_uppercase().starts_with("FROM ")),
            "Dockerfile FROM instruction",
        ),
        "/server-status" => (
            any(&["apache server status", "server uptime"]),
            "Apache server-status page",
        ),
        "/server-info" => (
            lower.contains("apache server information"),
            "Apache server-info page",
        ),
        "/phpinfo.php" => (
            any(&["<title>phpinfo()", "php version"]),
            "phpinfo() output",
        ),
        "/web.config.bak" => (lower.contains("<configuration"), "web.config XML"),
        "/settings.py.bak" => (
            any(&["secret_key", "installed_apps", "databases"]),
            "Django settings",
        ),
        "/index.html.bak" => (html, "HTML backup"),
        "/.idea/workspace.xml" => (lower.contains("<project"), "IDE project XML"),
        p if p.contains("terraform.tfstate") => {
            (lower.contains("\"terraform_version\""), "terraform state")
        }
        p if p.starts_with("/.env") || p.ends_with(".properties.bak") => {
            (!html && has_kv_line(&text), "KEY=VALUE lines")
        }
        p if p.ends_with(".zip") => (body.starts_with(b"PK\x03\x04"), "ZIP magic"),
        p if p.ends_with(".tar.gz") => (body.starts_with(&[0x1f, 0x8b]), "gzip magic"),
        p if p.ends_with(".sql") => (
            !html
                && any(&[
                    "create table",
                    "insert into",
                    "-- mysql dump",
                    "postgresql database dump",
                ]),
            "SQL dump statements",
        ),
        p if p.ends_with(".php.bak") => (lower.contains("<?php"), "PHP source"),
        p if p.ends_with(".json") || p.ends_with(".json.bak") => {
            (!html && text.trim_start().starts_with('{'), "JSON document")
        }
        p if p.ends_with(".yml") || p.ends_with(".yaml") => (
            !html
                && text
                    .lines()
                    .any(|l| l.trim_end().ends_with(':') || l.contains(": ")),
            "YAML mapping",
        ),
        _ => (false, ""),
    };
    ok.then_some(sig)
}

/// Content-aware classification of a management surface into one of three
/// states: reachable sign-in page (Low), authentication-protected API (Info),
/// exposed operational data (High).
fn classify_surface(
    product: &str,
    path: &str,
    surface: Surface,
    p: &Probe,
    baseline: &[Fingerprint],
    url: &str,
) -> Option<Finding> {
    let lower = String::from_utf8_lossy(&p.body).to_ascii_lowercase();
    let ok = (200..300).contains(&p.status);
    let owasp = "A05:2021 – Security Misconfiguration";
    match surface {
        // The marker is the signature; an SPA that *is* the product (Argo CD)
        // legitimately matches its own catch-all baseline.
        Surface::SignIn(marker) if ok && looks_html(&lower) && lower.contains(marker) => Some(
            Finding::new(
                format!("Management Sign-in Page Reachable: {product}"),
                Severity::Low,
                url,
                format!("The {product} sign-in page at {path} is reachable from the scanned network position. No data is exposed without credentials, but the administrative attack surface is public."),
                "Restrict administrative consoles to a management network, VPN, or IP allowlist and enforce MFA.",
                "active/sensitive-paths",
            )
            .with_evidence(evidence(p, "product marker in HTML"))
            .with_owasp(owasp),
        ),
        Surface::SignIn(_) => None,
        _ if matches_baseline(baseline, p, path) => None,
        _ if matches!(p.status, 401 | 403) => Some(
            Finding::new(
                format!("Authentication-Protected Management Endpoint: {product}"),
                Severity::Info,
                url,
                format!("{path} answered HTTP {} — a {product} endpoint appears to exist and requires authentication. Observation only; no data was returned.", p.status),
                "No action required if exposure of this endpoint is intended; otherwise restrict it at the network layer.",
                "active/sensitive-paths",
            )
            .with_evidence(format!("HTTP {} — {}", p.status, p.media))
            .with_owasp(owasp),
        ),
        Surface::Metrics
            if ok
                && lower.lines().any(|l| l.starts_with("# help "))
                && lower.lines().any(|l| l.starts_with("# type ")) =>
        {
            Some(exposed(product, path, p, url, "Prometheus exposition format"))
        }
        Surface::Api(marker) if ok && p.media.contains("json") && lower.contains(marker) => {
            Some(exposed(product, path, p, url, "management API JSON"))
        }
        _ => None,
    }
}

fn exposed(product: &str, path: &str, p: &Probe, url: &str, sig: &str) -> Finding {
    Finding::new(
        format!("Exposed Operational Data: {product}"),
        Severity::High,
        url,
        format!("{path} returns {product} data without authentication ({sig}). Operational data can reveal internal hosts, versions, configuration, and deployment topology."),
        "Require authentication on management and metrics endpoints, or bind them to an internal interface only.",
        "active/sensitive-paths",
    )
    .with_evidence(evidence(p, sig))
    .with_cwe(200)
    .with_owasp("A05:2021 – Security Misconfiguration")
    .confirmed()
}

/// Minimal evidence: status, media type, size read, signature, and at most one
/// redacted text line. Values after `=`/`:` and anything email-like are masked.
fn evidence(p: &Probe, sig: &str) -> String {
    let mut out = format!(
        "HTTP {} — {} — {} bytes read — signature: {}",
        p.status,
        p.media,
        p.body.len(),
        sig
    );
    if let Ok(text) = std::str::from_utf8(&p.body) {
        let first = text.lines().map(str::trim).find(|l| !l.is_empty());
        if let Some(line) = first.filter(|l| !l.chars().any(char::is_control)) {
            out.push_str(" — first line: ");
            out.push_str(&redact_line(safe_truncate(line, 80)));
        }
    }
    out
}

fn redact_line(line: &str) -> String {
    let masked = match line.find(['=', ':']) {
        Some(i) if i + 1 < line.len() => format!("{}[REDACTED]", &line[..=i]),
        _ => line.to_string(),
    };
    redact_string(&masked)
        .split(' ')
        .map(|w| if w.contains('@') { "[REDACTED]" } else { w })
        .collect::<Vec<_>>()
        .join(" ")
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

    #[test]
    fn signatures_reject_html_and_accept_real_content() {
        let spa = b"<!doctype html><html><body><div id=root></div></body></html>";
        for p in SENSITIVE_PATHS {
            if *p != "/index.html.bak" {
                assert!(file_signature(p, spa).is_none(), "SPA shell matched {p}");
            }
        }
        assert!(file_signature("/.git/config", b"[core]\n\tbare = false\n").is_some());
        assert!(file_signature("/.env", b"DB_PASSWORD=hunter2\n").is_some());
        assert!(file_signature(
            "/dump.sql",
            b"-- MySQL dump 10.13\nCREATE TABLE t (id int);"
        )
        .is_some());
        assert!(file_signature("/.DS_Store", b"\0\0\0\x01Bud1\0\0").is_some());
        assert!(file_signature("/.env", b"just some text").is_none());
    }

    #[test]
    fn redact_line_masks_values_and_emails() {
        assert_eq!(redact_line("DB_PASSWORD=hunter2"), "DB_PASSWORD=[REDACTED]");
        assert_eq!(redact_line("admin:$apr1$xyz"), "admin:[REDACTED]");
        assert_eq!(
            redact_line("owner bob@corp.example"),
            "owner [REDACTED_EMAIL]"
        );
        assert_eq!(redact_line("[core]"), "[core]");
    }
}
