//! Multi-identity authorization testing (BOLA/IDOR + vertical privilege
//! escalation), OWASP API1/API5:2023, CWE-639 / CWE-285.
//!
//! Two opt-in modes, both run after the active phase of `scan`:
//!
//! * `--auth-a` / `--auth-b`: A is the low-privilege/attacker identity, B the
//!   victim/higher-privilege one. For every discovered GET that carries an object
//!   id (or looks like an admin route) we fetch as B, as A, and anonymously, and
//!   flag only when A gets 2xx with *B's* object content (similar body + contains
//!   the id) while the anonymous request does not — so a generic 200 page, a
//!   login redirect or a shared error body never counts. Ownership is unknown in
//!   this mode (the object might be intentionally shared), so findings are `firm`.
//! * `--authz-matrix <file>`: an explicit ownership/role matrix (JSON or YAML).
//!   Every identity is validated (its own allowed object, or `check_url`, must
//!   return 2xx) before any of its denials are judged, and each cell reports
//!   expected vs observed access with redacted evidence. Findings are `confirmed`.
//!
//! Every request goes through `HttpSafetyGate`; write checks run only when the
//! matrix declares `operation: write` with an explicit method, and
//! `--read-only-safe` blocks them at the gate.

use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use regex::Regex;
use serde::Deserialize;
use url::Url;

use crate::active::bola::object_id_candidates;
use crate::safety::HttpSafetyGate;
use crate::scanner::{build_client, ScanConfig};
use crate::types::{DiscoveredUrl, Finding, Severity};
use crate::verify::body_similarity;

/// CLI-level opt-in for the multi-identity checks (all `None` = disabled).
#[derive(Debug, Clone, Default)]
pub struct AuthzOptions {
    /// `Authorization` header value for identity A (low privilege / attacker).
    pub auth_a: Option<String>,
    /// `Authorization` header value for identity B (victim / higher privilege).
    pub auth_b: Option<String>,
    /// Path to an ownership/role matrix (JSON, or YAML for other extensions).
    pub matrix: Option<String>,
}

impl AuthzOptions {
    pub fn is_enabled(&self) -> bool {
        (self.auth_a.is_some() && self.auth_b.is_some()) || self.matrix.is_some()
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct AuthzMatrix {
    pub identities: Vec<IdentitySpec>,
    pub checks: Vec<CheckSpec>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct IdentitySpec {
    pub name: String,
    /// Free-form role (owner, user, staff, admin…); usable in `allow`.
    #[serde(default)]
    pub role: Option<String>,
    #[serde(default)]
    pub tenant: Option<String>,
    /// `Authorization` header value (same format as `--auth`).
    #[serde(default)]
    pub auth: Option<String>,
    /// Raw `Cookie` header value.
    #[serde(default)]
    pub cookies: Option<String>,
    /// Optional URL that must answer 2xx for this identity to count as valid.
    #[serde(default)]
    pub check_url: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct CheckSpec {
    /// Absolute URL or path relative to the scan target.
    pub url: String,
    /// read | list | download | export | write
    #[serde(default = "default_operation")]
    pub operation: String,
    /// HTTP method; defaults to GET. Required (non-GET) for `write`.
    #[serde(default)]
    pub method: Option<String>,
    #[serde(default)]
    pub body: Option<String>,
    /// Object id that must appear in a response for access to count as granted.
    #[serde(default)]
    pub id: Option<String>,
    #[serde(default)]
    pub owner: Option<String>,
    #[serde(default)]
    pub tenant: Option<String>,
    /// Identity names or roles expected to be allowed; everyone else must be denied.
    pub allow: Vec<String>,
}

fn default_operation() -> String {
    "read".into()
}

/// A configured identity with its own client (independent cookie/token state).
pub struct Identity {
    pub spec: IdentitySpec,
    pub client: reqwest::Client,
}

/// Parse a matrix file (`.json` → JSON, otherwise YAML) and validate it.
pub fn load_matrix(path: &str) -> Result<AuthzMatrix> {
    let text =
        std::fs::read_to_string(path).with_context(|| format!("Read authz matrix {path}"))?;
    let m: AuthzMatrix = if path.to_ascii_lowercase().ends_with(".json") {
        serde_json::from_str(&text).context("Parse authz matrix JSON")?
    } else {
        serde_yaml::from_str(&text).context("Parse authz matrix YAML")?
    };
    for c in &m.checks {
        let method = c.method.as_deref().unwrap_or("GET").to_ascii_uppercase();
        match c.operation.as_str() {
            "write" if method == "GET" || method == "HEAD" => {
                bail!(
                    "authz matrix: write check {} needs an explicit non-GET method",
                    c.url
                )
            }
            "write" => {}
            "read" | "list" | "download" | "export" if method == "GET" => {}
            "read" | "list" | "download" | "export" => {
                bail!(
                    "authz matrix: {} check {} uses {method}; declare it as operation: write",
                    c.operation,
                    c.url
                )
            }
            other => bail!("authz matrix: unknown operation '{other}' for {}", c.url),
        }
    }
    Ok(m)
}

/// Entry point from the scanner: builds per-identity clients from `base`
/// (dropping its own credentials) and runs whichever modes are configured.
pub async fn run(
    opts: &AuthzOptions,
    base: &ScanConfig,
    discovered: &[DiscoveredUrl],
) -> Result<Vec<Finding>> {
    let gate = HttpSafetyGate::new(base.safety.clone());
    let client_for = |auth: Option<String>, cookies: Option<String>| {
        let mut c = base.clone();
        c.auth_header = auth;
        c.cookies = cookies;
        c.api_key = None;
        c.basic_auth = None;
        build_client(&c)
    };
    let anon = client_for(None, None)?;
    let mut findings = Vec::new();

    if let (Some(a), Some(b)) = (&opts.auth_a, &opts.auth_b) {
        let ident = |name: &str, auth: &str| -> Result<Identity> {
            Ok(Identity {
                spec: IdentitySpec {
                    name: name.into(),
                    role: None,
                    tenant: None,
                    auth: Some(auth.into()),
                    cookies: None,
                    check_url: None,
                },
                client: client_for(Some(auth.into()), None)?,
            })
        };
        let (a, b) = (ident("A", a)?, ident("B", b)?);
        findings.extend(two_identity_scan(&a, &b, &anon, discovered, &gate).await);
    }

    if let Some(path) = &opts.matrix {
        let matrix = load_matrix(path)?;
        let identities = matrix
            .identities
            .iter()
            .map(|s| {
                Ok(Identity {
                    spec: s.clone(),
                    client: client_for(s.auth.clone(), s.cookies.clone())?,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        findings
            .extend(evaluate_matrix(&matrix, &identities, &anon, &base.target_url, &gate).await);
    }
    Ok(findings)
}

type Obs = std::result::Result<(u16, String), String>;

async fn send(
    gate: &HttpSafetyGate,
    client: &reqwest::Client,
    method: &str,
    url: &str,
    body: Option<&str>,
) -> Obs {
    gate.before_url_request(method, url, body)
        .await
        .map_err(|e| e.to_string())?;
    let m = reqwest::Method::from_bytes(method.as_bytes()).map_err(|e| e.to_string())?;
    let mut req = client.request(m, url).timeout(Duration::from_secs(8));
    if let Some(b) = body {
        req = req
            .header("Content-Type", "application/json")
            .body(b.to_string());
    }
    let start = Instant::now();
    let resp = req.send().await.map_err(|e| e.to_string())?;
    let status = resp.status().as_u16();
    let text = resp.text().await.unwrap_or_default();
    let _ = gate.after_response(status, start.elapsed().as_millis() as u64);
    Ok((status, text))
}

fn is_2xx(o: &Obs) -> bool {
    matches!(o, Ok((s, _)) if (200..300).contains(s))
}

fn admin_route_regex() -> &'static Regex {
    static RE: std::sync::OnceLock<Regex> = std::sync::OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?i)/(?:admin|administrator|internal|manage|management|staff|superuser|backoffice)(?:/|$|\?)")
            .unwrap()
    })
}

/// A's view matches B's object: same content (≥0.9 similar) and contains the id.
fn same_object(a_body: &str, b_body: &str, ids: &[String]) -> bool {
    !b_body.trim().is_empty()
        && body_similarity(a_body, b_body) >= 0.9
        && (ids.is_empty() || ids.iter().any(|id| a_body.contains(id.as_str())))
}

/// Horizontal (BOLA) and vertical (admin route) checks over discovered GETs.
pub async fn two_identity_scan(
    a: &Identity,
    b: &Identity,
    anon: &reqwest::Client,
    urls: &[DiscoveredUrl],
    gate: &HttpSafetyGate,
) -> Vec<Finding> {
    let mut findings = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for du in urls {
        if !du.method.eq_ignore_ascii_case("GET") || !seen.insert(du.url.clone()) {
            continue;
        }
        let vertical = admin_route_regex().is_match(&du.url);
        let ids: Vec<String> = object_id_candidates(du)
            .into_iter()
            .map(|c| c.value)
            .collect();
        if ids.is_empty() && !vertical {
            continue;
        }

        // B must be able to read its object (proves B valid + route works).
        let rb = send(gate, &b.client, "GET", &du.url, None).await;
        let Ok((sb, body_b)) = &rb else { continue };
        if !is_2xx(&rb) {
            continue;
        }
        let ra = send(gate, &a.client, "GET", &du.url, None).await;
        let Ok((sa, body_a)) = &ra else { continue };
        if !is_2xx(&ra) || !same_object(body_a, body_b, &ids) {
            continue;
        }
        // Anonymous control: a public resource is not an authorization flaw, and a
        // 2xx for A while anon is denied shows A's credential was accepted.
        let rn = send(gate, anon, "GET", &du.url, None).await;
        if let Ok((_, body_n)) = &rn {
            if is_2xx(&rn) && body_similarity(body_n, body_b) >= 0.9 {
                continue;
            }
        }
        let anon_status = rn
            .as_ref()
            .map(|(s, _)| s.to_string())
            .unwrap_or_else(|e| e.clone());

        let (title, plugin, cwe, owasp, desc) = if vertical {
            (
                "Vertical Privilege Escalation (low-privilege identity reads privileged route)",
                "active/privesc-vertical",
                285,
                "API5:2023 – Broken Function Level Authorization",
                "Identity A (--auth-a, low privilege) received the same 2xx content as identity B (--auth-b) on an admin-style route that anonymous requests cannot reach. Low-privilege identities should get 401/403 here.",
            )
        } else {
            (
                "Broken Object Level Authorization (cross-identity BOLA / IDOR)",
                "active/bola-cross-identity",
                639,
                "API1:2023 – Broken Object Level Authorization",
                "Identity A (--auth-a) received identity B's object (same content, contains the object id) while anonymous access is denied. Unless this object is intentionally shared between these users, A can read another user's data. Use --authz-matrix with declared ownership to confirm.",
            )
        };
        findings.push(
            Finding::new(
                title,
                Severity::High,
                &du.url,
                desc,
                "Enforce object- and function-level authorization server-side for every request, based on the authenticated principal rather than client-supplied identifiers.",
                plugin,
            )
            .with_evidence(format!(
                "Request: GET {} [Authorization: <redacted>]\nB (owner/privileged): HTTP {sb}\nA (other identity): HTTP {sa}, {} bytes, similarity to B {:.2}, ids {:?}\nAnonymous: HTTP {anon_status}\nA response: {}",
                du.url,
                body_a.len(),
                body_similarity(body_a, body_b),
                ids,
                snippet(body_a)
            ))
            .with_cwe(cwe)
            .with_owasp(owasp),
        );
    }
    findings
}

fn redact_regex() -> &'static Regex {
    static RE: std::sync::OnceLock<Regex> = std::sync::OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r#"(?i)("?(?:password|passwd|secret|token|api[_-]?key|ssn|authorization|session)[a-z_]*"?\s*[:=]\s*)("[^"]*"|[^\s,&}]+)"#)
            .unwrap()
    })
}

/// Minimal, redacted response evidence: secrets masked, ≤160 chars.
fn snippet(body: &str) -> String {
    let red = redact_regex().replace_all(body, "$1\"***\"");
    let t = crate::types::safe_truncate(&red, 160);
    if t.len() < red.len() {
        format!("{t}...[TRUNCATED]")
    } else {
        t.to_string()
    }
}

fn resolve(base: &str, u: &str) -> String {
    if u.starts_with("http://") || u.starts_with("https://") {
        return u.to_string();
    }
    Url::parse(base)
        .and_then(|b| b.join(u))
        .map(|x| x.to_string())
        .unwrap_or_else(|_| u.to_string())
}

fn allowed(check: &CheckSpec, ident: &IdentitySpec) -> bool {
    check
        .allow
        .iter()
        .any(|a| a == &ident.name || ident.role.as_deref() == Some(a.as_str()))
}

fn boundary(check: &CheckSpec, ident: &IdentitySpec) -> String {
    match (&check.tenant, &ident.tenant) {
        (Some(ot), Some(it)) if ot != it => {
            return format!("cross-tenant ({} of tenant {it} → tenant {ot})", ident.name)
        }
        _ => {}
    }
    match &check.owner {
        Some(owner) if owner != &ident.name => {
            format!("cross-user ({} → {owner}'s object)", ident.name)
        }
        _ => format!(
            "role-restricted ({} as role '{}'; {} allowed only for [{}])",
            ident.name,
            ident.role.as_deref().unwrap_or("-"),
            check.operation,
            check.allow.join(", ")
        ),
    }
}

/// Evaluate an ownership/role matrix: expected vs observed access per cell.
pub async fn evaluate_matrix(
    matrix: &AuthzMatrix,
    identities: &[Identity],
    anon: &reqwest::Client,
    target: &str,
    gate: &HttpSafetyGate,
) -> Vec<Finding> {
    let mut valid = vec![false; identities.len()];
    for (i, ident) in identities.iter().enumerate() {
        if let Some(u) = &ident.spec.check_url {
            valid[i] = is_2xx(&send(gate, &ident.client, "GET", &resolve(target, u), None).await);
        }
    }

    // (check, identity, observation, granted)
    let mut cells: Vec<(usize, usize, Obs, bool)> = Vec::new();
    for (ci, check) in matrix.checks.iter().enumerate() {
        let url = resolve(target, &check.url);
        let method = check
            .method
            .as_deref()
            .unwrap_or("GET")
            .to_ascii_uppercase();
        let body = check.body.as_deref();

        let mut obs = Vec::new();
        for ident in identities {
            obs.push(send(gate, &ident.client, &method, &url, body).await);
        }
        // Anonymous control only for reads (never replay writes unauthenticated).
        let anon_body = if method == "GET" {
            match send(gate, anon, "GET", &url, None).await {
                Ok((s, b)) if (200..300).contains(&s) => Some(b),
                _ => None,
            }
        } else {
            None
        };
        let has_id = |b: &str| match check.id.as_deref() {
            Some(id) => b.contains(id),
            None => true,
        };
        // Reference = the first expected-allowed identity that actually got the object.
        let reference = identities
            .iter()
            .zip(&obs)
            .find(|(ident, o)| {
                allowed(check, &ident.spec)
                    && matches!(o, Ok((s, b)) if (200..300).contains(s) && has_id(b))
            })
            .and_then(|(_, o)| o.as_ref().ok().map(|(_, b)| b.clone()));

        for (ii, o) in obs.into_iter().enumerate() {
            let granted = match &o {
                Ok((s, b)) if (200..300).contains(s) && !b.trim().is_empty() => {
                    has_id(b)
                        && (check.id.is_some()
                            || reference
                                .as_deref()
                                .is_some_and(|r| body_similarity(b, r) >= 0.9))
                        && !anon_body
                            .as_deref()
                            .is_some_and(|n| body_similarity(b, n) >= 0.9)
                }
                _ => false,
            };
            if granted && allowed(check, &identities[ii].spec) {
                valid[ii] = true;
            }
            cells.push((ci, ii, o, granted));
        }
    }

    let mut findings = Vec::new();
    let mut unjudged = vec![0usize; identities.len()];
    for (ci, ii, o, granted) in cells {
        let (check, ident) = (&matrix.checks[ci], &identities[ii].spec);
        if allowed(check, ident) {
            continue;
        }
        if !valid[ii] {
            unjudged[ii] += 1;
            continue;
        }
        if !granted {
            continue;
        }
        let Ok((status, body)) = o else { continue };
        let url = resolve(target, &check.url);
        let method = check
            .method
            .as_deref()
            .unwrap_or("GET")
            .to_ascii_uppercase();
        let bnd = boundary(check, ident);
        let severity = if check.operation == "write" || bnd.starts_with("cross-tenant") {
            Severity::Critical
        } else {
            Severity::High
        };
        let (cwe, owasp) = if bnd.starts_with("role-restricted") {
            (285, "API5:2023 – Broken Function Level Authorization")
        } else {
            (639, "API1:2023 – Broken Object Level Authorization")
        };
        let assertion = match &check.id {
            Some(id) => format!("body contains object id '{id}'"),
            None => "body matches the allowed identity's response".to_string(),
        };
        findings.push(
            Finding::new(
                format!("Authorization Matrix Violation ({})", check.operation),
                severity,
                &url,
                format!(
                    "Identity '{}' was expected to be DENIED {} on this object but was GRANTED. Violated boundary: {bnd}.",
                    ident.name, check.operation
                ),
                "Enforce ownership, tenant and role checks server-side on every object access, keyed on the authenticated principal.",
                "active/authz-matrix",
            )
            .with_parameter(ident.name.clone())
            .with_evidence(format!(
                "Expected: deny (allowed: [{}])\nObserved: granted — HTTP {status}, {assertion}\nBoundary: {bnd}\nRequest: {method} {url} [identity={}, credentials redacted]{}\nResponse: HTTP {status}, {} bytes: {}",
                check.allow.join(", "),
                ident.name,
                check.body.as_deref().map(|b| format!("\nRequest body: {}", snippet(b))).unwrap_or_default(),
                body.len(),
                snippet(&body)
            ))
            .with_cwe(cwe)
            .with_owasp(owasp)
            .confirmed(),
        );
    }

    for (ii, n) in unjudged.into_iter().enumerate() {
        if n > 0 {
            findings.push(
                Finding::new(
                    "Authorization Matrix Identity Not Validated",
                    Severity::Info,
                    target,
                    format!(
                        "Identity '{}' never obtained one of its own allowed objects (or its check_url) with HTTP 2xx, so {n} expected-deny cell(s) were not judged — its credentials may be expired or wrong.",
                        identities[ii].spec.name
                    ),
                    "Refresh the identity's credentials or add a check_url / an allowed object for it in the matrix.",
                    "active/authz-matrix",
                )
                .tentative(),
            );
        }
    }
    findings
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snippet_redacts_secrets_and_truncates() {
        let s = snippet(r#"{"id":1,"password":"hunter2","api_key":"abc123"}"#);
        assert!(!s.contains("hunter2") && !s.contains("abc123"), "{s}");
        assert!(snippet(&"x".repeat(500)).ends_with("[TRUNCATED]"));
    }

    #[test]
    fn boundary_labels() {
        let ident = IdentitySpec {
            name: "bob".into(),
            role: Some("user".into()),
            tenant: Some("t2".into()),
            auth: None,
            cookies: None,
            check_url: None,
        };
        let mut check = CheckSpec {
            url: "/r/1".into(),
            operation: "read".into(),
            method: None,
            body: None,
            id: None,
            owner: Some("alice".into()),
            tenant: Some("t1".into()),
            allow: vec!["alice".into()],
        };
        assert!(boundary(&check, &ident).starts_with("cross-tenant"));
        check.tenant = None;
        assert!(boundary(&check, &ident).starts_with("cross-user"));
        check.owner = None;
        assert!(boundary(&check, &ident).starts_with("role-restricted"));
    }

    #[test]
    fn matrix_rejects_undeclared_writes() {
        let p = std::env::temp_dir().join(format!("rz-authz-{}.yaml", crate::types::uuid_v4()));
        std::fs::write(
            &p,
            "identities: [{name: a}]\nchecks: [{url: /x, method: PUT, allow: [a]}]\n",
        )
        .unwrap();
        let err = load_matrix(p.to_str().unwrap()).unwrap_err();
        std::fs::remove_file(&p).ok();
        assert!(err.to_string().contains("operation: write"), "{err}");
    }
}
