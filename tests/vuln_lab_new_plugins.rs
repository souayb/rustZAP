//! Regression matrix for the new bug-bounty-taxonomy plugins: CRLF injection,
//! Host header injection, RFI (OOB), Web Cache Deception, Web Cache
//! Poisoning, and the opt-in rate-limit-missing detector.
//!
//! Follows the same pattern as `tests/vuln_lab_dast.rs`: boot
//! `serve_full` on an ephemeral loopback port, build a `DiscoveredUrl`, and
//! call the plugin directly via `plugin_by_name`.

#[path = "support/lab.rs"]
mod lab;

use std::sync::{Arc, Mutex};

use lab::{client_nofollow, du_get, serve_full, Resp};
use rustzap::active::plugin_by_name;
use rustzap::types::{Confidence, DiscoveredUrl, Finding};

async fn run(name: &str, du: &DiscoveredUrl) -> Vec<Finding> {
    let client = client_nofollow();
    plugin_by_name(name)
        .unwrap_or_else(|| panic!("plugin '{name}' not registered"))
        .scan(&client, du)
        .await
}

fn has(findings: &[Finding], plugin: &str) -> bool {
    findings.iter().any(|f| f.plugin == plugin)
}

fn confirmed(findings: &[Finding]) -> bool {
    findings
        .iter()
        .any(|f| f.poc_validated && f.confidence == Confidence::Confirmed)
}

// ─────────────────────────────────────────────────────────────────────────────
// CRLF injection
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn crlf_injection_confirmed_on_raw_header_reflection() {
    // A vulnerable app that blindly writes a decoded query value into a raw
    // response header line — classic HTTP response splitting.
    let base = serve_full(|req| {
        let decoded = req.query_decoded();
        let mut resp = Resp::html("<html>ok</html>");
        if let Some(idx) = decoded.find("\r\n") {
            if let Some((k, v)) = decoded[idx + 2..].split_once(':') {
                resp = resp.header(k.trim(), v.trim());
            }
        }
        resp
    })
    .await;

    let findings = run(
        "crlf-injection",
        &du_get(&format!("{base}/page?q=1"), &["q"]),
    )
    .await;
    assert!(has(&findings, "active/crlf-injection"), "{findings:?}");
    assert!(confirmed(&findings), "{findings:?}");
}

#[tokio::test]
async fn crlf_injection_quiet_when_not_reflected() {
    let base = serve_full(|_req| Resp::html("<html>ok</html>")).await;
    let findings = run(
        "crlf-injection",
        &du_get(&format!("{base}/page?q=1"), &["q"]),
    )
    .await;
    assert!(findings.is_empty(), "{findings:?}");
}

// ─────────────────────────────────────────────────────────────────────────────
// Host header injection
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn host_header_injection_confirmed_on_body_reflection() {
    let base = serve_full(|req| {
        let host = req.headers.get("host").cloned().unwrap_or_default();
        Resp::html(format!("<html>welcome to {}</html>", host))
    })
    .await;

    let findings = run(
        "host-header-injection",
        &du_get(&format!("{base}/home"), &[]),
    )
    .await;
    assert!(
        has(&findings, "active/host-header-injection"),
        "{findings:?}"
    );
    assert!(confirmed(&findings), "{findings:?}");
}

#[tokio::test]
async fn host_header_injection_quiet_when_host_ignored() {
    let base = serve_full(|_req| Resp::html("<html>static page</html>")).await;
    let findings = run(
        "host-header-injection",
        &du_get(&format!("{base}/home"), &[]),
    )
    .await;
    assert!(findings.is_empty(), "{findings:?}");
}

// ─────────────────────────────────────────────────────────────────────────────
// RFI (OOB) — mirrors the sqli-oob "inert without env" test.
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn rfi_is_inert_without_env() {
    std::env::remove_var("RUSTZAP_OOB_DOMAIN");
    let base = serve_full(|_req| Resp::html("<html>ok</html>")).await;
    let findings = run("rfi", &du_get(&format!("{base}/page?file=1"), &["file"])).await;
    assert!(
        findings.is_empty(),
        "rfi must stay inert without RUSTZAP_OOB_DOMAIN: {findings:?}"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Web Cache Deception (opt-in)
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn cache_deception_flags_static_suffix_cache_hit() {
    let base = serve_full(|req| {
        let body = "<html>dynamic account content, balance: 42</html>";
        if req.path.ends_with(".css") {
            Resp::html(body).header("age", "120")
        } else {
            Resp::html(body)
        }
    })
    .await;

    let findings = run("cache-deception", &du_get(&format!("{base}/account"), &[])).await;
    assert!(has(&findings, "active/cache-deception"), "{findings:?}");
}

#[tokio::test]
async fn cache_deception_quiet_without_cache_indicator() {
    let base =
        serve_full(|_req| Resp::html("<html>dynamic account content, balance: 42</html>")).await;
    let findings = run("cache-deception", &du_get(&format!("{base}/account"), &[])).await;
    assert!(findings.is_empty(), "{findings:?}");
}

// ─────────────────────────────────────────────────────────────────────────────
// Web Cache Poisoning (opt-in)
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn cache_poisoning_confirmed_when_unkeyed_header_sticks() {
    let poisoned: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
    let base = serve_full(move |req| {
        let mut guard = poisoned.lock().unwrap();
        if let Some(h) = req.headers.get("x-forwarded-host") {
            *guard = Some(h.clone());
        }
        let reflect = guard.clone().unwrap_or_default();
        Resp::html(format!("<html>canonical: {}</html>", reflect)).header("age", "5")
    })
    .await;

    let findings = run("cache-poisoning", &du_get(&format!("{base}/home"), &[])).await;
    assert!(has(&findings, "active/cache-poisoning"), "{findings:?}");
    assert!(confirmed(&findings), "{findings:?}");
}

#[tokio::test]
async fn cache_poisoning_quiet_when_header_not_reflected() {
    let base = serve_full(|_req| Resp::html("<html>static</html>")).await;
    let findings = run("cache-poisoning", &du_get(&format!("{base}/home"), &[])).await;
    assert!(findings.is_empty(), "{findings:?}");
}

// ─────────────────────────────────────────────────────────────────────────────
// Rate-limit-missing (opt-in, bounded burst — not a load/DoS attack)
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn rate_limit_missing_flags_endpoint_that_never_throttles() {
    let base = serve_full(|_req| Resp::html("<html>ok</html>")).await;
    let findings = run("rate-limit-missing", &du_get(&format!("{base}/login"), &[])).await;
    assert!(has(&findings, "active/rate-limit-missing"), "{findings:?}");
}

#[tokio::test]
async fn rate_limit_missing_quiet_when_throttled() {
    let base = serve_full(|_req| Resp::ok("").status(429, "Too Many Requests")).await;
    let findings = run("rate-limit-missing", &du_get(&format!("{base}/login"), &[])).await;
    assert!(findings.is_empty(), "{findings:?}");
}
