//! Tier-B active-plugin regression matrix against the deterministic loopback lab.
//!
//! Each test boots `serve_full(vulnerable_app)` on an ephemeral port, builds a
//! `DiscoveredUrl`, and calls one `ScanPlugin::scan()` directly (bypassing the
//! params gate in `ActiveScanner::scan_all`, isolating detector logic). The
//! vulnerable responder keeps the baseline clean and only emits the tell-tale
//! signature under the payload, satisfying the evidence model in `src/verify.rs`.
//!
//! Timing detectors (`sqli-time`, `sqli-stacked`) can't sleep inside the sync
//! loopback handler and are flaky on shared CI, so here we assert the fast
//! NEGATIVE (a non-delaying endpoint yields nothing); positive timing coverage
//! lives in the Node lab (`tests/fixtures/lab`).

#[path = "support/lab.rs"]
mod lab;

use lab::{client_nofollow, du_get, du_post, second_order_app, serve_full, vulnerable_app};
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

#[tokio::test]
async fn xss_fires_on_raw_reflection() {
    let base = serve_full(vulnerable_app).await;
    let f = run("xss", &du_get(&format!("{base}/dast/xss?q=1"), &["q"])).await;
    assert!(has(&f, "active/xss"), "xss should fire: {f:?}");
    assert!(confirmed(&f), "xss should be confirmed");
}

#[tokio::test]
async fn sqli_error_based_fires() {
    let base = serve_full(vulnerable_app).await;
    let du = du_get(&format!("{base}/dast/sqli?id=1"), &["id"]);
    // Both the core and the advanced error-based plugins key off the same signal.
    for name in ["sqli", "sqli-error", "sqli-waf-bypass"] {
        let f = run(name, &du).await;
        assert!(
            has(&f, &format!("active/{name}")),
            "{name} should fire: {f:?}"
        );
    }
}

#[tokio::test]
async fn sqli_union_and_fingerprint_fire() {
    let base = serve_full(vulnerable_app).await;
    let u = run(
        "sqli-union",
        &du_get(&format!("{base}/dast/union?id=1"), &["id"]),
    )
    .await;
    assert!(has(&u, "active/sqli-union"), "union: {u:?}");
    let v = run(
        "sqli-fingerprint",
        &du_get(&format!("{base}/dast/version?id=1"), &["id"]),
    )
    .await;
    assert!(has(&v, "active/sqli-fingerprint"), "fingerprint: {v:?}");
}

#[tokio::test]
async fn sqli_boolean_blind_fires() {
    let base = serve_full(vulnerable_app).await;
    let f = run(
        "sqli-boolean",
        &du_get(&format!("{base}/dast/blind?id=1"), &["id"]),
    )
    .await;
    assert!(has(&f, "active/sqli-boolean"), "boolean: {f:?}");
}

#[tokio::test]
async fn sqli_second_order_fires() {
    let base = serve_full(second_order_app()).await;
    let f = run(
        "sqli-second-order",
        &du_post(&format!("{base}/dast/profile"), &["bio"]),
    )
    .await;
    assert!(has(&f, "active/sqli-second-order"), "second-order: {f:?}");
}

#[tokio::test]
async fn path_traversal_fires() {
    let base = serve_full(vulnerable_app).await;
    let f = run(
        "path-traversal",
        &du_get(&format!("{base}/dast/traversal?file=a"), &["file"]),
    )
    .await;
    assert!(has(&f, "active/path-traversal"), "traversal: {f:?}");
    assert!(confirmed(&f));
}

#[tokio::test]
async fn open_redirect_fires() {
    let base = serve_full(vulnerable_app).await;
    let f = run(
        "open-redirect",
        &du_get(&format!("{base}/dast/redirect?next=x"), &["next"]),
    )
    .await;
    assert!(has(&f, "active/open-redirect"), "open-redirect: {f:?}");
}

#[tokio::test]
async fn ssrf_fires() {
    let base = serve_full(vulnerable_app).await;
    let f = run(
        "ssrf",
        &du_get(&format!("{base}/dast/fetch?url=x"), &["url"]),
    )
    .await;
    assert!(has(&f, "active/ssrf"), "ssrf: {f:?}");
    assert!(confirmed(&f));
}

#[tokio::test]
async fn cmd_injection_fires() {
    let base = serve_full(vulnerable_app).await;
    let f = run(
        "cmd-injection",
        &du_get(&format!("{base}/dast/ping?host=h"), &["host"]),
    )
    .await;
    assert!(has(&f, "active/cmd-injection"), "cmd: {f:?}");
    assert!(confirmed(&f));
}

#[tokio::test]
async fn ssti_fires() {
    let base = serve_full(vulnerable_app).await;
    let f = run(
        "ssti",
        &du_get(&format!("{base}/dast/render?name=x"), &["name"]),
    )
    .await;
    assert!(has(&f, "active/ssti"), "ssti: {f:?}");
    assert!(confirmed(&f));
}

#[tokio::test]
async fn xxe_fires_on_post() {
    let base = serve_full(vulnerable_app).await;
    let f = run("xxe", &du_post(&format!("{base}/dast/xml"), &[])).await;
    assert!(has(&f, "active/xxe"), "xxe: {f:?}");
}

#[tokio::test]
async fn nosql_post_and_get_fire() {
    let base = serve_full(vulnerable_app).await;
    let p = run(
        "nosql",
        &du_post(&format!("{base}/dast/login"), &["username", "password"]),
    )
    .await;
    assert!(has(&p, "active/nosql"), "nosql POST: {p:?}");
    let g = run("nosql", &du_get(&format!("{base}/dast/search?q=1"), &["q"])).await;
    assert!(has(&g, "active/nosql"), "nosql GET: {g:?}");
}

#[tokio::test]
async fn graphql_introspection_fires() {
    let base = serve_full(vulnerable_app).await;
    let f = run(
        "graphql-introspection",
        &du_get(&format!("{base}/graphql"), &[]),
    )
    .await;
    assert!(has(&f, "active/graphql-introspection"), "graphql: {f:?}");
}

#[tokio::test]
async fn http_methods_fires() {
    let base = serve_full(vulnerable_app).await;
    let f = run(
        "http-methods",
        &du_get(&format!("{base}/dast/methods"), &[]),
    )
    .await;
    assert!(has(&f, "active/http-methods"), "http-methods: {f:?}");
}

#[tokio::test]
async fn redirect_chain_detects_loop() {
    let base = serve_full(vulnerable_app).await;
    let f = run(
        "redirect-chain",
        &du_get(&format!("{base}/dast/chain1"), &[]),
    )
    .await;
    assert!(has(&f, "active/redirect-chain"), "redirect-chain: {f:?}");
}

#[tokio::test]
async fn timing_plugins_are_quiet_without_delay() {
    // Fast negative: a non-delaying endpoint must NOT yield a timing finding.
    // Positive timing coverage lives in the Node lab (real sleeps).
    let base = serve_full(vulnerable_app).await;
    for name in ["sqli-time", "sqli-stacked"] {
        let f = run(name, &du_get(&format!("{base}/dast/sqli?id=1"), &["id"])).await;
        assert!(
            !has(&f, &format!("active/{name}")),
            "{name} must stay quiet without a real delay: {f:?}"
        );
    }
}

#[tokio::test]
async fn oob_is_inert_without_env() {
    // sqli-oob only dispatches when RUSTZAP_OOB_DOMAIN is set; otherwise inert.
    let base = serve_full(vulnerable_app).await;
    let f = run(
        "sqli-oob",
        &du_get(&format!("{base}/dast/sqli?id=1"), &["id"]),
    )
    .await;
    assert!(
        f.is_empty() || !confirmed(&f),
        "oob must not infer success from HTTP: {f:?}"
    );
}
