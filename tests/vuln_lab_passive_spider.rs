//! Tier-B passive-check and spider regression against the loopback lab.
//!
//! Passive: fetch each `/passive/*` variant and feed the real response into
//! `passive::check_response_passive`, asserting the intended `passive/*` id
//! fires (this also proves `serve_full` emits multi-`Set-Cookie`/CORS/CSP
//! correctly). Spider: crawl the lab's index/robots/sitemap and assert the
//! discovered surface (links+params, a POST form, a script, robots/sitemap
//! sources) while excluding an off-host link.

#[path = "support/lab.rs"]
mod lab;

use std::sync::Arc;

use indicatif::ProgressBar;
use lab::{serve_full, vulnerable_app};
use rustzap::passive::check_response_passive;
use rustzap::spider::Spider;
use rustzap::types::{Finding, UrlSource};

async fn passive_of(base: &str, path: &str) -> Vec<Finding> {
    let client = reqwest::Client::new();
    let url = format!("{base}{path}");
    let resp = client.get(&url).send().await.unwrap();
    let status = resp.status().as_u16();
    let headers = resp.headers().clone();
    let body = resp.text().await.unwrap();
    check_response_passive(&url, status, &headers, &body)
}

fn has(findings: &[Finding], plugin: &str) -> bool {
    findings.iter().any(|f| f.plugin == plugin)
}

#[tokio::test]
async fn passive_matrix_fires_expected_checks() {
    let base = serve_full(vulnerable_app).await;

    let naked = passive_of(&base, "/passive/naked").await;
    assert!(
        has(&naked, "passive/missing-headers"),
        "missing-headers: {naked:?}"
    );
    assert!(
        has(&naked, "passive/info-disclosure"),
        "info-disclosure: {naked:?}"
    );
    assert!(
        has(&naked, "passive/tech-fingerprint"),
        "tech-fingerprint: {naked:?}"
    );

    let cookie = passive_of(&base, "/passive/cookie").await;
    assert!(
        has(&cookie, "passive/cookie-flags"),
        "cookie-flags: {cookie:?}"
    );

    let cors = passive_of(&base, "/passive/cors").await;
    assert!(has(&cors, "passive/cors"), "cors: {cors:?}");

    let csp = passive_of(&base, "/passive/csp").await;
    assert!(has(&csp, "passive/csp-unsafe-directives"), "csp: {csp:?}");

    let leak = passive_of(&base, "/passive/leak").await;
    assert!(
        has(&leak, "passive/sensitive-data"),
        "sensitive-data: {leak:?}"
    );
    assert!(
        has(&leak, "passive/jwt-heuristic"),
        "jwt-heuristic: {leak:?}"
    );

    let error = passive_of(&base, "/passive/error").await;
    assert!(
        has(&error, "passive/error-disclosure"),
        "error-disclosure: {error:?}"
    );
}

#[tokio::test]
async fn spider_discovers_links_form_script_and_sitemap() {
    let base = serve_full(vulnerable_app).await;
    let client = Arc::new(reqwest::Client::new());
    let spider = Spider::new(client, base.clone(), 2, 4).unwrap();
    let discovered = spider.crawl(&ProgressBar::hidden()).await.unwrap();

    // The POST login form with its named inputs.
    assert!(
        discovered.iter().any(|d| d.source == UrlSource::Form
            && d.url.contains("/dast/login")
            && d.parameters.iter().any(|p| p == "username")
            && d.parameters.iter().any(|p| p == "password")),
        "expected the POST login form: {discovered:?}"
    );

    // The <script src> asset.
    assert!(
        discovered.iter().any(|d| d.url.contains("/static/app.js")),
        "expected /static/app.js"
    );

    // A parametered link.
    assert!(
        discovered
            .iter()
            .any(|d| d.url.contains("/dast/sqli") && !d.parameters.is_empty()),
        "expected a parametered link"
    );

    // robots.txt enrichment: the `Disallow: /admin/` path is enqueued as Robots.
    assert!(
        discovered
            .iter()
            .any(|d| d.source == UrlSource::Robots || d.url.contains("/admin")),
        "expected a robots.txt-discovered URL: {discovered:?}"
    );

    // The off-host link must be excluded.
    assert!(
        !discovered.iter().any(|d| d.url.contains("evil.example")),
        "off-host link must not be crawled"
    );
}
