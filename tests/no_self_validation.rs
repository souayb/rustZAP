//! Anti-"self-validation" integration tests.
//!
//! These prove the active scanner reaches real conclusions from a real HTTP
//! server instead of rubber-stamping vulnerabilities on weak signals:
//!
//!  * A benign page that merely contains the words "error"/"syntax" must NOT be
//!    reported as SQL injection.
//!  * A page that reflects an injected `127.0.0.1`/`localhost` value must NOT be
//!    reported as SSRF.
//!  * A page that emits a real DB error only when a quote is injected MUST be
//!    reported — and flagged `poc_validated`.

use std::sync::Arc;

use rustzap::active::{ScanPlugin, SqlInjectionPlugin, SsrfPlugin, XssPlugin};
use rustzap::types::{Confidence, DiscoveredUrl, UrlSource};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

/// Start a one-shot-per-connection HTTP/1.1 server. `responder` maps the raw
/// request line (`GET /path?query HTTP/1.1`) to a response body. Returns the
/// bound base URL (`http://127.0.0.1:PORT`).
async fn serve<F>(responder: F) -> String
where
    F: Fn(&str) -> String + Send + Sync + 'static,
{
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let responder = Arc::new(responder);
    tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                break;
            };
            let responder = responder.clone();
            tokio::spawn(async move {
                let mut buf = [0u8; 8192];
                let n = sock.read(&mut buf).await.unwrap_or(0);
                let req = String::from_utf8_lossy(&buf[..n]);
                let request_line = req.lines().next().unwrap_or("").to_string();
                let body = responder(&request_line);
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = sock.write_all(resp.as_bytes()).await;
                let _ = sock.flush().await;
            });
        }
    });
    format!("http://{}", addr)
}

fn du(url: &str) -> DiscoveredUrl {
    DiscoveredUrl::new(url, "GET", UrlSource::Link)
}

fn client() -> reqwest::Client {
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap()
}

#[tokio::test]
async fn sqli_does_not_self_validate_on_benign_error_text() {
    // Every response contains the words "error" and "syntax" — but no DB error.
    let base = serve(|_req| {
        "<html><body>An error occurred. Check your syntax. Warning: none.</body></html>".to_string()
    })
    .await;
    let url = format!("{}/page?q=1", base);
    let findings = SqlInjectionPlugin.scan(&client(), &du(&url)).await;
    assert!(
        findings.is_empty(),
        "benign page with 'error'/'syntax' text must NOT be flagged as SQLi, got: {:?}",
        findings.iter().map(|f| &f.title).collect::<Vec<_>>()
    );
}

#[tokio::test]
async fn sqli_is_reported_and_confirmed_on_real_db_error() {
    // Baseline (no quote) is clean; injecting a quote surfaces a real MySQL error.
    let base = serve(|req| {
        if req.contains("%27") || req.contains('\'') {
            "You have an error in your SQL syntax; check the manual near ''".to_string()
        } else {
            "<html><body>Welcome, product listing</body></html>".to_string()
        }
    })
    .await;
    let url = format!("{}/item?q=1", base);
    let findings = SqlInjectionPlugin.scan(&client(), &du(&url)).await;
    assert_eq!(findings.len(), 1, "expected one confirmed SQLi finding");
    assert!(findings[0].poc_validated, "finding must be poc_validated");
    assert_eq!(findings[0].confidence, Confidence::Confirmed);
}

#[tokio::test]
async fn ssrf_does_not_self_validate_on_reflected_input() {
    // App echoes the injected URL (so body contains "127.0.0.1"/"localhost")
    // but never actually fetched a metadata endpoint. Must NOT be flagged.
    let base = serve(|req| format!("<html>you requested: {}</html>", req)).await;
    let url = format!("{}/fetch?q=1", base);
    let findings = SsrfPlugin.scan(&client(), &du(&url)).await;
    assert!(
        findings.is_empty(),
        "reflected localhost/127.0.0.1 must NOT be flagged as SSRF, got: {:?}",
        findings.iter().map(|f| &f.title).collect::<Vec<_>>()
    );
}

#[tokio::test]
async fn xss_does_not_self_validate_on_encoded_reflection() {
    // The app reflects input but HTML-encodes angle brackets — not exploitable.
    let base = serve(|req| {
        // Extract the q= value and entity-encode < and >.
        let val = req
            .split("q=")
            .nth(1)
            .and_then(|s| s.split([' ', '&']).next())
            .unwrap_or("");
        let decoded = val.replace("%3C", "<").replace("%3E", ">");
        let encoded = decoded.replace('<', "&lt;").replace('>', "&gt;");
        format!("<html><body>search: {}</body></html>", encoded)
    })
    .await;
    let url = format!("{}/search?q=1", base);
    let findings = XssPlugin.scan(&client(), &du(&url)).await;
    assert!(
        findings.is_empty(),
        "entity-encoded reflection must NOT be flagged as XSS, got: {:?}",
        findings.iter().map(|f| &f.title).collect::<Vec<_>>()
    );
}

#[tokio::test]
async fn xss_is_reported_on_raw_reflection() {
    // The app reflects input verbatim (raw) — genuinely injectable.
    let base = serve(|req| {
        let val = req
            .split("q=")
            .nth(1)
            .and_then(|s| s.split([' ', '&']).next())
            .unwrap_or("");
        // Decode the few percent-escapes reqwest emits for our probe.
        let decoded = val
            .replace("%3C", "<")
            .replace("%3E", ">")
            .replace("%2F", "/")
            .replace("%22", "\"")
            .replace("%27", "'")
            .replace("%3D", "=")
            .replace("%28", "(")
            .replace("%29", ")");
        format!("<html><body>search: {}</body></html>", decoded)
    })
    .await;
    let url = format!("{}/search?q=1", base);
    let findings = XssPlugin.scan(&client(), &du(&url)).await;
    assert_eq!(findings.len(), 1, "expected one confirmed XSS finding");
    assert!(findings[0].poc_validated);
    assert_eq!(findings[0].confidence, Confidence::Confirmed);
}
