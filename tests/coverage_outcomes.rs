//! #41: every endpoint × plugin check gets an execution record, and every check
//! that did not complete cleanly carries a reason. Fixture covers a protected
//! (401) endpoint, a 429 endpoint, a dead connection (transport error/timeout),
//! a no-query-string skip, and a POST blocked by `--read-only-safe`.

#[path = "support/lab.rs"]
mod lab;

use std::sync::Arc;

use indicatif::{ProgressBar, ProgressDrawTarget};
use lab::{du_get, serve_full, Resp};
use rustzap::active::ActiveScanner;
use rustzap::coverage::{Coverage, ExecutionRecord, Outcome, ScanStatus};
use rustzap::report::Report;
use rustzap::safety::SafetyPolicy;
use rustzap::types::{DiscoveredUrl, UrlSource};

/// Accepts connections and drops them immediately — every request fails at
/// the transport layer.
async fn serve_dead() -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((sock, _)) = listener.accept().await {
            drop(sock);
        }
    });
    format!("http://{addr}")
}

fn find<'a>(records: &'a [ExecutionRecord], path: &str, plugin: &str) -> &'a ExecutionRecord {
    records
        .iter()
        .find(|r| r.endpoint.contains(path) && r.plugin == plugin)
        .unwrap_or_else(|| panic!("no record for {path} {plugin}: {records:#?}"))
}

#[tokio::test]
async fn every_incomplete_check_has_an_outcome_and_reason() {
    let base = serve_full(|req| match req.path.as_str() {
        "/protected" => Resp::html("denied").status(401, "Unauthorized"),
        "/limited" => Resp::html("slow down")
            .status(429, "Too Many Requests")
            .header("Retry-After", "1"),
        _ => Resp::html("<p>hello</p>"),
    })
    .await;
    let dead = serve_dead().await;

    let mut form = DiscoveredUrl::new(format!("{base}/form"), "POST", UrlSource::Link);
    form.parameters = vec!["q".into()];
    let urls = vec![
        du_get(&format!("{base}/ok?q=1"), &["q"]),
        du_get(&format!("{base}/protected?q=1"), &["q"]),
        du_get(&format!("{base}/limited?q=1"), &["q"]),
        du_get(&format!("{dead}/dead?q=1"), &["q"]),
        DiscoveredUrl::new(format!("{base}/static"), "GET", UrlSource::Link),
        form,
    ];

    let client = Arc::new(
        reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(3))
            .build()
            .unwrap(),
    );
    let scanner = ActiveScanner::new(
        client,
        vec!["xss".into(), "xxe".into()],
        4,
        false,
        SafetyPolicy {
            read_only_safe: true,
            max_rps: 0,
            ..Default::default()
        },
    );
    let pb = ProgressBar::with_draw_target(Some(urls.len() as u64), ProgressDrawTarget::hidden());
    scanner.scan_all(&urls, &pb).await.unwrap();
    let records = scanner.take_coverage();

    // One record per endpoint × plugin.
    assert_eq!(records.len(), urls.len() * 2, "{records:#?}");
    for r in &records {
        if !matches!(r.outcome, Outcome::CompletedNoFinding | Outcome::Finding) {
            assert!(!r.reason.is_empty(), "missing reason: {r:#?}");
        }
    }

    assert_eq!(
        find(&records, "/ok", "active/xss").outcome,
        Outcome::CompletedNoFinding
    );
    assert_eq!(
        find(&records, "/ok", "active/xxe").outcome,
        Outcome::Inapplicable
    );
    assert_eq!(
        find(&records, "/protected", "active/xss").outcome,
        Outcome::AuthRequired
    );
    assert_eq!(
        find(&records, "/limited", "active/xss").outcome,
        Outcome::Throttled
    );
    let dead_rec = find(&records, "/dead", "active/xss");
    assert_eq!(dead_rec.outcome, Outcome::Error);
    assert!(dead_rec.requests_attempted > dead_rec.requests_completed);
    let static_rec = find(&records, "/static", "active/xss");
    assert_eq!(static_rec.outcome, Outcome::Skipped);
    assert_eq!(static_rec.requests_attempted, 0);
    let form_rec = find(&records, "/form", "active/xxe");
    assert_eq!(form_rec.outcome, Outcome::Skipped, "{form_rec:#?}");
    assert!(form_rec.reason.contains("read-only-safe"), "{form_rec:#?}");

    let coverage = Coverage::new(records, vec![]);
    assert_eq!(coverage.status, ScanStatus::Partial);

    // Report round-trip, plus HTML / SARIF surfaces.
    let report = Report::new(
        &base,
        vec![],
        urls,
        vec![],
        std::time::Duration::from_secs(1),
    )
    .with_coverage(coverage.clone());
    let json = serde_json::to_string(&report).unwrap();
    let back: Report = serde_json::from_str(&json).unwrap();
    assert_eq!(back.coverage.as_ref(), Some(&coverage));

    let dir = std::env::temp_dir().join(format!("rz-cov-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let html = dir.join("r.html");
    report.save_html(html.to_str().unwrap()).await.unwrap();
    let html = std::fs::read_to_string(html).unwrap();
    assert!(html.contains("<h2>Coverage</h2>") && html.contains("auth_required"));
    let sarif = dir.join("r.sarif");
    rustzap::sarif::write_sarif(&report, sarif.to_str().unwrap()).unwrap();
    let sarif: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(sarif).unwrap()).unwrap();
    assert_eq!(
        sarif["runs"][0]["properties"]["coverage"]["status"],
        "partial"
    );
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn report_without_coverage_still_deserializes() {
    let old = Report::new(
        "https://example.com",
        vec![],
        vec![],
        vec![],
        std::time::Duration::from_secs(1),
    );
    let json = serde_json::to_value(&old).unwrap();
    assert!(json.get("coverage").is_none(), "absent coverage is omitted");
    let back: Report = serde_json::from_value(json).unwrap();
    assert!(back.coverage.is_none());
}

#[tokio::test]
async fn failed_tls_probe_is_an_error_record() {
    let (findings, records) =
        rustzap::tls::check_hosts_with_coverage(&["rustzap-probe.invalid".to_string()]).await;
    // A failed probe is reported as inconclusive, never as a real finding.
    assert!(findings
        .iter()
        .all(|f| f.plugin == "transport/tls-inconclusive"));
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].outcome, Outcome::Error);
    assert!(!records[0].reason.is_empty());
}
