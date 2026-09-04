//! Tier-B full-pipeline test: `collect_scan` (spider → passive → active) against
//! the loopback lab, proving the stages wire together end-to-end (the per-plugin
//! matrix and the passive golden matrix cover the stages in isolation).

#[path = "support/lab.rs"]
mod lab;

use std::collections::HashSet;

use lab::{serve_full, vulnerable_app};
use rustzap::scanner::{collect_scan, ScanConfig};

fn scan_config(target: &str) -> ScanConfig {
    ScanConfig {
        target_url: target.to_string(),
        max_depth: 2,
        concurrency: 4,
        passive_only: false,
        output_file: String::new(),
        sarif_out: None,
        timeout_secs: 10,
        user_agent: None,
        cookies: None,
        auth_header: None,
        api_key: None,
        basic_auth: None,
        insecure: false,
        plugins: vec!["all".to_string()],
        openapi_path: None,
        openapi_url: None,
        har_path: None,
        nuclei: false,
        nuclei_jsonl: None,
        active_all_paths: true,
        passive_all_methods: false,
        safety: rustzap::safety::SafetyPolicy::default(),
    }
}

#[tokio::test]
async fn full_scan_finds_active_and_passive_across_spidered_urls() {
    let base = serve_full(vulnerable_app).await;
    let collected = collect_scan(scan_config(&base)).await.unwrap();

    // The spider crawled the index's linked endpoints.
    assert!(!collected.discovered.is_empty(), "spider found nothing");

    let plugins: HashSet<String> = collected
        .findings
        .iter()
        .map(|f| f.plugin.clone())
        .collect();

    // Active plugins fired on spider-discovered, parametered endpoints.
    for expected in ["active/xss", "active/sqli", "active/path-traversal"] {
        assert!(
            plugins.contains(expected),
            "expected {expected} from the full scan; got {plugins:?}"
        );
    }

    // Passive checks fired on at least one fetched response.
    assert!(
        plugins.iter().any(|p| p.starts_with("passive/")),
        "expected passive findings; got {plugins:?}"
    );
}
