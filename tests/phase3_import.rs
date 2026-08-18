//! Phase 3 fixture tests: OpenAPI, HAR, Nuclei parsers (no network).

use std::path::Path;

use rustzap::har::load_har_file;
use rustzap::nuclei::parse_nuclei_jsonl_file;
use rustzap::openapi::load_openapi_file;
use rustzap::types::{Severity, UrlSource};

#[test]
fn openapi_fixture_expands_operations() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/openapi_small.json");
    let (urls, finding) =
        load_openapi_file(path.to_str().unwrap(), "https://api.example.com").expect("openapi");
    assert!(urls.len() >= 3);
    assert_eq!(finding.plugin, "passive/openapi-import");
    assert!(urls.iter().all(|u| u.source == UrlSource::OpenApi));
    assert!(urls.iter().any(|u| u.url.contains("/users/1")));
    assert!(urls
        .iter()
        .any(|u| u.url.contains("q=1") || u.parameters.iter().any(|p| p == "q")));
}

#[test]
fn har_fixture_same_origin_only() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/har_small.har");
    let urls = load_har_file(path.to_str().unwrap(), "https://app.example.com/").expect("har");
    assert_eq!(urls.len(), 2);
    assert!(urls.iter().all(|u| u.source == UrlSource::Har));
    assert!(!urls.iter().any(|u| u.url.contains("cdn.other.com")));
}

#[test]
fn nuclei_fixture_maps_severities() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/nuclei_small.jsonl");
    let findings = parse_nuclei_jsonl_file(path.to_str().unwrap()).expect("nuclei");
    assert_eq!(findings.len(), 2);
    assert!(findings.iter().any(|f| f.severity == Severity::Critical));
    assert!(findings
        .iter()
        .all(|f| f.plugin.starts_with("active/nuclei/")));
    assert!(findings
        .iter()
        .all(|f| f.source_tool.as_deref() == Some("nuclei")));
}
