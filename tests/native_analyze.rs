//! Crate-level integration for Phase 2.5 native analyzers.

use std::path::Path;

use rustzap::analyze::inventory::collect_repo_files;
use rustzap::analyze::{native, parse_tools, run_static_analysis, AnalyzeTool, StaticInputs};
use rustzap::report::Report;

#[tokio::test]
async fn native_run_on_fixture_is_non_empty() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/native_app");
    let result = native::run(&root).await.expect("native");
    assert!(result
        .findings
        .iter()
        .any(|f| f.plugin == "sast/js-secrets"));
    assert!(result.findings.iter().any(|f| f.plugin == "sast/dom-sinks"));
    assert!(result
        .findings
        .iter()
        .any(|f| f.plugin == "sast/js-cookies"));
    assert!(result
        .findings
        .iter()
        .any(|f| f.plugin == "sast/js-storage"));
    assert!(result
        .findings
        .iter()
        .any(|f| f.plugin == "sast/js-postmessage"));
    assert!(result.findings.iter().any(|f| f.plugin == "sast/forms"));
    assert!(!result.attack_plan.is_empty());
    assert!(result
        .attack_plan
        .iter()
        .any(|e| e.url.contains("login") || e.reason.contains("form")));
    assert!(result.findings.iter().all(|f| {
        !f.location
            .as_ref()
            .is_some_and(|l| l.file.contains("ignored_dir"))
    }));
}

#[test]
fn gitignore_excludes_ignored_dir_in_native_fixture() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/native_app");
    let files = collect_repo_files(&root);
    assert!(
        files.iter().any(|p| p.ends_with("app.js")),
        "fixture app.js should still be scanned"
    );
    assert!(
        !files
            .iter()
            .any(|p| p.to_string_lossy().contains("ignored_dir")),
        "paths under ignored_dir/ must not be collected"
    );
}

#[tokio::test]
async fn run_static_analysis_native_attaches_static_block() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/native_app");
    let tools = parse_tools("native").unwrap();
    assert_eq!(tools, vec![AnalyzeTool::Native]);
    let run = run_static_analysis(&StaticInputs {
        repo: root,
        tools,
        tools_explicit: true,
        semgrep_json: None,
        trivy_json: None,
        gitleaks_json: None,
        checkov_json: None,
        walk: rustzap::analyze::inventory::WalkConfig::default(),
    })
    .await
    .expect("static native");
    let block = run.static_analysis.expect("static{}");
    assert!(!block.detection_checks.is_empty());
    assert!(block.detection_checks.iter().any(|c| c.triggered));
    assert!(block
        .detection_checks
        .iter()
        .any(|c| c.id == "js-cookies" && c.triggered));
    assert!(block
        .detection_checks
        .iter()
        .any(|c| c.id == "js-storage" && c.triggered));
    assert!(block
        .detection_checks
        .iter()
        .any(|c| c.id == "js-postmessage" && c.triggered));
    assert!(!block.attack_plan.is_empty());

    let report = rustzap::report::Report::new(
        "fixture",
        vec![],
        vec![],
        run.findings,
        std::time::Duration::from_secs(0),
    )
    .with_static(block);
    let json = serde_json::to_string(&report).expect("json");
    let decoded: Report = serde_json::from_str(&json).expect("decode");
    assert!(decoded.static_analysis.is_some());
}
