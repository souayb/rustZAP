//! #19: `scan` folds container-image CVEs and dependency SCA into one report,
//! dedups a shared advisory across both, keeps dependency scope, and says
//! loudly what was NOT assessed (missing input or unavailable scanner).

use std::time::Duration;

use rustzap::assess::{not_assessed_lines, run, AssessInputs};
use rustzap::coverage::{Coverage, InputOutcome, ScanStatus};
use rustzap::report::Report;
use rustzap::types::Severity;

fn fixture(name: &str) -> String {
    format!("{}/tests/fixtures/{name}", env!("CARGO_MANIFEST_DIR"))
}

fn report_with(
    inputs: Vec<rustzap::coverage::AssessmentInput>,
    findings: Vec<rustzap::types::Finding>,
) -> Report {
    let mut r = Report::new(
        "http://lab.local/",
        vec![],
        vec![],
        findings,
        Duration::ZERO,
    )
    .with_coverage(Coverage::new(vec![], vec![]).with_inputs(inputs.clone()));
    r.meta
        .coverage_limitations
        .extend(not_assessed_lines(&inputs));
    r
}

#[tokio::test]
async fn image_and_lockfile_are_assessed_with_scope_and_shared_advisory_deduped() {
    let inputs = AssessInputs {
        image_json: Some(fixture("trivy_image_vuln.json")),
        manifest_json: vec![fixture("trivy_lockfile_vuln.json")],
        ..Default::default()
    };
    let (findings, records) = run("http://lab.local/", &inputs).await;

    let kinds: Vec<_> = records
        .iter()
        .map(|r| (r.kind.as_str(), r.outcome))
        .collect();
    assert_eq!(
        kinds,
        [
            ("dast", InputOutcome::Assessed),
            ("image", InputOutcome::Assessed),
            ("dependencies", InputOutcome::Assessed),
        ]
    );
    let image = &records[1];
    assert_eq!(
        image.image_digest.as_deref(),
        Some("registry.example/app@sha256:2222222222222222222222222222222222222222222222222222222222222222")
    );
    assert_eq!(image.repository_revision.as_deref(), Some("0123abcd"));
    assert_eq!(image.findings, 2);
    assert_eq!(records[2].findings, 2);
    assert!(not_assessed_lines(&records).is_empty());

    // 4 raw advisories, CVE-2021-23337 shared → 3 findings.
    assert_eq!(findings.len(), 3, "{findings:#?}");
    let shared = findings
        .iter()
        .find(|f| f.parameter.as_deref() == Some("CVE-2021-23337"))
        .unwrap();
    assert_eq!(shared.plugin, "sca/image");
    assert_eq!(shared.instances.len(), 2, "{:?}", shared.instances);
    assert!(shared.instances[0]
        .starts_with("image://registry.example/app:1.0?pkg=lodash@4.17.19&scope=application"));
    assert!(shared.instances[1]
        .starts_with("file://package-lock.json?pkg=lodash@4.17.20&scope=application"));

    let os = findings
        .iter()
        .find(|f| f.parameter.as_deref() == Some("CVE-2024-0001"))
        .unwrap();
    assert_eq!(os.severity, Severity::Critical);
    assert!(os.url.ends_with("scope=base-os"));
    assert!(os.evidence.as_deref().unwrap().contains("scope=base-os"));

    let dev = findings
        .iter()
        .find(|f| f.parameter.as_deref() == Some("CVE-2023-9999"))
        .unwrap();
    assert_eq!(dev.plugin, "sca/manifest");
    assert!(dev.url.ends_with("scope=development"));

    // Report-level dedup keeps the cross-source merge intact.
    let report = report_with(records, findings);
    assert_eq!(report.findings.len(), 3);
    assert_eq!(
        report.coverage.as_ref().unwrap().status,
        ScanStatus::Completed
    );
    let json = report.to_export_json().unwrap();
    assert!(json.contains("\"sca/manifest\"") && json.contains("\"assessed\""));
    assert!(!json.contains("NOT ASSESSED"));
}

#[tokio::test]
async fn dast_only_scan_is_flagged_not_assessed_in_json_and_html() {
    let (findings, records) = run("http://lab.local/", &AssessInputs::default()).await;
    assert!(findings.is_empty());
    assert_eq!(records[1].outcome, InputOutcome::MissingInput);
    assert_eq!(records[2].outcome, InputOutcome::MissingInput);
    let lines = not_assessed_lines(&records);
    assert_eq!(lines.len(), 2);
    assert!(lines[0].starts_with("NOT ASSESSED: container image CVEs (missing_input"));
    assert!(lines[1].starts_with("NOT ASSESSED: dependency (SCA) CVEs (missing_input"));

    let report = report_with(records, findings);
    let json = report.to_export_json().unwrap();
    assert!(json.contains("\"missing_input\""));
    assert!(json.contains("NOT ASSESSED: container image CVEs"));
    let html = report.to_html();
    assert!(html.contains("NOT ASSESSED: dependency (SCA) CVEs"));
    assert!(html.contains("Assessment inputs"));
    // Reports without inputs keep their old JSON shape.
    let old = Report::new("x", vec![], vec![], vec![], Duration::ZERO)
        .with_coverage(Coverage::new(vec![], vec![]));
    assert!(!old.to_export_json().unwrap().contains("\"inputs\""));
}

#[tokio::test]
async fn unavailable_scanner_is_failed_with_reason_not_silent() {
    // Point discovery at a path that does not exist: Trivy is unavailable.
    std::env::set_var("RUSTZAP_TOOL_TRIVY", "/nonexistent/rustzap-test/trivy");
    let inputs = AssessInputs {
        image: Some("registry.example/app:1.0".into()),
        manifests: vec![fixture("trivy_lockfile_vuln.json")],
        ..Default::default()
    };
    let (findings, records) = run("http://lab.local/", &inputs).await;
    assert!(findings.is_empty());
    for r in &records[1..] {
        assert_eq!(r.outcome, InputOutcome::Failed, "{r:?}");
        assert_eq!(r.tool.as_deref(), Some("trivy"));
        assert!(r.exit_status.is_none());
        assert!(
            r.diagnostic.as_deref().unwrap().contains("trivy not found"),
            "{r:?}"
        );
    }
    let lines = not_assessed_lines(&records);
    assert_eq!(lines.len(), 2);
    assert!(lines[0].contains("(failed, registry.example/app:1.0: trivy not found"));

    let report = report_with(records, findings);
    assert_eq!(
        report.coverage.as_ref().unwrap().status,
        ScanStatus::Partial
    );
    assert!(report.to_export_json().unwrap().contains("\"failed\""));
}

#[tokio::test]
async fn malformed_json_and_missing_lockfile_fail_with_diagnostic() {
    let dir = std::env::temp_dir().join(format!("rz-i19-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let bad = dir.join("bad.json");
    std::fs::write(&bad, "not json").unwrap();
    let inputs = AssessInputs {
        image_json: Some(bad.to_string_lossy().into()),
        manifests: vec![dir.join("missing.lock").to_string_lossy().into()],
        ..Default::default()
    };
    let (_, records) = run("http://lab.local/", &inputs).await;
    assert_eq!(records[1].outcome, InputOutcome::Failed);
    assert!(records[1]
        .diagnostic
        .as_deref()
        .unwrap()
        .contains("Trivy JSON parse error"));
    assert_eq!(records[2].outcome, InputOutcome::Failed);
    assert_eq!(records[2].diagnostic.as_deref(), Some("lockfile not found"));
    let _ = std::fs::remove_dir_all(dir);
}
