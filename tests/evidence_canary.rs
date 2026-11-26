//! Evidence-contract canary test (issue #49): inject synthetic credentials and
//! personal-data canaries into every supported evidence location and assert
//! none of them survive into any exported artifact, while the stable finding
//! id and validation status stay consistent across formats.

use rustzap::agent::{autofix, trace::Trace};
use rustzap::evidence;
use rustzap::report::Report;
use rustzap::types::{
    CodeLocation, Finding, HttpRequest, HttpResponse, HttpTransaction, PocProof, Severity,
};

const CANARIES: &[&str] = &[
    "CANARY-SECRET-AUTH",
    "CANARY-SECRET-COOKIE",
    "CANARY-SECRET-SETCOOKIE",
    "CANARY-SECRET-QUERY",
    "CANARY-SECRET-BODY",
    "CANARY-SECRET-JSON",
    "CANARY-SECRET-EXC",
    "CANARY-SECRET-TARGET",
    "CANARY-SECRET-USERINFO",
    "canary.person",
    "987-65-4321",
];

fn canary_finding(location: Option<CodeLocation>) -> Finding {
    let mut f = Finding::new(
        "SQL injection",
        Severity::High,
        "https://app.test/items?id=1&access_token=CANARY-SECRET-QUERY",
        "Backend raised: DbError for user canary.person@example.test \
         (session=CANARY-SECRET-EXC)",
        "Use parameterized queries",
        "sqli",
    )
    .with_parameter("id")
    .with_method("POST")
    .with_evidence("Cookie: sid=CANARY-SECRET-COOKIE\nSSN 987-65-4321 in response")
    .with_behaviour(
        "401 for password=CANARY-SECRET-BODY",
        "200 with {\"api_key\":\"CANARY-SECRET-JSON\"}",
    )
    .with_poc(PocProof {
        script_type: "curl".into(),
        script_content: "curl -H 'Authorization: Bearer CANARY-SECRET-AUTH' \
                         https://u:CANARY-SECRET-USERINFO@app.test/items"
            .into(),
        canary_sent: "token=CANARY-SECRET-QUERY".into(),
        canary_received: "token=CANARY-SECRET-QUERY".into(),
        raw_request: "POST /items?id=1'\nAuthorization: Bearer CANARY-SECRET-AUTH\n\
                      Cookie: sid=CANARY-SECRET-COOKIE\n\npassword=CANARY-SECRET-BODY"
            .into(),
        raw_response: "HTTP/1.1 200 OK\nSet-Cookie: SESSION=CANARY-SECRET-SETCOOKIE\n\n\
                       {\"email\":\"canary.person@example.test\"}"
            .into(),
        execution_time_ms: 3,
    });
    f.location = location;
    f
}

fn assert_clean(name: &str, artifact: &str) {
    for c in CANARIES {
        assert!(
            !artifact.contains(c),
            "{name} leaked canary {c}:\n{artifact}"
        );
    }
}

#[test]
fn canaries_absent_from_every_exported_artifact() {
    let tmp = std::env::temp_dir().join(format!("rz-canary-{}", rustzap::types::uuid_v4()));
    std::fs::create_dir_all(&tmp).unwrap();
    let src = tmp.join("app.py");
    std::fs::write(&src, "query = 'select ' + id\n").unwrap();

    let finding = canary_finding(None);
    let fp = evidence::finding_fingerprint(&finding);
    let mut report = Report::new(
        "https://app.test/?api_key=CANARY-SECRET-TARGET",
        vec![],
        vec![],
        vec![finding.clone()],
        std::time::Duration::from_secs(1),
    );
    report.meta.source_revision = Some("abc123".into());
    report
        .meta
        .coverage_limitations
        .push("login failed: token=CANARY-SECRET-EXC".into());

    // JSON, CSV, HTML.
    let json = report.to_export_json().unwrap();
    let csv = report.to_csv();
    let html = report.to_html();
    // SARIF.
    let sarif_path = tmp.join("r.sarif");
    rustzap::sarif::write_sarif(&report, sarif_path.to_str().unwrap()).unwrap();
    let sarif = std::fs::read_to_string(&sarif_path).unwrap();
    // Replay artifact (captured transaction).
    let txn = HttpTransaction {
        id: "t1".into(),
        request: HttpRequest {
            method: "POST".into(),
            url: "https://app.test/login?token=CANARY-SECRET-QUERY".into(),
            headers: vec![
                ("Authorization".into(), "Bearer CANARY-SECRET-AUTH".into()),
                ("Cookie".into(), "sid=CANARY-SECRET-COOKIE".into()),
            ],
            body: Some("{\"password\":\"CANARY-SECRET-JSON\"}".into()),
        },
        response: Some(HttpResponse {
            status: 200,
            headers: vec![("Set-Cookie".into(), "s=CANARY-SECRET-SETCOOKIE".into())],
            body: "hello canary.person@example.test".into(),
            elapsed_ms: 1,
        }),
        timestamp: chrono::Utc::now(),
    };
    let replay = serde_json::to_string(&vec![evidence::redact_transaction(&txn)]).unwrap();
    // Autofix prompt (per-finding export) and audit-trace log/exception text.
    let prompts = autofix::export_findings(
        &[canary_finding(Some(CodeLocation {
            file: src.display().to_string(),
            line_start: 1,
            line_end: None,
        }))],
        tmp.join("autofix"),
        None,
    )
    .unwrap();
    let prompt = std::fs::read_to_string(&prompts[0]).unwrap();
    let trace_path = tmp.join("trace.jsonl");
    let trace = Trace::new(&trace_path);
    trace.note(
        "tool_error",
        "GET https://app.test/?session=CANARY-SECRET-EXC failed",
    );
    trace.tool_call(
        "probe",
        &serde_json::json!({"headers": {"Authorization": "Bearer CANARY-SECRET-AUTH"}}),
    );
    let trace_log = std::fs::read_to_string(&trace_path).unwrap();

    for (name, artifact) in [
        ("json", &json),
        ("csv", &csv),
        ("html", &html),
        ("sarif", &sarif),
        ("replay", &replay),
        ("autofix", &prompt),
        ("trace", &trace_log),
    ] {
        assert_clean(name, artifact);
    }

    // Same stable id + validation status in every report format.
    for (name, artifact) in [
        ("json", &json),
        ("csv", &csv),
        ("html", &html),
        ("sarif", &sarif),
    ] {
        assert!(artifact.contains(&fp), "{name} missing fingerprint");
        assert!(artifact.contains("confirmed"), "{name} missing validation");
    }
    assert!(json.contains("\"source_revision\": \"abc123\""));
    assert!(sarif.contains("abc123") && html.contains("abc123"));
    assert!(json.contains("coverage_limitations") && sarif.contains("coverageLimitations"));
    // Redaction keeps the evidence useful: the vulnerable parameter and method survive.
    let v: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert_eq!(v["findings"][0]["parameter"], "id");
    assert_eq!(v["findings"][0]["method"], "POST");
    assert_eq!(v["findings"][0]["fingerprint"], fp.as_str());

    let _ = std::fs::remove_dir_all(&tmp);
}
