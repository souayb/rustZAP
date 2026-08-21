//! Tier-B SAST regression: run the native analyzers over the lab source tree
//! (`tests/fixtures/lab`) and assert every planted artifact surfaces. Mirrors
//! `tests/native_analyze.rs`, but the lab additionally exercises non-JS secrets
//! and IaC that `native_app` intentionally omits.

use std::collections::HashSet;
use std::path::Path;

use rustzap::analyze::native;

#[tokio::test]
async fn lab_source_tree_lights_up_every_analyzer() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/lab");
    let result = native::run(&root).await.expect("native run");

    let plugins: HashSet<String> = result.findings.iter().map(|f| f.plugin.clone()).collect();

    for expected in [
        "sast/inventory",
        "sast/js-secrets",
        "sast/dom-sinks",
        "sast/js-storage",
        "sast/js-cookies",
        "sast/js-postmessage",
        "sast/js-urls",
        "sast/secrets",
        "sast/forms",
        "sast/params",
        "iac/native",
    ] {
        assert!(
            plugins.contains(expected),
            "expected {expected} from the lab SAST tree; got {plugins:?}"
        );
    }

    // The login form feeds the attack-plan frontier.
    assert!(
        result
            .attack_plan
            .iter()
            .any(|e| e.url.contains("login") || e.reason.contains("form")),
        "expected a form-derived attack-plan entry"
    );
}
