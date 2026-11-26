//! Regression suite for the syntax-aware Rust auth analyzer (`sast/rust-auth`, #44).
//! Fixtures under `tests/fixtures/rust_auth/` are data files, never compiled.

use std::path::{Path, PathBuf};

use rustzap::analyze::inventory::collect_repo_files;
use rustzap::analyze::native::rust_auth;
use rustzap::types::{Confidence, Finding};

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/rust_auth")
        .join(name)
}

/// Findings for one fixture, minus the informational limits roll-up.
fn scan(name: &str) -> Vec<Finding> {
    let root = fixture(name);
    rust_auth::scan(&root, &collect_repo_files(&root))
        .into_iter()
        .filter(|f| f.parameter.as_deref() != Some("analysis-limits"))
        .collect()
}

fn with_rule<'a>(f: &'a [Finding], rule: &str) -> Vec<&'a Finding> {
    f.iter()
        .filter(|f| f.parameter.as_deref() == Some(rule))
        .collect()
}

fn evidence(f: &Finding) -> &str {
    f.evidence.as_deref().unwrap_or_default()
}

#[test]
fn axum_vulnerable_app_reports_every_rule() {
    let f = scan("axum_vuln");
    assert!(f.iter().all(|f| f.plugin == rust_auth::PLUGIN));
    assert!(f.iter().all(|f| f.location.is_some()
        && f.evidence.is_some()
        && f.description.contains("Analysis limits")));

    let fallback = with_rule(&f, "reset-fallback");
    assert_eq!(fallback.len(), 2, "{fallback:#?}");
    assert!(fallback
        .iter()
        .any(|f| f.location.as_ref().unwrap().line_start == 9
            && evidence(f).starts_with("reset_password -> .unwrap_or(")));
    assert!(fallback
        .iter()
        .any(|f| evidence(f).starts_with("register -> DEFAULT_PASSWORD")));
    assert!(fallback.iter().all(|f| !evidence(f).contains("Welcome123")));

    let revoke = with_rule(&f, "session-not-revoked");
    let names: Vec<_> = revoke.iter().map(|f| evidence(f)).collect();
    assert_eq!(revoke.len(), 2, "{names:?}");
    assert!(names
        .iter()
        .any(|e| e.contains("change_password -> store_new_password -> update_password")));
    assert!(names.iter().any(|e| e.contains("reset_password")));
    assert!(revoke.iter().all(|f| f.confidence == Confidence::Tentative));

    // Layer ordering: /profile is above route_layer; /admin/cache and the
    // nested admin router are registered after it and stay unprotected.
    let missing = with_rule(&f, "missing-auth");
    let mut handlers: Vec<_> = missing
        .iter()
        .map(|f| {
            evidence(f)
                .split(" -> ")
                .nth(1)
                .unwrap()
                .split(';')
                .next()
                .unwrap()
        })
        .collect();
    handlers.sort();
    assert_eq!(handlers, vec!["admin_flush_cache", "delete_user"]);
    assert!(missing
        .iter()
        .any(|f| evidence(f).starts_with("DELETE /admin/users/:id")));

    let perm = with_rule(&f, "read-perm-write");
    assert_eq!(perm.len(), 1);
    assert!(evidence(perm[0]).contains("orders:read via delete_order -> \"orders:read\""));
}

#[test]
fn axum_fixed_app_is_clean() {
    // Covers: env-required config, revocation via helper, middleware resolved
    // through the call graph, helper-wrapped JWT check, write permission,
    // and test-only credentials in `#[cfg(test)]` and `tests/`.
    let f = scan("axum_fixed");
    assert!(f.is_empty(), "{f:#?}");
}

#[test]
fn actix_vulnerable_app_reports_missing_auth_and_revocation() {
    let f = scan("actix_vuln");
    let missing: Vec<_> = with_rule(&f, "missing-auth")
        .into_iter()
        .map(evidence)
        .collect();
    assert_eq!(missing.len(), 2, "{missing:?}");
    assert!(missing
        .iter()
        .any(|e| e.starts_with("DELETE /admin/users/{id} -> delete_user")));
    assert!(missing
        .iter()
        .any(|e| e.starts_with("POST /keys/rotate -> rotate_keys")));
    let revoke = with_rule(&f, "session-not-revoked");
    assert_eq!(revoke.len(), 1);
    assert!(evidence(revoke[0]).contains("change_password"));
    // No permission map in this fixture: the check is skipped cleanly.
    assert!(with_rule(&f, "read-perm-write").is_empty());
}

#[test]
fn actix_fixed_app_is_clean() {
    // scope.wrap() applied after services, configure(), helper middleware,
    // HttpAuthentication wrap, and session.purge() after a password change.
    let f = scan("actix_fixed");
    assert!(f.is_empty(), "{f:#?}");
}

#[tokio::test]
async fn native_run_includes_rust_auth() {
    let result = rustzap::analyze::native::run(&fixture("axum_vuln"))
        .await
        .expect("native");
    assert!(result
        .findings
        .iter()
        .any(|f| f.plugin == rust_auth::PLUGIN));
}
