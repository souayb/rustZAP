//! Fixture tests for `iac/transport-encryption`, `iac/backup-encryption`,
//! `iac/storage-encryption` (issue #47).

use std::path::{Path, PathBuf};

use rustzap::analyze::inventory::collect_repo_files;
use rustzap::analyze::native::transport_encryption::{
    scan, BACKUP_PLUGIN, STORAGE_PLUGIN, TRANSPORT_PLUGIN,
};
use rustzap::types::{Confidence, Finding, Severity};

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/transport_encryption")
        .join(name)
}

fn run(name: &str) -> Vec<Finding> {
    let root = fixture(name);
    scan(&root, &collect_repo_files(&root))
}

fn with_param<'a>(f: &'a [Finding], param: &str) -> Vec<&'a Finding> {
    f.iter()
        .filter(|f| f.parameter.as_deref() == Some(param))
        .collect()
}

fn problems(f: &[Finding]) -> Vec<&Finding> {
    f.iter().filter(|f| f.severity != Severity::Info).collect()
}

#[test]
fn compose_vulnerable_flags_each_transport_and_backup() {
    let f = run("compose_vulnerable");
    for p in [
        "postgres-sslmode",
        "redis-plaintext",
        "amqp-plaintext",
        "internal-http-hop",
        "smtp-no-tls",
        "backup-unencrypted",
        "unknown-effective-value",
    ] {
        assert!(!with_param(&f, p).is_empty(), "missing {p}: {f:#?}");
    }
    // Every finding names the service and artifact, and never leaks credentials.
    for x in &f {
        assert!(x.description.contains("Service: "), "{x:?}");
        assert!(x.description.contains("docker-compose.yml:"), "{x:?}");
        assert!(x.location.as_ref().unwrap().line_start > 1);
        let ev = x.evidence.as_deref().unwrap_or("");
        assert!(!ev.contains("fixturepass"), "credential leaked: {ev}");
    }
}

#[test]
fn compose_env_overrides_are_resolved() {
    let f = run("compose_vulnerable");
    let pg = with_param(&f, "postgres-sslmode");
    // `${PG_SSLMODE:-disable}` default -> disable (High), resolution keeps it tentative.
    let api = pg
        .iter()
        .find(|x| x.description.contains("`api`"))
        .expect("api pg");
    assert_eq!(api.severity, Severity::High);
    assert_eq!(api.confidence, Confidence::Tentative);
    assert!(api
        .evidence
        .as_deref()
        .unwrap()
        .contains("postgres://app:***@db"));
    // `${WORKER_DB_URL}` resolved from .env -> sslmode=prefer.
    let worker = pg
        .iter()
        .find(|x| x.description.contains("`worker`"))
        .expect("worker pg");
    assert!(worker.description.contains("`prefer`"));
    // `environment:` overrides env_file (app.env sets rediss://).
    let redis = with_param(&f, "redis-plaintext");
    assert_eq!(redis.len(), 1);
    assert!(redis[0].description.contains("docker-compose.yml:"));
    // Unresolvable `${PAYMENTS_URL}` is not guessed.
    let unknown = with_param(&f, "unknown-effective-value");
    assert!(unknown
        .iter()
        .any(|x| x.description.contains("PAYMENTS_URL")
            && x.description.contains("unknown effective value")));
}

#[test]
fn compose_fixed_has_no_problems_and_verified_backup() {
    let f = run("compose_fixed");
    assert!(problems(&f).is_empty(), "{:#?}", problems(&f));
    assert_eq!(with_param(&f, "backup-encryption-verified").len(), 1);
}

#[test]
fn k8s_vulnerable_flags_transport_backup_and_unverified_storage() {
    let f = run("k8s_vulnerable");
    let pg = with_param(&f, "postgres-sslmode");
    assert_eq!(pg.len(), 1);
    assert!(pg[0].description.contains("`require`"));
    assert!(pg[0]
        .description
        .contains("Deployment `api` container `api`"));
    assert!(!with_param(&f, "internal-http-hop").is_empty());
    let smtp = with_param(&f, "smtp-no-tls");
    assert_eq!(smtp.len(), 1);
    assert_eq!(smtp[0].confidence, Confidence::Firm);
    assert!(with_param(&f, "unknown-effective-value")
        .iter()
        .any(|x| x.description.contains("REDIS_URL")));
    let backup = with_param(&f, "backup-unencrypted");
    assert_eq!(backup.len(), 1);
    assert!(backup[0].description.contains("CronJob `nightly-backup`"));
    // StorageClass named "encrypted-gp3" is NOT evidence.
    let sc = with_param(&f, "disk-encryption-not-verified");
    assert!(sc
        .iter()
        .any(|x| x.description.contains("a name alone is not evidence")));
    assert!(with_param(&f, "disk-encryption-verified").is_empty());
    assert_eq!(with_param(&f, "secrets-encryption-not-verified").len(), 1);
    assert!(f
        .iter()
        .all(|x| [TRANSPORT_PLUGIN, BACKUP_PLUGIN, STORAGE_PLUGIN].contains(&x.plugin.as_str())));
}

#[test]
fn k8s_fixed_reports_verified_storage_evidence() {
    let f = run("k8s_fixed");
    assert!(problems(&f).is_empty(), "{:#?}", problems(&f));
    assert_eq!(with_param(&f, "secrets-encryption-verified").len(), 1);
    assert_eq!(with_param(&f, "disk-encryption-verified").len(), 1);
    assert_eq!(with_param(&f, "snapshot-encryption-verified").len(), 1);
    assert!(with_param(&f, "disk-encryption-not-verified").is_empty());
    assert_eq!(with_param(&f, "backup-encryption-verified").len(), 1);
    // `$(DB_HOST)` resolved from the ConfigMap; no unknown values remain.
    assert!(with_param(&f, "unknown-effective-value").is_empty());
}

#[test]
fn backup_scripts_vulnerable_vs_encrypted() {
    let v = run("backup_vulnerable");
    let b = with_param(&v, "backup-unencrypted");
    assert_eq!(b.len(), 1);
    assert_eq!(b[0].location.as_ref().unwrap().line_start, 4);
    let ev = b[0].evidence.as_deref().unwrap();
    assert!(ev.contains("postgres://app:***@db"), "{ev}");

    let fixed = run("backup_fixed");
    assert!(problems(&fixed).is_empty(), "{:#?}", problems(&fixed));
    assert_eq!(with_param(&fixed, "backup-encryption-verified").len(), 1);
}
