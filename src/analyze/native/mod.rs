//! Built-in (no-subprocess) static analyzers inspired by Argus JS/HTML surface.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result};

use crate::analyze::inventory::{self, collect_repo_files_with, WalkConfig};
use crate::report::{AttackPlanEntry, Inventory};
use crate::types::Finding;

pub mod cloud;
pub mod config_audit;
pub mod dlp;
pub mod dom_sinks;
pub mod forms;
pub mod hashes;
pub mod js_surface;
pub mod params;
pub mod rust_auth;
pub mod sbom;
pub mod secrets;
pub mod transport_encryption;

pub const SOURCE_TOOL: &str = "rustzap-native";

pub const NATIVE_MODULES: &[&str] = &[
    "sast/inventory",
    "sast/secrets",
    "sast/js-secrets",
    "sast/js-urls",
    "sast/dom-sinks",
    "sast/js-cookies",
    "sast/js-storage",
    "sast/js-postmessage",
    "sast/forms",
    "sast/params",
    "iac/native",
    "iac/cloud",
    "sast/dlp-pii",
    "sast/crypto-audit",
    "sca/native-sbom",
    transport_encryption::TRANSPORT_PLUGIN,
    transport_encryption::BACKUP_PLUGIN,
    transport_encryption::STORAGE_PLUGIN,
    "sast/rust-auth",
];

pub struct NativeScanResult {
    pub findings: Vec<Finding>,
    pub inventory: Inventory,
    pub attack_plan: Vec<AttackPlanEntry>,
    /// Analyzer/file caps that were hit (#41).
    pub omitted: Vec<crate::coverage::OmittedRecord>,
}

/// Record `source` as capped when it produced at least `limit` results.
fn note_cap(out: &mut Vec<crate::coverage::OmittedRecord>, source: &str, len: usize, limit: usize) {
    if len >= limit {
        out.push(crate::coverage::OmittedRecord {
            source: source.to_string(),
            limit,
            omitted: None,
            reason: format!(
                "{source} stopped at its cap of {limit}; remaining results were not collected"
            ),
        });
    }
}

/// Run inventory, then JS/HTML/param analyzers in parallel over `repo`,
/// using the default [`WalkConfig`].
pub async fn run(repo: &Path) -> Result<NativeScanResult> {
    run_with(repo, WalkConfig::default()).await
}

/// Like [`run`], but with an explicit walk configuration (ignore/symlink flags).
pub async fn run_with(repo: &Path, walk: WalkConfig) -> Result<NativeScanResult> {
    let files = collect_repo_files_with(repo, walk);
    let mut res = run_on_files(repo, &files).await?;
    note_cap(
        &mut res.omitted,
        "files",
        files.len(),
        inventory::MAX_REPO_FILES,
    );
    Ok(res)
}

pub async fn run_on_files(repo: &Path, files: &[PathBuf]) -> Result<NativeScanResult> {
    let (inventory, inv_finding) = inventory::analyze(repo, files);

    let root = Arc::new(repo.to_path_buf());
    let files = Arc::<[PathBuf]>::from(files.to_vec());

    let js_root = Arc::clone(&root);
    let js_files = Arc::clone(&files);
    let sinks_root = Arc::clone(&root);
    let sinks_files = Arc::clone(&files);
    let forms_root = Arc::clone(&root);
    let forms_files = Arc::clone(&files);
    let params_root = Arc::clone(&root);
    let params_files = Arc::clone(&files);
    let secrets_root = Arc::clone(&root);
    let secrets_files = Arc::clone(&files);
    let config_root = Arc::clone(&root);
    let config_files = Arc::clone(&files);
    let dlp_root = Arc::clone(&root);
    let dlp_files = Arc::clone(&files);
    let hashes_root = Arc::clone(&root);
    let hashes_files = Arc::clone(&files);
    let sbom_root = Arc::clone(&root);
    let cloud_root = Arc::clone(&root);
    let cloud_files = Arc::clone(&files);
    let rust_auth_root = Arc::clone(&root);
    let rust_auth_files = Arc::clone(&files);

    let (
        js_res,
        sinks_res,
        forms_res,
        params_res,
        secrets_res,
        config_res,
        dlp_res,
        hashes_res,
        sbom_res,
        cloud_res,
        rust_auth_res,
    ) = tokio::join!(
        tokio::task::spawn_blocking(move || js_surface::scan(js_root.as_path(), js_files.as_ref())),
        tokio::task::spawn_blocking(move || {
            dom_sinks::scan(sinks_root.as_path(), sinks_files.as_ref())
        }),
        tokio::task::spawn_blocking(move || forms::scan(
            forms_root.as_path(),
            forms_files.as_ref()
        )),
        tokio::task::spawn_blocking(move || {
            params::scan(params_root.as_path(), params_files.as_ref())
        }),
        tokio::task::spawn_blocking(move || {
            secrets::scan(secrets_root.as_path(), secrets_files.as_ref())
        }),
        tokio::task::spawn_blocking(move || {
            config_audit::scan(config_root.as_path(), config_files.as_ref())
        }),
        tokio::task::spawn_blocking(move || { dlp::scan(dlp_root.as_path(), dlp_files.as_ref()) }),
        tokio::task::spawn_blocking(move || {
            hashes::scan(hashes_root.as_path(), hashes_files.as_ref())
        }),
        tokio::task::spawn_blocking(move || { sbom::scan_repository_sbom(sbom_root.as_path()) }),
        tokio::task::spawn_blocking(move || {
            cloud::scan(cloud_root.as_path(), cloud_files.as_ref())
        }),
        tokio::task::spawn_blocking(move || {
            rust_auth::scan(rust_auth_root.as_path(), rust_auth_files.as_ref())
        }),
    );

    let js = js_res.context("js_surface analyzer task failed")?;
    let sinks = sinks_res.context("dom_sinks analyzer task failed")?;
    let form_result = forms_res.context("forms analyzer task failed")?;
    let param_result = params_res.context("params analyzer task failed")?;
    let secret_findings = secrets_res.context("secrets analyzer task failed")?;
    let config_findings = config_res.context("config_audit analyzer task failed")?;
    let dlp_findings = dlp_res.context("dlp analyzer task failed")?;
    let hashes_findings = hashes_res.context("hashes analyzer task failed")?;
    let sbom_report = sbom_res.context("sbom analyzer task failed")?;
    let cloud_findings = cloud_res.context("cloud analyzer task failed")?;
    let rust_auth_findings = rust_auth_res.context("rust_auth analyzer task failed")?;

    let mut omitted = Vec::new();
    for (source, len, limit) in [
        (
            "sast/js-surface",
            js.len(),
            js_surface::MAX_SECRET_FINDINGS + js_surface::MAX_URL_FINDINGS + 20,
        ),
        ("sast/dom-sinks", sinks.len(), dom_sinks::MAX_SINK_FINDINGS),
        (
            "sast/forms",
            form_result.findings.len(),
            forms::MAX_FORM_FINDINGS,
        ),
        (
            "sast/params",
            param_result.findings.len(),
            params::MAX_PARAM_FINDINGS,
        ),
        (
            "sast/secrets",
            secret_findings.len(),
            secrets::MAX_SECRET_FINDINGS,
        ),
        (
            "iac/native",
            config_findings.len(),
            config_audit::MAX_CONFIG_FINDINGS,
        ),
        ("sast/dlp-pii", dlp_findings.len(), dlp::MAX_DLP_FINDINGS),
        (
            "sast/crypto-audit",
            hashes_findings.len(),
            hashes::MAX_CRYPTO_FINDINGS,
        ),
        ("iac/cloud", cloud_findings.len(), 100),
    ] {
        note_cap(&mut omitted, source, len, limit);
    }

    let mut findings = vec![inv_finding];
    findings.extend(js);
    findings.extend(sinks);
    findings.extend(form_result.findings);
    findings.extend(param_result.findings);
    findings.extend(secret_findings);
    findings.extend(config_findings);
    findings.extend(dlp_findings);
    findings.extend(hashes_findings);
    findings.extend(sbom_report.findings);
    findings.extend(cloud_findings);
    // Kept outside the join tuple above to keep this wiring additive.
    let te_root = Arc::clone(&root);
    let te_files = Arc::clone(&files);
    findings.extend(
        tokio::task::spawn_blocking(move || {
            transport_encryption::scan(te_root.as_path(), te_files.as_ref())
        })
        .await
        .context("transport_encryption analyzer task failed")?,
    );
    findings.extend(rust_auth_findings);
    sort_native_findings(&mut findings);

    let mut attack_plan = form_result.attack_plan;
    attack_plan.extend(param_result.attack_plan);

    Ok(NativeScanResult {
        findings,
        inventory,
        attack_plan: merge_attack_plan(attack_plan),
        omitted,
    })
}

/// Deterministic merge order: plugin, then file/url, then line, then title.
pub fn sort_native_findings(findings: &mut [Finding]) {
    findings.sort_by(|a, b| {
        a.plugin
            .cmp(&b.plugin)
            .then_with(|| {
                let fa = a
                    .location
                    .as_ref()
                    .map(|l| l.file.as_str())
                    .unwrap_or(a.url.as_str());
                let fb = b
                    .location
                    .as_ref()
                    .map(|l| l.file.as_str())
                    .unwrap_or(b.url.as_str());
                fa.cmp(fb)
            })
            .then_with(|| {
                let la = a.location.as_ref().map(|l| l.line_start).unwrap_or(0);
                let lb = b.location.as_ref().map(|l| l.line_start).unwrap_or(0);
                la.cmp(&lb)
            })
            .then_with(|| a.title.cmp(&b.title))
    });
}

pub fn merge_attack_plan(entries: Vec<AttackPlanEntry>) -> Vec<AttackPlanEntry> {
    use std::collections::BTreeMap;
    let mut map: BTreeMap<(String, String), AttackPlanEntry> = BTreeMap::new();
    for mut e in entries {
        e.method = e.method.to_uppercase();
        if e.method.is_empty() {
            e.method = "GET".to_string();
        }
        let key = (e.url.clone(), e.method.clone());
        map.entry(key)
            .and_modify(|existing| {
                for p in &e.params {
                    if !existing.params.contains(p) {
                        existing.params.push(p.clone());
                    }
                }
                if !e.reason.is_empty() && !existing.reason.contains(&e.reason) {
                    existing.reason = format!("{}; {}", existing.reason, e.reason);
                }
            })
            .or_insert(e);
    }
    let mut out: Vec<_> = map.into_values().collect();
    out.truncate(80);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::Severity;

    #[test]
    fn merge_combines_same_url_method() {
        let merged = merge_attack_plan(vec![
            AttackPlanEntry {
                url: "/login".into(),
                method: "post".into(),
                params: vec!["user".into()],
                reason: "form".into(),
            },
            AttackPlanEntry {
                url: "/login".into(),
                method: "POST".into(),
                params: vec!["pass".into()],
                reason: "form+password".into(),
            },
        ]);
        assert_eq!(merged.len(), 1);
        assert!(merged[0].params.contains(&"user".to_string()));
        assert!(merged[0].params.contains(&"pass".to_string()));
    }

    #[test]
    fn sort_is_plugin_then_file() {
        let mut findings = vec![
            Finding::new("b", Severity::Info, "file://b.js", "d", "s", "sast/params"),
            Finding::new(
                "a",
                Severity::Info,
                "file://a.js",
                "d",
                "s",
                "sast/dom-sinks",
            ),
            Finding::new(
                "c",
                Severity::Info,
                "file://c.js",
                "d",
                "s",
                "sast/dom-sinks",
            ),
        ];
        findings[0].location = Some(crate::types::CodeLocation {
            file: "b.js".into(),
            line_start: 1,
            line_end: None,
        });
        findings[1].location = Some(crate::types::CodeLocation {
            file: "z.js".into(),
            line_start: 1,
            line_end: None,
        });
        findings[2].location = Some(crate::types::CodeLocation {
            file: "a.js".into(),
            line_start: 1,
            line_end: None,
        });
        sort_native_findings(&mut findings);
        assert_eq!(findings[0].plugin, "sast/dom-sinks");
        assert_eq!(findings[0].location.as_ref().unwrap().file, "a.js");
        assert_eq!(findings[1].location.as_ref().unwrap().file, "z.js");
        assert_eq!(findings[2].plugin, "sast/params");
    }
}
