//! Unified assessment (#19): fold container-image CVEs (`sca/image`) and
//! dependency SCA (`sca/manifest`) into a `scan` report via Trivy, and record
//! an explicit outcome per input so a DAST-only run is never mistaken for a
//! full assessment. Nothing is auto-detected and nothing is published.

use crate::analyze::trivy;
use crate::coverage::{AssessmentInput, InputOutcome};
use crate::evidence::redact_string;
use crate::types::{safe_truncate, Finding};

/// Opt-in image / dependency inputs (CLI flags flattened into `rustzap scan`).
#[derive(clap::Args, Debug, Clone, Default)]
pub struct AssessInputs {
    /// Opt-in: scan this container image with `trivy image` (findings: sca/image)
    #[arg(long, value_name = "REF", conflicts_with = "image_json")]
    pub image: Option<String>,
    /// Opt-in: import precomputed `trivy image --format json` output (no spawn)
    #[arg(long, value_name = "FILE")]
    pub image_json: Option<String>,
    /// Opt-in, repeatable: scan a lockfile with `trivy fs` (package-lock.json, requirements.txt, Cargo.lock, ...; findings: sca/manifest)
    #[arg(long = "manifest", value_name = "LOCKFILE")]
    pub manifests: Vec<String>,
    /// Opt-in, repeatable: import precomputed Trivy JSON for a lockfile (no spawn)
    #[arg(long, value_name = "FILE")]
    pub manifest_json: Vec<String>,
}

/// Findings from the image/dependency inputs (one finding per advisory, each
/// affected component in `instances`) plus one record per input, DAST first.
pub async fn run(target: &str, inputs: &AssessInputs) -> (Vec<Finding>, Vec<AssessmentInput>) {
    let mut findings = Vec::new();
    let mut records = vec![AssessmentInput {
        outcome: InputOutcome::Assessed,
        source: Some(target.to_string()),
        tool: Some("rustzap".into()),
        ..blank("dast")
    }];

    if let Some(path) = &inputs.image_json {
        records.push(import(path, "image", "sca/image", &mut findings));
    } else if let Some(image) = &inputs.image {
        records.push(scan_image(image, &mut findings).await);
    } else {
        records.push(missing("image", "no --image or --image-json supplied"));
    }

    for path in &inputs.manifest_json {
        records.push(import(path, "dependencies", "sca/manifest", &mut findings));
    }
    for path in &inputs.manifests {
        records.push(scan_manifest(path, &mut findings).await);
    }
    if inputs.manifest_json.is_empty() && inputs.manifests.is_empty() {
        records.push(missing(
            "dependencies",
            "no --manifest or --manifest-json supplied",
        ));
    }

    // Same advisory in image and lockfile → one finding listing every component.
    let findings = crate::finding_dedup::collapse_by(findings, |f| {
        f.parameter.clone().unwrap_or_else(|| f.id.clone())
    });
    (findings, records)
}

/// CLI/JSON/HTML banner lines for every input that was not assessed.
pub fn not_assessed_lines(records: &[AssessmentInput]) -> Vec<String> {
    records
        .iter()
        .filter(|r| r.outcome != InputOutcome::Assessed)
        .map(|r| {
            let what = match r.kind.as_str() {
                "image" => "container image CVEs",
                "dependencies" => "dependency (SCA) CVEs",
                other => other,
            };
            format!(
                "NOT ASSESSED: {what} ({}{}{})",
                r.outcome,
                r.source
                    .as_deref()
                    .map(|s| format!(", {s}"))
                    .unwrap_or_default(),
                r.diagnostic
                    .as_deref()
                    .map(|d| format!(": {d}"))
                    .unwrap_or_default()
            )
        })
        .collect()
}

fn blank(kind: &str) -> AssessmentInput {
    AssessmentInput {
        kind: kind.into(),
        outcome: InputOutcome::MissingInput,
        source: None,
        tool: None,
        exit_status: None,
        diagnostic: None,
        image_digest: None,
        repository_revision: None,
        vulnerability_db_updated_at: None,
        findings: 0,
    }
}

fn missing(kind: &str, why: &str) -> AssessmentInput {
    AssessmentInput {
        diagnostic: Some(why.into()),
        ..blank(kind)
    }
}

fn failed(kind: &str, source: &str, exit_status: Option<i32>, why: &str) -> AssessmentInput {
    AssessmentInput {
        outcome: InputOutcome::Failed,
        source: Some(source.to_string()),
        tool: Some("trivy".into()),
        exit_status,
        diagnostic: Some(redact_string(safe_truncate(why.trim(), 500))),
        ..blank(kind)
    }
}

/// Parse Trivy JSON and turn it into an `assessed` record (or `failed` on parse error).
fn ingest(
    json: &str,
    kind: &str,
    plugin: &str,
    source: &str,
    origin: &str,
    findings: &mut Vec<Finding>,
) -> AssessmentInput {
    match trivy::parse_trivy_scoped(json, plugin, origin) {
        Ok((found, meta)) => {
            let rec = AssessmentInput {
                outcome: InputOutcome::Assessed,
                source: Some(source.to_string()),
                tool: Some("trivy".into()),
                image_digest: meta.image_digest,
                repository_revision: meta.revision,
                findings: found.len(),
                ..blank(kind)
            };
            findings.extend(found);
            rec
        }
        Err(e) => failed(kind, source, None, &format!("{e:#}")),
    }
}

fn import(path: &str, kind: &str, plugin: &str, findings: &mut Vec<Finding>) -> AssessmentInput {
    let json = match std::fs::read_to_string(path) {
        Ok(j) => j,
        Err(e) => return failed(kind, path, None, &format!("read {path}: {e}")),
    };
    // Prefer the artifact Trivy scanned (image ref / lockfile) as the location.
    let name = serde_json::from_str::<serde_json::Value>(&json)
        .ok()
        .and_then(|v| v["ArtifactName"].as_str().map(str::to_string))
        .unwrap_or_else(|| path.to_string());
    let scheme = if kind == "image" { "image" } else { "file" };
    let mut rec = ingest(
        &json,
        kind,
        plugin,
        path,
        &format!("{scheme}://{name}"),
        findings,
    );
    rec.tool = Some("trivy (imported JSON)".into());
    rec
}

async fn scan_image(image: &str, findings: &mut Vec<Finding>) -> AssessmentInput {
    if image.starts_with('-') || image.trim().is_empty() {
        return failed("image", image, None, "invalid image reference");
    }
    match run_trivy(&["image", "--format", "json", "--quiet", "--", image]).await {
        Ok(json) => {
            let mut rec = ingest(
                &json,
                "image",
                "sca/image",
                image,
                &format!("image://{image}"),
                findings,
            );
            rec.vulnerability_db_updated_at = db_updated_at().await;
            rec
        }
        Err((code, why)) => failed("image", image, code, &why),
    }
}

async fn scan_manifest(path: &str, findings: &mut Vec<Finding>) -> AssessmentInput {
    if !std::path::Path::new(path).is_file() {
        return failed("dependencies", path, None, "lockfile not found");
    }
    // `--include-dev-deps --list-all-pkgs` so dev tooling is reported and tagged as such.
    let args = [
        "fs",
        "--format",
        "json",
        "--quiet",
        "--include-dev-deps",
        "--list-all-pkgs",
        "--",
        path,
    ];
    match run_trivy(&args).await {
        Ok(json) => {
            let mut rec = ingest(
                &json,
                "dependencies",
                "sca/manifest",
                path,
                &format!("file://{path}"),
                findings,
            );
            rec.vulnerability_db_updated_at = db_updated_at().await;
            rec
        }
        Err((code, why)) => failed("dependencies", path, code, &why),
    }
}

/// Run Trivy; on failure return (exit code, diagnostic). A missing binary is a
/// failure with no exit code — never silently skipped.
async fn run_trivy(args: &[&str]) -> Result<String, (Option<i32>, String)> {
    let bin = crate::executable::require("trivy").map_err(|e| (None, e.to_string()))?;
    let out = tokio::process::Command::new(bin)
        .args(args)
        .output()
        .await
        .map_err(|e| (None, format!("failed to spawn trivy: {e}")))?;
    if !out.status.success() {
        return Err((
            out.status.code(),
            format!(
                "trivy exited with {}: {}",
                out.status,
                String::from_utf8_lossy(&out.stderr)
            ),
        ));
    }
    String::from_utf8(out.stdout).map_err(|e| (None, format!("trivy stdout not UTF-8: {e}")))
}

/// Vulnerability-DB timestamp from `trivy version --format json` (best effort).
async fn db_updated_at() -> Option<String> {
    let json = run_trivy(&["version", "--format", "json"]).await.ok()?;
    let v: serde_json::Value = serde_json::from_str(&json).ok()?;
    v["VulnerabilityDB"]["UpdatedAt"]
        .as_str()
        .map(str::to_string)
}
