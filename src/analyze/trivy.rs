//! Trivy filesystem / image scan JSON → RustZAP findings.

use std::collections::{HashMap, HashSet};
use std::path::Path;

use anyhow::{Context, Result};
use serde::Deserialize;

use crate::types::{Finding, Severity};

#[derive(Debug, Deserialize)]
struct TrivyReport {
    #[serde(default, alias = "Results")]
    results: Vec<TrivyResult>,
    #[serde(default, alias = "ArtifactName")]
    artifact_name: Option<String>,
    #[serde(default, alias = "Metadata")]
    metadata: TrivyMetadata,
}

#[derive(Debug, Default, Deserialize)]
struct TrivyMetadata {
    #[serde(default, alias = "ImageID")]
    image_id: Option<String>,
    #[serde(default, alias = "RepoDigests")]
    repo_digests: Vec<String>,
    /// Repository scans (`trivy repo`) record the scanned commit here.
    #[serde(default, alias = "Commit")]
    commit: Option<String>,
    #[serde(default, alias = "ImageConfig")]
    image_config: TrivyImageConfig,
}

#[derive(Debug, Default, Deserialize)]
struct TrivyImageConfig {
    #[serde(default)]
    config: TrivyContainerConfig,
}

#[derive(Debug, Default, Deserialize)]
struct TrivyContainerConfig {
    #[serde(default, alias = "Labels")]
    labels: Option<HashMap<String, String>>,
}

#[derive(Debug, Deserialize)]
struct TrivyResult {
    #[serde(default, alias = "Target")]
    target: Option<String>,
    /// `os-pkgs` (base image) or `lang-pkgs` (application dependencies).
    #[serde(default, alias = "Class")]
    class: Option<String>,
    /// Ecosystem: `debian`, `npm`, `pip`, `cargo`, ...
    #[serde(default, alias = "Type")]
    kind: Option<String>,
    #[serde(default, alias = "Vulnerabilities")]
    vulnerabilities: Vec<TrivyVuln>,
    /// Only present with `--list-all-pkgs`; carries the lockfile `Dev` flag.
    #[serde(default, alias = "Packages")]
    packages: Vec<TrivyPackage>,
}

#[derive(Debug, Deserialize)]
struct TrivyPackage {
    #[serde(default, alias = "Name")]
    name: Option<String>,
    #[serde(default, alias = "Version")]
    version: Option<String>,
    #[serde(default, alias = "Dev")]
    dev: bool,
}

#[derive(Debug, Deserialize)]
struct TrivyVuln {
    #[serde(default, alias = "VulnerabilityID")]
    vulnerability_id: Option<String>,
    #[serde(default, alias = "PkgName")]
    pkg_name: Option<String>,
    #[serde(default, alias = "InstalledVersion")]
    installed_version: Option<String>,
    #[serde(default, alias = "Severity")]
    severity: Option<String>,
    #[serde(default, alias = "Title")]
    title: Option<String>,
    #[serde(default, alias = "Description")]
    description: Option<String>,
}

pub fn parse_trivy_json_file(json_path: &str) -> Result<Vec<Finding>> {
    let bytes = std::fs::read(json_path).with_context(|| format!("Read {}", json_path))?;
    let s = String::from_utf8(bytes).context("Trivy JSON must be valid UTF-8")?;
    parse_trivy_json_str(&s)
}

pub fn parse_trivy_json_str(json: &str) -> Result<Vec<Finding>> {
    let report: TrivyReport =
        serde_json::from_str(json).context("Trivy JSON parse error (expected Results[])")?;

    let mut out = Vec::new();
    for result in report.results {
        let target = result.target.unwrap_or_else(|| "filesystem".to_string());
        for vuln in result.vulnerabilities {
            out.push(vuln_to_finding(&target, &vuln)?);
        }
    }
    Ok(out)
}

fn vuln_to_finding(target: &str, vuln: &TrivyVuln) -> Result<Finding> {
    let cve = vuln
        .vulnerability_id
        .clone()
        .unwrap_or_else(|| "UNKNOWN-CVE".to_string());
    let title = vuln
        .title
        .clone()
        .unwrap_or_else(|| format!("{} in {}", cve, vuln.pkg_name.as_deref().unwrap_or("pkg")));
    let description = vuln.description.clone().unwrap_or_else(|| title.clone());
    let severity = map_trivy_severity(vuln.severity.as_deref());

    let url = format!("file://{}", target);
    let evidence = format!(
        "{} {}@{}",
        cve,
        vuln.pkg_name.as_deref().unwrap_or("unknown"),
        vuln.installed_version.as_deref().unwrap_or("?")
    );

    Ok(Finding::new(
        title,
        severity,
        url,
        description,
        "Upgrade the affected package or apply vendor patches.",
        "sca/trivy",
    )
    .with_parameter(cve)
    .with_source_tool("trivy")
    .with_evidence(evidence)
    .with_cwe(1395)
    .with_owasp("A06:2021 – Vulnerable and Outdated Components"))
}

fn map_trivy_severity(sev: Option<&str>) -> Severity {
    match sev.map(|s| s.trim().to_ascii_uppercase()).as_deref() {
        Some("CRITICAL") => Severity::Critical,
        Some("HIGH") => Severity::High,
        Some("MEDIUM") => Severity::Medium,
        Some("LOW") => Severity::Low,
        Some("UNKNOWN") | None => Severity::Info,
        _ => Severity::Medium,
    }
}

/// Provenance Trivy recorded for the scanned artifact (all optional).
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct TrivyArtifactMeta {
    pub artifact_name: Option<String>,
    /// First `RepoDigests` entry, else the image ID.
    pub image_digest: Option<String>,
    /// `Metadata.Commit`, else the image's `org.opencontainers.image.revision` label.
    pub revision: Option<String>,
}

/// Dependency scope of a vulnerable package: base-OS vs application vs dev tooling.
pub fn dependency_scope(class: Option<&str>, dev: bool) -> &'static str {
    match class {
        Some("os-pkgs") => "base-os",
        _ if dev => "development",
        Some("lang-pkgs") => "application",
        _ => "unknown",
    }
}

/// Parse Trivy JSON into findings under `plugin`, locating each vulnerable
/// component as `<origin>?pkg=<name>@<version>&scope=<scope>`. `parameter`
/// stays the advisory ID (as for `sca/trivy`) so callers can dedup on it.
pub fn parse_trivy_scoped(
    json: &str,
    plugin: &str,
    origin: &str,
) -> Result<(Vec<Finding>, TrivyArtifactMeta)> {
    let report: TrivyReport =
        serde_json::from_str(json).context("Trivy JSON parse error (expected Results[])")?;
    let md = &report.metadata;
    let labels = md.image_config.config.labels.as_ref();
    let meta = TrivyArtifactMeta {
        artifact_name: report.artifact_name.clone(),
        image_digest: md.repo_digests.first().or(md.image_id.as_ref()).cloned(),
        revision: md
            .commit
            .clone()
            .or_else(|| labels.and_then(|l| l.get("org.opencontainers.image.revision").cloned())),
    };

    let mut out = Vec::new();
    for result in &report.results {
        let target = result.target.as_deref().unwrap_or("filesystem");
        let dev: HashSet<(&str, &str)> = result
            .packages
            .iter()
            .filter(|p| p.dev)
            .filter_map(|p| Some((p.name.as_deref()?, p.version.as_deref()?)))
            .collect();
        for vuln in &result.vulnerabilities {
            let pkg = vuln.pkg_name.as_deref().unwrap_or("unknown");
            let ver = vuln.installed_version.as_deref().unwrap_or("?");
            let scope = dependency_scope(result.class.as_deref(), dev.contains(&(pkg, ver)));
            let mut f = vuln_to_finding(target, vuln)?;
            let cve = f.parameter.clone().unwrap_or_default();
            if !f.title.contains(&cve) {
                f.title = format!("{cve}: {}", f.title);
            }
            f.plugin = plugin.to_string();
            f.url = format!("{origin}?pkg={pkg}@{ver}&scope={scope}");
            f.evidence = Some(format!(
                "{cve} {pkg}@{ver} scope={scope} class={} type={} target={target}",
                result.class.as_deref().unwrap_or("-"),
                result.kind.as_deref().unwrap_or("-"),
            ));
            out.push(f);
        }
    }
    Ok((out, meta))
}

pub async fn run_trivy_fs(repo_path: &Path) -> Result<String> {
    let output = tokio::process::Command::new(
        crate::executable::require("trivy").map_err(|e| super::map_spawn_io(e, "trivy"))?,
    )
    .args(["fs", "--format", "json", "--quiet", "."])
    .current_dir(repo_path)
    .output()
    .await
    .map_err(|e| super::map_spawn_io(e, "trivy"))?;

    if !output.status.success() {
        anyhow::bail!(
            "Trivy exited with {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        );
    }

    Ok(String::from_utf8(output.stdout)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture(name: &str) -> String {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures")
            .join(name);
        std::fs::read_to_string(path).expect("read fixture")
    }

    #[test]
    fn parse_trivy_fixture() {
        let findings = parse_trivy_json_str(&fixture("trivy_small.json")).expect("parse");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].plugin, "sca/trivy");
        assert_eq!(findings[0].severity, Severity::High);
        assert_eq!(findings[0].parameter.as_deref(), Some("CVE-2024-1234"));
        assert_eq!(findings[0].source_tool.as_deref(), Some("trivy"));
    }
}
