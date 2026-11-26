//! Anchore Grype directory scan JSON → RustZAP findings.

use std::path::Path;

use anyhow::{Context, Result};
use serde::Deserialize;

use crate::types::{Finding, Severity};

#[derive(Debug, Deserialize)]
struct GrypeReport {
    #[serde(default)]
    matches: Vec<GrypeMatch>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct GrypeMatch {
    vulnerability: GrypeVuln,
    #[serde(default)]
    related_vulnerabilities: Vec<GrypeVuln>,
    artifact: GrypeArtifact,
}

#[derive(Debug, Deserialize)]
struct GrypeVuln {
    #[serde(default)]
    id: Option<String>,
    #[serde(default)]
    severity: Option<String>,
    #[serde(default)]
    description: Option<String>,
    #[serde(default)]
    fix: Option<GrypeFix>,
}

#[derive(Debug, Deserialize)]
struct GrypeFix {
    #[serde(default)]
    versions: Vec<String>,
    #[serde(default)]
    state: Option<String>,
}

#[derive(Debug, Deserialize)]
struct GrypeArtifact {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    version: Option<String>,
    #[serde(default, rename = "type")]
    kind: Option<String>,
    #[serde(default)]
    locations: Vec<GrypeLocation>,
}

#[derive(Debug, Deserialize)]
struct GrypeLocation {
    #[serde(default)]
    path: Option<String>,
}

pub fn parse_grype_json_file(json_path: &str) -> Result<Vec<Finding>> {
    let bytes = std::fs::read(json_path).with_context(|| format!("Read {}", json_path))?;
    let s = String::from_utf8(bytes).context("Grype JSON must be valid UTF-8")?;
    parse_grype_json_str(&s)
}

pub fn parse_grype_json_str(json: &str) -> Result<Vec<Finding>> {
    let report: GrypeReport =
        serde_json::from_str(json).context("Grype JSON parse error (expected matches[])")?;
    Ok(report.matches.iter().map(match_to_finding).collect())
}

fn match_to_finding(m: &GrypeMatch) -> Finding {
    let vuln = &m.vulnerability;
    let id = vuln.id.clone().unwrap_or_else(|| "UNKNOWN-CVE".to_string());
    let pkg = m.artifact.name.as_deref().unwrap_or("unknown");
    let version = m.artifact.version.as_deref().unwrap_or("?");
    let title = format!("{} in {}", id, pkg);
    // GHSA entries often carry the prose only on the related CVE.
    let description = vuln
        .description
        .clone()
        .or_else(|| {
            m.related_vulnerabilities
                .iter()
                .find_map(|r| r.description.clone())
        })
        .unwrap_or_else(|| title.clone());
    let target = m
        .artifact
        .locations
        .iter()
        .find_map(|l| l.path.as_deref())
        .map(|p| p.trim_start_matches('/'))
        .filter(|p| !p.is_empty())
        .unwrap_or("filesystem");

    let fixed: Vec<&str> = vuln
        .fix
        .as_ref()
        .filter(|f| f.state.as_deref() == Some("fixed"))
        .map(|f| f.versions.iter().map(String::as_str).collect())
        .unwrap_or_default();
    let solution = if fixed.is_empty() {
        "No fixed version published yet; apply vendor mitigations or replace the package."
            .to_string()
    } else {
        format!("Upgrade {} to {}.", pkg, fixed.join(" or "))
    };

    // Evidence starts with "<id> <pkg>@<version>" like Trivy so overlaps can be matched.
    let mut evidence = format!("{} {}@{}", id, pkg, version);
    if let Some(kind) = &m.artifact.kind {
        evidence.push_str(&format!(" ({kind})"));
    }
    let related: Vec<&str> = m
        .related_vulnerabilities
        .iter()
        .filter_map(|r| r.id.as_deref())
        .filter(|r| *r != id)
        .collect();
    if !related.is_empty() {
        evidence.push_str(&format!(" related: {}", related.join(", ")));
    }

    Finding::new(
        title,
        map_grype_severity(vuln.severity.as_deref()),
        format!("file://{}", target),
        description,
        solution,
        "sca/grype",
    )
    .with_parameter(id)
    .with_source_tool("grype")
    .with_evidence(evidence)
    .with_cwe(1395)
    .with_owasp("A06:2021 – Vulnerable and Outdated Components")
}

fn map_grype_severity(sev: Option<&str>) -> Severity {
    match sev.map(|s| s.trim().to_ascii_uppercase()).as_deref() {
        Some("CRITICAL") => Severity::Critical,
        Some("HIGH") => Severity::High,
        Some("MEDIUM") => Severity::Medium,
        Some("LOW") => Severity::Low,
        Some("NEGLIGIBLE") | Some("UNKNOWN") | None => Severity::Info,
        _ => Severity::Medium,
    }
}

/// `(advisory ids, package name)` parsed from an SCA evidence string
/// (`"<id> <pkg>@<ver> … related: A, B"`).
fn sca_key(f: &Finding) -> Option<(Vec<&str>, &str)> {
    let ev = f.evidence.as_deref()?;
    let mut parts = ev.split_whitespace();
    let id = parts.next()?;
    let pkg = parts.next()?.rsplit_once('@')?.0;
    let mut ids = vec![id];
    if let Some((_, rel)) = ev.split_once(" related: ") {
        ids.extend(rel.split(", ").map(str::trim));
    }
    Some((ids, pkg))
}

/// Drop Grype findings that Trivy already reported (same advisory — directly or
/// via `relatedVulnerabilities` — for the same package) and note Grype on the
/// kept Trivy finding's evidence.
pub fn merge_trivy_overlap(findings: &mut Vec<Finding>) {
    let mut drop = vec![false; findings.len()];
    let mut notes: Vec<(usize, String)> = Vec::new();
    for (gi, g) in findings.iter().enumerate() {
        if g.plugin != "sca/grype" {
            continue;
        }
        let Some((gids, gpkg)) = sca_key(g) else {
            continue;
        };
        let hit = findings.iter().position(|t| {
            t.plugin == "sca/trivy"
                && sca_key(t).is_some_and(|(tids, tpkg)| tpkg == gpkg && gids.contains(&tids[0]))
        });
        if let Some(ti) = hit {
            drop[gi] = true;
            notes.push((ti, gids[0].to_string()));
        }
    }
    for (ti, gid) in notes {
        if let Some(ev) = findings[ti].evidence.as_mut() {
            ev.push_str(&format!(" [also reported by grype as {gid}]"));
        }
    }
    let mut i = 0;
    findings.retain(|_| {
        i += 1;
        !drop[i - 1]
    });
}

pub async fn run_grype_dir(repo_path: &Path) -> Result<String> {
    let output = tokio::process::Command::new(
        crate::executable::require("grype").map_err(|e| super::map_spawn_io(e, "grype"))?,
    )
    .args(["dir:.", "-o", "json", "--quiet"])
    .env("GRYPE_CHECK_FOR_APP_UPDATE", "false")
    .current_dir(repo_path)
    .output()
    .await
    .map_err(|e| super::map_spawn_io(e, "grype"))?;

    if !output.status.success() {
        anyhow::bail!(
            "Grype exited with {}: {}",
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
    fn parse_grype_fixture() {
        let findings = parse_grype_json_str(&fixture("grype_small.json")).expect("parse");
        assert_eq!(findings.len(), 3);
        assert!(findings.iter().all(|f| f.plugin == "sca/grype"
            && f.source_tool.as_deref() == Some("grype")
            && f.cwe == Some(1395)));

        let fixed = &findings[0];
        assert_eq!(fixed.parameter.as_deref(), Some("GHSA-35jh-r3h4-6jhm"));
        assert_eq!(fixed.severity, Severity::High);
        assert_eq!(fixed.url, "file://package-lock.json");
        assert!(fixed.solution.contains("4.17.21"), "{}", fixed.solution);
        assert!(fixed.description.contains("Command injection"));

        let unfixed = &findings[1];
        assert_eq!(unfixed.severity, Severity::Info, "Negligible → Info");
        assert!(unfixed.solution.starts_with("No fixed version"));

        let overlap = &findings[2];
        assert_eq!(overlap.parameter.as_deref(), Some("GHSA-xxxx-openssl"));
        assert!(overlap
            .evidence
            .as_deref()
            .unwrap()
            .contains("related: CVE-2024-1234"));
    }

    #[test]
    fn rejects_non_grype_json() {
        assert!(parse_grype_json_str("[1,2]").is_err());
        assert!(parse_grype_json_str("{}").unwrap().is_empty());
    }

    #[test]
    fn merges_same_advisory_and_package_with_trivy() {
        let mut all = crate::analyze::trivy::parse_trivy_json_str(&fixture("trivy_small.json"))
            .expect("trivy");
        all.extend(parse_grype_json_str(&fixture("grype_small.json")).expect("grype"));
        // A same-advisory finding for a different package must survive.
        let mut other_pkg = all[1].clone();
        other_pkg.evidence = Some("CVE-2024-1234 libssl@1.0".into());
        other_pkg.plugin = "sca/grype".into();
        all.push(other_pkg);

        merge_trivy_overlap(&mut all);
        assert_eq!(all.len(), 4, "only the openssl overlap is dropped");
        assert_eq!(all.iter().filter(|f| f.plugin == "sca/trivy").count(), 1);
        let trivy = all.iter().find(|f| f.plugin == "sca/trivy").unwrap();
        assert!(trivy
            .evidence
            .as_deref()
            .unwrap()
            .ends_with("[also reported by grype as GHSA-xxxx-openssl]"));
        assert!(!all
            .iter()
            .any(|f| f.parameter.as_deref() == Some("GHSA-xxxx-openssl")));
    }
}
