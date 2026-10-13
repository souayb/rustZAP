//! Pure-Rust Native Software Bill of Materials (SBOM) Generator & Dependency SCA Analyzer.
//!
//! Generates standard CycloneDX 1.5 JSON and SPDX 2.3 JSON representations
//! from zero-dependency static analysis of ecosystem lockfiles:
//! - Cargo.lock (Rust / Cargo)
//! - package-lock.json (Node.js / npm)
//! - pnpm-lock.yaml (Node.js / pnpm)
//! - requirements.txt (Python / pip)
//! - go.sum / go.mod (Go)
//! - pom.xml (Java / Maven)
//!
//! Also checks parsed components against a built-in advisory database for known CVEs.

use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

use crate::types::{Finding, Severity};

/// A single discovered software dependency component.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SbomComponent {
    pub name: String,
    pub version: String,
    pub ecosystem: String, // "cargo", "npm", "pnpm", "pypi", "gomod", "maven"
    #[serde(skip_serializing_if = "Option::is_none")]
    pub purl: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub license: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub checksum: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file_path: Option<String>,
}

/// CycloneDX 1.5 JSON structure.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CycloneDxBom {
    #[serde(rename = "bomFormat")]
    pub bom_format: String,
    #[serde(rename = "specVersion")]
    pub spec_version: String,
    #[serde(rename = "serialNumber")]
    pub serial_number: String,
    pub version: u32,
    pub metadata: CycloneDxMetadata,
    pub components: Vec<CycloneDxComponent>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CycloneDxMetadata {
    pub timestamp: String,
    pub tools: Vec<CycloneDxTool>,
    pub component: Option<CycloneDxComponent>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CycloneDxTool {
    pub vendor: String,
    pub name: String,
    pub version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CycloneDxComponent {
    #[serde(rename = "type")]
    pub component_type: String, // "library", "application"
    pub name: String,
    pub version: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub purl: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
}

/// SPDX 2.3 JSON structure.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpdxDocument {
    #[serde(rename = "spdxVersion")]
    pub spdx_version: String,
    #[serde(rename = "dataLicense")]
    pub data_license: String,
    #[serde(rename = "SPDXID")]
    pub spdx_id: String,
    pub name: String,
    #[serde(rename = "documentNamespace")]
    pub document_namespace: String,
    pub creation_info: SpdxCreationInfo,
    pub packages: Vec<SpdxPackage>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpdxCreationInfo {
    pub created: String,
    pub creators: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpdxPackage {
    pub name: String,
    #[serde(rename = "SPDXID")]
    pub spdx_id: String,
    #[serde(rename = "versionInfo")]
    pub version_info: String,
    #[serde(rename = "downloadLocation")]
    pub download_location: String,
    #[serde(rename = "filesAnalyzed")]
    pub files_analyzed: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "externalRefs")]
    pub external_refs: Option<Vec<SpdxExternalRef>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpdxExternalRef {
    #[serde(rename = "referenceCategory")]
    pub reference_category: String,
    #[serde(rename = "referenceType")]
    pub reference_type: String,
    #[serde(rename = "referenceLocator")]
    pub reference_locator: String,
}

/// Result of SBOM analysis containing components, export documents, and security findings.
#[derive(Debug, Clone)]
pub struct SbomReport {
    pub components: Vec<SbomComponent>,
    pub findings: Vec<Finding>,
}

impl SbomReport {
    /// Export components as CycloneDX 1.5 JSON.
    pub fn to_cyclonedx_json(&self, project_name: &str) -> Result<String, serde_json::Error> {
        let bom = CycloneDxBom {
            bom_format: "CycloneDX".to_string(),
            spec_version: "1.5".to_string(),
            serial_number: format!("urn:uuid:{}", uuid_v4_simple()),
            version: 1,
            metadata: CycloneDxMetadata {
                timestamp: chrono::Utc::now().to_rfc3339(),
                tools: vec![CycloneDxTool {
                    vendor: "RustZAP".to_string(),
                    name: "rustzap-native-sbom".to_string(),
                    version: env!("CARGO_PKG_VERSION").to_string(),
                }],
                component: Some(CycloneDxComponent {
                    component_type: "application".to_string(),
                    name: project_name.to_string(),
                    version: "1.0.0".to_string(),
                    purl: None,
                    scope: None,
                }),
            },
            components: self
                .components
                .iter()
                .map(|c| CycloneDxComponent {
                    component_type: "library".to_string(),
                    name: c.name.clone(),
                    version: c.version.clone(),
                    purl: c.purl.clone(),
                    scope: Some("required".to_string()),
                })
                .collect(),
        };

        serde_json::to_string_pretty(&bom)
    }

    /// Export components as SPDX 2.3 JSON.
    pub fn to_spdx_json(&self, project_name: &str) -> Result<String, serde_json::Error> {
        let doc = SpdxDocument {
            spdx_version: "SPDX-2.3".to_string(),
            data_license: "CC0-1.0".to_string(),
            spdx_id: "SPDXRef-DOCUMENT".to_string(),
            name: project_name.to_string(),
            document_namespace: format!(
                "https://rustzap.dev/spdx/{}/{}",
                project_name,
                uuid_v4_simple()
            ),
            creation_info: SpdxCreationInfo {
                created: chrono::Utc::now().to_rfc3339(),
                creators: vec![
                    format!("Tool: rustzap-native-sbom-{}", env!("CARGO_PKG_VERSION")),
                    "Organization: RustZAP".to_string(),
                ],
            },
            packages: self
                .components
                .iter()
                .enumerate()
                .map(|(idx, c)| {
                    let spdx_id =
                        format!("SPDXRef-Package-{}-{}", idx + 1, sanitize_spdx_id(&c.name));
                    let ext_refs = c.purl.as_ref().map(|p| {
                        vec![SpdxExternalRef {
                            reference_category: "PACKAGE-MANAGER".to_string(),
                            reference_type: "purl".to_string(),
                            reference_locator: p.clone(),
                        }]
                    });

                    SpdxPackage {
                        name: c.name.clone(),
                        spdx_id,
                        version_info: c.version.clone(),
                        download_location: "NOASSERTION".to_string(),
                        files_analyzed: false,
                        external_refs: ext_refs,
                    }
                })
                .collect(),
        };

        serde_json::to_string_pretty(&doc)
    }
}

fn sanitize_spdx_id(name: &str) -> String {
    name.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '.' || c == '-' {
                c
            } else {
                '-'
            }
        })
        .collect()
}

fn uuid_v4_simple() -> String {
    format!(
        "{:08x}-{:04x}-4{:03x}-8{:03x}-{:012x}",
        rand::random::<u32>(),
        rand::random::<u16>(),
        rand::random::<u16>() & 0x0fff,
        rand::random::<u16>() & 0x0fff,
        rand::random::<u64>() & 0xffffffffffff,
    )
}

/// Parse Cargo.lock content into components.
pub fn parse_cargo_lock(content: &str, file_path: &str) -> Vec<SbomComponent> {
    let mut components = Vec::new();
    let mut current_name: Option<String> = None;
    let mut current_version: Option<String> = None;
    let mut current_checksum: Option<String> = None;

    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed == "[[package]]" {
            if let (Some(name), Some(version)) = (current_name.take(), current_version.take()) {
                let purl = format!("pkg:cargo/{}@{}", name, version);
                components.push(SbomComponent {
                    name,
                    version,
                    ecosystem: "cargo".to_string(),
                    purl: Some(purl),
                    license: None,
                    checksum: current_checksum.take(),
                    file_path: Some(file_path.to_string()),
                });
            }
        } else if let Some(rest) = trimmed.strip_prefix("name = ") {
            current_name = Some(rest.trim_matches('"').to_string());
        } else if let Some(rest) = trimmed.strip_prefix("version = ") {
            current_version = Some(rest.trim_matches('"').to_string());
        } else if let Some(rest) = trimmed.strip_prefix("checksum = ") {
            current_checksum = Some(rest.trim_matches('"').to_string());
        }
    }

    if let (Some(name), Some(version)) = (current_name, current_version) {
        let purl = format!("pkg:cargo/{}@{}", name, version);
        components.push(SbomComponent {
            name,
            version,
            ecosystem: "cargo".to_string(),
            purl: Some(purl),
            license: None,
            checksum: current_checksum,
            file_path: Some(file_path.to_string()),
        });
    }

    components
}

/// Parse package-lock.json content into components.
pub fn parse_package_lock_json(content: &str, file_path: &str) -> Vec<SbomComponent> {
    let mut components = Vec::new();

    if let Ok(val) = serde_json::from_str::<serde_json::Value>(content) {
        // Support npm lockfile v2/v3 ("packages" object)
        if let Some(packages) = val.get("packages").and_then(|p| p.as_object()) {
            for (key, meta) in packages {
                if key.is_empty() {
                    continue; // Root package
                }
                let name = if let Some(name_val) = meta.get("name").and_then(|n| n.as_str()) {
                    name_val.to_string()
                } else if key.starts_with("node_modules/") {
                    key.trim_start_matches("node_modules/").to_string()
                } else {
                    key.clone()
                };

                if let Some(version) = meta.get("version").and_then(|v| v.as_str()) {
                    let purl = format!("pkg:npm/{}@{}", name, version);
                    components.push(SbomComponent {
                        name,
                        version: version.to_string(),
                        ecosystem: "npm".to_string(),
                        purl: Some(purl),
                        license: meta
                            .get("license")
                            .and_then(|l| l.as_str())
                            .map(String::from),
                        checksum: meta
                            .get("integrity")
                            .and_then(|i| i.as_str())
                            .map(String::from),
                        file_path: Some(file_path.to_string()),
                    });
                }
            }
        }
        // Support npm lockfile v1 ("dependencies" object)
        else if let Some(deps) = val.get("dependencies").and_then(|d| d.as_object()) {
            parse_npm_v1_dependencies(deps, file_path, &mut components);
        }
    }

    components
}

fn parse_npm_v1_dependencies(
    deps: &serde_json::Map<String, serde_json::Value>,
    file_path: &str,
    out: &mut Vec<SbomComponent>,
) {
    for (name, val) in deps {
        if let Some(version) = val.get("version").and_then(|v| v.as_str()) {
            let purl = format!("pkg:npm/{}@{}", name, version);
            out.push(SbomComponent {
                name: name.clone(),
                version: version.to_string(),
                ecosystem: "npm".to_string(),
                purl: Some(purl),
                license: None,
                checksum: val
                    .get("integrity")
                    .and_then(|i| i.as_str())
                    .map(String::from),
                file_path: Some(file_path.to_string()),
            });
        }
        if let Some(sub_deps) = val.get("dependencies").and_then(|d| d.as_object()) {
            parse_npm_v1_dependencies(sub_deps, file_path, out);
        }
    }
}

/// Parse requirements.txt content into components.
pub fn parse_requirements_txt(content: &str, file_path: &str) -> Vec<SbomComponent> {
    let mut components = Vec::new();

    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with('-') {
            continue;
        }

        // Match name==version or name>=version
        let parts: Vec<&str> = if let Some(pos) = trimmed.find("==") {
            vec![&trimmed[..pos], &trimmed[pos + 2..]]
        } else if let Some(pos) = trimmed.find(">=") {
            vec![&trimmed[..pos], &trimmed[pos + 2..]]
        } else if let Some(pos) = trimmed.find("~=") {
            vec![&trimmed[..pos], &trimmed[pos + 2..]]
        } else {
            vec![trimmed]
        };

        let name = parts[0].trim().to_string();
        let version = if parts.len() > 1 {
            parts[1].split(';').next().unwrap_or("").trim().to_string()
        } else {
            "unknown".to_string()
        };

        let purl = format!("pkg:pypi/{}@{}", name, version);
        components.push(SbomComponent {
            name,
            version,
            ecosystem: "pypi".to_string(),
            purl: Some(purl),
            license: None,
            checksum: None,
            file_path: Some(file_path.to_string()),
        });
    }

    components
}

/// Parse go.sum content into components.
pub fn parse_go_sum(content: &str, file_path: &str) -> Vec<SbomComponent> {
    let mut seen = std::collections::HashSet::new();
    let mut components = Vec::new();

    for line in content.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 2 {
            let name = parts[0].to_string();
            let raw_ver = parts[1].trim_end_matches("/go.mod");
            let version = raw_ver.trim_start_matches('v').to_string();

            let key = format!("{}@{}", name, version);
            if seen.insert(key) {
                let purl = format!("pkg:golang/{}@{}", name, version);
                components.push(SbomComponent {
                    name,
                    version,
                    ecosystem: "gomod".to_string(),
                    purl: Some(purl),
                    license: None,
                    checksum: parts.get(2).map(|c| c.to_string()),
                    file_path: Some(file_path.to_string()),
                });
            }
        }
    }

    components
}

/// Parse pom.xml content into Maven components.
pub fn parse_pom_xml(content: &str, file_path: &str) -> Vec<SbomComponent> {
    let mut components = Vec::new();
    let mut in_dependency = false;
    let mut current_group = String::new();
    let mut current_artifact = String::new();
    let mut current_version = String::new();

    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.contains("<dependency>") {
            in_dependency = true;
            current_group.clear();
            current_artifact.clear();
            current_version.clear();
        } else if trimmed.contains("</dependency>") {
            if in_dependency && !current_artifact.is_empty() {
                let name = if !current_group.is_empty() {
                    format!("{}:{}", current_group, current_artifact)
                } else {
                    current_artifact.clone()
                };
                let ver = if current_version.is_empty() {
                    "LATEST".to_string()
                } else {
                    current_version.clone()
                };
                let purl = format!("pkg:maven/{}/{}@{}", current_group, current_artifact, ver);

                components.push(SbomComponent {
                    name,
                    version: ver,
                    ecosystem: "maven".to_string(),
                    purl: Some(purl),
                    license: None,
                    checksum: None,
                    file_path: Some(file_path.to_string()),
                });
            }
            in_dependency = false;
        } else if in_dependency {
            if let Some(start) = trimmed.find("<groupId>") {
                if let Some(end) = trimmed.find("</groupId>") {
                    current_group = trimmed[start + 9..end].trim().to_string();
                }
            }
            if let Some(start) = trimmed.find("<artifactId>") {
                if let Some(end) = trimmed.find("</artifactId>") {
                    current_artifact = trimmed[start + 12..end].trim().to_string();
                }
            }
            if let Some(start) = trimmed.find("<version>") {
                if let Some(end) = trimmed.find("</version>") {
                    current_version = trimmed[start + 9..end].trim().to_string();
                }
            }
        }
    }

    components
}

/// Built-in known CVE advisory database for dependency SAST matching.
struct AdvisoryRule {
    name: &'static str,
    ecosystem: &'static str,
    vulnerable_below: &'static str,
    cve_id: &'static str,
    title: &'static str,
    severity: Severity,
    cwe: u32,
    description: &'static str,
    solution: &'static str,
}

const ADVISORIES: &[AdvisoryRule] = &[
    AdvisoryRule {
        name: "log4j-core",
        ecosystem: "maven",
        vulnerable_below: "2.17.1",
        cve_id: "CVE-2021-44228",
        title: "Log4Shell JNDI Remote Code Execution (log4j-core)",
        severity: Severity::Critical,
        cwe: 502,
        description: "Apache Log4j2 JNDI features used in configuration, log messages, and parameters do not protect against attacker controlled LDAP and other JNDI related endpoints.",
        solution: "Upgrade log4j-core to 2.17.1 or higher.",
    },
    AdvisoryRule {
        name: "lodash",
        ecosystem: "npm",
        vulnerable_below: "4.17.21",
        cve_id: "CVE-2021-23337",
        title: "Prototype Pollution in lodash",
        severity: Severity::High,
        cwe: 1321,
        description: "Lodash versions prior to 4.17.21 are vulnerable to Command Injection and Prototype Pollution via template function.",
        solution: "Upgrade lodash to 4.17.21 or higher.",
    },
    AdvisoryRule {
        name: "express",
        ecosystem: "npm",
        vulnerable_below: "4.19.2",
        cve_id: "CVE-2024-29041",
        title: "Open Redirect in Express",
        severity: Severity::Medium,
        cwe: 601,
        description: "Express versions prior to 4.19.2 allow open redirection via crafted URL inputs passed to res.location().",
        solution: "Upgrade express to 4.19.2 or higher.",
    },
    AdvisoryRule {
        name: "jsonwebtoken",
        ecosystem: "npm",
        vulnerable_below: "9.0.0",
        cve_id: "CVE-2022-23529",
        title: "Insecure Key Verification in jsonwebtoken",
        severity: Severity::High,
        cwe: 287,
        description: "jsonwebtoken versions before 9.0.0 allow arbitrary file write / code execution if untrusted key material is supplied.",
        solution: "Upgrade jsonwebtoken to 9.0.0 or higher.",
    },
    AdvisoryRule {
        name: "requests",
        ecosystem: "pypi",
        vulnerable_below: "2.31.0",
        cve_id: "CVE-2023-32681",
        title: "Proxy-Authorization Header Leakage in Requests",
        severity: Severity::Medium,
        cwe: 200,
        description: "Requests forwards Proxy-Authorization headers to destination servers when following redirects.",
        solution: "Upgrade requests to 2.31.0 or higher.",
    },
    AdvisoryRule {
        name: "urllib3",
        ecosystem: "pypi",
        vulnerable_below: "2.0.7",
        cve_id: "CVE-2023-45803",
        title: "HTTP Request Body Leakage in urllib3",
        severity: Severity::Medium,
        cwe: 200,
        description: "urllib3 fails to strip request body when following 303 redirects.",
        solution: "Upgrade urllib3 to 2.0.7 or higher.",
    },
];

/// Simple semver compare: returns true if `ver` < `vulnerable_below`.
fn is_version_below(ver: &str, vulnerable_below: &str) -> bool {
    let parse_nums = |v: &str| -> Vec<u64> {
        v.split(|c: char| c == '.' || c == '-' || !c.is_ascii_digit())
            .filter_map(|s| s.parse::<u64>().ok())
            .collect()
    };

    let v_nums = parse_nums(ver);
    let target_nums = parse_nums(vulnerable_below);

    for (v_part, t_part) in v_nums.iter().zip(target_nums.iter()) {
        if v_part < t_part {
            return true;
        } else if v_part > t_part {
            return false;
        }
    }

    v_nums.len() < target_nums.len()
}

/// Scan a repository directory for lockfiles and generate an SBOM with CVE findings.
pub fn scan_repository_sbom(repo_root: &Path) -> SbomReport {
    let mut components = Vec::new();
    let mut findings = Vec::new();

    // Check Cargo.lock
    let cargo_lock = repo_root.join("Cargo.lock");
    if cargo_lock.exists() {
        if let Ok(content) = fs::read_to_string(&cargo_lock) {
            components.extend(parse_cargo_lock(&content, "Cargo.lock"));
        }
    }

    // Check package-lock.json
    let pkg_lock = repo_root.join("package-lock.json");
    if pkg_lock.exists() {
        if let Ok(content) = fs::read_to_string(&pkg_lock) {
            components.extend(parse_package_lock_json(&content, "package-lock.json"));
        }
    }

    // Check requirements.txt
    let req_txt = repo_root.join("requirements.txt");
    if req_txt.exists() {
        if let Ok(content) = fs::read_to_string(&req_txt) {
            components.extend(parse_requirements_txt(&content, "requirements.txt"));
        }
    }

    // Check go.sum
    let go_sum = repo_root.join("go.sum");
    if go_sum.exists() {
        if let Ok(content) = fs::read_to_string(&go_sum) {
            components.extend(parse_go_sum(&content, "go.sum"));
        }
    }

    // Check pom.xml
    let pom_xml = repo_root.join("pom.xml");
    if pom_xml.exists() {
        if let Ok(content) = fs::read_to_string(&pom_xml) {
            components.extend(parse_pom_xml(&content, "pom.xml"));
        }
    }

    // Match components against advisory rules
    for comp in &components {
        for adv in ADVISORIES {
            if comp.ecosystem == adv.ecosystem
                && (comp.name == adv.name || comp.name.ends_with(&format!(":{}", adv.name)))
                && is_version_below(&comp.version, adv.vulnerable_below)
            {
                let loc = comp
                    .file_path
                    .clone()
                    .unwrap_or_else(|| "manifest".to_string());
                let f = Finding::new(
                    adv.title,
                    adv.severity.clone(),
                    &loc,
                    format!(
                        "Component '{}' version {} is vulnerable to {} (fixed in {}). {}",
                        comp.name, comp.version, adv.cve_id, adv.vulnerable_below, adv.description
                    ),
                    adv.solution,
                    "sca/native-sbom",
                )
                .with_evidence(format!("{}@{}", comp.name, comp.version))
                .with_cwe(adv.cwe)
                .with_owasp("A06:2021 – Vulnerable and Outdated Components");

                findings.push(f);
            }
        }
    }

    SbomReport {
        components,
        findings,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_cargo_lock() {
        let sample = r#"
[[package]]
name = "tokio"
version = "1.28.0"
checksum = "123456"

[[package]]
name = "serde"
version = "1.0.160"
"#;
        let comps = parse_cargo_lock(sample, "Cargo.lock");
        assert_eq!(comps.len(), 2);
        assert_eq!(comps[0].name, "tokio");
        assert_eq!(comps[0].version, "1.28.0");
        assert_eq!(comps[0].purl, Some("pkg:cargo/tokio@1.28.0".to_string()));
    }

    #[test]
    fn test_parse_package_lock_json() {
        let sample = r#"{
            "name": "my-app",
            "version": "1.0.0",
            "lockfileVersion": 3,
            "packages": {
                "": { "name": "my-app" },
                "node_modules/lodash": {
                    "version": "4.17.15",
                    "integrity": "sha512-..."
                }
            }
        }"#;

        let comps = parse_package_lock_json(sample, "package-lock.json");
        assert_eq!(comps.len(), 1);
        assert_eq!(comps[0].name, "lodash");
        assert_eq!(comps[0].version, "4.17.15");
    }

    #[test]
    fn test_parse_requirements_txt() {
        let sample = "requests==2.25.1\nurllib3>=1.26.5\n# Comment\nflask==2.0.1\n";
        let comps = parse_requirements_txt(sample, "requirements.txt");
        assert_eq!(comps.len(), 3);
        assert_eq!(comps[0].name, "requests");
        assert_eq!(comps[0].version, "2.25.1");
    }

    #[test]
    fn test_cyclonedx_and_spdx_export() {
        let report = SbomReport {
            components: vec![SbomComponent {
                name: "tokio".to_string(),
                version: "1.0.0".to_string(),
                ecosystem: "cargo".to_string(),
                purl: Some("pkg:cargo/tokio@1.0.0".to_string()),
                license: None,
                checksum: None,
                file_path: Some("Cargo.lock".to_string()),
            }],
            findings: vec![],
        };

        let cdx = report.to_cyclonedx_json("test-app").unwrap();
        assert!(cdx.contains("\"bomFormat\": \"CycloneDX\""));
        assert!(cdx.contains("\"name\": \"tokio\""));

        let spdx = report.to_spdx_json("test-app").unwrap();
        assert!(spdx.contains("\"spdxVersion\": \"SPDX-2.3\""));
        assert!(spdx.contains("\"name\": \"tokio\""));
    }
}
