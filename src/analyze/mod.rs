//! Static analysis orchestration (Phase 1–2) and unified `audit` command.

use std::path::PathBuf;
use std::time::Instant;

use anyhow::{bail, Context, Result};

use crate::correlate::correlate_findings;
use crate::report::Report;
use crate::sarif;
use crate::scanner::{collect_scan, ScanConfig};
use crate::types::{summarize_modules, DiscoveredUrl, Finding, ModuleSummary};

pub mod gitleaks;
pub mod semgrep;
pub mod trivy;

/// Static analysis tools supported by `analyze` / `audit`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AnalyzeTool {
    Semgrep,
    Trivy,
    Gitleaks,
}

impl AnalyzeTool {
    pub fn module_id(self) -> &'static str {
        match self {
            AnalyzeTool::Semgrep => "sast/semgrep",
            AnalyzeTool::Trivy => "sca/trivy",
            AnalyzeTool::Gitleaks => "secrets/gitleaks",
        }
    }
}

/// Parse comma-separated tool names (`semgrep`, `trivy`, `gitleaks`).
pub fn parse_tools(spec: &str) -> Result<Vec<AnalyzeTool>> {
    let mut out = Vec::new();
    for part in spec.split(',') {
        let name = part.trim().to_ascii_lowercase();
        if name.is_empty() {
            continue;
        }
        let tool = match name.as_str() {
            "semgrep" | "sast" => AnalyzeTool::Semgrep,
            "trivy" | "sca" => AnalyzeTool::Trivy,
            "gitleaks" | "secrets" => AnalyzeTool::Gitleaks,
            other => bail!(
                "Unknown analyze tool '{}'. Supported: semgrep, trivy, gitleaks",
                other
            ),
        };
        if !out.contains(&tool) {
            out.push(tool);
        }
    }
    if out.is_empty() {
        bail!("No analyze tools selected");
    }
    Ok(out)
}

pub struct StaticInputs {
    pub repo: PathBuf,
    pub tools: Vec<AnalyzeTool>,
    pub semgrep_json: Option<PathBuf>,
    pub trivy_json: Option<PathBuf>,
    pub gitleaks_json: Option<PathBuf>,
}

/// Run selected static tools and return findings.
pub async fn run_static_analysis(inputs: &StaticInputs) -> Result<Vec<Finding>> {
    let mut all = Vec::new();
    for tool in &inputs.tools {
        let chunk = match tool {
            AnalyzeTool::Semgrep => run_semgrep(inputs).await?,
            AnalyzeTool::Trivy => run_trivy(inputs).await?,
            AnalyzeTool::Gitleaks => run_gitleaks(inputs).await?,
        };
        all.extend(chunk);
    }
    Ok(all)
}

async fn run_semgrep(inputs: &StaticInputs) -> Result<Vec<Finding>> {
    if let Some(path) = &inputs.semgrep_json {
        return semgrep::parse_semgrep_json_file(&path.to_string_lossy(), &inputs.repo)
            .with_context(|| format!("Parsing Semgrep JSON: {}", path.display()));
    }
    let json = semgrep::run_semgrep_scan(&inputs.repo)
        .await
        .context("Running Semgrep failed")?;
    semgrep::parse_semgrep_json_str(&json, &inputs.repo).context("Parsing Semgrep stdout JSON")
}

async fn run_trivy(inputs: &StaticInputs) -> Result<Vec<Finding>> {
    if let Some(path) = &inputs.trivy_json {
        return trivy::parse_trivy_json_file(&path.to_string_lossy())
            .with_context(|| format!("Parsing Trivy JSON: {}", path.display()));
    }
    let json = trivy::run_trivy_fs(&inputs.repo)
        .await
        .context("Running Trivy failed")?;
    trivy::parse_trivy_json_str(&json).context("Parsing Trivy stdout JSON")
}

async fn run_gitleaks(inputs: &StaticInputs) -> Result<Vec<Finding>> {
    if let Some(path) = &inputs.gitleaks_json {
        return gitleaks::parse_gitleaks_json_file(&path.to_string_lossy(), &inputs.repo)
            .with_context(|| format!("Parsing Gitleaks JSON: {}", path.display()));
    }
    let json = gitleaks::run_gitleaks(&inputs.repo)
        .await
        .context("Running Gitleaks failed")?;
    gitleaks::parse_gitleaks_json_str(&json, &inputs.repo).context("Parsing Gitleaks JSON")
}

pub fn static_known_modules(tools: &[AnalyzeTool]) -> Vec<&'static str> {
    tools.iter().map(|t| t.module_id()).collect()
}

/// Build module summaries for static + optional DAST findings.
pub fn build_module_summaries(
    findings: &[Finding],
    static_tools: &[AnalyzeTool],
    dast_modules: &[ModuleSummary],
) -> Vec<ModuleSummary> {
    let mut known: Vec<&str> = static_known_modules(static_tools);
    for m in dast_modules {
        known.push(m.name.as_str());
    }
    summarize_modules(findings, &known)
}

#[allow(clippy::too_many_arguments)]
pub async fn write_report(
    target: &str,
    modules: Vec<ModuleSummary>,
    urls: Vec<DiscoveredUrl>,
    mut findings: Vec<Finding>,
    correlate: bool,
    elapsed: std::time::Duration,
    output: &str,
    sarif_out: Option<&str>,
) -> Result<()> {
    let correlations = if correlate {
        correlate_findings(&mut findings)
    } else {
        Vec::new()
    };

    let report =
        Report::new(target, modules, urls, findings, elapsed).with_correlations(correlations);

    if output.ends_with(".csv") {
        report.save_csv(output).await?;
    } else if output.ends_with(".html") {
        report.save_html(output).await?;
    } else {
        report.save_json(output).await?;
    }

    if let Some(sarif_path) = sarif_out {
        sarif::write_sarif(&report, sarif_path)?;
    }

    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub async fn run_analyze_cli(
    repo: String,
    tools: String,
    semgrep_json: Option<String>,
    trivy_json: Option<String>,
    gitleaks_json: Option<String>,
    correlate: bool,
    output: String,
    sarif_out: Option<String>,
) -> Result<()> {
    let start = Instant::now();
    let parsed_tools = parse_tools(&tools)?;
    let inputs = StaticInputs {
        repo: PathBuf::from(&repo),
        tools: parsed_tools.clone(),
        semgrep_json: semgrep_json.map(PathBuf::from),
        trivy_json: trivy_json.map(PathBuf::from),
        gitleaks_json: gitleaks_json.map(PathBuf::from),
    };

    let findings = run_static_analysis(&inputs).await?;
    let modules = build_module_summaries(&findings, &parsed_tools, &[]);

    write_report(
        &repo,
        modules,
        vec![],
        findings,
        correlate,
        start.elapsed(),
        &output,
        sarif_out.as_deref(),
    )
    .await
}

#[allow(clippy::too_many_arguments)]
pub async fn run_audit_cli(
    repo: String,
    target: Option<String>,
    tools: String,
    semgrep_json: Option<String>,
    trivy_json: Option<String>,
    gitleaks_json: Option<String>,
    correlate: bool,
    output: String,
    sarif_out: Option<String>,
    passive_only: bool,
    depth: usize,
    concurrency: usize,
    plugins: String,
    timeout: u64,
    insecure: bool,
) -> Result<()> {
    let start = Instant::now();
    let parsed_tools = parse_tools(&tools)?;

    let static_inputs = StaticInputs {
        repo: PathBuf::from(&repo),
        tools: parsed_tools.clone(),
        semgrep_json: semgrep_json.map(PathBuf::from),
        trivy_json: trivy_json.map(PathBuf::from),
        gitleaks_json: gitleaks_json.map(PathBuf::from),
    };

    let mut findings = run_static_analysis(&static_inputs).await?;
    let mut urls = Vec::new();
    let mut dast_modules = Vec::new();

    let report_target = target.clone().unwrap_or_else(|| repo.clone());

    if let Some(url) = target {
        let scan_config = ScanConfig {
            target_url: url.clone(),
            max_depth: depth,
            concurrency,
            passive_only,
            output_file: output.clone(),
            sarif_out: None,
            timeout_secs: timeout,
            user_agent: None,
            cookies: None,
            auth_header: None,
            api_key: None,
            basic_auth: None,
            insecure,
            plugins: plugins.split(',').map(|s| s.trim().to_string()).collect(),
            openapi_path: None,
            openapi_url: None,
            har_path: None,
            nuclei: false,
            nuclei_jsonl: None,
        };
        let collected = collect_scan(scan_config).await?;
        findings.extend(collected.findings);
        urls = collected.discovered;
        dast_modules = collected.modules;
    }

    let modules = build_module_summaries(&findings, &parsed_tools, &dast_modules);

    write_report(
        &report_target,
        modules,
        urls,
        findings,
        correlate,
        start.elapsed(),
        &output,
        sarif_out.as_deref(),
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::Severity;
    use std::path::Path;

    #[test]
    fn parse_tools_accepts_aliases() {
        let tools = parse_tools("semgrep,trivy,gitleaks").expect("parse");
        assert_eq!(tools.len(), 3);
    }

    #[test]
    fn golden_semgrep_fixture_produces_two_findings() {
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/semgrep_small.json");
        let findings = semgrep::parse_semgrep_json_file(path.to_str().unwrap(), Path::new("/repo"))
            .expect("parse fixture");
        assert_eq!(findings.len(), 2);
        assert!(findings.iter().all(|f| f.plugin == "sast/semgrep"));
        assert!(findings
            .iter()
            .any(|f| f.parameter.as_deref()
                == Some("python.lang.security.audit.formatted-sql-query")));
    }

    #[test]
    fn build_module_summaries_includes_quiet_static_modules() {
        let tools = vec![AnalyzeTool::Semgrep, AnalyzeTool::Trivy];
        let modules = build_module_summaries(&[], &tools, &[]);
        assert_eq!(modules.len(), 2);
        assert!(modules.iter().all(|m| m.quiet));
    }

    #[test]
    fn correlate_flag_wires_through_write_report() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let mut findings = vec![
                Finding::new(
                    "SQLi",
                    Severity::High,
                    "file:///repo/api.py",
                    "sql",
                    "fix",
                    "sast/semgrep",
                )
                .with_parameter("python.sql.injection"),
                Finding::new(
                    "SQLi",
                    Severity::High,
                    "https://x.example.com/api.py?q=1",
                    "d",
                    "s",
                    "active/sqli-error",
                ),
            ];
            findings[0].location = Some(crate::types::CodeLocation {
                file: "/repo/api.py".to_string(),
                line_start: 1,
                line_end: None,
            });

            let tmp = std::env::temp_dir().join(format!("rustzap-audit-{}.json", uuid()));
            write_report(
                "audit-test",
                vec![],
                vec![],
                findings,
                true,
                std::time::Duration::from_secs(0),
                tmp.to_str().unwrap(),
                None,
            )
            .await
            .expect("write");

            let json = std::fs::read_to_string(&tmp).expect("read");
            assert!(json.contains("\"correlations\""));
            let _ = std::fs::remove_file(tmp);
        });
    }

    #[tokio::test]
    async fn audit_merges_static_fixtures_without_dast() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"));
        let out = std::env::temp_dir().join(format!("rustzap-audit-static-{}.json", uuid()));
        run_audit_cli(
            root.to_string_lossy().to_string(),
            None,
            "semgrep,trivy,gitleaks".to_string(),
            Some(
                root.join("tests/fixtures/semgrep_small.json")
                    .to_string_lossy()
                    .to_string(),
            ),
            Some(
                root.join("tests/fixtures/trivy_small.json")
                    .to_string_lossy()
                    .to_string(),
            ),
            Some(
                root.join("tests/fixtures/gitleaks_small.json")
                    .to_string_lossy()
                    .to_string(),
            ),
            false,
            out.to_string_lossy().to_string(),
            None,
            true,
            1,
            4,
            "all".to_string(),
            30,
            false,
        )
        .await
        .expect("audit static");

        let json = std::fs::read_to_string(&out).expect("read report");
        assert!(json.contains("\"sast/semgrep\""));
        assert!(json.contains("\"sca/trivy\""));
        assert!(json.contains("\"secrets/gitleaks\""));
        let _ = std::fs::remove_file(out);
    }

    fn uuid() -> String {
        crate::types::uuid_v4()
    }
}
