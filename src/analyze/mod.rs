//! Static analysis orchestration (Phase 1–2.5) and unified `audit` command.

use std::io::{self, IsTerminal, Write};
use std::path::{Path, PathBuf};
use std::time::Instant;

use anyhow::{bail, Context, Result};

use crate::correlate::correlate_findings;
use crate::report::{Report, StaticAnalysis};
use crate::sarif;
use crate::scanner::{collect_scan, ScanConfig};
use crate::types::{summarize_modules, DiscoveredUrl, Finding, ModuleSummary};

mod gitignore;
pub mod gitleaks;
pub mod inventory;
pub mod native;
pub mod semgrep;
pub mod static_report;
pub mod trivy;

/// Static analysis tools supported by `analyze` / `audit`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AnalyzeTool {
    Semgrep,
    Trivy,
    Gitleaks,
    Native,
}

impl AnalyzeTool {
    pub fn module_id(self) -> &'static str {
        match self {
            AnalyzeTool::Semgrep => "sast/semgrep",
            AnalyzeTool::Trivy => "sca/trivy",
            AnalyzeTool::Gitleaks => "secrets/gitleaks",
            AnalyzeTool::Native => "sast/inventory",
        }
    }
}

/// Parse comma-separated tool names (`semgrep`, `trivy`, `gitleaks`, `native`).
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
            "native" => AnalyzeTool::Native,
            other => bail!(
                "Unknown analyze tool '{}'. Supported: semgrep, trivy, gitleaks, native",
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

/// Outcome of the pre-walk repo-access gate (no I/O).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RepoAccessGate {
    /// `--yes` / `-y` was passed; do not prompt.
    Granted,
    /// stdin is a TTY; the caller must prompt.
    Prompt,
}

/// Decide whether to grant, prompt, or refuse before reading a local repo.
///
/// Non-TTY sessions (CI) must pass `assume_yes` (`--yes`); attaching a terminal
/// always prompts unless `--yes` is set.
pub fn repo_access_gate(assume_yes: bool, stdin_is_tty: bool) -> Result<RepoAccessGate> {
    if assume_yes {
        return Ok(RepoAccessGate::Granted);
    }
    if !stdin_is_tty {
        bail!(
            "Non-interactive stdin requires --yes to confirm repo access \
             (e.g. `rustzap analyze --repo . --tools native --yes`)."
        );
    }
    Ok(RepoAccessGate::Prompt)
}

/// `y` / `yes` (any case, surrounding whitespace ignored) → proceed.
/// Empty, `n`, `no`, and any other reply → decline.
pub fn confirm_reply_is_yes(input: &str) -> bool {
    matches!(input.trim().to_ascii_lowercase().as_str(), "y" | "yes")
}

/// Absolute path shown in the consent prompt (`canonicalize`, then cwd join).
pub fn absolute_repo_path(repo: &Path) -> PathBuf {
    if let Ok(canon) = repo.canonicalize() {
        return canon;
    }
    if repo.is_absolute() {
        return repo.to_path_buf();
    }
    match std::env::current_dir() {
        Ok(cwd) => cwd.join(repo),
        Err(_) => repo.to_path_buf(),
    }
}

/// Ask before walking/reading `repo`. Tests should pass `assume_yes: true`.
pub fn confirm_repo_access(repo: &Path, assume_yes: bool) -> Result<()> {
    let abs = absolute_repo_path(repo);
    match repo_access_gate(assume_yes, io::stdin().is_terminal())? {
        RepoAccessGate::Granted => Ok(()),
        RepoAccessGate::Prompt => prompt_repo_access(&abs),
    }
}

fn prompt_repo_access(abs: &Path) -> Result<()> {
    println!(
        "RustZAP will read files under `{}` for static analysis",
        abs.display()
    );
    println!("(inventory, secrets/sinks heuristics, and any selected tools).");
    println!("Only analyze repositories you own or have permission to scan.");
    print!("Proceed? [y/N]: ");
    io::stdout().flush().ok();
    let mut buf = String::new();
    io::stdin()
        .read_line(&mut buf)
        .context("read repo-access confirmation")?;
    if confirm_reply_is_yes(&buf) {
        Ok(())
    } else {
        bail!("Repo access declined");
    }
}

pub struct StaticInputs {
    pub repo: PathBuf,
    pub tools: Vec<AnalyzeTool>,
    pub semgrep_json: Option<PathBuf>,
    pub trivy_json: Option<PathBuf>,
    pub gitleaks_json: Option<PathBuf>,
}

/// Findings plus optional Phase 2.5 `static{}` roll-up (when `native` ran).
pub struct StaticRunResult {
    pub findings: Vec<Finding>,
    pub static_analysis: Option<StaticAnalysis>,
}

/// Run selected static tools and return findings (+ `static{}` when native is on).
pub async fn run_static_analysis(inputs: &StaticInputs) -> Result<StaticRunResult> {
    let mut all = Vec::new();
    let mut inventory = None;
    let mut attack_plan = Vec::new();
    for tool in &inputs.tools {
        match tool {
            AnalyzeTool::Semgrep => all.extend(run_semgrep(inputs).await?),
            AnalyzeTool::Trivy => all.extend(run_trivy(inputs).await?),
            AnalyzeTool::Gitleaks => all.extend(run_gitleaks(inputs).await?),
            AnalyzeTool::Native => {
                let native = native::run(&inputs.repo)
                    .await
                    .context("Running native static analyzers")?;
                all.extend(native.findings);
                inventory = Some(native.inventory);
                attack_plan = native.attack_plan;
            }
        }
    }
    let static_analysis =
        inventory.map(|inv| static_report::build_static_analysis(inv, &all, attack_plan));
    Ok(StaticRunResult {
        findings: all,
        static_analysis,
    })
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
    let mut out = Vec::new();
    for t in tools {
        match t {
            AnalyzeTool::Native => out.extend(native::NATIVE_MODULES.iter().copied()),
            other => out.push(other.module_id()),
        }
    }
    out
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
    static_analysis: Option<StaticAnalysis>,
) -> Result<()> {
    let correlations = if correlate {
        correlate_findings(&mut findings)
    } else {
        Vec::new()
    };

    let mut report =
        Report::new(target, modules, urls, findings, elapsed).with_correlations(correlations);
    if let Some(block) = static_analysis {
        report = report.with_static(block);
    }

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
    assume_yes: bool,
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

    confirm_repo_access(&inputs.repo, assume_yes)?;

    let run = run_static_analysis(&inputs).await?;
    let modules = build_module_summaries(&run.findings, &parsed_tools, &[]);

    write_report(
        &repo,
        modules,
        vec![],
        run.findings,
        correlate,
        start.elapsed(),
        &output,
        sarif_out.as_deref(),
        run.static_analysis,
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
    assume_yes: bool,
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

    confirm_repo_access(&static_inputs.repo, assume_yes)?;

    let run = run_static_analysis(&static_inputs).await?;
    let mut findings = run.findings;
    let static_analysis = run.static_analysis;
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
        static_analysis,
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
    fn parse_tools_accepts_native() {
        let tools = parse_tools("native").expect("parse");
        assert_eq!(tools, vec![AnalyzeTool::Native]);
        let mixed = parse_tools("semgrep,native").expect("parse");
        assert!(mixed.contains(&AnalyzeTool::Native));
        assert!(mixed.contains(&AnalyzeTool::Semgrep));
    }

    #[test]
    fn confirm_reply_is_yes_accepts_y_and_yes() {
        for reply in ["y", "Y", "yes", "YES", "Yes", " y ", "\tyes\n"] {
            assert!(confirm_reply_is_yes(reply), "expected yes for {reply:?}");
        }
    }

    #[test]
    fn confirm_reply_is_yes_rejects_empty_no_and_other() {
        for reply in ["", "   ", "n", "N", "no", "NO", "No", "nope", "yeah", "1"] {
            assert!(
                !confirm_reply_is_yes(reply),
                "expected decline for {reply:?}"
            );
        }
    }

    #[test]
    fn repo_access_gate_yes_skips_prompt() {
        assert_eq!(
            repo_access_gate(true, true).unwrap(),
            RepoAccessGate::Granted
        );
        assert_eq!(
            repo_access_gate(true, false).unwrap(),
            RepoAccessGate::Granted
        );
    }

    #[test]
    fn repo_access_gate_tty_prompts() {
        assert_eq!(
            repo_access_gate(false, true).unwrap(),
            RepoAccessGate::Prompt
        );
    }

    #[test]
    fn repo_access_gate_non_tty_requires_yes() {
        let err = repo_access_gate(false, false).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("--yes"), "error should mention --yes: {msg}");
    }

    #[test]
    fn absolute_repo_path_is_absolute() {
        let p = absolute_repo_path(Path::new("."));
        assert!(p.is_absolute(), "{}", p.display());
    }

    #[tokio::test]
    async fn native_fixture_produces_plugins_and_attack_plan() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/native_app");
        let result = native::run(&root).await.expect("native scan");
        assert!(
            result.findings.iter().any(|f| f.plugin == "sast/inventory"),
            "inventory finding"
        );
        assert!(
            result
                .findings
                .iter()
                .any(|f| f.plugin == "sast/js-secrets"),
            "js secrets"
        );
        assert!(
            result.findings.iter().any(|f| f.plugin == "sast/dom-sinks"),
            "dom sinks"
        );
        assert!(
            result
                .findings
                .iter()
                .any(|f| f.plugin == "sast/js-cookies"),
            "js cookies"
        );
        assert!(
            result
                .findings
                .iter()
                .any(|f| f.plugin == "sast/js-storage"),
            "js storage"
        );
        assert!(
            result
                .findings
                .iter()
                .any(|f| f.plugin == "sast/js-postmessage"),
            "js postMessage"
        );
        assert!(
            result.findings.iter().any(|f| f.plugin == "sast/forms"),
            "forms"
        );
        assert!(
            result.findings.iter().any(|f| f.plugin == "sast/params"),
            "params"
        );
        assert!(
            !result.attack_plan.is_empty(),
            "attack_plan should be non-empty"
        );
        assert!(result
            .inventory
            .languages
            .iter()
            .any(|l| l == "JavaScript" || l == "Python" || l == "HTML"));
        let plugins: Vec<&str> = result.findings.iter().map(|f| f.plugin.as_str()).collect();
        let mut sorted = plugins.clone();
        sorted.sort_unstable();
        assert_eq!(
            plugins, sorted,
            "native findings should be sorted by plugin"
        );
        let st = static_report::build_static_analysis(
            result.inventory,
            &result.findings,
            result.attack_plan,
        );
        assert!(st.detection_checks.iter().any(|c| c.triggered));
        assert!(st
            .detection_checks
            .iter()
            .any(|c| c.id == "js-cookies" && c.triggered));
        assert!(st
            .detection_checks
            .iter()
            .any(|c| c.id == "js-storage" && c.triggered));
        assert!(st
            .detection_checks
            .iter()
            .any(|c| c.id == "js-postmessage" && c.triggered));
        assert!(st.risk_score > 0);
    }

    #[tokio::test]
    async fn analyze_native_writes_static_block() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/native_app");
        let out = std::env::temp_dir().join(format!("rustzap-native-{}.json", uuid()));
        run_analyze_cli(
            root.to_string_lossy().to_string(),
            "native".to_string(),
            None,
            None,
            None,
            false,
            out.to_string_lossy().to_string(),
            None,
            true,
        )
        .await
        .expect("analyze native");

        let json = std::fs::read_to_string(&out).expect("read report");
        assert!(json.contains("\"static\""));
        assert!(json.contains("attack_plan"));
        assert!(json.contains("sast/js-secrets"));
        assert!(json.contains("sast/forms"));
        let _ = std::fs::remove_file(out);
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
            true,
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
