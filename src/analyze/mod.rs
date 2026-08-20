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

pub mod checkov;
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
    Checkov,
}

impl AnalyzeTool {
    pub fn module_id(self) -> &'static str {
        match self {
            AnalyzeTool::Semgrep => "sast/semgrep",
            AnalyzeTool::Trivy => "sca/trivy",
            AnalyzeTool::Gitleaks => "secrets/gitleaks",
            AnalyzeTool::Native => "sast/inventory",
            AnalyzeTool::Checkov => "iac/checkov",
        }
    }
}

/// Parse comma-separated tool names (`semgrep`, `trivy`, `gitleaks`, `native`, `checkov`).
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
            "checkov" | "iac" => AnalyzeTool::Checkov,
            other => bail!(
                "Unknown analyze tool '{}'. Supported: semgrep, trivy, gitleaks, native, checkov",
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

/// Default `--tools` for `analyze` when the flag is omitted.
pub const DEFAULT_ANALYZE_TOOLS: &str = "semgrep";
/// Default `--tools` for `audit` when the flag is omitted.
pub const DEFAULT_AUDIT_TOOLS: &str = "semgrep,trivy,gitleaks";

/// Spawn failed because the tool binary was not on PATH (`ENOENT`).
#[derive(Debug, thiserror::Error)]
#[error("{tool} not found on PATH")]
pub struct MissingToolBinary {
    pub tool: &'static str,
}

/// Map a `Command::output` I/O error into `MissingToolBinary` when the binary is absent.
pub fn map_spawn_io(err: std::io::Error, tool: &'static str) -> anyhow::Error {
    if err.kind() == std::io::ErrorKind::NotFound {
        anyhow::Error::new(MissingToolBinary { tool })
    } else {
        anyhow::Error::new(err).context(format!("Failed to spawn {tool}"))
    }
}

/// If `err` (or any cause) is a missing analyze-tool binary, return that tool name.
pub fn missing_tool_from_error(err: &anyhow::Error) -> Option<&'static str> {
    for cause in err.chain() {
        if let Some(missing) = cause.downcast_ref::<MissingToolBinary>() {
            return Some(missing.tool);
        }
    }
    None
}

/// What to do when an external tool binary is missing (`ENOENT`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MissingBinaryAction {
    /// Skip this tool and continue with the remaining tools.
    Skip,
    /// Default toolset (user did not pass `--tools`); run native analyzers instead.
    FallbackNative,
    /// User explicitly requested this tool (only); abort with a helpful message.
    Fail,
}

/// Decide skip / native fallback / fail for a missing external binary.
///
/// `selected_count` is the original `--tools` list length (before injecting native).
pub fn missing_binary_action(selected_count: usize, tools_explicit: bool) -> MissingBinaryAction {
    if selected_count <= 1 {
        if tools_explicit {
            MissingBinaryAction::Fail
        } else {
            MissingBinaryAction::FallbackNative
        }
    } else {
        MissingBinaryAction::Skip
    }
}

pub fn missing_binary_fail_message(tool: &str) -> String {
    format!(
        "{tool} not found on PATH. Install it (e.g. `rustzap install --tool {tool}`) \
         or run `rustzap analyze REPO --tools native`."
    )
}

fn warn_missing_skip(tool: &str) {
    eprintln!("{tool} not found on PATH; skipping.");
}

fn warn_fallback_native(tool: &str) {
    eprintln!(
        "{tool} not found; running native analyzers. Pass --tools native to skip this warning."
    );
}

/// Trim a typed/CLI path; empty input means the current directory.
pub fn normalize_repo_input(input: &str) -> String {
    let t = input.trim();
    if t.is_empty() {
        ".".to_string()
    } else {
        t.to_string()
    }
}

/// Positional `REPO` overrides `--repo`. Empty strings are treated as omitted.
pub fn resolve_repo_spec(positional: Option<String>, repo_flag: Option<String>) -> Option<String> {
    fn cleaned(s: Option<String>) -> Option<String> {
        s.map(|v| v.trim().to_string()).filter(|v| !v.is_empty())
    }
    cleaned(positional).or_else(|| cleaned(repo_flag))
}

/// How to obtain a repo path when neither positional nor `--repo` was given.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnspecifiedRepoAction {
    /// Non-TTY CI with `--yes`: analyze `.`
    UseDot,
    /// TTY: prompt `Repository path [.] :`
    Prompt,
}

pub fn unspecified_repo_action(
    assume_yes: bool,
    stdin_is_tty: bool,
) -> Result<UnspecifiedRepoAction> {
    if stdin_is_tty {
        return Ok(UnspecifiedRepoAction::Prompt);
    }
    if assume_yes {
        return Ok(UnspecifiedRepoAction::UseDot);
    }
    bail!(
        "Provide a repository path as a positional argument or --repo, \
         or pass --yes to analyze the current directory in CI."
    );
}

fn prompt_repo_path() -> Result<String> {
    print!("Repository path [.] : ");
    io::stdout().flush().ok();
    let mut buf = String::new();
    io::stdin()
        .read_line(&mut buf)
        .context("read repository path")?;
    Ok(normalize_repo_input(&buf))
}

/// Resolve the repo path for `analyze` / `audit`. Positional overrides `--repo`.
pub fn resolve_repo_path(
    positional: Option<String>,
    repo_flag: Option<String>,
    assume_yes: bool,
) -> Result<String> {
    if let Some(p) = resolve_repo_spec(positional, repo_flag) {
        return Ok(p);
    }
    match unspecified_repo_action(assume_yes, io::stdin().is_terminal())? {
        UnspecifiedRepoAction::UseDot => Ok(".".to_string()),
        UnspecifiedRepoAction::Prompt => prompt_repo_path(),
    }
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
             (e.g. `rustzap analyze . --tools native --yes`)."
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
    /// True when the user passed `--tools` (no native fallback for a missing default Semgrep).
    pub tools_explicit: bool,
    pub semgrep_json: Option<PathBuf>,
    pub trivy_json: Option<PathBuf>,
    pub gitleaks_json: Option<PathBuf>,
    pub checkov_json: Option<PathBuf>,
}

/// Findings plus optional Phase 2.5 `static{}` roll-up (when `native` ran).
pub struct StaticRunResult {
    pub findings: Vec<Finding>,
    pub static_analysis: Option<StaticAnalysis>,
    /// Tools that actually executed (skipped missing binaries are omitted).
    pub tools_ran: Vec<AnalyzeTool>,
}

/// Run selected static tools and return findings (+ `static{}` when native is on).
pub async fn run_static_analysis(inputs: &StaticInputs) -> Result<StaticRunResult> {
    let selected_count = inputs.tools.len();
    let mut queue = inputs.tools.clone();
    let mut all = Vec::new();
    let mut inventory = None;
    let mut attack_plan = Vec::new();
    let mut tools_ran = Vec::new();
    let mut idx = 0;

    while idx < queue.len() {
        let tool = queue[idx];
        idx += 1;
        match run_one_static_tool(tool, inputs).await {
            Ok(ToolChunk::Findings(findings)) => {
                all.extend(findings);
                push_ran(&mut tools_ran, tool);
            }
            Ok(ToolChunk::Native(native)) => {
                all.extend(native.findings);
                inventory = Some(native.inventory);
                attack_plan = native.attack_plan;
                push_ran(&mut tools_ran, AnalyzeTool::Native);
            }
            Err(err) => {
                if let Some(name) = missing_tool_from_error(&err) {
                    match missing_binary_action(selected_count, inputs.tools_explicit) {
                        MissingBinaryAction::Skip => warn_missing_skip(name),
                        MissingBinaryAction::FallbackNative => {
                            warn_fallback_native(name);
                            if !queue.contains(&AnalyzeTool::Native) {
                                queue.push(AnalyzeTool::Native);
                            }
                        }
                        MissingBinaryAction::Fail => {
                            bail!("{}", missing_binary_fail_message(name));
                        }
                    }
                } else {
                    return Err(err);
                }
            }
        }
    }

    if tools_ran.is_empty() {
        if inputs.tools_explicit {
            bail!(
                "None of the selected tools could be run (binaries not found on PATH). \
                 Install them or pass --tools native."
            );
        }
        warn_fallback_native("semgrep");
        let native = native::run(&inputs.repo)
            .await
            .context("Running native static analyzers")?;
        all.extend(native.findings);
        inventory = Some(native.inventory);
        attack_plan = native.attack_plan;
        push_ran(&mut tools_ran, AnalyzeTool::Native);
    }

    let static_analysis =
        inventory.map(|inv| static_report::build_static_analysis(inv, &all, attack_plan));
    Ok(StaticRunResult {
        findings: all,
        static_analysis,
        tools_ran,
    })
}

enum ToolChunk {
    Findings(Vec<Finding>),
    Native(native::NativeScanResult),
}

fn push_ran(tools_ran: &mut Vec<AnalyzeTool>, tool: AnalyzeTool) {
    if !tools_ran.contains(&tool) {
        tools_ran.push(tool);
    }
}

async fn run_one_static_tool(tool: AnalyzeTool, inputs: &StaticInputs) -> Result<ToolChunk> {
    match tool {
        AnalyzeTool::Semgrep => Ok(ToolChunk::Findings(run_semgrep(inputs).await?)),
        AnalyzeTool::Trivy => Ok(ToolChunk::Findings(run_trivy(inputs).await?)),
        AnalyzeTool::Gitleaks => Ok(ToolChunk::Findings(run_gitleaks(inputs).await?)),
        AnalyzeTool::Checkov => Ok(ToolChunk::Findings(run_checkov_tool(inputs).await?)),
        AnalyzeTool::Native => {
            let native = native::run(&inputs.repo)
                .await
                .context("Running native static analyzers")?;
            Ok(ToolChunk::Native(native))
        }
    }
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

async fn run_checkov_tool(inputs: &StaticInputs) -> Result<Vec<Finding>> {
    if let Some(path) = &inputs.checkov_json {
        return checkov::parse_checkov_json_file(&path.to_string_lossy(), &inputs.repo)
            .with_context(|| format!("Parsing Checkov JSON: {}", path.display()));
    }
    let json = checkov::run_checkov(&inputs.repo)
        .await
        .context("Running Checkov failed")?;
    checkov::parse_checkov_json_str(&json, &inputs.repo).context("Parsing Checkov stdout JSON")
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
) -> Result<Report> {
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

    Ok(report)
}

/// Run static analysis, write the report, and return it.
///
/// TUI callers must show a consent dialog first, then pass `assume_yes: true`
/// (never skip the dialog). CLI uses stdin `Proceed? [y/N]` unless `--yes`.
#[allow(clippy::too_many_arguments)]
pub async fn run_analyze(
    repo: String,
    tools: String,
    semgrep_json: Option<String>,
    trivy_json: Option<String>,
    gitleaks_json: Option<String>,
    checkov_json: Option<String>,
    correlate: bool,
    output: String,
    sarif_out: Option<String>,
    assume_yes: bool,
    tools_explicit: bool,
) -> Result<Report> {
    let start = Instant::now();
    let parsed_tools = parse_tools(&tools)?;
    let repo_path = absolute_repo_path(Path::new(&repo));
    let inputs = StaticInputs {
        repo: repo_path.clone(),
        tools: parsed_tools,
        tools_explicit,
        semgrep_json: semgrep_json.map(PathBuf::from),
        trivy_json: trivy_json.map(PathBuf::from),
        gitleaks_json: gitleaks_json.map(PathBuf::from),
        checkov_json: checkov_json.map(PathBuf::from),
    };

    confirm_repo_access(&inputs.repo, assume_yes)?;

    let run = run_static_analysis(&inputs).await?;
    let modules = build_module_summaries(&run.findings, &run.tools_ran, &[]);
    let target = repo_path.to_string_lossy().to_string();

    write_report(
        &target,
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
pub async fn run_analyze_cli(
    repo: String,
    tools: String,
    semgrep_json: Option<String>,
    trivy_json: Option<String>,
    gitleaks_json: Option<String>,
    checkov_json: Option<String>,
    correlate: bool,
    output: String,
    sarif_out: Option<String>,
    assume_yes: bool,
    tools_explicit: bool,
) -> Result<()> {
    run_analyze(
        repo,
        tools,
        semgrep_json,
        trivy_json,
        gitleaks_json,
        checkov_json,
        correlate,
        output,
        sarif_out,
        assume_yes,
        tools_explicit,
    )
    .await
    .map(|_| ())
}

#[allow(clippy::too_many_arguments)]
pub async fn run_audit_cli(
    repo: String,
    target: Option<String>,
    tools: String,
    semgrep_json: Option<String>,
    trivy_json: Option<String>,
    gitleaks_json: Option<String>,
    checkov_json: Option<String>,
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
    tools_explicit: bool,
) -> Result<()> {
    let start = Instant::now();
    let parsed_tools = parse_tools(&tools)?;
    let repo_path = absolute_repo_path(Path::new(&repo));

    let static_inputs = StaticInputs {
        repo: repo_path.clone(),
        tools: parsed_tools,
        tools_explicit,
        semgrep_json: semgrep_json.map(PathBuf::from),
        trivy_json: trivy_json.map(PathBuf::from),
        gitleaks_json: gitleaks_json.map(PathBuf::from),
        checkov_json: checkov_json.map(PathBuf::from),
    };

    confirm_repo_access(&static_inputs.repo, assume_yes)?;

    let run = run_static_analysis(&static_inputs).await?;
    let mut findings = run.findings;
    let static_analysis = run.static_analysis;
    let tools_ran = run.tools_ran;
    let mut urls = Vec::new();
    let mut dast_modules = Vec::new();

    let report_target = target
        .clone()
        .unwrap_or_else(|| repo_path.to_string_lossy().to_string());

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

    let modules = build_module_summaries(&findings, &tools_ran, &dast_modules);

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
    .map(|_| ())
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
    fn parse_tools_accepts_checkov_and_iac_alias() {
        let tools = parse_tools("checkov").expect("parse");
        assert_eq!(tools, vec![AnalyzeTool::Checkov]);
        let aliased = parse_tools("iac").expect("parse");
        assert_eq!(aliased, vec![AnalyzeTool::Checkov]);
        let mixed = parse_tools("semgrep,checkov").expect("parse");
        assert!(mixed.contains(&AnalyzeTool::Checkov));
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

    #[test]
    fn positional_overrides_repo_flag() {
        assert_eq!(
            resolve_repo_spec(Some("/from/pos".into()), Some("/from/flag".into())).as_deref(),
            Some("/from/pos")
        );
    }

    #[test]
    fn repo_flag_used_when_no_positional() {
        assert_eq!(
            resolve_repo_spec(None, Some("/from/flag".into())).as_deref(),
            Some("/from/flag")
        );
    }

    #[test]
    fn empty_positional_falls_through_to_repo_flag() {
        assert_eq!(
            resolve_repo_spec(Some("  ".into()), Some("/from/flag".into())).as_deref(),
            Some("/from/flag")
        );
    }

    #[test]
    fn neither_path_arg_is_unspecified() {
        assert!(resolve_repo_spec(None, None).is_none());
        assert!(resolve_repo_spec(Some(String::new()), Some("   ".into())).is_none());
    }

    #[test]
    fn empty_path_prompt_defaults_to_dot() {
        assert_eq!(normalize_repo_input(""), ".");
        assert_eq!(normalize_repo_input("  \n"), ".");
        assert_eq!(normalize_repo_input(" ~/src/app "), "~/src/app");
    }

    #[test]
    fn unspecified_repo_tty_prompts() {
        assert_eq!(
            unspecified_repo_action(false, true).unwrap(),
            UnspecifiedRepoAction::Prompt
        );
        assert_eq!(
            unspecified_repo_action(true, true).unwrap(),
            UnspecifiedRepoAction::Prompt
        );
    }

    #[test]
    fn unspecified_repo_non_tty_yes_uses_dot() {
        assert_eq!(
            unspecified_repo_action(true, false).unwrap(),
            UnspecifiedRepoAction::UseDot
        );
    }

    #[test]
    fn unspecified_repo_non_tty_without_yes_errors() {
        let err = unspecified_repo_action(false, false).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("--repo"), "should mention --repo: {msg}");
        assert!(msg.contains("--yes"), "should mention --yes: {msg}");
    }

    #[test]
    fn map_spawn_io_not_found_is_missing_tool() {
        let err = map_spawn_io(
            std::io::Error::new(std::io::ErrorKind::NotFound, "No such file or directory"),
            "semgrep",
        );
        assert_eq!(missing_tool_from_error(&err), Some("semgrep"));
        let wrapped = err.context("Running Semgrep failed");
        assert_eq!(missing_tool_from_error(&wrapped), Some("semgrep"));
    }

    #[test]
    fn map_spawn_io_permission_denied_is_not_missing_tool() {
        let err = map_spawn_io(
            std::io::Error::new(std::io::ErrorKind::PermissionDenied, "nope"),
            "semgrep",
        );
        assert!(missing_tool_from_error(&err).is_none());
    }

    #[test]
    fn json_file_not_found_is_not_missing_tool_binary() {
        let err = semgrep::parse_semgrep_json_file(
            "/no/such/rustzap-semgrep-fixture.json",
            Path::new("/repo"),
        )
        .unwrap_err();
        assert!(
            missing_tool_from_error(&err).is_none(),
            "JSON read ENOENT must not be classified as a missing tool binary"
        );
    }

    #[test]
    fn missing_binary_default_single_falls_back_to_native() {
        assert_eq!(
            missing_binary_action(1, false),
            MissingBinaryAction::FallbackNative
        );
    }

    #[test]
    fn missing_binary_explicit_single_fails() {
        assert_eq!(missing_binary_action(1, true), MissingBinaryAction::Fail);
        let msg = missing_binary_fail_message("semgrep");
        assert!(msg.contains("--tools native"), "{msg}");
        assert!(msg.contains("rustzap install --tool semgrep"), "{msg}");
    }

    #[test]
    fn missing_binary_multi_skips() {
        assert_eq!(missing_binary_action(3, false), MissingBinaryAction::Skip);
        assert_eq!(missing_binary_action(2, true), MissingBinaryAction::Skip);
    }

    #[tokio::test]
    async fn spawn_of_missing_binary_is_classified() {
        let io_err = tokio::process::Command::new("rustzap-definitely-not-installed-semgrep")
            .output()
            .await
            .expect_err("binary must not exist");
        assert_eq!(io_err.kind(), std::io::ErrorKind::NotFound);
        let err = map_spawn_io(io_err, "semgrep");
        assert_eq!(missing_tool_from_error(&err), Some("semgrep"));
    }

    fn path_has_binary(name: &str) -> bool {
        let Some(paths) = std::env::var_os("PATH") else {
            return false;
        };
        std::env::split_paths(&paths)
            .any(|dir| dir.join(name).is_file() || dir.join(format!("{name}.exe")).is_file())
    }

    #[tokio::test]
    async fn default_semgrep_falls_back_to_native_when_binary_missing() {
        if path_has_binary("semgrep") {
            return;
        }
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/native_app");
        let run = run_static_analysis(&StaticInputs {
            repo: root,
            tools: vec![AnalyzeTool::Semgrep],
            tools_explicit: false,
            semgrep_json: None,
            trivy_json: None,
            gitleaks_json: None,
            checkov_json: None,
        })
        .await
        .expect("native fallback");
        assert!(run.tools_ran.contains(&AnalyzeTool::Native));
        assert!(!run.tools_ran.contains(&AnalyzeTool::Semgrep));
        assert!(run.static_analysis.is_some());
    }

    #[tokio::test]
    async fn explicit_semgrep_only_fails_helpfully_when_binary_missing() {
        if path_has_binary("semgrep") {
            return;
        }
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/native_app");
        let err = match run_static_analysis(&StaticInputs {
            repo: root,
            tools: vec![AnalyzeTool::Semgrep],
            tools_explicit: true,
            semgrep_json: None,
            trivy_json: None,
            gitleaks_json: None,
            checkov_json: None,
        })
        .await
        {
            Ok(_) => panic!("explicit missing semgrep should fail"),
            Err(e) => e,
        };
        let msg = err.to_string();
        assert!(msg.contains("--tools native"), "{msg}");
        assert!(msg.contains("semgrep"), "{msg}");
    }

    #[tokio::test]
    async fn skips_missing_semgrep_and_continues_other_tools() {
        if path_has_binary("semgrep") {
            return;
        }
        let root = Path::new(env!("CARGO_MANIFEST_DIR"));
        let run = run_static_analysis(&StaticInputs {
            repo: root.to_path_buf(),
            tools: vec![AnalyzeTool::Semgrep, AnalyzeTool::Checkov],
            tools_explicit: true,
            semgrep_json: None,
            trivy_json: None,
            gitleaks_json: None,
            checkov_json: Some(root.join("tests/fixtures/checkov_small.json")),
        })
        .await
        .expect("skip semgrep, keep checkov");
        assert!(!run.tools_ran.contains(&AnalyzeTool::Semgrep));
        assert!(run.tools_ran.contains(&AnalyzeTool::Checkov));
        assert_eq!(run.findings.len(), 2);
        assert!(run.findings.iter().all(|f| f.plugin == "iac/checkov"));
    }

    #[tokio::test]
    async fn explicit_all_missing_tools_fail() {
        if path_has_binary("semgrep") || path_has_binary("trivy") {
            return;
        }
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/native_app");
        let err = match run_static_analysis(&StaticInputs {
            repo: root,
            tools: vec![AnalyzeTool::Semgrep, AnalyzeTool::Trivy],
            tools_explicit: true,
            semgrep_json: None,
            trivy_json: None,
            gitleaks_json: None,
            checkov_json: None,
        })
        .await
        {
            Ok(_) => panic!("all missing explicit tools should fail"),
            Err(e) => e,
        };
        let msg = err.to_string();
        assert!(
            msg.contains("None of the selected tools") || msg.contains("not found"),
            "{msg}"
        );
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
            None,
            false,
            out.to_string_lossy().to_string(),
            None,
            true,
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
    fn golden_checkov_fixture_produces_two_findings() {
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/checkov_small.json");
        let findings = checkov::parse_checkov_json_file(path.to_str().unwrap(), Path::new("/repo"))
            .expect("parse fixture");
        assert_eq!(findings.len(), 2);
        assert!(findings.iter().all(|f| f.plugin == "iac/checkov"));
        assert!(findings
            .iter()
            .any(|f| f.parameter.as_deref() == Some("CKV_AWS_20")));
    }

    #[tokio::test]
    async fn run_static_analysis_checkov_fixture_via_parse_tools() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"));
        let tools = parse_tools("checkov").expect("parse");
        assert_eq!(tools, vec![AnalyzeTool::Checkov]);
        assert_eq!(AnalyzeTool::Checkov.module_id(), "iac/checkov");
        let run = run_static_analysis(&StaticInputs {
            repo: root.to_path_buf(),
            tools,
            tools_explicit: true,
            semgrep_json: None,
            trivy_json: None,
            gitleaks_json: None,
            checkov_json: Some(root.join("tests/fixtures/checkov_small.json")),
        })
        .await
        .expect("checkov fixture");
        assert_eq!(run.findings.len(), 2);
        assert!(run.findings.iter().all(|f| f.plugin == "iac/checkov"));
        assert!(run
            .findings
            .iter()
            .all(|f| f.source_tool.as_deref() == Some("checkov")));
        let modules = build_module_summaries(&run.findings, &[AnalyzeTool::Checkov], &[]);
        assert!(modules.iter().any(|m| m.name == "iac/checkov" && !m.quiet));
    }

    #[tokio::test]
    async fn native_plus_checkov_feeds_risk_breakdown_iac() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"));
        let run = run_static_analysis(&StaticInputs {
            repo: root.join("tests/fixtures/native_app"),
            tools: parse_tools("native,checkov").unwrap(),
            tools_explicit: true,
            semgrep_json: None,
            trivy_json: None,
            gitleaks_json: None,
            checkov_json: Some(root.join("tests/fixtures/checkov_small.json")),
        })
        .await
        .expect("native+checkov");
        let st = run.static_analysis.expect("static{}");
        assert!(st.risk_breakdown.iac > 0);
        assert!(run.findings.iter().any(|f| f.plugin == "iac/checkov"));
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
            None,
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
