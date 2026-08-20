//! Agentic tester — orchestrator loop (observe → plan → act → verify).
//!
//! An `AgentBrain` chooses tool calls; the loop enforces the scope file's
//! autonomy/approval rules, executes tools from the shared registry, accumulates
//! findings + the attack-plan frontier, and finally assembles a `Report`. It
//! never runs without a scope file. See `IMPLEMENTATION_PLAN.md` Phase 5.

pub mod brain;
pub mod privacy;
pub mod scope;
pub mod shield;
pub mod tools;
pub mod trace;

use std::io::{self, IsTerminal, Write};
use std::path::Path;
use std::sync::Arc;
use std::time::Instant;

use anyhow::{Context, Result};
use serde_json::json;

use crate::agent::brain::{
    AgentAction, AgentBrain, AgentState, LlmBrain, ScriptedBrain, TranscriptEntry,
};
use crate::agent::scope::{ActionClass, Autonomy, ScopeConfig};
use crate::agent::tools::ToolCtx;
use crate::agent::trace::Trace;
use crate::report::{Report, StaticAnalysis};
use crate::types::{self, DiscoveredUrl, Finding};

/// Everything a run needs (after scope is loaded and the brain is chosen).
pub struct AgentConfig {
    pub scope: ScopeConfig,
    pub goal: String,
    pub target: Option<String>,
    pub repo: Option<String>,
    pub output: String,
    pub sarif_out: Option<String>,
    pub trace_path: String,
    /// CI / headless: approvals are auto-denied instead of prompting.
    pub non_interactive: bool,
}

/// Drive the agent loop to completion and write the report.
pub async fn run_agent(cfg: AgentConfig, mut brain: Box<dyn AgentBrain>) -> Result<Report> {
    let start = Instant::now();
    // Clone into the Arc so `cfg` stays whole (the approval gate borrows it).
    let scope = Arc::new(cfg.scope.clone());
    let trace = Arc::new(Trace::new(&cfg.trace_path));
    trace.note(
        "start",
        format!(
            "autonomy={:?} target={:?} repo={:?}",
            scope_autonomy(&scope),
            cfg.target,
            cfg.repo
        ),
    );
    let ctx = ToolCtx::new(Arc::clone(&scope), Arc::clone(&trace))?;

    let mut state = AgentState {
        goal: cfg.goal.clone(),
        target: cfg.target.clone(),
        repo: cfg.repo.clone(),
        turn: 0,
        transcript: Vec::new(),
        findings_count: 0,
        attack_plan: Vec::new(),
    };

    let mut all_findings: Vec<Finding> = Vec::new();
    let mut all_discovered: Vec<DiscoveredUrl> = Vec::new();
    let mut static_analysis: Option<StaticAnalysis> = None;
    let max_turns = scope.budget.max_turns.max(1);
    // Loop guard: weaker models re-issue the same tool call instead of finishing.
    let mut last_sig: Option<String> = None;
    let mut repeats: u32 = 0;

    while state.turn < max_turns {
        let action = brain.next_action(&state).await?;
        match action {
            AgentAction::Finish { summary } => {
                trace.note("finish", summary);
                break;
            }
            AgentAction::CallTool { tool, args } => {
                // Detect a repeated identical call: nudge the brain, and bail out
                // if it keeps looping — the result would not change.
                let sig = format!("{tool}|{args}");
                if last_sig.as_deref() == Some(sig.as_str()) {
                    repeats += 1;
                    trace.note("repeat_call", tool.clone());
                    if repeats >= 2 {
                        trace.note("loop_guard", "stopping after repeated identical tool calls");
                        break;
                    }
                    state.transcript.push(TranscriptEntry {
                        tool,
                        result: json!({"note": "You already ran this exact call; its result is unchanged. Call a DIFFERENT tool or reply {\"finish\": ...}."}),
                    });
                    state.turn += 1;
                    continue;
                }
                last_sig = Some(sig);
                repeats = 0;

                let class = tools::action_class_of(&tool);
                if scope.requires_approval(class) && !approve(&cfg, &tool, class) {
                    trace.note("approval_denied", tool.clone());
                    state.transcript.push(TranscriptEntry {
                        tool,
                        result: json!({"error": "approval denied"}),
                    });
                    state.turn += 1;
                    continue;
                }
                match tools::execute(&tool, &args, &ctx).await {
                    Ok(out) => {
                        let tools::ToolOutput {
                            value,
                            findings,
                            discovered,
                            attack_plan,
                            static_analysis: sa,
                        } = out;
                        all_findings.extend(findings);
                        all_discovered.extend(discovered);
                        if !attack_plan.is_empty() {
                            state.attack_plan = attack_plan;
                        }
                        if sa.is_some() {
                            static_analysis = sa;
                        }
                        state.findings_count = all_findings.len();
                        // Tool output is attacker-controlled; neutralize any
                        // prompt-injection directives before the brain sees it.
                        let mut value = value;
                        let hits = shield::defang_value(&mut value);
                        if !hits.is_empty() {
                            trace.note(
                                "injection_shield",
                                format!(
                                    "{tool}: neutralized {} directive(s): {}",
                                    hits.len(),
                                    hits.join(", ")
                                ),
                            );
                        }
                        state.transcript.push(TranscriptEntry {
                            tool,
                            result: value,
                        });
                    }
                    Err(e) => {
                        trace.note("tool_error", format!("{tool}: {e}"));
                        state.transcript.push(TranscriptEntry {
                            tool,
                            result: json!({"error": e.to_string()}),
                        });
                    }
                }
                state.turn += 1;
            }
        }
    }

    // A brain may call the same scan/analysis more than once; collapse duplicates
    // so the report reflects distinct findings, not turn count.
    dedup_findings(&mut all_findings);

    // Persist captured HTTP traffic (Strix-style) alongside the report, in the
    // same JSON shape `proxy.rs` dumps, so runs are replayable/auditable.
    let captures = ctx.take_captures();
    if !captures.is_empty() {
        let cap_path = captures_path(&cfg.output);
        match serde_json::to_string_pretty(&captures) {
            Ok(js) => {
                if let Err(e) = std::fs::write(&cap_path, js) {
                    trace.note("captures_error", format!("{cap_path}: {e}"));
                } else {
                    trace.note(
                        "captures",
                        format!("{} transactions → {cap_path}", captures.len()),
                    );
                }
            }
            Err(e) => trace.note("captures_error", e.to_string()),
        }
    }

    let target_label = cfg
        .target
        .clone()
        .or_else(|| cfg.repo.clone())
        .unwrap_or_else(|| "agent".to_string());
    let modules = types::summarize_modules(&all_findings, &[]);

    let report = crate::analyze::write_report(
        &target_label,
        modules,
        all_discovered,
        all_findings,
        true, // correlate SAST↔DAST findings
        start.elapsed(),
        &cfg.output,
        cfg.sarif_out.as_deref(),
        static_analysis,
    )
    .await?;

    trace.note(
        "report",
        format!("{} findings → {}", report.findings.len(), cfg.output),
    );
    Ok(report)
}

fn scope_autonomy(scope: &ScopeConfig) -> Autonomy {
    scope.autonomy
}

/// Path for the captured-traffic dump: the report path with a `.captures.json`
/// suffix (`agent-report.json` → `agent-report.captures.json`).
fn captures_path(output: &str) -> String {
    match output.strip_suffix(".json") {
        Some(stem) => format!("{stem}.captures.json"),
        None => format!("{output}.captures.json"),
    }
}

/// Drop duplicate findings, keyed by (plugin, title, url, code location).
fn dedup_findings(findings: &mut Vec<Finding>) {
    let mut seen = std::collections::HashSet::new();
    findings.retain(|f| {
        let loc = f
            .location
            .as_ref()
            .map(|l| format!("{}:{}", l.file, l.line_start))
            .unwrap_or_default();
        seen.insert(format!("{}|{}|{}|{}", f.plugin, f.title, f.url, loc))
    });
}

/// Approval gate: prompt on a TTY, auto-deny when headless.
fn approve(cfg: &AgentConfig, tool: &str, class: ActionClass) -> bool {
    if cfg.non_interactive || !io::stdin().is_terminal() {
        eprintln!("[agent] approval required for `{tool}` ({class:?}); non-interactive → denied");
        return false;
    }
    print!("[agent] approve `{tool}` ({class:?})? [y/N]: ");
    io::stdout().flush().ok();
    let mut buf = String::new();
    if io::stdin().read_line(&mut buf).is_err() {
        return false;
    }
    crate::analyze::confirm_reply_is_yes(&buf)
}

/// CLI-supplied overrides for the LLM brain (take precedence over the scope file).
#[derive(Debug, Default)]
pub struct LlmOverrides {
    pub base_url: Option<String>,
    pub model: Option<String>,
    pub api_key_env: Option<String>,
    pub json_mode: bool,
    /// Force privacy tokenization on regardless of the scope file.
    pub privacy: bool,
}

/// Build a privacy vault seeded with the scope's concrete hosts and the target
/// host. Disabled vaults return a no-op.
fn build_vault(enabled: bool, allowed_hosts: &[String], target: Option<&str>) -> privacy::Vault {
    let mut vault = privacy::Vault::new(enabled);
    if !enabled {
        return vault;
    }
    for h in allowed_hosts {
        vault.seed_host(h);
    }
    if let Some(t) = target {
        if let Ok(u) = url::Url::parse(t) {
            if let Some(h) = u.host_str() {
                vault.seed_host(h);
            }
        }
    }
    vault
}

/// Default OpenAI-compatible endpoint: local Ollama.
pub const DEFAULT_LLM_BASE_URL: &str = "http://localhost:11434/v1";

/// CLI entry: load scope, pick the brain, run, print a one-line summary.
#[allow(clippy::too_many_arguments)]
pub async fn run_agent_cli(
    scope_path: String,
    goal: Option<String>,
    target: Option<String>,
    repo: Option<String>,
    output: String,
    sarif_out: Option<String>,
    trace_path: String,
    autonomy_override: Option<String>,
    non_interactive: bool,
    script: Option<String>,
    llm: LlmOverrides,
) -> Result<()> {
    let mut scope = ScopeConfig::load(Path::new(&scope_path))?;
    if let Some(a) = autonomy_override {
        let parsed = Autonomy::parse(&a)
            .with_context(|| format!("invalid --autonomy '{a}' (assisted|semi|auto)"))?;
        scope.set_autonomy(parsed);
    }

    let brain: Box<dyn AgentBrain> = match script {
        Some(sp) => Box::new(ScriptedBrain::from_json_file(Path::new(&sp))?),
        None => {
            // CLI override → scope file → Ollama default.
            let base = llm
                .base_url
                .or_else(|| scope.model.base_url.clone())
                .unwrap_or_else(|| DEFAULT_LLM_BASE_URL.to_string());
            let model = llm.model.or_else(|| scope.model.model.clone()).context(
                "LLM model not set — pass --model or set scope.model.model \
                 (e.g. qwen2.5-coder, gpt-4o-mini, claude-3-5-sonnet), or use --script",
            )?;
            // Key from env only if an env var is named; keyless is fine for local servers.
            let key_env = llm.api_key_env.or_else(|| scope.model.api_key_env.clone());
            let api_key =
                key_env.and_then(|env| std::env::var(&env).ok().filter(|k| !k.is_empty()));
            let json_mode = llm.json_mode || scope.model.json_mode;
            let privacy_on = llm.privacy || scope.privacy;
            let vault = build_vault(privacy_on, &scope.allowed_hosts, target.as_deref());
            Box::new(LlmBrain::with_vault(
                &base, &model, api_key, json_mode, vault,
            ))
        }
    };

    let goal = goal.unwrap_or_else(|| {
        format!(
            "Assess the security of {}",
            target
                .as_deref()
                .or(repo.as_deref())
                .unwrap_or("the provided scope")
        )
    });
    let output_for_msg = output.clone();
    let cfg = AgentConfig {
        scope,
        goal,
        target,
        repo,
        output,
        sarif_out,
        trace_path,
        non_interactive,
    };
    let report = run_agent(cfg, brain).await?;
    println!(
        "Agent run complete: {} findings, report → {}",
        report.findings.len(),
        output_for_msg
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent::brain::AgentAction;

    fn scope_yaml(y: &str) -> ScopeConfig {
        let mut s: ScopeConfig = serde_yaml::from_str(y).unwrap();
        s.compile().unwrap();
        s
    }

    #[test]
    fn captures_path_swaps_json_suffix() {
        assert_eq!(
            captures_path("agent-report.json"),
            "agent-report.captures.json"
        );
        assert_eq!(captures_path("out"), "out.captures.json");
        assert_eq!(captures_path("/tmp/a/b.json"), "/tmp/a/b.captures.json");
    }

    #[tokio::test]
    async fn scripted_agent_analyzes_repo_and_writes_report() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/native_app");
        let out = std::env::temp_dir().join(format!("rz-agent-{}.json", crate::types::uuid_v4()));
        let trace =
            std::env::temp_dir().join(format!("rz-agent-{}.jsonl", crate::types::uuid_v4()));
        let brain = Box::new(ScriptedBrain::new(vec![
            AgentAction::CallTool {
                tool: "analyze_repo".into(),
                args: json!({"path": root.to_string_lossy(), "tools": "native"}),
            },
            AgentAction::Finish {
                summary: "done".into(),
            },
        ]));
        let cfg = AgentConfig {
            scope: scope_yaml("allowed_hosts: []\nautonomy: assisted\n"),
            goal: "test".into(),
            target: None,
            repo: Some(root.to_string_lossy().to_string()),
            output: out.to_string_lossy().to_string(),
            sarif_out: None,
            trace_path: trace.to_string_lossy().to_string(),
            non_interactive: true,
        };
        let report = run_agent(cfg, brain).await.expect("agent run");
        assert!(!report.findings.is_empty());
        assert!(report.static_analysis.is_some());
        assert!(out.exists());
        assert!(std::fs::read_to_string(&trace)
            .unwrap()
            .contains("tool_call"));
        let _ = std::fs::remove_file(out);
        let _ = std::fs::remove_file(trace);
    }

    #[test]
    fn dedup_collapses_identical_findings() {
        use crate::types::{Finding, Severity};
        let mk = || Finding::new("XSS", Severity::High, "http://x/a", "d", "s", "active/xss");
        let mut v = vec![mk(), mk(), mk()];
        dedup_findings(&mut v);
        assert_eq!(v.len(), 1);
    }

    #[tokio::test]
    async fn assisted_mode_denies_exploit_class_headless() {
        // Recon runs; a hypothetical exploit-class tool would be denied. We assert
        // the approval gate: in assisted+non-interactive, requires_approval is honored.
        let scope = scope_yaml("allowed_hosts: []\nautonomy: assisted\n");
        assert!(scope.requires_approval(ActionClass::Exploit));
        assert!(!scope.requires_approval(ActionClass::Recon));
    }
}
