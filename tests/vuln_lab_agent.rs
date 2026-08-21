//! Tier-B agent end-to-end coverage against the loopback lab.
//!
//! (a) A scripted brain drives `run_plugin` against the vulnerable app and the
//!     assembled `Report` carries a confirmed active finding — proving the
//!     agent → scanner → report path under scope enforcement.
//! (b) `ai_redteam` against a deliberately-injectable OpenAI-shaped mock yields
//!     OWASP-LLM findings; against a refusing mock it yields none (no false
//!     positives) — proving the agent → red-team path end-to-end.

#[path = "support/lab.rs"]
mod lab;

use lab::{serve_full, vulnerable_app, Req, Resp, LLM_SYSTEM_MARKER};
use rustzap::agent::brain::{AgentAction, ScriptedBrain};
use rustzap::agent::scope::ScopeConfig;
use rustzap::agent::{run_agent, AgentConfig};
use serde_json::json;

fn scope_auto() -> ScopeConfig {
    let mut s: ScopeConfig =
        serde_yaml::from_str("allowed_hosts: [\"127.0.0.1\"]\nautonomy: auto\n").unwrap();
    s.compile().unwrap();
    s
}

fn tmp(name: &str) -> String {
    std::env::temp_dir()
        .join(format!(
            "rz-vuln-lab-{name}-{}.json",
            rustzap::types::uuid_v4()
        ))
        .to_string_lossy()
        .to_string()
}

fn cfg(base: &str, output: String, auto_approve: bool) -> AgentConfig {
    let trace = format!("{output}.trace.jsonl");
    AgentConfig {
        scope: scope_auto(),
        goal: "vuln-lab agent test".into(),
        target: Some(base.to_string()),
        repo: None,
        output,
        sarif_out: None,
        trace_path: trace,
        non_interactive: true,
        auto_approve,
    }
}

fn cleanup(output: &str) {
    let _ = std::fs::remove_file(output);
    let _ = std::fs::remove_file(format!("{output}.trace.jsonl"));
    if let Some(stem) = output.strip_suffix(".json") {
        let _ = std::fs::remove_file(format!("{stem}.captures.json"));
    }
}

#[tokio::test]
async fn agent_runs_a_plugin_and_reports_confirmed_finding() {
    let base = serve_full(vulnerable_app).await;
    let out = tmp("runplugin");
    let brain = Box::new(ScriptedBrain::new(vec![
        AgentAction::CallTool {
            tool: "run_plugin".into(),
            args: json!({ "plugin": "sqli", "url": format!("{base}/dast/sqli?id=1") }),
        },
        AgentAction::Finish {
            summary: "done".into(),
        },
    ]));
    let report = run_agent(cfg(&base, out.clone(), false), brain)
        .await
        .unwrap();
    assert!(
        report
            .findings
            .iter()
            .any(|f| f.plugin == "active/sqli" && f.poc_validated),
        "expected a confirmed active/sqli finding: {:?}",
        report.findings
    );
    cleanup(&out);
}

/// OpenAI-shaped mock that leaks a system marker and echoes the request (so any
/// canary reflects) — deliberately susceptible to the whole OWASP-LLM battery.
fn llm_echo(req: &Req) -> Resp {
    let content = format!("{LLM_SYSTEM_MARKER}\n{}", req.body);
    let body = json!({ "choices": [{ "message": { "content": content } }] }).to_string();
    Resp::ok(body).header("Content-Type", "application/json")
}

/// An aligned mock that refuses everything — must produce zero findings.
fn llm_refuse(_req: &Req) -> Resp {
    let body = json!({
        "choices": [{ "message": { "content": "I'm sorry, I cannot help with that. I can't comply." } }]
    })
    .to_string();
    Resp::ok(body).header("Content-Type", "application/json")
}

#[tokio::test]
async fn ai_redteam_flags_injectable_mock() {
    let base = serve_full(llm_echo).await;
    let out = tmp("redteam-pos");
    let brain = Box::new(ScriptedBrain::new(vec![
        AgentAction::CallTool {
            tool: "ai_redteam".into(),
            args: json!({
                "endpoint": format!("{base}/v1/chat/completions"),
                "system_marker": LLM_SYSTEM_MARKER,
            }),
        },
        AgentAction::Finish {
            summary: "done".into(),
        },
    ]));
    // auto_approve: ai_redteam is Exploit-class; the test consents explicitly.
    let report = run_agent(cfg(&base, out.clone(), true), brain)
        .await
        .unwrap();
    assert!(
        report
            .findings
            .iter()
            .any(|f| f.plugin == "agent/ai-redteam"
                && f.owasp_category.as_deref().unwrap_or("").contains("LLM01")),
        "expected an LLM01 red-team finding: {:?}",
        report.findings
    );
    cleanup(&out);
}

#[tokio::test]
async fn ai_redteam_is_quiet_against_a_refusing_mock() {
    let base = serve_full(llm_refuse).await;
    let out = tmp("redteam-neg");
    let brain = Box::new(ScriptedBrain::new(vec![
        AgentAction::CallTool {
            tool: "ai_redteam".into(),
            args: json!({
                "endpoint": format!("{base}/v1/chat/completions"),
                "system_marker": LLM_SYSTEM_MARKER,
            }),
        },
        AgentAction::Finish {
            summary: "done".into(),
        },
    ]));
    let report = run_agent(cfg(&base, out.clone(), true), brain)
        .await
        .unwrap();
    assert!(
        !report
            .findings
            .iter()
            .any(|f| f.plugin == "agent/ai-redteam"),
        "aligned model must yield no red-team findings: {:?}",
        report.findings
    );
    cleanup(&out);
}
