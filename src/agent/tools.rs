//! The shared AgentTool registry — the single set of capabilities exposed both
//! to the native agent loop and to external brains via the MCP server.
//!
//! Every tool wraps existing RustZAP logic (no scanning code is duplicated):
//! `scanner::collect_scan`, `analyze::run_static_analysis`, `native::run`, the
//! active `ScanPlugin`s, and a bounded HTTP probe. Network-touching tools are
//! gated by the scope file.

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Result};
use serde_json::{json, Value};

use crate::agent::scope::{ActionClass, ScopeConfig};
use crate::agent::trace::Trace;
use crate::analyze::{self, StaticInputs};
use crate::report::{AttackPlanEntry, StaticAnalysis};
use crate::scanner::{self, ScanConfig};
use crate::types::{DiscoveredUrl, Finding, Severity, UrlSource};

const HTTP_PROBE_TIMEOUT_SECS: u64 = 10;
const HTTP_PROBE_MAX_BODY: usize = 64 * 1024;

/// Shared execution context for all tools.
pub struct ToolCtx {
    pub scope: Arc<ScopeConfig>,
    pub trace: Arc<Trace>,
    client: reqwest::Client,
    requests: AtomicU32,
}

impl ToolCtx {
    pub fn new(scope: Arc<ScopeConfig>, trace: Arc<Trace>) -> Result<Self> {
        let client = scanner::build_client(&default_scan_config("http://placeholder.invalid"))?;
        Ok(Self {
            scope,
            trace,
            client,
            requests: AtomicU32::new(0),
        })
    }

    fn charge_request(&self) -> Result<()> {
        let n = self.requests.fetch_add(1, Ordering::Relaxed) + 1;
        let cap = self.scope.budget.max_requests;
        if cap > 0 && n > cap {
            bail!("request budget of {cap} exhausted");
        }
        Ok(())
    }

    fn enforce_scope(&self, url: &str) -> Result<()> {
        let verdict = self.scope.check_url(url);
        if !verdict.is_allowed() {
            self.trace
                .note("scope_reject", format!("{url}: {}", verdict.reason()));
            bail!("out of scope ({}): {url}", verdict.reason());
        }
        Ok(())
    }
}

/// The structured result of a tool call. `value` is the compact summary handed
/// to the brain / MCP client; the other fields let the agent loop accumulate
/// state (findings, frontier) across turns.
#[derive(Default)]
pub struct ToolOutput {
    pub value: Value,
    pub findings: Vec<Finding>,
    pub discovered: Vec<DiscoveredUrl>,
    pub attack_plan: Vec<AttackPlanEntry>,
    pub static_analysis: Option<StaticAnalysis>,
}

impl ToolOutput {
    fn value_only(value: Value) -> Self {
        Self {
            value,
            ..Default::default()
        }
    }
}

/// One entry in the tool catalogue (name + description + JSON input schema),
/// used for MCP `tools/list` and to prompt the LLM brain.
#[derive(Debug, Clone)]
pub struct ToolSpec {
    pub name: &'static str,
    pub description: &'static str,
    pub action_class: ActionClass,
    pub input_schema: Value,
}

/// Full catalogue of Phase-A tools.
pub fn tool_specs() -> Vec<ToolSpec> {
    vec![
        ToolSpec {
            name: "scan_target",
            description: "Run RustZAP DAST (spider + passive + active plugins) against an in-scope URL and return findings.",
            action_class: ActionClass::Recon,
            input_schema: json!({
                "type": "object",
                "properties": {
                    "target": {"type": "string", "description": "Absolute http(s) URL to scan"},
                    "passive_only": {"type": "boolean", "default": false},
                    "depth": {"type": "integer", "default": 2},
                    "plugins": {"type": "string", "description": "Comma list or 'all'", "default": "all"}
                },
                "required": ["target"]
            }),
        },
        ToolSpec {
            name: "analyze_repo",
            description: "Run RustZAP static analysis (native inventory/secrets/IaC, or semgrep/trivy/gitleaks/checkov) over a local repo path.",
            action_class: ActionClass::Recon,
            input_schema: json!({
                "type": "object",
                "properties": {
                    "path": {"type": "string"},
                    "tools": {"type": "string", "default": "native"},
                    "include_ignored": {"type": "boolean", "default": false}
                },
                "required": ["path"]
            }),
        },
        ToolSpec {
            name: "get_attack_plan",
            description: "Return the native attack-plan frontier (endpoints+params+reason) for a local repo — the agent's exploration queue.",
            action_class: ActionClass::Recon,
            input_schema: json!({
                "type": "object",
                "properties": {"path": {"type": "string"}},
                "required": ["path"]
            }),
        },
        ToolSpec {
            name: "list_plugins",
            description: "List available active scan plugins (name + description).",
            action_class: ActionClass::Recon,
            input_schema: json!({"type": "object", "properties": {}}),
        },
        ToolSpec {
            name: "run_plugin",
            description: "Run one active plugin against one in-scope URL.",
            action_class: ActionClass::Recon,
            input_schema: json!({
                "type": "object",
                "properties": {
                    "plugin": {"type": "string"},
                    "url": {"type": "string"},
                    "method": {"type": "string", "default": "GET"},
                    "parameters": {"type": "array", "items": {"type": "string"}}
                },
                "required": ["plugin", "url"]
            }),
        },
        ToolSpec {
            name: "http_probe",
            description: "Send one bounded HTTP request to an in-scope URL and return status/headers/body-snippet.",
            action_class: ActionClass::Recon,
            input_schema: json!({
                "type": "object",
                "properties": {
                    "url": {"type": "string"},
                    "method": {"type": "string", "default": "GET"},
                    "body": {"type": "string"}
                },
                "required": ["url"]
            }),
        },
    ]
}

/// The action class declared for `name` (defaults to Recon for unknown tools).
pub fn action_class_of(name: &str) -> ActionClass {
    tool_specs()
        .iter()
        .find(|s| s.name == name)
        .map(|s| s.action_class)
        .unwrap_or(ActionClass::Recon)
}

/// Dispatch a tool call. `args` is the JSON object of arguments.
pub async fn execute(name: &str, args: &Value, ctx: &ToolCtx) -> Result<ToolOutput> {
    ctx.trace.tool_call(name, args);
    match name {
        "scan_target" => scan_target(args, ctx).await,
        "analyze_repo" => analyze_repo(args, ctx).await,
        "get_attack_plan" => get_attack_plan(args, ctx).await,
        "list_plugins" => Ok(list_plugins_tool()),
        "run_plugin" => run_plugin(args, ctx).await,
        "http_probe" => http_probe(args, ctx).await,
        other => bail!("unknown tool: {other}"),
    }
}

fn arg_str(args: &Value, key: &str) -> Result<String> {
    args.get(key)
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .ok_or_else(|| anyhow::anyhow!("missing required string argument '{key}'"))
}

async fn scan_target(args: &Value, ctx: &ToolCtx) -> Result<ToolOutput> {
    let target = arg_str(args, "target")?;
    ctx.enforce_scope(&target)?;
    let passive_only = args
        .get("passive_only")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let depth = args.get("depth").and_then(|v| v.as_u64()).unwrap_or(2) as usize;
    let plugins = args
        .get("plugins")
        .and_then(|v| v.as_str())
        .unwrap_or("all");

    let mut config = default_scan_config(&target);
    config.passive_only = passive_only;
    config.max_depth = depth;
    config.plugins = plugins.split(',').map(|s| s.trim().to_string()).collect();

    let collected = scanner::collect_scan(config).await?;
    let value = json!({
        "target": target,
        "findings": summarize_findings(&collected.findings),
        "discovered_urls": collected.discovered.len(),
        "modules": collected.modules.iter().map(|m| json!({
            "name": m.name, "findings": m.findings, "quiet": m.quiet
        })).collect::<Vec<_>>(),
    });
    Ok(ToolOutput {
        value,
        findings: collected.findings,
        discovered: collected.discovered,
        ..Default::default()
    })
}

async fn analyze_repo(args: &Value, ctx: &ToolCtx) -> Result<ToolOutput> {
    let path = arg_str(args, "path")?;
    let tools = args
        .get("tools")
        .and_then(|v| v.as_str())
        .unwrap_or("native");
    let include_ignored = args
        .get("include_ignored")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    let inputs = StaticInputs {
        repo: analyze::absolute_repo_path(std::path::Path::new(&path)),
        tools: analyze::parse_tools(tools)?,
        tools_explicit: true,
        semgrep_json: None,
        trivy_json: None,
        gitleaks_json: None,
        checkov_json: None,
        walk: crate::analyze::inventory::WalkConfig {
            include_ignored,
            follow_symlinks: false,
        },
    };
    let run = analyze::run_static_analysis(&inputs).await?;

    let static_val = run.static_analysis.as_ref().map(|s| {
        json!({
            "risk_score": s.risk_score,
            "languages": s.inventory.languages,
            "frameworks": s.inventory.frameworks,
            "attack_plan_entries": s.attack_plan.len(),
        })
    });
    let value = json!({
        "path": path,
        "tools_ran": run.tools_ran.iter().map(|t| t.module_id()).collect::<Vec<_>>(),
        "findings": summarize_findings(&run.findings),
        "static": static_val,
    });
    let attack_plan = run
        .static_analysis
        .as_ref()
        .map(|s| s.attack_plan.clone())
        .unwrap_or_default();
    let _ = ctx; // repo consent handled at the CLI entry
    Ok(ToolOutput {
        value,
        findings: run.findings,
        attack_plan,
        static_analysis: run.static_analysis,
        ..Default::default()
    })
}

async fn get_attack_plan(args: &Value, _ctx: &ToolCtx) -> Result<ToolOutput> {
    let path = arg_str(args, "path")?;
    let native = crate::analyze::native::run(std::path::Path::new(&path)).await?;
    let value = json!({
        "path": path,
        "entries": native.attack_plan.iter().map(|e| json!({
            "url": e.url, "method": e.method, "params": e.params, "reason": e.reason
        })).collect::<Vec<_>>(),
    });
    Ok(ToolOutput {
        value,
        attack_plan: native.attack_plan,
        ..Default::default()
    })
}

fn list_plugins_tool() -> ToolOutput {
    let plugins: Vec<Value> = crate::active::all_active_plugins()
        .iter()
        .map(|p| json!({"name": p.name(), "description": p.description()}))
        .collect();
    ToolOutput::value_only(json!({ "plugins": plugins }))
}

async fn run_plugin(args: &Value, ctx: &ToolCtx) -> Result<ToolOutput> {
    let plugin_name = arg_str(args, "plugin")?;
    let url = arg_str(args, "url")?;
    ctx.enforce_scope(&url)?;
    ctx.charge_request()?;
    let Some(plugin) = crate::active::plugin_by_name(&plugin_name) else {
        bail!("unknown plugin: {plugin_name}");
    };
    let parameters = args
        .get("parameters")
        .and_then(|v| v.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|x| x.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();
    let du = DiscoveredUrl {
        url: url.clone(),
        method: args
            .get("method")
            .and_then(|v| v.as_str())
            .unwrap_or("GET")
            .to_string(),
        parameters,
        source: UrlSource::Seed,
    };
    let findings = plugin.scan(&ctx.client, &du).await;
    let value = json!({
        "plugin": plugin_name,
        "url": url,
        "findings": summarize_findings(&findings),
    });
    Ok(ToolOutput {
        value,
        findings,
        ..Default::default()
    })
}

async fn http_probe(args: &Value, ctx: &ToolCtx) -> Result<ToolOutput> {
    let url = arg_str(args, "url")?;
    ctx.enforce_scope(&url)?;
    ctx.charge_request()?;
    let method = args.get("method").and_then(|v| v.as_str()).unwrap_or("GET");
    let body = args.get("body").and_then(|v| v.as_str()).map(String::from);

    let m = reqwest::Method::from_bytes(method.as_bytes())
        .map_err(|_| anyhow::anyhow!("bad HTTP method: {method}"))?;
    let mut req = ctx
        .client
        .request(m, &url)
        .timeout(Duration::from_secs(HTTP_PROBE_TIMEOUT_SECS));
    if let Some(b) = body {
        req = req.body(b);
    }
    let resp = req.send().await?;
    let status = resp.status().as_u16();
    let headers: Vec<Value> = resp
        .headers()
        .iter()
        .map(|(k, v)| json!({"name": k.as_str(), "value": v.to_str().unwrap_or("")}))
        .collect();
    let full = resp.text().await.unwrap_or_default();
    let truncated = full.len() > HTTP_PROBE_MAX_BODY;
    let snippet = full.chars().take(HTTP_PROBE_MAX_BODY).collect::<String>();
    Ok(ToolOutput::value_only(json!({
        "url": url,
        "status": status,
        "headers": headers,
        "body_snippet": snippet,
        "body_truncated": truncated,
    })))
}

/// Compact, brain-friendly summary of a finding set.
pub fn summarize_findings(findings: &[Finding]) -> Value {
    let mut by_sev = std::collections::BTreeMap::<String, usize>::new();
    for f in findings {
        *by_sev.entry(f.severity.to_string()).or_insert(0) += 1;
    }
    let top: Vec<Value> = findings
        .iter()
        .filter(|f| f.severity >= Severity::Medium)
        .take(20)
        .map(|f| {
            json!({
                "title": f.title,
                "severity": f.severity.to_string(),
                "url": f.url,
                "plugin": f.plugin,
                "confidence": f.confidence.to_string(),
                "poc_validated": f.poc_validated,
            })
        })
        .collect();
    json!({ "count": findings.len(), "by_severity": by_sev, "notable": top })
}

/// A ScanConfig with safe agent defaults for a given target.
pub fn default_scan_config(target: &str) -> ScanConfig {
    ScanConfig {
        target_url: target.to_string(),
        max_depth: 2,
        concurrency: 8,
        passive_only: false,
        output_file: String::new(),
        sarif_out: None,
        timeout_secs: 10,
        user_agent: None,
        cookies: None,
        auth_header: None,
        api_key: None,
        basic_auth: None,
        insecure: false,
        plugins: vec!["all".to_string()],
        openapi_path: None,
        openapi_url: None,
        har_path: None,
        nuclei: false,
        nuclei_jsonl: None,
        active_all_paths: false,
        passive_all_methods: false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent::scope::ScopeConfig;

    fn ctx_for(scope_yaml: &str) -> ToolCtx {
        let mut scope: ScopeConfig = serde_yaml::from_str(scope_yaml).unwrap();
        scope.compile().unwrap();
        let trace = Arc::new(Trace::new(
            std::env::temp_dir().join(format!("rz-tools-{}.jsonl", crate::types::uuid_v4())),
        ));
        ToolCtx::new(Arc::new(scope), trace).unwrap()
    }

    #[tokio::test]
    async fn scan_target_rejects_out_of_scope() {
        let ctx = ctx_for("allowed_hosts: [\"only.example.com\"]\n");
        let res = execute("scan_target", &json!({"target": "http://evil.com/"}), &ctx).await;
        assert!(res.is_err());
        assert!(res.err().unwrap().to_string().contains("out of scope"));
    }

    #[tokio::test]
    async fn list_plugins_returns_catalog() {
        let ctx = ctx_for("allowed_hosts: []\n");
        let out = execute("list_plugins", &json!({}), &ctx).await.unwrap();
        assert!(out.value["plugins"].as_array().unwrap().len() >= 10);
    }

    #[tokio::test]
    async fn analyze_repo_runs_native_on_fixture() {
        let ctx = ctx_for("allowed_hosts: []\n");
        let root =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/native_app");
        let out = execute(
            "analyze_repo",
            &json!({"path": root.to_string_lossy(), "tools": "native"}),
            &ctx,
        )
        .await
        .unwrap();
        assert!(out.value["findings"]["count"].as_u64().unwrap() > 0);
        assert!(out.static_analysis.is_some());
    }

    #[tokio::test]
    async fn unknown_tool_errors() {
        let ctx = ctx_for("allowed_hosts: []\n");
        assert!(execute("nope", &json!({}), &ctx).await.is_err());
    }

    #[test]
    fn tool_specs_are_nonempty_and_recon() {
        let specs = tool_specs();
        assert!(specs.len() >= 6);
        assert_eq!(action_class_of("scan_target"), ActionClass::Recon);
    }
}
