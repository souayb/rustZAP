//! The shared AgentTool registry — the single set of capabilities exposed both
//! to the native agent loop and to external brains via the MCP server.
//!
//! Every tool wraps existing RustZAP logic (no scanning code is duplicated):
//! `scanner::collect_scan`, `analyze::run_static_analysis`, `native::run`, the
//! active `ScanPlugin`s, and a bounded HTTP probe. Network-touching tools are
//! gated by the scope file.

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{bail, Result};
use serde_json::{json, Value};

use crate::agent::redteam;
use crate::agent::scope::{ActionClass, ScopeConfig};
use crate::agent::trace::Trace;
use crate::analyze::{self, StaticInputs};
use crate::report::{AttackPlanEntry, StaticAnalysis};
use crate::scanner::{self, ScanConfig};
use crate::types::{
    DiscoveredUrl, Finding, HttpRequest, HttpResponse, HttpTransaction, Severity, UrlSource,
};

/// Response/request headers that reqwest manages itself; forwarding them from a
/// captured request breaks a replay (wrong length, double compression, …).
const REPLAY_SKIP_HEADERS: &[&str] = &[
    "host",
    "content-length",
    "connection",
    "accept-encoding",
    "transfer-encoding",
];

const HTTP_PROBE_TIMEOUT_SECS: u64 = 10;
const HTTP_PROBE_MAX_BODY: usize = 64 * 1024;
/// Upper bound on the number of steps a single sub-task may run.
const SUBTASK_MAX_STEPS: usize = 20;

/// Shared execution context for all tools.
pub struct ToolCtx {
    pub scope: Arc<ScopeConfig>,
    pub trace: Arc<Trace>,
    client: reqwest::Client,
    requests: AtomicU32,
    /// Strix-style traffic capture: every probe/replay is recorded here so the
    /// brain can list past requests and replay them with mutations. Reuses the
    /// `proxy.rs` transaction record so both share one on-disk format.
    captures: Mutex<Vec<HttpTransaction>>,
}

impl ToolCtx {
    pub fn new(scope: Arc<ScopeConfig>, trace: Arc<Trace>) -> Result<Self> {
        let client = scanner::build_client(&default_scan_config("http://placeholder.invalid"))?;
        Ok(Self {
            scope,
            trace,
            client,
            requests: AtomicU32::new(0),
            captures: Mutex::new(Vec::new()),
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

    /// Look up a captured transaction by id (clone of the stored record).
    fn capture_by_id(&self, id: &str) -> Option<HttpTransaction> {
        self.captures
            .lock()
            .ok()?
            .iter()
            .find(|t| t.id == id)
            .cloned()
    }

    /// Drain the captured transactions (called once at end of run to persist them).
    pub fn take_captures(&self) -> Vec<HttpTransaction> {
        self.captures
            .lock()
            .map(|mut c| std::mem::take(&mut *c))
            .unwrap_or_default()
    }

    /// Send one in-scope request, record it as a capture, and return the stored
    /// transaction plus whether the body was truncated. Shared by `http_probe`
    /// and `replay_request`.
    async fn send_and_capture(
        &self,
        method: &str,
        url: &str,
        body: Option<String>,
        headers: &[(String, String)],
    ) -> Result<(HttpTransaction, bool)> {
        self.enforce_scope(url)?;
        self.charge_request()?;
        let m = reqwest::Method::from_bytes(method.as_bytes())
            .map_err(|_| anyhow::anyhow!("bad HTTP method: {method}"))?;
        let mut req = self
            .client
            .request(m, url)
            .timeout(Duration::from_secs(HTTP_PROBE_TIMEOUT_SECS));
        for (k, v) in headers {
            req = req.header(k, v);
        }
        if let Some(b) = &body {
            req = req.body(b.clone());
        }
        let start = Instant::now();
        let resp = req.send().await?;
        let status = resp.status().as_u16();
        let resp_headers: Vec<(String, String)> = resp
            .headers()
            .iter()
            .map(|(k, v)| (k.as_str().to_string(), v.to_str().unwrap_or("").to_string()))
            .collect();
        let full = resp.text().await.unwrap_or_default();
        let elapsed_ms = start.elapsed().as_millis() as u64;
        let truncated = full.len() > HTTP_PROBE_MAX_BODY;
        let snippet: String = full.chars().take(HTTP_PROBE_MAX_BODY).collect();
        let txn = HttpTransaction {
            id: crate::types::uuid_v4(),
            request: HttpRequest {
                method: method.to_string(),
                url: url.to_string(),
                headers: headers.to_vec(),
                body,
            },
            response: Some(HttpResponse {
                status,
                headers: resp_headers,
                body: snippet,
                elapsed_ms,
            }),
            timestamp: chrono::Utc::now(),
        };
        if let Ok(mut caps) = self.captures.lock() {
            caps.push(txn.clone());
        }
        Ok((txn, truncated))
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
            description: "Send one bounded HTTP request to an in-scope URL and return status/headers/body-snippet. The request/response is captured (returns a capture_id) for later replay.",
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
        ToolSpec {
            name: "ai_redteam",
            description: "Run the OWASP LLM Top-10 red-team battery (prompt injection, insecure output handling, system-prompt leakage, excessive agency) against an in-scope OpenAI-compatible chat endpoint. Intrusive — requires approval.",
            action_class: ActionClass::Exploit,
            input_schema: json!({
                "type": "object",
                "properties": {
                    "endpoint": {"type": "string", "description": "In-scope chat-completions URL of the app under test"},
                    "model": {"type": "string", "description": "Model id to request (default gpt-4o-mini)"},
                    "api_key_env": {"type": "string", "description": "Env var holding a bearer token for the target, if it needs one"},
                    "system_marker": {"type": "string", "description": "A phrase known to be in the target's system prompt; enables leak detection"}
                },
                "required": ["endpoint"]
            }),
        },
        ToolSpec {
            name: "spawn_subtask",
            description: "Delegate a focused plan of recon-class tool calls to a bounded sub-agent; its findings merge into the report. `steps` is an array of {tool, args}. Recon-only and non-nesting; shares the parent scope, budget, and trace.",
            action_class: ActionClass::Recon,
            input_schema: json!({
                "type": "object",
                "properties": {
                    "goal": {"type": "string", "description": "What this subtask investigates"},
                    "steps": {
                        "type": "array",
                        "description": "Ordered recon tool calls to run",
                        "items": {
                            "type": "object",
                            "properties": {
                                "tool": {"type": "string"},
                                "args": {"type": "object"}
                            },
                            "required": ["tool"]
                        }
                    }
                },
                "required": ["steps"]
            }),
        },
        ToolSpec {
            name: "list_captures",
            description: "List captured HTTP transactions from this run (id, method, url, status) — the traffic available to replay.",
            action_class: ActionClass::Recon,
            input_schema: json!({"type": "object", "properties": {}}),
        },
        ToolSpec {
            name: "replay_request",
            description: "Re-send a captured request (by capture_id) with optional mutations, or a fresh request. Overrides: method/url/body, and headers (object of name→value). Returns the new response plus a diff vs the original (status change, body-length delta).",
            action_class: ActionClass::Recon,
            input_schema: json!({
                "type": "object",
                "properties": {
                    "capture_id": {"type": "string", "description": "Id of a captured request to base the replay on (from http_probe/list_captures). Omit to send a fresh request (url required)."},
                    "url": {"type": "string", "description": "Override the URL (required if no capture_id)."},
                    "method": {"type": "string", "description": "Override the HTTP method."},
                    "body": {"type": "string", "description": "Override the request body."},
                    "headers": {"type": "object", "description": "Header name→value overrides merged onto the captured request."}
                }
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
        "list_captures" => Ok(list_captures_tool(ctx)),
        "replay_request" => replay_request(args, ctx).await,
        "ai_redteam" => ai_redteam(args, ctx).await,
        "spawn_subtask" => spawn_subtask(args, ctx).await,
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
        headers: Vec::new(),
        body: None,
        content_type: None,
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
    let method = args.get("method").and_then(|v| v.as_str()).unwrap_or("GET");
    let body = args.get("body").and_then(|v| v.as_str()).map(String::from);
    let (txn, truncated) = ctx.send_and_capture(method, &url, body, &[]).await?;
    Ok(ToolOutput::value_only(probe_value(&txn, truncated)))
}

/// Brain-facing view of a captured transaction.
fn probe_value(txn: &HttpTransaction, truncated: bool) -> Value {
    let resp = txn.response.as_ref();
    let headers: Vec<Value> = resp
        .map(|r| {
            r.headers
                .iter()
                .map(|(k, v)| json!({"name": k, "value": v}))
                .collect()
        })
        .unwrap_or_default();
    json!({
        "capture_id": txn.id,
        "url": txn.request.url,
        "method": txn.request.method,
        "status": resp.map(|r| r.status),
        "headers": headers,
        "body_snippet": resp.map(|r| r.body.clone()).unwrap_or_default(),
        "body_truncated": truncated,
    })
}

fn list_captures_tool(ctx: &ToolCtx) -> ToolOutput {
    let caps = ctx.captures.lock().map(|c| c.clone()).unwrap_or_default();
    let items: Vec<Value> = caps
        .iter()
        .map(|t| {
            json!({
                "capture_id": t.id,
                "method": t.request.method,
                "url": t.request.url,
                "status": t.response.as_ref().map(|r| r.status),
            })
        })
        .collect();
    ToolOutput::value_only(json!({"count": items.len(), "captures": items}))
}

/// Merge header overrides (case-insensitive) onto a base header list.
fn merge_headers(base: &[(String, String)], overrides: &Value) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = base
        .iter()
        .filter(|(k, _)| {
            !REPLAY_SKIP_HEADERS
                .iter()
                .any(|s| k.eq_ignore_ascii_case(s))
        })
        .cloned()
        .collect();
    if let Some(map) = overrides.as_object() {
        for (k, v) in map {
            let Some(val) = v.as_str() else { continue };
            out.retain(|(ek, _)| !ek.eq_ignore_ascii_case(k));
            out.push((k.clone(), val.to_string()));
        }
    }
    out
}

async fn replay_request(args: &Value, ctx: &ToolCtx) -> Result<ToolOutput> {
    // Base the replay on a captured request when an id is given.
    let base = match args.get("capture_id").and_then(|v| v.as_str()) {
        Some(id) => Some(
            ctx.capture_by_id(id)
                .ok_or_else(|| anyhow::anyhow!("no captured request with capture_id '{id}'"))?,
        ),
        None => None,
    };

    let (base_method, base_url, base_headers, base_body, base_resp) = match &base {
        Some(t) => (
            t.request.method.clone(),
            t.request.url.clone(),
            t.request.headers.clone(),
            t.request.body.clone(),
            t.response.clone(),
        ),
        None => ("GET".to_string(), String::new(), Vec::new(), None, None),
    };

    let method = args
        .get("method")
        .and_then(|v| v.as_str())
        .map(String::from)
        .unwrap_or(base_method);
    let url = match args.get("url").and_then(|v| v.as_str()) {
        Some(u) => u.to_string(),
        None if !base_url.is_empty() => base_url,
        None => bail!("replay_request needs a url (or a capture_id to base on)"),
    };
    let body = match args.get("body").and_then(|v| v.as_str()) {
        Some(b) => Some(b.to_string()),
        None => base_body,
    };
    let headers = match args.get("headers") {
        Some(h) => merge_headers(&base_headers, h),
        None => base_headers
            .into_iter()
            .filter(|(k, _)| {
                !REPLAY_SKIP_HEADERS
                    .iter()
                    .any(|s| k.eq_ignore_ascii_case(s))
            })
            .collect(),
    };

    let (txn, truncated) = ctx.send_and_capture(&method, &url, body, &headers).await?;

    // Diff vs the original response, if we replayed a captured one.
    let mut value = probe_value(&txn, truncated);
    if let (Some(orig), Some(new)) = (base_resp.as_ref(), txn.response.as_ref()) {
        value["diff"] = json!({
            "based_on": base.as_ref().map(|t| t.id.clone()),
            "status_changed": orig.status != new.status,
            "orig_status": orig.status,
            "new_status": new.status,
            "body_len_delta": new.body.len() as i64 - orig.body.len() as i64,
        });
    }
    Ok(ToolOutput::value_only(value))
}

async fn ai_redteam(args: &Value, ctx: &ToolCtx) -> Result<ToolOutput> {
    let endpoint = arg_str(args, "endpoint")?;
    let model = args
        .get("model")
        .and_then(|v| v.as_str())
        .unwrap_or("gpt-4o-mini");
    let marker = args.get("system_marker").and_then(|v| v.as_str());
    let api_key = args
        .get("api_key_env")
        .and_then(|v| v.as_str())
        .and_then(|env| std::env::var(env).ok())
        .filter(|k| !k.is_empty());

    // Per-run unique canary the injection probes ask the model to echo.
    let canary = format!(
        "RZ-CANARY-{}",
        crate::types::uuid_v4().split('-').next().unwrap_or("token")
    );
    let probes = redteam::probes(&canary, marker);

    let mut findings: Vec<Finding> = Vec::new();
    let mut results: Vec<Value> = Vec::new();
    for p in &probes {
        let body = json!({
            "model": model,
            "messages": [{"role": "user", "content": p.prompt}],
            "temperature": 0,
        })
        .to_string();
        let mut headers = vec![("content-type".to_string(), "application/json".to_string())];
        if let Some(k) = &api_key {
            headers.push(("authorization".to_string(), format!("Bearer {k}")));
        }
        match ctx
            .send_and_capture("POST", &endpoint, Some(body), &headers)
            .await
        {
            Ok((txn, _)) => {
                let raw = txn
                    .response
                    .as_ref()
                    .map(|r| r.body.as_str())
                    .unwrap_or_default();
                let text = redteam::extract_text(raw);
                let hit = redteam::is_susceptible(p, &canary, marker, &text);
                if hit {
                    findings.push(redteam::to_finding(p, &endpoint, &text));
                }
                results.push(json!({
                    "probe": p.id,
                    "owasp": p.owasp,
                    "susceptible": hit,
                }));
            }
            Err(e) => {
                results.push(json!({"probe": p.id, "owasp": p.owasp, "error": e.to_string()}))
            }
        }
    }

    let value = json!({
        "endpoint": endpoint,
        "probes_run": probes.len(),
        "susceptible_count": findings.len(),
        "results": results,
    });
    Ok(ToolOutput {
        value,
        findings,
        ..Default::default()
    })
}

/// Run a delegated plan of recon-class tool calls as a bounded sub-agent, then
/// merge its findings back into the parent report. The sub-agent shares the
/// parent `ToolCtx` — so scope, request budget, capture store, and trace are all
/// unified. Safety invariant: sub-tasks may call **only recon-class** tools and
/// **cannot nest**, so any intrusive action still flows through the top-level,
/// approval-gated loop.
async fn spawn_subtask(args: &Value, ctx: &ToolCtx) -> Result<ToolOutput> {
    let goal = args
        .get("goal")
        .and_then(|v| v.as_str())
        .unwrap_or("(subtask)");
    let steps = args
        .get("steps")
        .and_then(|v| v.as_array())
        .ok_or_else(|| {
            anyhow::anyhow!(
                "spawn_subtask requires 'steps': an array of {{tool, args}} recon calls"
            )
        })?;
    if steps.len() > SUBTASK_MAX_STEPS {
        bail!(
            "subtask plan too large: {} steps (max {SUBTASK_MAX_STEPS})",
            steps.len()
        );
    }
    ctx.trace
        .note("subtask", format!("{goal}: {} step(s)", steps.len()));

    let mut findings: Vec<Finding> = Vec::new();
    let mut discovered: Vec<DiscoveredUrl> = Vec::new();
    let mut static_analysis: Option<StaticAnalysis> = None;
    let mut attack_plan: Vec<AttackPlanEntry> = Vec::new();
    let mut results: Vec<Value> = Vec::new();

    for (i, step) in steps.iter().enumerate() {
        let tool = step
            .get("tool")
            .and_then(|v| v.as_str())
            .unwrap_or_default();
        let sargs = step.get("args").cloned().unwrap_or_else(|| json!({}));

        if tool == "spawn_subtask" {
            results
                .push(json!({"step": i, "tool": tool, "error": "nested subtasks are not allowed"}));
            continue;
        }
        if action_class_of(tool) != ActionClass::Recon {
            results.push(json!({"step": i, "tool": tool, "error": "sub-tasks may only call recon-class tools"}));
            continue;
        }

        // Box the recursive call to break the async cycle (execute → spawn_subtask).
        match Box::pin(execute(tool, &sargs, ctx)).await {
            Ok(out) => {
                let (nf, nd) = (out.findings.len(), out.discovered.len());
                findings.extend(out.findings);
                discovered.extend(out.discovered);
                if out.static_analysis.is_some() {
                    static_analysis = out.static_analysis;
                }
                if !out.attack_plan.is_empty() {
                    attack_plan = out.attack_plan;
                }
                results.push(
                    json!({"step": i, "tool": tool, "ok": true, "findings": nf, "discovered": nd}),
                );
            }
            Err(e) => {
                results.push(json!({"step": i, "tool": tool, "error": e.to_string()}));
            }
        }
    }

    let value = json!({
        "goal": goal,
        "steps_run": steps.len(),
        "findings_count": findings.len(),
        "results": results,
    });
    Ok(ToolOutput {
        value,
        findings,
        discovered,
        attack_plan,
        static_analysis,
    })
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
        assert_eq!(action_class_of("replay_request"), ActionClass::Recon);
    }

    #[test]
    fn merge_headers_drops_skip_list_and_applies_overrides() {
        let base = vec![
            ("Host".into(), "old".into()),
            ("Cookie".into(), "sid=1".into()),
            ("Accept".into(), "text/html".into()),
        ];
        let merged = merge_headers(&base, &json!({"Accept": "application/json", "X-New": "1"}));
        // Host (skip-list) is gone; Cookie survives; Accept is overridden; X-New added.
        assert!(!merged.iter().any(|(k, _)| k.eq_ignore_ascii_case("host")));
        assert!(merged.iter().any(|(k, v)| k == "Cookie" && v == "sid=1"));
        assert!(merged
            .iter()
            .any(|(k, v)| k.eq_ignore_ascii_case("accept") && v == "application/json"));
        assert_eq!(
            merged
                .iter()
                .filter(|(k, _)| k.eq_ignore_ascii_case("accept"))
                .count(),
            1,
            "override replaces rather than duplicates"
        );
        assert!(merged.iter().any(|(k, v)| k == "X-New" && v == "1"));
    }

    /// Minimal echo server: body reflects the method + path so replay mutations
    /// are observable. Returns the bound address.
    async fn spawn_echo_server() -> std::net::SocketAddr {
        use hyper::service::{make_service_fn, service_fn};
        use hyper::{Body, Request, Response, Server};
        let make = make_service_fn(|_| async {
            Ok::<_, std::convert::Infallible>(service_fn(|req: Request<Body>| async move {
                let method = req.method().to_string();
                let path = req.uri().path().to_string();
                Ok::<_, std::convert::Infallible>(Response::new(Body::from(format!(
                    "method={method} path={path}"
                ))))
            }))
        });
        let addr = ([127, 0, 0, 1], 0).into();
        let server = Server::bind(&addr).serve(make);
        let local = server.local_addr();
        tokio::spawn(async move {
            let _ = server.await;
        });
        local
    }

    #[tokio::test]
    async fn probe_captures_then_replay_mutates_and_diffs() {
        let addr = spawn_echo_server().await;
        let ctx = ctx_for("allowed_hosts: [\"127.0.0.1\"]\n");
        let url = format!("http://{addr}/a");

        // Probe records a capture and returns its id.
        let probe = execute("http_probe", &json!({ "url": url }), &ctx)
            .await
            .unwrap();
        let id = probe.value["capture_id"].as_str().unwrap().to_string();
        assert!(probe.value["body_snippet"]
            .as_str()
            .unwrap()
            .contains("method=GET"));

        let listed = execute("list_captures", &json!({}), &ctx).await.unwrap();
        assert_eq!(listed.value["count"].as_u64().unwrap(), 1);

        // Replay the captured request with a method mutation.
        let replay = execute(
            "replay_request",
            &json!({ "capture_id": id, "method": "POST" }),
            &ctx,
        )
        .await
        .unwrap();
        assert!(replay.value["body_snippet"]
            .as_str()
            .unwrap()
            .contains("method=POST"));
        assert_eq!(replay.value["diff"]["status_changed"], json!(false));

        // Both requests are now captured and drainable for the report dump.
        assert_eq!(ctx.take_captures().len(), 2);
    }

    /// LLM echo server: returns an OpenAI-shaped reply whose content is the
    /// request body, so any canary in the probe prompt is reflected back.
    async fn spawn_llm_echo_server() -> std::net::SocketAddr {
        use hyper::service::{make_service_fn, service_fn};
        use hyper::{Body, Request, Response, Server};
        let make = make_service_fn(|_| async {
            Ok::<_, std::convert::Infallible>(service_fn(|req: Request<Body>| async move {
                let bytes = hyper::body::to_bytes(req.into_body())
                    .await
                    .unwrap_or_default();
                let content = String::from_utf8_lossy(&bytes).to_string();
                let reply = json!({"choices": [{"message": {"content": content}}]}).to_string();
                Ok::<_, std::convert::Infallible>(Response::new(Body::from(reply)))
            }))
        });
        let addr = ([127, 0, 0, 1], 0).into();
        let server = Server::bind(&addr).serve(make);
        let local = server.local_addr();
        tokio::spawn(async move {
            let _ = server.await;
        });
        local
    }

    #[tokio::test]
    async fn ai_redteam_flags_reflected_canary() {
        let addr = spawn_llm_echo_server().await;
        let ctx = ctx_for("allowed_hosts: [\"127.0.0.1\"]\n");
        let endpoint = format!("http://{addr}/v1/chat/completions");

        let out = execute("ai_redteam", &json!({ "endpoint": endpoint }), &ctx)
            .await
            .unwrap();

        // The echo reflects the canary → the injection/output probes are flagged.
        assert!(out.value["probes_run"].as_u64().unwrap() >= 6);
        assert!(out.value["susceptible_count"].as_u64().unwrap() >= 1);
        assert!(out.findings.iter().any(|f| f
            .owasp_category
            .as_deref()
            .unwrap_or("")
            .contains("LLM01")));
        // All probe requests were captured for audit/replay.
        assert!(ctx.take_captures().len() >= 6);
    }

    #[tokio::test]
    async fn ai_redteam_is_exploit_class() {
        assert_eq!(action_class_of("ai_redteam"), ActionClass::Exploit);
    }

    #[tokio::test]
    async fn subtask_runs_recon_steps_and_merges_findings() {
        let ctx = ctx_for("allowed_hosts: []\n");
        let root =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/native_app");
        let out = execute(
            "spawn_subtask",
            &json!({
                "goal": "static recon of the fixture",
                "steps": [
                    { "tool": "analyze_repo", "args": { "path": root.to_string_lossy(), "tools": "native" } },
                    { "tool": "list_plugins", "args": {} }
                ]
            }),
            &ctx,
        )
        .await
        .unwrap();

        assert_eq!(out.value["steps_run"].as_u64().unwrap(), 2);
        // analyze_repo produced findings, which bubble up to the parent report.
        assert!(!out.findings.is_empty(), "subtask findings should merge up");
        assert!(
            out.static_analysis.is_some(),
            "static analysis carried through"
        );
        assert!(out.value["results"][0]["ok"].as_bool().unwrap());
    }

    #[tokio::test]
    async fn subtask_refuses_non_recon_and_nested_steps() {
        let ctx = ctx_for("allowed_hosts: [\"127.0.0.1\"]\n");
        let out = execute(
            "spawn_subtask",
            &json!({
                "steps": [
                    { "tool": "ai_redteam", "args": { "endpoint": "http://127.0.0.1/v1" } },
                    { "tool": "spawn_subtask", "args": { "steps": [] } }
                ]
            }),
            &ctx,
        )
        .await
        .unwrap();

        // Both steps are rejected before any request is made → no findings.
        assert!(out.findings.is_empty());
        assert!(out.value["results"][0]["error"]
            .as_str()
            .unwrap()
            .contains("recon-class"));
        assert!(out.value["results"][1]["error"]
            .as_str()
            .unwrap()
            .contains("nested"));
    }

    #[tokio::test]
    async fn subtask_caps_plan_size() {
        let ctx = ctx_for("allowed_hosts: []\n");
        let steps: Vec<Value> = (0..SUBTASK_MAX_STEPS + 1)
            .map(|_| json!({ "tool": "list_plugins", "args": {} }))
            .collect();
        let res = execute("spawn_subtask", &json!({ "steps": steps }), &ctx).await;
        assert!(res.err().unwrap().to_string().contains("too large"));
    }

    #[tokio::test]
    async fn replay_unknown_capture_id_errors() {
        let ctx = ctx_for("allowed_hosts: [\"127.0.0.1\"]\n");
        let res = execute(
            "replay_request",
            &json!({ "capture_id": "does-not-exist" }),
            &ctx,
        )
        .await;
        assert!(res.is_err());
    }

    #[tokio::test]
    async fn replay_enforces_scope() {
        let ctx = ctx_for("allowed_hosts: [\"127.0.0.1\"]\n");
        let res = execute(
            "replay_request",
            &json!({ "url": "http://evil.com/" }),
            &ctx,
        )
        .await;
        let err = res.err().expect("expected an out-of-scope error");
        assert!(err.to_string().contains("out of scope"));
    }
}
