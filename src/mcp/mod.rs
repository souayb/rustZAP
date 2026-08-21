//! Minimal MCP (Model Context Protocol) server over stdio.
//!
//! Exposes RustZAP's shared AgentTool registry as MCP tools so any external
//! brain (Claude Code, Cursor, …) can drive scans/static-analysis. Speaks
//! JSON-RPC 2.0, one compact JSON message per line on stdin/stdout. All
//! diagnostics go to stderr so they never corrupt the protocol channel.
//!
//! Network-touching tools are still gated by the scope file; without one, an
//! empty (deny-all-network) scope is used so only local analysis works.

use std::path::Path;
use std::sync::Arc;

use anyhow::Result;
use serde_json::{json, Value};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

use crate::agent::scope::ScopeConfig;
use crate::agent::tools::{self, ToolCtx};
use crate::agent::trace::Trace;

const PROTOCOL_VERSION: &str = "2024-11-05";

/// Run the MCP server on stdio until stdin closes.
pub async fn run_mcp_stdio(scope_path: Option<String>, trace_path: String) -> Result<()> {
    let scope = match scope_path {
        Some(p) => ScopeConfig::load(Path::new(&p))?,
        None => {
            let mut s: ScopeConfig = serde_yaml::from_str("allowed_hosts: []\n")?;
            s.compile()?;
            s
        }
    };
    let trace = Arc::new(Trace::new(trace_path));
    let ctx = ToolCtx::new(Arc::new(scope), trace)?;

    let mut lines = BufReader::new(tokio::io::stdin()).lines();
    let mut stdout = tokio::io::stdout();
    eprintln!(
        "rustzap mcp: ready on stdio ({} tools)",
        tools::tool_specs().len()
    );

    while let Some(line) = lines.next_line().await? {
        if line.trim().is_empty() {
            continue;
        }
        let msg: Value = match serde_json::from_str(&line) {
            Ok(v) => v,
            Err(e) => {
                write_line(&mut stdout, &parse_error(e)).await?;
                continue;
            }
        };
        if let Some(resp) = handle_message(&msg, &ctx).await {
            write_line(&mut stdout, &resp).await?;
        }
    }
    Ok(())
}

async fn write_line(out: &mut tokio::io::Stdout, v: &Value) -> Result<()> {
    let s = serde_json::to_string(v)?;
    out.write_all(s.as_bytes()).await?;
    out.write_all(b"\n").await?;
    out.flush().await?;
    Ok(())
}

/// Handle one JSON-RPC message. Returns `None` for notifications (no `id`).
async fn handle_message(msg: &Value, ctx: &ToolCtx) -> Option<Value> {
    let method = msg.get("method").and_then(|m| m.as_str()).unwrap_or("");
    // Notifications carry no id and expect no response.
    let id = msg.get("id")?.clone();

    match method {
        "initialize" => Some(success(
            id,
            json!({
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "rustzap", "version": env!("CARGO_PKG_VERSION")}
            }),
        )),
        "ping" => Some(success(id, json!({}))),
        "tools/list" => Some(success(id, json!({ "tools": tool_list() }))),
        "tools/call" => Some(tools_call(id, msg.get("params"), ctx).await),
        other => Some(error(id, -32601, &format!("method not found: {other}"))),
    }
}

fn tool_list() -> Vec<Value> {
    tools::tool_specs()
        .iter()
        .map(|s| {
            json!({
                "name": s.name,
                "description": s.description,
                "inputSchema": s.input_schema,
            })
        })
        .collect()
}

async fn tools_call(id: Value, params: Option<&Value>, ctx: &ToolCtx) -> Value {
    let Some(params) = params else {
        return error(id, -32602, "missing params");
    };
    let name = params.get("name").and_then(|n| n.as_str()).unwrap_or("");
    let empty = json!({});
    let args = params.get("arguments").unwrap_or(&empty);

    match tools::execute(name, args, ctx).await {
        Ok(out) => {
            let text = serde_json::to_string_pretty(&out.value).unwrap_or_default();
            success(
                id,
                json!({
                    "content": [{"type": "text", "text": text}],
                    "isError": false
                }),
            )
        }
        Err(e) => success(
            id,
            json!({
                "content": [{"type": "text", "text": format!("error: {e}")}],
                "isError": true
            }),
        ),
    }
}

fn success(id: Value, result: Value) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "result": result})
}

fn error(id: Value, code: i64, message: &str) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "error": {"code": code, "message": message}})
}

fn parse_error(e: serde_json::Error) -> Value {
    json!({"jsonrpc": "2.0", "id": null, "error": {"code": -32700, "message": format!("parse error: {e}")}})
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn ctx() -> ToolCtx {
        let mut s: ScopeConfig = serde_yaml::from_str("allowed_hosts: []\n").unwrap();
        s.compile().unwrap();
        let trace = Arc::new(Trace::new(
            std::env::temp_dir().join(format!("rz-mcp-{}.jsonl", crate::types::uuid_v4())),
        ));
        ToolCtx::new(Arc::new(s), trace).unwrap()
    }

    #[tokio::test]
    async fn initialize_returns_server_info() {
        let ctx = ctx().await;
        let req = json!({"jsonrpc":"2.0","id":1,"method":"initialize"});
        let resp = handle_message(&req, &ctx).await.unwrap();
        assert_eq!(resp["result"]["serverInfo"]["name"], "rustzap");
        assert_eq!(resp["result"]["protocolVersion"], PROTOCOL_VERSION);
    }

    #[tokio::test]
    async fn tools_list_has_scan_target() {
        let ctx = ctx().await;
        let req = json!({"jsonrpc":"2.0","id":2,"method":"tools/list"});
        let resp = handle_message(&req, &ctx).await.unwrap();
        let names: Vec<&str> = resp["result"]["tools"]
            .as_array()
            .unwrap()
            .iter()
            .map(|t| t["name"].as_str().unwrap())
            .collect();
        assert!(names.contains(&"scan_target"));
        assert!(names.contains(&"analyze_repo"));
    }

    #[tokio::test]
    async fn notification_yields_no_response() {
        let ctx = ctx().await;
        let note = json!({"jsonrpc":"2.0","method":"notifications/initialized"});
        assert!(handle_message(&note, &ctx).await.is_none());
    }

    #[tokio::test]
    async fn tools_call_analyze_repo_roundtrips() {
        let ctx = ctx().await;
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/native_app");
        let req = json!({
            "jsonrpc":"2.0","id":3,"method":"tools/call",
            "params": {"name":"analyze_repo","arguments":{"path": root.to_string_lossy(), "tools":"native"}}
        });
        let resp = handle_message(&req, &ctx).await.unwrap();
        assert_eq!(resp["result"]["isError"], false);
        let text = resp["result"]["content"][0]["text"].as_str().unwrap();
        assert!(text.contains("findings"));
    }

    #[tokio::test]
    async fn unknown_method_errors() {
        let ctx = ctx().await;
        let req = json!({"jsonrpc":"2.0","id":9,"method":"bogus"});
        let resp = handle_message(&req, &ctx).await.unwrap();
        assert_eq!(resp["error"]["code"], -32601);
    }
}
