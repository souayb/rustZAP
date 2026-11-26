//! Append-only agent trace (`agent-trace.jsonl`).
//!
//! Every tool call, approval decision, and scope rejection is written as one
//! JSON line so a run is fully auditable and replayable. Sensitive request
//! headers are redacted before they are written.

use std::fs::OpenOptions;
use std::io::Write;
use std::path::PathBuf;
use std::sync::Mutex;

use chrono::Utc;
use serde::Serialize;
use serde_json::Value;

/// Redaction lives in `crate::evidence` (single source of truth for every export).
pub use crate::evidence::{redact, redact_string};

/// One line in the trace file.
#[derive(Debug, Serialize)]
pub struct TraceEvent {
    pub ts: String,
    pub kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub args: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

/// Thread-safe append-only writer. Write failures are logged, never fatal.
pub struct Trace {
    path: PathBuf,
    lock: Mutex<()>,
}

impl Trace {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            lock: Mutex::new(()),
        }
    }

    pub fn path(&self) -> &std::path::Path {
        &self.path
    }

    fn write_event(&self, ev: &TraceEvent) {
        let Ok(line) = serde_json::to_string(ev) else {
            return;
        };
        let _guard = self.lock.lock().unwrap_or_else(|e| e.into_inner());
        match OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
        {
            Ok(mut f) => {
                if let Err(e) = writeln!(f, "{line}") {
                    tracing::warn!("agent trace write failed: {e}");
                }
            }
            Err(e) => tracing::warn!("agent trace open failed: {e}"),
        }
    }

    /// Record a tool invocation with its (redacted) arguments.
    pub fn tool_call(&self, tool: &str, args: &Value) {
        self.write_event(&TraceEvent {
            ts: Utc::now().to_rfc3339(),
            kind: "tool_call".into(),
            tool: Some(tool.to_string()),
            args: Some(redact(args)),
            detail: None,
        });
    }

    /// Record a free-form event (approval, scope rejection, finish, error).
    pub fn note(&self, kind: &str, detail: impl Into<String>) {
        self.write_event(&TraceEvent {
            ts: Utc::now().to_rfc3339(),
            kind: kind.to_string(),
            tool: None,
            args: None,
            // Exception/log text can echo request URLs or headers.
            detail: Some(redact_string(&detail.into())),
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn redacts_sensitive_headers_nested() {
        let v = json!({
            "url": "http://x",
            "headers": {"Authorization": "Bearer secret", "Accept": "json"},
            "list": [{"Cookie": "sid=abc"}]
        });
        let r = redact(&v);
        assert_eq!(r["headers"]["Authorization"], json!("[REDACTED]"));
        assert_eq!(r["headers"]["Accept"], json!("json"));
        assert_eq!(r["list"][0]["Cookie"], json!("[REDACTED]"));
        assert_eq!(r["url"], json!("http://x"));
    }

    #[test]
    fn writes_jsonl_lines() {
        let tmp = std::env::temp_dir().join(format!("rz-trace-{}.jsonl", crate::types::uuid_v4()));
        let t = Trace::new(&tmp);
        t.tool_call("scan_target", &json!({"target": "http://x"}));
        t.note("finish", "done");
        let content = std::fs::read_to_string(&tmp).unwrap();
        let lines: Vec<&str> = content.lines().collect();
        assert_eq!(lines.len(), 2);
        assert!(lines[0].contains("tool_call"));
        assert!(lines[1].contains("finish"));
        let _ = std::fs::remove_file(&tmp);
    }

    #[test]
    fn redacts_embedded_secrets_in_strings() {
        assert_eq!(
            redact_string("GET /login?password=mysecretpassword123&user=admin"),
            "GET /login?password=[REDACTED]&user=admin"
        );
        assert_eq!(
            redact_string("Header: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.xyz token"),
            "Header: Bearer [REDACTED] token"
        );
    }
}
