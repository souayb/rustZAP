//! The planner abstraction. `AgentBrain::next_action` decides the next tool
//! call (or to finish) given the run state. Two impls:
//!
//! * `ScriptedBrain` — deterministic, used in tests and CI (no network).
//! * `LlmBrain`      — an OpenAI-compatible chat endpoint that replies with a
//!   single JSON action. Provider-agnostic; Claude via a compat gateway is the
//!   intended default.

use std::collections::VecDeque;

use anyhow::{Context, Result};
use async_trait::async_trait;
use serde::Deserialize;
use serde_json::{json, Value};

use crate::agent::tools::tool_specs;
use crate::report::AttackPlanEntry;

/// What the brain observes each turn.
pub struct AgentState {
    pub goal: String,
    pub target: Option<String>,
    pub repo: Option<String>,
    pub turn: u32,
    pub transcript: Vec<TranscriptEntry>,
    pub findings_count: usize,
    pub attack_plan: Vec<AttackPlanEntry>,
}

/// One past tool call and its (summarized) result.
#[derive(Clone)]
pub struct TranscriptEntry {
    pub tool: String,
    pub result: Value,
}

/// The brain's decision for a turn.
#[derive(Debug, Clone)]
pub enum AgentAction {
    CallTool { tool: String, args: Value },
    Finish { summary: String },
}

#[async_trait]
pub trait AgentBrain: Send {
    async fn next_action(&mut self, state: &AgentState) -> Result<AgentAction>;
}

// ── ScriptedBrain ───────────────────────────────────────────────────────────

/// Replays a fixed list of actions, then finishes. Deterministic — the CI brain.
pub struct ScriptedBrain {
    steps: VecDeque<AgentAction>,
}

impl ScriptedBrain {
    pub fn new(steps: Vec<AgentAction>) -> Self {
        Self {
            steps: steps.into(),
        }
    }

    /// Load a JSON array of steps: each `{"tool": "...", "args": {...}}` or
    /// `{"finish": "summary"}`.
    pub fn from_json_file(path: &std::path::Path) -> Result<Self> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("reading script file {}", path.display()))?;
        let raw: Vec<RawAction> =
            serde_json::from_str(&text).context("parsing agent script JSON")?;
        let steps = raw.into_iter().map(RawAction::into_action).collect();
        Ok(Self::new(steps))
    }
}

#[async_trait]
impl AgentBrain for ScriptedBrain {
    async fn next_action(&mut self, _state: &AgentState) -> Result<AgentAction> {
        Ok(self.steps.pop_front().unwrap_or(AgentAction::Finish {
            summary: "scripted steps exhausted".into(),
        }))
    }
}

#[derive(Deserialize)]
struct RawAction {
    #[serde(default)]
    tool: Option<String>,
    #[serde(default)]
    args: Option<Value>,
    #[serde(default)]
    finish: Option<String>,
}

impl RawAction {
    fn into_action(self) -> AgentAction {
        if let Some(summary) = self.finish {
            AgentAction::Finish { summary }
        } else if let Some(tool) = self.tool {
            AgentAction::CallTool {
                tool,
                args: self.args.unwrap_or(json!({})),
            }
        } else {
            AgentAction::Finish {
                summary: "empty scripted step".into(),
            }
        }
    }
}

// ── LlmBrain ────────────────────────────────────────────────────────────────

/// Talks to an OpenAI-compatible `/chat/completions` endpoint. To stay portable
/// across gateways we do NOT use the function-calling protocol; instead the
/// model is instructed to reply with a single JSON action object, which we parse.
pub struct LlmBrain {
    client: reqwest::Client,
    endpoint: String,
    model: String,
    api_key: String,
    messages: Vec<Value>,
}

impl LlmBrain {
    /// `base_url` is the API root (e.g. `https://api.provider.com/v1`).
    pub fn new(base_url: &str, model: &str, api_key: &str) -> Self {
        let endpoint = format!("{}/chat/completions", base_url.trim_end_matches('/'));
        let mut messages = Vec::new();
        messages.push(json!({"role": "system", "content": system_prompt()}));
        Self {
            client: reqwest::Client::new(),
            endpoint,
            model: model.to_string(),
            api_key: api_key.to_string(),
            messages,
        }
    }
}

fn system_prompt() -> String {
    let menu: Vec<Value> = tool_specs()
        .iter()
        .map(|s| json!({"name": s.name, "description": s.description, "input_schema": s.input_schema}))
        .collect();
    format!(
        "You are RustZAP's autonomous web-security tester. You act by calling tools.\n\
         Available tools (JSON menu):\n{}\n\n\
         Each turn, reply with EXACTLY ONE JSON object and nothing else:\n\
         - to call a tool: {{\"tool\": \"<name>\", \"args\": {{...}}}}\n\
         - to stop: {{\"finish\": \"<short summary of findings>\"}}\n\
         Only target hosts that are in scope. Prefer read-only recon; validate before concluding.",
        serde_json::to_string_pretty(&menu).unwrap_or_default()
    )
}

#[async_trait]
impl AgentBrain for LlmBrain {
    async fn next_action(&mut self, state: &AgentState) -> Result<AgentAction> {
        let user = match state.transcript.last() {
            None => format!(
                "Goal: {}\nTarget: {}\nRepo: {}\nBegin.",
                state.goal,
                state.target.as_deref().unwrap_or("(none)"),
                state.repo.as_deref().unwrap_or("(none)"),
            ),
            Some(entry) => {
                let obs = serde_json::to_string(&entry.result).unwrap_or_default();
                let obs = obs.chars().take(4000).collect::<String>();
                format!("Observation from {}: {}", entry.tool, obs)
            }
        };
        self.messages.push(json!({"role": "user", "content": user}));

        let body = json!({
            "model": self.model,
            "messages": self.messages,
            "temperature": 0,
        });
        let resp = self
            .client
            .post(&self.endpoint)
            .bearer_auth(&self.api_key)
            .json(&body)
            .send()
            .await
            .context("LLM request failed")?;
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        if !status.is_success() {
            anyhow::bail!(
                "LLM endpoint returned {status}: {}",
                text.chars().take(300).collect::<String>()
            );
        }
        let content = extract_content(&text).unwrap_or_default();
        self.messages
            .push(json!({"role": "assistant", "content": content}));
        Ok(parse_action(&content))
    }
}

/// Pull `choices[0].message.content` out of a chat-completions response.
fn extract_content(resp_body: &str) -> Option<String> {
    let v: Value = serde_json::from_str(resp_body).ok()?;
    v.get("choices")?
        .get(0)?
        .get("message")?
        .get("content")?
        .as_str()
        .map(|s| s.to_string())
}

/// Parse a single JSON action object out of model text (tolerating prose/markdown
/// around it). Falls back to `Finish` with the raw text if no action is found.
fn parse_action(content: &str) -> AgentAction {
    if let Some(obj) = first_json_object(content) {
        if let Ok(raw) = serde_json::from_str::<RawAction>(&obj) {
            if raw.tool.is_some() || raw.finish.is_some() {
                return raw.into_action();
            }
        }
    }
    AgentAction::Finish {
        summary: content.trim().chars().take(500).collect::<String>(),
    }
}

/// Extract the first balanced `{...}` substring.
fn first_json_object(s: &str) -> Option<String> {
    let start = s.find('{')?;
    let mut depth = 0usize;
    let mut in_str = false;
    let mut escaped = false;
    for (i, c) in s[start..].char_indices() {
        match c {
            '"' if !escaped => in_str = !in_str,
            '\\' if in_str => {
                escaped = !escaped;
                continue;
            }
            '{' if !in_str => depth += 1,
            '}' if !in_str => {
                depth -= 1;
                if depth == 0 {
                    return Some(s[start..start + i + 1].to_string());
                }
            }
            _ => {}
        }
        escaped = false;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn scripted_brain_replays_then_finishes() {
        let mut b = ScriptedBrain::new(vec![AgentAction::CallTool {
            tool: "list_plugins".into(),
            args: json!({}),
        }]);
        let state = AgentState {
            goal: "g".into(),
            target: None,
            repo: None,
            turn: 0,
            transcript: vec![],
            findings_count: 0,
            attack_plan: vec![],
        };
        assert!(matches!(
            b.next_action(&state).await.unwrap(),
            AgentAction::CallTool { .. }
        ));
        assert!(matches!(
            b.next_action(&state).await.unwrap(),
            AgentAction::Finish { .. }
        ));
    }

    #[test]
    fn parse_action_handles_tool_and_finish_and_prose() {
        assert!(matches!(
            parse_action("{\"tool\":\"scan_target\",\"args\":{\"target\":\"http://x\"}}"),
            AgentAction::CallTool { .. }
        ));
        assert!(matches!(
            parse_action("Sure! {\"finish\":\"done\"}"),
            AgentAction::Finish { .. }
        ));
        // No JSON → graceful finish with the text.
        assert!(matches!(parse_action("hello"), AgentAction::Finish { .. }));
    }

    #[test]
    fn first_json_object_ignores_braces_in_strings() {
        let s = "prefix {\"a\": \"}{\", \"b\": 1} suffix";
        assert_eq!(
            first_json_object(s).as_deref(),
            Some("{\"a\": \"}{\", \"b\": 1}")
        );
    }

    #[test]
    fn extract_content_reads_choices() {
        let body = "{\"choices\":[{\"message\":{\"content\":\"hi\"}}]}";
        assert_eq!(extract_content(body).as_deref(), Some("hi"));
    }
}
