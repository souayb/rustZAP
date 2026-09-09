//! Target adapters — how to speak to the application under test.
//!
//! The battery was OpenAI-shaped in both directions, so an Anthropic-style
//! endpoint or an in-house `POST /chat {"question": …}` service could not be
//! probed at all. The prompt is the same either way; only the envelope differs,
//! so the envelope is data: pick a built-in shape, or supply a body template and
//! a JSON pointer for the reply.

use anyhow::{Context, Result};
use serde_json::{json, Value};

/// Placeholder replaced by the (JSON-escaped) probe prompt in a custom body.
pub const PROMPT_PLACEHOLDER: &str = "{{prompt}}";

/// Wire format of the application under test.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Shape {
    /// `POST /v1/chat/completions` with `messages`, bearer auth.
    OpenAiChat,
    /// `POST /v1/messages` with `max_tokens`, `x-api-key` + `anthropic-version`.
    AnthropicMessages,
    /// Any other HTTP API: a JSON body template plus a pointer to the reply text.
    Custom {
        body_template: String,
        /// RFC-6901 pointer, e.g. `/data/answer`. Falls back to the built-in
        /// shapes when absent.
        text_path: Option<String>,
    },
}

/// Anthropic pins the API version by header; this is the long-stable value.
const ANTHROPIC_VERSION: &str = "2023-06-01";
/// Anthropic requires `max_tokens`. Generous enough not to truncate a leak,
/// small enough to keep an intrusive battery cheap.
const ANTHROPIC_MAX_TOKENS: u32 = 1024;

/// Everything needed to turn a probe prompt into an HTTP request.
#[derive(Debug, Clone)]
pub struct TargetSpec {
    pub endpoint: String,
    pub model: String,
    pub shape: Shape,
    /// Omitted unless set: some reasoning endpoints reject the field outright.
    pub temperature: Option<f64>,
    /// Header carrying the credential, and the prefix before it.
    pub auth_header: String,
    pub auth_prefix: String,
}

impl TargetSpec {
    /// Build from `ai_redteam` arguments. Unknown shape names are rejected
    /// rather than silently falling back to OpenAI, which would send a
    /// well-formed request that the target rejects on every probe.
    pub fn from_args(args: &Value) -> Result<Self> {
        let endpoint = args
            .get("endpoint")
            .and_then(|v| v.as_str())
            .context("ai_redteam requires 'endpoint'")?
            .to_string();
        let model = args
            .get("model")
            .and_then(|v| v.as_str())
            .unwrap_or("gpt-4o-mini")
            .to_string();

        let shape = match args
            .get("shape")
            .and_then(|v| v.as_str())
            .unwrap_or("openai")
        {
            s if s.eq_ignore_ascii_case("openai") => Shape::OpenAiChat,
            s if s.eq_ignore_ascii_case("anthropic") => Shape::AnthropicMessages,
            s if s.eq_ignore_ascii_case("custom") => {
                let body_template = args
                    .get("body_template")
                    .and_then(|v| v.as_str())
                    .context(
                        "shape 'custom' requires 'body_template' containing the \
                         {{prompt}} placeholder",
                    )?
                    .to_string();
                anyhow::ensure!(
                    body_template.contains(PROMPT_PLACEHOLDER),
                    "body_template must contain the {PROMPT_PLACEHOLDER} placeholder"
                );
                Shape::Custom {
                    body_template,
                    text_path: args
                        .get("text_path")
                        .and_then(|v| v.as_str())
                        .map(str::to_string),
                }
            }
            other => anyhow::bail!("unknown shape '{other}' (openai, anthropic, custom)"),
        };

        let (default_header, default_prefix) = match shape {
            Shape::AnthropicMessages => ("x-api-key", ""),
            _ => ("authorization", "Bearer "),
        };
        Ok(Self {
            endpoint,
            model,
            shape,
            temperature: args.get("temperature").and_then(|v| v.as_f64()),
            auth_header: args
                .get("auth_header")
                .and_then(|v| v.as_str())
                .unwrap_or(default_header)
                .to_string(),
            auth_prefix: args
                .get("auth_prefix")
                .and_then(|v| v.as_str())
                .unwrap_or(default_prefix)
                .to_string(),
        })
    }

    /// The request body for one prompt.
    pub fn body_for(&self, prompt: &str) -> String {
        match &self.shape {
            Shape::OpenAiChat => {
                let mut body = json!({
                    "model": self.model,
                    "messages": [{"role": "user", "content": prompt}],
                });
                if let Some(t) = self.temperature {
                    body["temperature"] = json!(t);
                }
                body.to_string()
            }
            Shape::AnthropicMessages => {
                let mut body = json!({
                    "model": self.model,
                    "max_tokens": ANTHROPIC_MAX_TOKENS,
                    "messages": [{"role": "user", "content": prompt}],
                });
                if let Some(t) = self.temperature {
                    body["temperature"] = json!(t);
                }
                body.to_string()
            }
            // Substitute the JSON-*encoded* prompt minus its surrounding quotes,
            // so a prompt containing a quote or newline cannot break the body.
            Shape::Custom { body_template, .. } => {
                let encoded = Value::String(prompt.to_string()).to_string();
                let escaped = &encoded[1..encoded.len() - 1];
                body_template.replace(PROMPT_PLACEHOLDER, escaped)
            }
        }
    }

    /// Headers for one request, including the credential when there is one.
    pub fn headers(&self, api_key: Option<&str>) -> Vec<(String, String)> {
        let mut headers = vec![("content-type".to_string(), "application/json".to_string())];
        if self.shape == Shape::AnthropicMessages {
            headers.push((
                "anthropic-version".to_string(),
                ANTHROPIC_VERSION.to_string(),
            ));
        }
        if let Some(k) = api_key {
            headers.push((self.auth_header.clone(), format!("{}{k}", self.auth_prefix)));
        }
        headers
    }

    /// Pointer to the reply text, when the shape defines a custom one.
    pub fn text_path(&self) -> Option<&str> {
        match &self.shape {
            Shape::Custom { text_path, .. } => text_path.as_deref(),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn openai_is_the_default_and_omits_temperature() {
        let spec = TargetSpec::from_args(&json!({"endpoint": "http://x/v1"})).unwrap();
        assert_eq!(spec.shape, Shape::OpenAiChat);
        assert_eq!(spec.model, "gpt-4o-mini");

        let body: Value = serde_json::from_str(&spec.body_for("hi")).unwrap();
        assert_eq!(body["messages"][0]["content"], json!("hi"));
        assert!(body.get("temperature").is_none());

        let headers = spec.headers(Some("sk-test"));
        assert!(headers.contains(&("authorization".into(), "Bearer sk-test".into())));
    }

    #[test]
    fn anthropic_shape_uses_its_own_auth_and_required_fields() {
        let spec = TargetSpec::from_args(&json!({
            "endpoint": "https://api.anthropic.com/v1/messages",
            "model": "claude-sonnet-5",
            "shape": "anthropic",
        }))
        .unwrap();

        let body: Value = serde_json::from_str(&spec.body_for("hi")).unwrap();
        assert_eq!(body["max_tokens"], json!(ANTHROPIC_MAX_TOKENS));

        let headers = spec.headers(Some("sk-ant"));
        // The key goes in x-api-key with no Bearer prefix, and the version
        // header is mandatory — without either the API rejects every probe.
        assert!(headers.contains(&("x-api-key".into(), "sk-ant".into())));
        assert!(headers.iter().any(|(k, _)| k == "anthropic-version"));
        assert!(!headers.iter().any(|(k, _)| k == "authorization"));
    }

    #[test]
    fn custom_shape_escapes_the_prompt_into_the_template() {
        let spec = TargetSpec::from_args(&json!({
            "endpoint": "http://x/chat",
            "shape": "custom",
            "body_template": r#"{"question": "{{prompt}}", "session": "t1"}"#,
            "text_path": "/data/answer",
        }))
        .unwrap();

        // A prompt containing quotes and newlines must not break the JSON.
        let body = spec.body_for("say \"hi\"\nnow");
        let parsed: Value = serde_json::from_str(&body).expect("body stays valid JSON");
        assert_eq!(parsed["question"], json!("say \"hi\"\nnow"));
        assert_eq!(parsed["session"], json!("t1"));
        assert_eq!(spec.text_path(), Some("/data/answer"));
    }

    #[test]
    fn invalid_shapes_are_rejected_rather_than_defaulted() {
        let err = TargetSpec::from_args(&json!({"endpoint": "http://x", "shape": "cohere"}))
            .unwrap_err()
            .to_string();
        assert!(err.contains("unknown shape"), "{err}");

        let err = TargetSpec::from_args(&json!({"endpoint": "http://x", "shape": "custom"}))
            .unwrap_err()
            .to_string();
        assert!(err.contains("body_template"), "{err}");

        let err = TargetSpec::from_args(&json!({
            "endpoint": "http://x",
            "shape": "custom",
            "body_template": "{\"q\": \"static\"}",
        }))
        .unwrap_err()
        .to_string();
        assert!(err.contains("placeholder"), "{err}");
    }
}
