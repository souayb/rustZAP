//! Privacy tokenization gateway (Dark-Moon pattern), opt-in.
//!
//! When enabled, real hostnames, secrets, emails, and IPs are replaced with
//! stable placeholders (`RZ_HOST_1`, `RZ_SECRET_1`, …) *before* any text reaches
//! the LLM brain, and restored locally *before* the chosen tool runs. The model
//! reasons over the structure of the target without ever seeing the real host or
//! the credentials a response may have leaked; the loop still executes against
//! the real values because detokenization happens in-process.
//!
//! Scope: the target host and the scope's concrete hosts are pre-seeded so the
//! model never learns them; response bodies are additionally scanned for
//! well-known secret shapes. This is defence-in-depth for the *egress to the
//! model* — it does not replace the audit-trace header redaction.

use std::collections::BTreeMap;
use std::sync::OnceLock;

use regex::Regex;
use serde_json::Value;

use crate::agent::brain::AgentAction;

/// Bidirectional real ⇆ placeholder map for one agent run.
#[derive(Default)]
pub struct Vault {
    enabled: bool,
    /// real value → placeholder (host keys are lowercased for case-insensitive dedup).
    forward: BTreeMap<String, String>,
    /// placeholder → real value (original casing preserved for restore).
    back: BTreeMap<String, String>,
    /// Seeded host matchers: `(host_len, compiled_regex, placeholder)`, applied
    /// longest-host-first so `app.example.com` wins over `example.com`.
    host_seeds: Vec<(usize, Regex, String)>,
    /// Per-category counter for placeholder numbering.
    counters: BTreeMap<&'static str, u32>,
}

impl Vault {
    /// A vault that does nothing until `enabled`.
    pub fn new(enabled: bool) -> Self {
        Self {
            enabled,
            ..Default::default()
        }
    }

    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Number of distinct real values currently mapped (for the trace/summary).
    pub fn len(&self) -> usize {
        self.back.len()
    }

    pub fn is_empty(&self) -> bool {
        self.back.is_empty()
    }

    /// Pre-register a host so the model never sees it. A wildcard entry's base
    /// domain (`*.example.com` → `example.com`) may be passed directly.
    pub fn seed_host(&mut self, host: &str) {
        if !self.enabled {
            return;
        }
        let host = host.trim().trim_start_matches("*.");
        if host.is_empty() || self.forward.contains_key(&host.to_ascii_lowercase()) {
            return;
        }
        let ph = self.next_placeholder("HOST");
        let re = match Regex::new(&format!("(?i){}", regex::escape(host))) {
            Ok(re) => re,
            Err(_) => return,
        };
        self.host_seeds.push((host.len(), re, ph.clone()));
        // Longest host first, so a subdomain is consumed before its base domain.
        self.host_seeds.sort_by_key(|s| std::cmp::Reverse(s.0));
        self.forward.insert(host.to_ascii_lowercase(), ph.clone());
        self.back.insert(ph, host.to_string());
    }

    /// Replace real values in `text` with placeholders, learning new mappings.
    pub fn tokenize(&mut self, text: &str) -> String {
        if !self.enabled {
            return text.to_string();
        }
        let mut out = text.to_string();
        // 1. Seeded hosts (case-insensitive, longest first).
        for (_, re, ph) in self.host_seeds.clone() {
            if re.is_match(&out) {
                out = re.replace_all(&out, ph.as_str()).into_owned();
            }
        }
        // 2. Secret / email / IP shapes.
        out = self.apply_bearer(&out);
        for (cat, re) in secret_patterns() {
            out = self.apply_full(&out, re, cat);
        }
        out
    }

    /// Restore real values from placeholders. Non-mutating.
    pub fn detokenize(&self, text: &str) -> String {
        if !self.enabled || self.back.is_empty() {
            return text.to_string();
        }
        // Longest placeholder first so `RZ_HOST_10` is restored before `RZ_HOST_1`.
        let mut keys: Vec<&String> = self.back.keys().collect();
        keys.sort_by_key(|k| std::cmp::Reverse(k.len()));
        let mut out = text.to_string();
        for k in keys {
            if out.contains(k.as_str()) {
                out = out.replace(k.as_str(), &self.back[k]);
            }
        }
        out
    }

    /// Restore real values inside every string of a JSON value.
    pub fn detokenize_value(&self, v: &Value) -> Value {
        if !self.enabled {
            return v.clone();
        }
        match v {
            Value::String(s) => Value::String(self.detokenize(s)),
            Value::Array(a) => Value::Array(a.iter().map(|x| self.detokenize_value(x)).collect()),
            Value::Object(m) => Value::Object(
                m.iter()
                    .map(|(k, x)| (k.clone(), self.detokenize_value(x)))
                    .collect(),
            ),
            other => other.clone(),
        }
    }

    /// Restore real values in an action the model produced (tool args or the
    /// finish summary) so the loop executes and reports against real values.
    pub fn detokenize_action(&self, action: AgentAction) -> AgentAction {
        if !self.enabled {
            return action;
        }
        match action {
            AgentAction::CallTool { tool, args } => AgentAction::CallTool {
                tool,
                args: self.detokenize_value(&args),
            },
            AgentAction::Finish { summary } => AgentAction::Finish {
                summary: self.detokenize(&summary),
            },
        }
    }

    /// Bearer tokens: replace only the credential, keep the `Bearer ` marker.
    fn apply_bearer(&mut self, text: &str) -> String {
        let re = bearer_pattern();
        let vals: Vec<String> = re
            .captures_iter(text)
            .filter_map(|c| c.get(1).map(|m| m.as_str().to_string()))
            .collect();
        let mut out = text.to_string();
        for v in vals {
            let ph = self.placeholder_for(&v, "SECRET");
            out = out.replace(&v, &ph);
        }
        out
    }

    /// Replace each full match of `re` with a stable per-value placeholder.
    fn apply_full(&mut self, text: &str, re: &Regex, cat: &'static str) -> String {
        let vals: Vec<String> = re.find_iter(text).map(|m| m.as_str().to_string()).collect();
        let mut out = text.to_string();
        for v in vals {
            let ph = self.placeholder_for(&v, cat);
            out = out.replace(&v, &ph);
        }
        out
    }

    /// Stable placeholder for a real value; reuses an existing mapping.
    fn placeholder_for(&mut self, real: &str, cat: &'static str) -> String {
        if let Some(ph) = self.forward.get(real) {
            return ph.clone();
        }
        let ph = self.next_placeholder(cat);
        self.forward.insert(real.to_string(), ph.clone());
        self.back.insert(ph.clone(), real.to_string());
        ph
    }

    fn next_placeholder(&mut self, cat: &'static str) -> String {
        let n = self.counters.entry(cat).or_insert(0);
        *n += 1;
        format!("RZ_{cat}_{n}")
    }
}

/// Bearer-token matcher (credential captured in group 1).
fn bearer_pattern() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?i)bearer\s+([A-Za-z0-9._\-]{10,})").unwrap())
}

/// Well-known secret / PII shapes → placeholder category. Deliberately targeted
/// (no broad high-entropy matcher) so ordinary body text is not tokenized.
fn secret_patterns() -> &'static [(&'static str, Regex)] {
    static SET: OnceLock<Vec<(&'static str, Regex)>> = OnceLock::new();
    SET.get_or_init(|| {
        let raw: &[(&str, &str)] = &[
            // JWT (header.payload.signature).
            (
                "SECRET",
                r"\beyJ[A-Za-z0-9_\-]{6,}\.[A-Za-z0-9_\-]{6,}\.[A-Za-z0-9_\-]{6,}",
            ),
            // AWS access key id.
            ("SECRET", r"\bAKIA[0-9A-Z]{16}\b"),
            // OpenAI-style / generic `sk-` key.
            ("SECRET", r"\bsk-[A-Za-z0-9]{20,}\b"),
            // GitHub tokens.
            ("SECRET", r"\bgh[pousr]_[A-Za-z0-9]{20,}\b"),
            // Slack tokens.
            ("SECRET", r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"),
            // Email address.
            (
                "EMAIL",
                r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b",
            ),
            // IPv4 address.
            ("IP", r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
        ];
        raw.iter()
            .filter_map(|(cat, pat)| Regex::new(pat).ok().map(|re| (*cat, re)))
            .collect()
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn disabled_vault_is_identity() {
        let mut v = Vault::new(false);
        v.seed_host("app.local");
        assert_eq!(v.tokenize("visit app.local"), "visit app.local");
        assert_eq!(v.detokenize("visit app.local"), "visit app.local");
        assert!(v.is_empty());
    }

    #[test]
    fn host_round_trips_case_insensitively() {
        let mut v = Vault::new(true);
        v.seed_host("app.local");
        let tok = v.tokenize("GET http://APP.local/login");
        assert!(!tok.to_lowercase().contains("app.local"));
        assert!(tok.contains("RZ_HOST_1"));
        // The model echoes the placeholder in a new URL; we restore the real host.
        assert_eq!(
            v.detokenize("http://RZ_HOST_1/admin"),
            "http://app.local/admin"
        );
    }

    #[test]
    fn subdomain_wins_over_base_domain() {
        let mut v = Vault::new(true);
        v.seed_host("example.com"); // from a *.example.com scope entry
        v.seed_host("app.example.com"); // from the target
        let tok = v.tokenize("http://app.example.com/x");
        // The whole subdomain host is one placeholder, not `app.RZ_HOST_x`.
        assert!(!tok.contains('.') || !tok.contains("example"));
        assert!(tok.contains("RZ_HOST_2"));
        assert_eq!(v.detokenize(&tok), "http://app.example.com/x");
    }

    #[test]
    fn tokenizes_secrets_emails_ips() {
        let mut v = Vault::new(true);
        let body = "user admin@corp.com key AKIAIOSFODNN7EXAMPLE from 10.0.0.5";
        let tok = v.tokenize(body);
        assert!(!tok.contains("admin@corp.com"));
        assert!(!tok.contains("AKIAIOSFODNN7EXAMPLE"));
        assert!(!tok.contains("10.0.0.5"));
        assert!(tok.contains("RZ_EMAIL_1"));
        assert!(tok.contains("RZ_SECRET_1"));
        assert!(tok.contains("RZ_IP_1"));
    }

    #[test]
    fn bearer_keeps_marker_hides_credential() {
        let mut v = Vault::new(true);
        let tok = v.tokenize("Authorization: Bearer abcdef123456ghijkl");
        assert!(tok.contains("Bearer RZ_SECRET_1"));
        assert!(!tok.contains("abcdef123456ghijkl"));
    }

    #[test]
    fn same_value_reuses_placeholder() {
        let mut v = Vault::new(true);
        let tok = v.tokenize("admin@corp.com and again admin@corp.com");
        assert_eq!(tok.matches("RZ_EMAIL_1").count(), 2);
        assert_eq!(v.len(), 1);
    }

    #[test]
    fn detokenize_action_restores_tool_args() {
        let mut v = Vault::new(true);
        v.seed_host("app.local");
        let _ = v.tokenize("target http://app.local");
        let action = AgentAction::CallTool {
            tool: "http_probe".into(),
            args: json!({"url": "http://RZ_HOST_1/login", "method": "GET"}),
        };
        match v.detokenize_action(action) {
            AgentAction::CallTool { args, .. } => {
                assert_eq!(args["url"], json!("http://app.local/login"));
            }
            _ => panic!("expected CallTool"),
        }
    }

    #[test]
    fn benign_text_is_untouched() {
        let mut v = Vault::new(true);
        let s = "The login form lacks a CSRF token and rate limiting.";
        assert_eq!(v.tokenize(s), s);
    }
}
