//! Agent scope & configuration — the mandatory guardrail file.
//!
//! An agent (or the MCP server's network-touching tools) MUST run under a scope
//! file. It declares which hosts/schemes are in bounds, rate/budget caps, the
//! autonomy mode, and which action classes require human approval. Loading is
//! strict: an unreadable or malformed scope is a hard error, never a default.

use std::path::Path;

use anyhow::{Context, Result};
use regex::Regex;
use serde::Deserialize;
use url::Url;

/// How much the agent may do without asking. Chosen in the scope file
/// (overridable per run); defaults to the safest, `Assisted`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum Autonomy {
    /// Recon/scan/verify run freely; every state-changing action needs approval.
    #[default]
    Assisted,
    /// Runs autonomously; only the classes in `approval_for` need approval.
    Semi,
    /// Runs the whole loop with no prompts (scope + budget are the only guardrails).
    Auto,
}

impl Autonomy {
    pub fn parse(s: &str) -> Option<Autonomy> {
        match s.trim().to_ascii_lowercase().as_str() {
            "assisted" => Some(Autonomy::Assisted),
            "semi" | "semi-auto" | "semiauto" => Some(Autonomy::Semi),
            "auto" | "autonomous" => Some(Autonomy::Auto),
            _ => None,
        }
    }
}

/// The risk class of a tool action, used to decide whether approval is required.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActionClass {
    /// Read-only recon: spider, passive/active scan, static analysis, bounded probe.
    Recon,
    /// An action intended to exploit a vulnerability (state-changing payloads).
    Exploit,
    /// Remote code execution attempt.
    Rce,
    /// Data exfiltration attempt.
    Exfil,
}

impl ActionClass {
    fn keyword(self) -> &'static str {
        match self {
            ActionClass::Recon => "recon",
            ActionClass::Exploit => "exploit",
            ActionClass::Rce => "rce",
            ActionClass::Exfil => "exfil",
        }
    }
}

fn default_schemes() -> Vec<String> {
    vec!["http".into(), "https".into()]
}
fn default_rate() -> u32 {
    120
}

/// Per-run resource ceilings. Zero means "unlimited" for `max_tokens`.
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct Budget {
    pub max_requests: u32,
    pub max_turns: u32,
    pub max_tokens: u64,
}

impl Default for Budget {
    fn default() -> Self {
        Self {
            max_requests: 500,
            max_turns: 40,
            max_tokens: 0,
        }
    }
}

/// LLM brain configuration (provider-agnostic, OpenAI-compatible).
///
/// Works with any server that speaks OpenAI `/chat/completions`: OpenAI,
/// OpenRouter/Together/Groq, Anthropic & Gemini compat endpoints, and local
/// servers (Ollama, vLLM, LM Studio, llama.cpp). Local keyless servers just
/// omit `api_key_env`.
#[derive(Debug, Clone, Deserialize, Default)]
#[serde(default)]
pub struct ModelConfig {
    /// OpenAI-compatible base URL. Defaults to local Ollama (`http://localhost:11434/v1`).
    pub base_url: Option<String>,
    /// Model id (e.g. `qwen2.5-coder`, `gpt-4o-mini`, `claude-3-5-sonnet`).
    pub model: Option<String>,
    /// Env var holding the API key. Omit for keyless local servers.
    pub api_key_env: Option<String>,
    /// Request strict JSON output via `response_format` (helps open-source models
    /// that otherwise wrap actions in prose). Off by default for max compatibility.
    pub json_mode: bool,
}

/// Parsed, validated scope file.
#[derive(Debug, Clone, Deserialize)]
pub struct ScopeConfig {
    #[serde(default = "default_schemes")]
    pub allowed_schemes: Vec<String>,
    /// Allowed hosts. Exact (`api.example.com`) or suffix wildcard (`*.example.com`).
    /// Empty means "no host is in scope" — network tools will refuse.
    #[serde(default)]
    pub allowed_hosts: Vec<String>,
    /// Regex patterns; a URL whose path matches any is out of bounds.
    #[serde(default)]
    pub forbidden_paths: Vec<String>,
    #[serde(default = "default_rate")]
    pub max_requests_per_min: u32,
    #[serde(default)]
    pub autonomy: Autonomy,
    /// Action classes that always require approval in `Semi` mode.
    #[serde(default)]
    pub approval_for: Vec<String>,
    #[serde(default)]
    pub budget: Budget,
    #[serde(default)]
    pub model: ModelConfig,
    /// Opt-in Dark-Moon privacy tokenization: redact real hosts/secrets/emails/IPs
    /// before they reach the LLM, restore locally before tool execution. Off by
    /// default. Only applies to the `LlmBrain` (the scripted CI brain is offline).
    #[serde(default)]
    pub privacy: bool,

    /// Compiled `forbidden_paths` (built by `compile`, not deserialized).
    #[serde(skip)]
    forbidden_re: Vec<Regex>,
}

/// Why a URL was rejected by the scope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScopeVerdict {
    Allowed,
    BadUrl,
    SchemeNotAllowed,
    HostNotAllowed,
    ForbiddenPath,
}

impl ScopeVerdict {
    pub fn is_allowed(&self) -> bool {
        matches!(self, ScopeVerdict::Allowed)
    }
    pub fn reason(&self) -> &'static str {
        match self {
            ScopeVerdict::Allowed => "in scope",
            ScopeVerdict::BadUrl => "URL could not be parsed",
            ScopeVerdict::SchemeNotAllowed => "scheme not in allowed_schemes",
            ScopeVerdict::HostNotAllowed => "host not in allowed_hosts",
            ScopeVerdict::ForbiddenPath => "path matches a forbidden_paths pattern",
        }
    }
}

impl ScopeConfig {
    /// Load and validate a scope file (`.yaml`/`.yml`/`.json` — serde_yaml parses both).
    pub fn load(path: &Path) -> Result<Self> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("reading scope file {}", path.display()))?;
        let mut cfg: ScopeConfig = serde_yaml::from_str(&text)
            .with_context(|| format!("parsing scope file {}", path.display()))?;
        cfg.compile()?;
        Ok(cfg)
    }

    /// Compile the forbidden-path regexes. Called by `load`; also for hand-built
    /// configs in tests.
    pub fn compile(&mut self) -> Result<()> {
        self.forbidden_re.clear();
        for pat in &self.forbidden_paths {
            let re =
                Regex::new(pat).with_context(|| format!("invalid forbidden_paths regex: {pat}"))?;
            self.forbidden_re.push(re);
        }
        Ok(())
    }

    /// Decide whether `url` may be requested under this scope.
    pub fn check_url(&self, url: &str) -> ScopeVerdict {
        let Ok(parsed) = Url::parse(url) else {
            return ScopeVerdict::BadUrl;
        };
        let scheme = parsed.scheme().to_ascii_lowercase();
        if !self
            .allowed_schemes
            .iter()
            .any(|s| s.eq_ignore_ascii_case(&scheme))
        {
            return ScopeVerdict::SchemeNotAllowed;
        }
        let Some(host) = parsed.host_str() else {
            return ScopeVerdict::BadUrl;
        };
        if !self.host_allowed(host) {
            return ScopeVerdict::HostNotAllowed;
        }
        let path = parsed.path();
        if self.forbidden_re.iter().any(|re| re.is_match(path)) {
            return ScopeVerdict::ForbiddenPath;
        }
        ScopeVerdict::Allowed
    }

    fn host_allowed(&self, host: &str) -> bool {
        let host = host.to_ascii_lowercase();
        self.allowed_hosts.iter().any(|entry| {
            let entry = entry.trim().to_ascii_lowercase();
            if let Some(suffix) = entry.strip_prefix("*.") {
                host == suffix || host.ends_with(&format!(".{suffix}"))
            } else {
                host == entry
            }
        })
    }

    /// Whether an action of `class` requires human approval under the current
    /// autonomy mode.
    pub fn requires_approval(&self, class: ActionClass) -> bool {
        match self.autonomy {
            Autonomy::Auto => false,
            // Recon is always allowed without approval; anything else needs it.
            Autonomy::Assisted => !matches!(class, ActionClass::Recon),
            // Only the explicitly listed classes gate in semi-auto.
            Autonomy::Semi => {
                if matches!(class, ActionClass::Recon) {
                    return false;
                }
                let want = class.keyword();
                self.approval_for
                    .iter()
                    .any(|c| c.eq_ignore_ascii_case(want))
            }
        }
    }

    /// Override the autonomy mode (e.g. from a CLI flag).
    pub fn set_autonomy(&mut self, autonomy: Autonomy) {
        self.autonomy = autonomy;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scope() -> ScopeConfig {
        let mut c: ScopeConfig = serde_yaml::from_str(
            "allowed_hosts: [\"app.local\", \"*.example.com\"]\nforbidden_paths: [\"^/admin\"]\nautonomy: assisted\n",
        )
        .unwrap();
        c.compile().unwrap();
        c
    }

    #[test]
    fn host_exact_and_wildcard() {
        let c = scope();
        assert!(c.check_url("http://app.local/x").is_allowed());
        assert!(c.check_url("https://api.example.com/y").is_allowed());
        assert_eq!(
            c.check_url("http://evil.com/"),
            ScopeVerdict::HostNotAllowed
        );
    }

    #[test]
    fn forbidden_path_blocks() {
        let c = scope();
        assert_eq!(
            c.check_url("http://app.local/admin/users"),
            ScopeVerdict::ForbiddenPath
        );
    }

    #[test]
    fn scheme_must_be_allowed() {
        let c = scope();
        assert_eq!(
            c.check_url("ftp://app.local/x"),
            ScopeVerdict::SchemeNotAllowed
        );
    }

    #[test]
    fn empty_hosts_denies_everything() {
        let mut c: ScopeConfig = serde_yaml::from_str("autonomy: auto\n").unwrap();
        c.compile().unwrap();
        assert_eq!(c.check_url("http://x.com/"), ScopeVerdict::HostNotAllowed);
    }

    #[test]
    fn approval_matrix() {
        let mut c = scope(); // assisted
        assert!(!c.requires_approval(ActionClass::Recon));
        assert!(c.requires_approval(ActionClass::Exploit));
        c.set_autonomy(Autonomy::Auto);
        assert!(!c.requires_approval(ActionClass::Rce));
        c.set_autonomy(Autonomy::Semi);
        c.approval_for = vec!["rce".into()];
        assert!(c.requires_approval(ActionClass::Rce));
        assert!(!c.requires_approval(ActionClass::Exploit));
    }

    #[test]
    fn autonomy_parses() {
        assert_eq!(Autonomy::parse("assisted"), Some(Autonomy::Assisted));
        assert_eq!(Autonomy::parse("SEMI"), Some(Autonomy::Semi));
        assert_eq!(Autonomy::parse("autonomous"), Some(Autonomy::Auto));
        assert_eq!(Autonomy::parse("nope"), None);
    }
}
