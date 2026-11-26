//! Opt-in, **state-changing** authentication-lifecycle scenarios (#42, #52).
//!
//! Driven entirely by an operator-supplied YAML/JSON scenario describing the
//! application's real auth contract (login, reset, change-password, refresh,
//! logout, optional register/cleanup), how to extract session material from
//! responses, explicit success predicates, and the *expected* policy. Checks:
//!
//! - sessions surviving a password reset / change (two pre-existing sessions
//!   replayed after the mutation),
//! - passwords echoed in reset/registration responses and identical temporary
//!   credentials across resets (fixed-fallback signature),
//! - reset accepted with an absent/empty new-password field,
//! - reset-token single use and expiry,
//! - refresh-token rotation and logout revocation.
//!
//! A finding is `confirmed` only when observed before/after behaviour violates
//! the supplied policy; anything that cannot complete is reported as an `info`
//! "inconclusive" record, never as a vulnerability. Evidence lists only
//! request lines and statuses; every password/token/cookie seen is scrubbed.
//!
//! Safety: never part of the active plugin registry or any default `--plugins`
//! list. Runs only via `rustzap auth-lifecycle --auth-scenario FILE`, only when
//! the scenario declares a synthetic identity and acknowledges state changes,
//! never under `--read-only-safe`, and every request goes through
//! `HttpSafetyGate` and must target a host in `mutation_scope.hosts`.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use serde::Deserialize;
use serde_json::Value;
use url::Url;

use crate::safety::{HttpSafetyGate, SafetyPolicy};
use crate::types::{Finding, Severity};

/// Longest reset-token TTL we are willing to sleep through.
const MAX_TTL_WAIT_SECS: u64 = 900;
const OWASP_AUTH: &str = "A07:2021 – Identification and Authentication Failures";

pub type Vars = HashMap<String, String>;

// ─────────────────────────────────────────────────────────────────────────────
// Scenario schema
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Deserialize)]
pub struct Scenario {
    pub base_url: String,
    pub synthetic_identity: SyntheticIdentity,
    pub mutation_scope: MutationScope,
    /// Initial template variables; values may reference `${env:NAME}`.
    #[serde(default)]
    pub variables: BTreeMap<String, String>,
    #[serde(default)]
    pub policy: Policy,
    pub steps: Steps,
}

#[derive(Debug, Clone, Deserialize)]
pub struct SyntheticIdentity {
    pub username: String,
    /// Operator attests the account is synthetic / test-only.
    #[serde(default)]
    pub synthetic: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub struct MutationScope {
    #[serde(default)]
    pub acknowledge_state_changes: bool,
    /// Hosts requests may target (default: the `base_url` host).
    #[serde(default)]
    pub hosts: Vec<String>,
}

/// Expected behaviour. A check runs only when its policy is set.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct Policy {
    pub revoke_sessions_on_reset: Option<bool>,
    pub revoke_sessions_on_change: Option<bool>,
    pub revoke_session_on_logout: Option<bool>,
    pub refresh_revoked_on_logout: Option<bool>,
    pub refresh_rotation: Option<bool>,
    pub reset_token_single_use: Option<bool>,
    pub reset_token_ttl_secs: Option<u64>,
    pub reject_missing_new_password: Option<bool>,
    /// Body field holding the new password (default `new_password`).
    pub new_password_field: Option<String>,
    pub unique_temp_passwords: Option<bool>,
    /// Set when returning a (temporary) password in a response is by design.
    pub password_in_response_allowed: bool,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct Steps {
    pub login: Option<Op>,
    /// Authenticated request whose success predicate means "session is valid".
    pub session_check: Option<Op>,
    pub register: Option<Op>,
    /// Mints a reset token (e.g. into `reset_token`) before `reset`.
    pub reset_request: Option<Op>,
    pub reset: Option<Op>,
    pub change_password: Option<Op>,
    pub refresh: Option<Op>,
    pub logout: Option<Op>,
    /// Restores the synthetic account after every mutation.
    pub cleanup: Option<Op>,
}

/// One request, or a sequence (e.g. fetch CSRF form, then POST).
#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub enum Op {
    One(RequestSpec),
    Many(Vec<RequestSpec>),
}

impl Op {
    fn requests(&self) -> &[RequestSpec] {
        match self {
            Op::One(r) => std::slice::from_ref(r),
            Op::Many(v) => v,
        }
    }

    fn uses_var(&self, name: &str) -> bool {
        let needle = format!("${{{name}}}");
        self.requests().iter().any(|r| {
            r.url.contains(&needle)
                || r.body.as_deref().is_some_and(|b| b.contains(&needle))
                || r.headers.values().any(|v| v.contains(&needle))
        })
    }

    fn extracts(&self, name: &str) -> bool {
        self.requests().iter().any(|r| r.extract.contains_key(name))
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct RequestSpec {
    #[serde(default = "default_method")]
    pub method: String,
    pub url: String,
    #[serde(default)]
    pub headers: BTreeMap<String, String>,
    #[serde(default)]
    pub body: Option<String>,
    #[serde(default)]
    pub follow_redirects: bool,
    /// variable name → source (`json: /ptr`, `header: x`, `cookie: sid`, `regex: '...'`).
    #[serde(default)]
    pub extract: BTreeMap<String, Extract>,
    /// Default when omitted: any 2xx/3xx status.
    #[serde(default)]
    pub success: Option<Success>,
}

fn default_method() -> String {
    "GET".into()
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Extract {
    Json(String),
    Header(String),
    Cookie(String),
    Regex(String),
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct Success {
    pub status: Vec<u16>,
    pub body_contains: Option<String>,
}

pub fn load_scenario(path: &str) -> Result<Scenario> {
    let text = std::fs::read_to_string(path).with_context(|| format!("read scenario {path}"))?;
    // YAML is a superset of JSON, so this accepts both.
    serde_yaml::from_str(&text).with_context(|| format!("parse scenario {path}"))
}

/// Refuse unless the scenario explicitly opts in to mutating a synthetic account.
pub fn validate(sc: &Scenario, safety: &SafetyPolicy) -> Result<()> {
    if safety.read_only_safe {
        bail!(
            "auth-lifecycle scenarios change account state and are refused under --read-only-safe"
        );
    }
    if !sc.synthetic_identity.synthetic || sc.synthetic_identity.username.trim().is_empty() {
        bail!("scenario must declare `synthetic_identity: {{ username: ..., synthetic: true }}` — only run against operator-owned synthetic accounts");
    }
    if !sc.mutation_scope.acknowledge_state_changes {
        bail!("scenario must set `mutation_scope.acknowledge_state_changes: true` — these checks reset passwords and revoke sessions");
    }
    if sc.policy.reset_token_ttl_secs.unwrap_or(0) > MAX_TTL_WAIT_SECS {
        bail!("policy.reset_token_ttl_secs must be <= {MAX_TTL_WAIT_SECS}");
    }
    Url::parse(&sc.base_url).context("scenario base_url")?;
    Ok(())
}

/// Run every check the scenario's policy enables. Returns findings (violations,
/// inconclusive records, and a run log), all redacted.
pub async fn run(
    sc: &Scenario,
    safety: SafetyPolicy,
    insecure: bool,
    timeout_secs: u64,
) -> Result<Vec<Finding>> {
    validate(sc, &safety)?;
    let mut r = Runner::new(sc, safety, insecure, timeout_secs)?;
    r.run_all().await;
    Ok(r.finish())
}

/// CLI entry: load, run, print, and save a JSON (or `.sarif`) report.
pub async fn run_cli(
    path: &str,
    safety: SafetyPolicy,
    insecure: bool,
    timeout_secs: u64,
    output: &str,
) -> Result<()> {
    let sc = load_scenario(path)?;
    let start = Instant::now();
    let findings = run(&sc, safety, insecure, timeout_secs).await?;
    for f in &findings {
        println!(
            "  {} [{}] {} — {}",
            f.severity.color_str(),
            f.confidence.to_string().to_lowercase(),
            f.title,
            f.url
        );
    }
    let report =
        crate::report::Report::new(&sc.base_url, vec![], vec![], findings, start.elapsed());
    if output.ends_with(".sarif") {
        crate::sarif::write_sarif(&report, output)?;
    } else {
        report.save_json(output).await?;
    }
    println!("Report saved to: {output}");
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// Check metadata
// ─────────────────────────────────────────────────────────────────────────────

struct Check {
    title: &'static str,
    severity: Severity,
    plugin: &'static str,
    cwe: u32,
    solution: &'static str,
}

const SESSION_RESET: Check = Check {
    title: "Session Not Revoked After Password Reset",
    severity: Severity::High,
    plugin: "active/auth-session-not-revoked",
    cwe: 613,
    solution: "Invalidate every existing session and access token for the account when its password is reset (server-side session store / token version bump).",
};
const SESSION_CHANGE: Check = Check {
    title: "Session Not Revoked After Password Change",
    severity: Severity::High,
    plugin: "active/auth-session-not-revoked",
    cwe: 613,
    solution: "Invalidate all other sessions and tokens for the account when its password changes; re-issue only the caller's session if needed.",
};
const ECHO: Check = Check {
    title: "Password Returned in Response",
    severity: Severity::Medium,
    plugin: "active/auth-credential-echo",
    cwe: 200,
    solution: "Never return passwords (new, current, or temporary) in API responses; deliver temporary credentials out-of-band and force a change on first use.",
};
const PREDICTABLE: Check = Check {
    title: "Predictable Temporary Credential",
    severity: Severity::High,
    plugin: "active/auth-predictable-credential",
    cwe: 798,
    solution: "Generate temporary passwords with a CSPRNG per reset; remove any hard-coded fallback password.",
};
const MISSING_FIELD: Check = Check {
    title: "Password Reset Accepts Missing New Password",
    severity: Severity::High,
    plugin: "active/auth-missing-field-reset",
    cwe: 20,
    solution: "Reject reset/change requests whose new-password field is absent or empty (400) instead of falling back to a default.",
};
const TOKEN_REUSE: Check = Check {
    title: "Password Reset Token Reusable",
    severity: Severity::High,
    plugin: "active/auth-reset-token-reuse",
    cwe: 640,
    solution:
        "Mark reset tokens consumed atomically on first successful use and reject any replay.",
};
const TOKEN_EXPIRY: Check = Check {
    title: "Password Reset Token Does Not Expire",
    severity: Severity::Medium,
    plugin: "active/auth-reset-token-expiry",
    cwe: 640,
    solution: "Enforce a short server-side expiry on reset tokens and reject expired tokens.",
};
const REFRESH_ROTATION: Check = Check {
    title: "Refresh Token Not Rotated",
    severity: Severity::Medium,
    plugin: "active/auth-refresh-token",
    cwe: 613,
    solution: "Issue a new refresh token on every refresh and revoke the previous one (detect reuse and revoke the token family).",
};
const LOGOUT_SESSION: Check = Check {
    title: "Session Still Valid After Logout",
    severity: Severity::Medium,
    plugin: "active/auth-logout",
    cwe: 613,
    solution: "Invalidate the session / access token server-side on logout rather than only clearing it client-side.",
};
const LOGOUT_REFRESH: Check = Check {
    title: "Refresh Token Still Valid After Logout",
    severity: Severity::Medium,
    plugin: "active/auth-logout",
    cwe: 613,
    solution: "Revoke the refresh token (and its family) on logout.",
};

// ─────────────────────────────────────────────────────────────────────────────
// Runner
// ─────────────────────────────────────────────────────────────────────────────

struct Resp {
    status: u16,
    headers: reqwest::header::HeaderMap,
    body: String,
}

enum StepErr {
    /// Request completed but a success predicate / extraction failed.
    Failed(String),
    /// Could not send (template, scope, safety gate, transport).
    Error(String),
}

impl StepErr {
    fn msg(self) -> String {
        match self {
            StepErr::Failed(m) | StepErr::Error(m) => m,
        }
    }
}

struct Runner<'a> {
    sc: &'a Scenario,
    base_url: Url,
    hosts: Vec<String>,
    gate: HttpSafetyGate,
    follow: reqwest::Client,
    nofollow: reqwest::Client,
    base: Vars,
    secrets: Vec<String>,
    trace: Vec<String>,
    log: Vec<String>,
    reported: HashSet<String>,
    findings: Vec<Finding>,
}

impl<'a> Runner<'a> {
    fn new(sc: &'a Scenario, safety: SafetyPolicy, insecure: bool, timeout: u64) -> Result<Self> {
        let base_url = Url::parse(&sc.base_url)?;
        let mut hosts: Vec<String> = sc
            .mutation_scope
            .hosts
            .iter()
            .map(|h| h.trim().to_ascii_lowercase())
            .collect();
        if hosts.is_empty() {
            hosts.push(base_url.host_str().unwrap_or("").to_ascii_lowercase());
        }
        let build = |policy| {
            reqwest::Client::builder()
                .timeout(Duration::from_secs(timeout))
                .danger_accept_invalid_certs(insecure)
                .redirect(policy)
                .user_agent("RustZAP/0.1 (Security Scanner)")
                .build()
        };
        let mut r = Runner {
            sc,
            base_url,
            hosts,
            gate: HttpSafetyGate::new(safety),
            follow: build(reqwest::redirect::Policy::limited(10))?,
            nofollow: build(reqwest::redirect::Policy::none())?,
            base: Vars::new(),
            secrets: Vec::new(),
            trace: Vec::new(),
            log: Vec::new(),
            reported: HashSet::new(),
            findings: Vec::new(),
        };
        for (k, tpl) in &sc.variables {
            let v = render(tpl, &Vars::new()).map_err(anyhow::Error::msg)?;
            if tpl.contains("${env:") || is_secret_name(k) {
                r.add_secret(&v);
            }
            r.base.insert(k.clone(), v);
        }
        r.base
            .entry("username".into())
            .or_insert_with(|| sc.synthetic_identity.username.clone());
        Ok(r)
    }

    async fn run_all(&mut self) {
        let sc = self.sc;
        let p = &sc.policy;
        self.log.push(format!(
            "setup: synthetic identity `{}` (operator-declared), state changes acknowledged",
            sc.synthetic_identity.username
        ));
        if let Some(op) = &sc.steps.register {
            self.check_register(op).await;
        }
        if p.revoke_sessions_on_reset == Some(true) {
            self.check_revocation(true).await;
        }
        if p.revoke_sessions_on_change == Some(true) {
            self.check_revocation(false).await;
        }
        if p.reset_token_single_use == Some(true) {
            self.check_reset_single_use().await;
        }
        if let Some(ttl) = p.reset_token_ttl_secs {
            self.check_reset_expiry(ttl).await;
        }
        if p.unique_temp_passwords == Some(true) {
            self.check_unique_temp().await;
        }
        if p.reject_missing_new_password == Some(true) {
            self.check_missing_field().await;
        }
        if p.refresh_rotation == Some(true) {
            self.check_refresh_rotation().await;
        }
        if p.revoke_session_on_logout == Some(true) || p.refresh_revoked_on_logout == Some(true) {
            self.check_logout().await;
        }
    }

    fn finish(mut self) -> Vec<Finding> {
        let log = Finding::new(
            "Auth Lifecycle Scenario Run Log",
            Severity::Info,
            &self.sc.base_url,
            "Setup, per-check outcome, and cleanup results for the operator-supplied synthetic-identity scenario. Informational — not a vulnerability.",
            "Review cleanup failures: the synthetic account may have been left with a changed password or revoked sessions.",
            "active/auth-lifecycle",
        )
        .with_evidence(self.log.join("\n"));
        self.findings.push(log);

        self.secrets.sort_by_key(|s| std::cmp::Reverse(s.len()));
        let scrub = |s: &str| {
            let mut out = s.to_string();
            for sec in &self.secrets {
                out = out.replace(sec.as_str(), "[REDACTED]");
            }
            crate::agent::trace::redact_string(&out)
        };
        self.findings
            .iter()
            .map(|f| {
                let mut f = f.clone();
                f.title = scrub(&f.title);
                f.description = scrub(&f.description);
                f.url = scrub(&f.url);
                f.evidence = f.evidence.as_deref().map(scrub);
                f.parameter = f.parameter.as_deref().map(scrub);
                f
            })
            .collect()
    }

    fn add_secret(&mut self, v: &str) {
        if v.len() >= 4 && !self.secrets.iter().any(|s| s == v) {
            self.secrets.push(v.to_string());
        }
    }

    fn op_url(&self, op: &Op) -> String {
        op.requests()
            .last()
            .and_then(|r| self.base_url.join(&r.url).ok())
            .map(|u| u.to_string())
            .unwrap_or_else(|| self.sc.base_url.clone())
    }

    fn violation(&mut self, c: &Check, url: String, description: String, qualifier: &str) {
        let title = if qualifier.is_empty() {
            c.title.to_string()
        } else {
            format!("{} ({qualifier})", c.title)
        };
        if !self.reported.insert(title.clone()) {
            return;
        }
        self.log.push(format!("{title}: VIOLATION"));
        self.findings.push(
            Finding::new(
                &title,
                c.severity.clone(),
                url,
                description,
                c.solution,
                c.plugin,
            )
            .with_evidence(format!("Replay (redacted):\n{}", self.trace.join("\n")))
            .with_cwe(c.cwe)
            .with_owasp(OWASP_AUTH)
            .confirmed(),
        );
    }

    fn inconclusive(&mut self, check: &str, reason: String) {
        self.log.push(format!("{check}: INCONCLUSIVE — {reason}"));
        self.findings.push(
            Finding::new(
                format!("Auth Lifecycle Check Inconclusive: {check}"),
                Severity::Info,
                &self.sc.base_url,
                format!("The scenario could not complete this check, so no conclusion was drawn (not a vulnerability): {reason}"),
                "Fix the scenario (steps, extraction, success predicates) or the synthetic account state and re-run.",
                "active/auth-lifecycle",
            )
            .with_evidence(self.trace.join("\n"))
            .tentative(),
        );
    }

    fn pass(&mut self, check: &str, detail: &str) {
        self.log.push(format!("{check}: policy held — {detail}"));
    }

    // ── HTTP ────────────────────────────────────────────────────────────────

    async fn send(&mut self, label: &str, spec: &RequestSpec, vars: &Vars) -> Result<Resp, String> {
        let url = self
            .base_url
            .join(&render(&spec.url, vars)?)
            .map_err(|e| format!("{label}: bad url: {e}"))?;
        let host = url.host_str().unwrap_or("").to_ascii_lowercase();
        if !self.hosts.contains(&host) {
            return Err(format!(
                "{label}: host `{host}` is outside mutation_scope.hosts"
            ));
        }
        let method = reqwest::Method::from_bytes(spec.method.to_ascii_uppercase().as_bytes())
            .map_err(|_| format!("{label}: bad method `{}`", spec.method))?;
        let body = spec.body.as_deref().map(|b| render(b, vars)).transpose()?;
        self.gate
            .before_url_request(method.as_str(), url.as_str(), body.as_deref())
            .await
            .map_err(|e| format!("{label}: blocked by safety gate: {e}"))?;
        let client = if spec.follow_redirects {
            &self.follow
        } else {
            &self.nofollow
        };
        let mut req = client.request(method.clone(), url.clone());
        for (k, v) in &spec.headers {
            req = req.header(k.as_str(), render(v, vars)?);
        }
        if let Some(b) = body {
            req = req.body(b);
        }
        let start = Instant::now();
        let resp = req
            .send()
            .await
            .map_err(|e| format!("{label}: transport error: {e}"))?;
        let status = resp.status().as_u16();
        let headers = resp.headers().clone();
        let body = resp.text().await.unwrap_or_default();
        let _ = self
            .gate
            .after_response(status, start.elapsed().as_millis() as u64);
        let q = if url.query().is_some() { "?…" } else { "" };
        self.trace
            .push(format!("{label}: {method} {}{q} -> {status}", url.path()));
        Ok(Resp {
            status,
            headers,
            body,
        })
    }

    async fn run_op(&mut self, label: &str, op: &Op, vars: &mut Vars) -> Result<Resp, StepErr> {
        let mut last = None;
        for spec in op.requests() {
            let resp = self.send(label, spec, vars).await.map_err(StepErr::Error)?;
            if !success_matches(spec.success.as_ref(), &resp) {
                return Err(StepErr::Failed(format!(
                    "{label}: HTTP {} did not satisfy the success predicate",
                    resp.status
                )));
            }
            for (name, ex) in &spec.extract {
                match extract(ex, &resp) {
                    Some(v) => {
                        self.add_secret(&v);
                        vars.insert(name.clone(), v);
                    }
                    None => {
                        return Err(StepErr::Failed(format!(
                            "{label}: could not extract `{name}`"
                        )))
                    }
                }
            }
            last = Some(resp);
        }
        last.ok_or_else(|| StepErr::Error(format!("{label}: no requests configured")))
    }

    /// `Ok(true)` when the op's success predicates all pass.
    async fn accepted(&mut self, label: &str, op: &Op, vars: &Vars) -> Result<bool, String> {
        let mut v = vars.clone();
        match self.run_op(label, op, &mut v).await {
            Ok(_) => Ok(true),
            Err(StepErr::Failed(_)) => Ok(false),
            Err(StepErr::Error(e)) => Err(e),
        }
    }

    async fn alive(&mut self, label: &str, vars: &Vars) -> Result<bool, String> {
        let op = self
            .sc
            .steps
            .session_check
            .as_ref()
            .ok_or("no `session_check` step configured")?;
        self.accepted(label, op, vars).await
    }

    async fn login(&mut self) -> Result<Vars, String> {
        let op = self
            .sc
            .steps
            .login
            .as_ref()
            .ok_or("no `login` step configured")?;
        let mut v = self.base.clone();
        self.run_op("login", op, &mut v)
            .await
            .map_err(StepErr::msg)?;
        Ok(v)
    }

    /// Vars for an actor performing a reset: a logged-in session if `login`
    /// is configured (admin/self reset), otherwise the base variables.
    async fn actor(&mut self) -> Result<Vars, String> {
        if self.sc.steps.login.is_some() {
            self.login().await
        } else {
            Ok(self.base.clone())
        }
    }

    async fn do_reset(&mut self, vars: &mut Vars) -> Result<Resp, StepErr> {
        let sc = self.sc;
        if let Some(rr) = &sc.steps.reset_request {
            self.run_op("reset_request", rr, vars).await?;
        }
        let op = sc
            .steps
            .reset
            .as_ref()
            .ok_or_else(|| StepErr::Error("no `reset` step configured".into()))?;
        self.run_op("reset", op, vars).await
    }

    async fn cleanup(&mut self, after: &str) {
        let sc = self.sc;
        match &sc.steps.cleanup {
            Some(op) => {
                let mut v = self.base.clone();
                match self.run_op("cleanup", op, &mut v).await {
                    Ok(_) => self.log.push(format!("cleanup after {after}: ok")),
                    Err(e) => self
                        .log
                        .push(format!("cleanup after {after}: FAILED — {}", e.msg())),
                }
            }
            None => self.log.push(format!(
                "cleanup after {after}: no cleanup step configured — synthetic account left mutated"
            )),
        }
    }

    /// Report (once per `kind`) a password visible in `resp`; returns it.
    fn inspect_echo(
        &mut self,
        kind: &str,
        url: String,
        resp: &Resp,
        vars: &Vars,
    ) -> Option<String> {
        let leaked = leaked_password(resp, vars)?;
        self.add_secret(&leaked);
        if !self.sc.policy.password_in_response_allowed {
            self.violation(
                &ECHO,
                url,
                format!("The `{kind}` response body contains a password value (HTTP {}). Anyone who can read the response or its logs obtains the credential.", resp.status),
                kind,
            );
        }
        Some(leaked)
    }

    // ── Checks ──────────────────────────────────────────────────────────────

    async fn check_register(&mut self, op: &Op) {
        self.trace.clear();
        let mut v = self.base.clone();
        match self.run_op("register", op, &mut v).await {
            Ok(resp) => {
                self.log.push("setup: register ok".into());
                let url = self.op_url(op);
                self.inspect_echo("register", url, &resp, &v);
            }
            Err(e) => self
                .log
                .push(format!("setup: register failed — {}", e.msg())),
        }
    }

    async fn check_revocation(&mut self, reset: bool) {
        let sc = self.sc;
        let (kind, check, info, op) = if reset {
            (
                "reset",
                "session revocation after reset",
                &SESSION_RESET,
                sc.steps.reset.as_ref(),
            )
        } else {
            (
                "change_password",
                "session revocation after password change",
                &SESSION_CHANGE,
                sc.steps.change_password.as_ref(),
            )
        };
        self.trace.clear();
        let Some(op) = op else {
            return self.inconclusive(check, format!("no `{kind}` step configured"));
        };
        let mut sessions = Vec::new();
        for i in 1..=2 {
            let s = match self.login().await {
                Ok(s) => s,
                Err(e) => return self.inconclusive(check, e),
            };
            match self
                .alive(&format!("session_check #{i} (before)"), &s)
                .await
            {
                Ok(true) => sessions.push(s),
                Ok(false) => {
                    return self.inconclusive(
                        check,
                        "a fresh session was not accepted by session_check — no baseline".into(),
                    )
                }
                Err(e) => return self.inconclusive(check, e),
            }
        }
        let mut v = sessions[0].clone();
        let res = if reset {
            self.do_reset(&mut v).await
        } else {
            self.run_op(kind, op, &mut v).await
        };
        let resp = match res {
            Ok(r) => r,
            Err(e) => {
                self.cleanup(check).await;
                return self.inconclusive(check, e.msg());
            }
        };
        let url = self.op_url(op);
        self.inspect_echo(kind, url.clone(), &resp, &v);
        let mut survived = Vec::new();
        for (i, s) in sessions.iter().enumerate() {
            match self
                .alive(&format!("replay old session #{} (after {kind})", i + 1), s)
                .await
            {
                Ok(true) => survived.push(i + 1),
                Ok(false) => {}
                Err(e) => {
                    self.cleanup(check).await;
                    return self.inconclusive(check, e);
                }
            }
        }
        if survived.is_empty() {
            self.pass(check, "both pre-existing sessions were rejected");
        } else {
            self.violation(
                info,
                url,
                format!("Two sessions were established and accepted by session_check, then `{kind}` succeeded. Replaying the old session(s) {survived:?} afterwards was still accepted, violating the scenario policy that existing sessions are revoked."),
                "",
            );
        }
        self.cleanup(check).await;
    }

    async fn check_reset_single_use(&mut self) {
        let check = "reset-token single use";
        self.trace.clear();
        let Some(op) = self.sc.steps.reset.as_ref() else {
            return self.inconclusive(check, "no `reset` step configured".into());
        };
        if !op.uses_var("reset_token") {
            return self.inconclusive(
                check,
                "the `reset` step does not use ${reset_token}; the scenario provides no reset token".into(),
            );
        }
        let mut v = match self.actor().await {
            Ok(v) => v,
            Err(e) => return self.inconclusive(check, e),
        };
        if let Err(e) = self.do_reset(&mut v).await {
            self.cleanup(check).await;
            return self.inconclusive(check, e.msg());
        }
        let replay = self.accepted("reset (token replayed)", op, &v).await;
        match replay {
            Ok(true) => {
                let url = self.op_url(op);
                self.violation(&TOKEN_REUSE, url, "A password reset succeeded, then the same reset token was submitted again and the reset was accepted a second time, violating the single-use policy.".into(), "");
            }
            Ok(false) => self.pass(check, "replayed reset token was rejected"),
            Err(e) => self.inconclusive(check, e),
        }
        self.cleanup(check).await;
    }

    async fn check_reset_expiry(&mut self, ttl: u64) {
        let check = "reset-token expiry";
        self.trace.clear();
        let sc = self.sc;
        let (Some(rr), Some(op)) = (&sc.steps.reset_request, &sc.steps.reset) else {
            return self.inconclusive(
                check,
                "needs both `reset_request` (mints a token) and `reset` steps".into(),
            );
        };
        let mut v = match self.actor().await {
            Ok(v) => v,
            Err(e) => return self.inconclusive(check, e),
        };
        if let Err(e) = self.run_op("reset_request", rr, &mut v).await {
            return self.inconclusive(check, e.msg());
        }
        self.log.push(format!(
            "{check}: waiting {}s past the declared TTL",
            ttl + 1
        ));
        tokio::time::sleep(Duration::from_secs(ttl + 1)).await;
        match self.accepted("reset (token past TTL)", op, &v).await {
            Ok(true) => {
                let url = self.op_url(op);
                self.violation(&TOKEN_EXPIRY, url, format!("A reset token was used {}s after issue (declared TTL {ttl}s) and the reset was accepted.", ttl + 1), "");
            }
            Ok(false) => self.pass(check, "token past TTL was rejected"),
            Err(e) => self.inconclusive(check, e),
        }
        self.cleanup(check).await;
    }

    async fn check_unique_temp(&mut self) {
        let check = "temporary credential uniqueness";
        self.trace.clear();
        let Some(op) = self.sc.steps.reset.as_ref() else {
            return self.inconclusive(check, "no `reset` step configured".into());
        };
        let url = self.op_url(op);
        let mut seen = Vec::new();
        for _ in 0..2 {
            let mut v = match self.actor().await {
                Ok(v) => v,
                Err(e) => return self.inconclusive(check, e),
            };
            match self.do_reset(&mut v).await {
                Ok(resp) => {
                    let echoed = self.inspect_echo("reset", url.clone(), &resp, &v);
                    let temp = v
                        .get("temp_password")
                        .cloned()
                        .or(echoed)
                        .filter(|t| Some(t) != v.get("new_password"));
                    seen.push(temp);
                }
                Err(e) => {
                    self.cleanup(check).await;
                    return self.inconclusive(check, e.msg());
                }
            }
            self.cleanup(check).await;
        }
        match (&seen[0], &seen[1]) {
            (Some(a), Some(b)) if a == b => self.violation(&PREDICTABLE, url, "Two consecutive resets returned the identical temporary password — a fixed/hard-coded fallback credential.".into(), ""),
            (Some(_), Some(_)) => self.pass(check, "temporary credentials differed"),
            _ => self.pass(check, "no temporary credential exposed; uniqueness not observable"),
        }
    }

    async fn check_missing_field(&mut self) {
        let check = "reset with missing new password";
        self.trace.clear();
        let sc = self.sc;
        let field = sc
            .policy
            .new_password_field
            .clone()
            .unwrap_or_else(|| "new_password".into());
        let Some(op) = sc.steps.reset.as_ref() else {
            return self.inconclusive(check, "no `reset` step configured".into());
        };
        let url = self.op_url(op);
        let mut accepted = Vec::new();
        let mut temps = Vec::new();
        for (empty, variant) in [(false, "absent"), (true, "empty")] {
            let Some(mutated) = mutate_op(op, &field, empty) else {
                return self.inconclusive(
                    check,
                    format!(
                        "could not find `{field}` in the reset body (JSON object or form-encoded)"
                    ),
                );
            };
            let mut v = match self.actor().await {
                Ok(v) => v,
                Err(e) => return self.inconclusive(check, e),
            };
            if let Some(rr) = &sc.steps.reset_request {
                if let Err(e) = self.run_op("reset_request", rr, &mut v).await {
                    return self.inconclusive(check, e.msg());
                }
            }
            match self
                .run_op(&format!("reset ({variant} {field})"), &mutated, &mut v)
                .await
            {
                Ok(resp) => {
                    accepted.push(variant);
                    temps.push(self.inspect_echo("reset", url.clone(), &resp, &v));
                    self.cleanup(check).await;
                }
                Err(StepErr::Failed(_)) => {}
                Err(StepErr::Error(e)) => return self.inconclusive(check, e),
            }
        }
        if accepted.is_empty() {
            return self.pass(check, "absent and empty values were rejected");
        }
        self.violation(
            &MISSING_FIELD,
            url.clone(),
            format!("The reset endpoint returned 2xx with `{field}` {}. The account password was changed to a server-chosen value or left unset.", accepted.join(" and ")),
            "",
        );
        if temps.len() == 2 && temps[0].is_some() && temps[0] == temps[1] {
            self.violation(&PREDICTABLE, url, "Resets with an absent and an empty new password both returned the identical temporary password — a hard-coded fallback credential.".into(), "");
        }
    }

    async fn check_refresh_rotation(&mut self) {
        let check = "refresh-token rotation";
        self.trace.clear();
        let Some(op) = self.sc.steps.refresh.as_ref() else {
            return self.inconclusive(check, "no `refresh` step configured".into());
        };
        if !op.uses_var("refresh_token") {
            return self.inconclusive(
                check,
                "the `refresh` step does not use ${refresh_token}".into(),
            );
        }
        let s = match self.login().await {
            Ok(s) => s,
            Err(e) => return self.inconclusive(check, e),
        };
        let Some(old) = s.get("refresh_token").cloned() else {
            return self.inconclusive(check, "login did not extract `refresh_token`".into());
        };
        let mut v = s.clone();
        if let Err(e) = self.run_op("refresh", op, &mut v).await {
            return self.inconclusive(check, e.msg());
        }
        let same_issued = op.extracts("refresh_token") && v.get("refresh_token") == Some(&old);
        match self.accepted("refresh (old token replayed)", op, &s).await {
            Ok(replayed) if same_issued || replayed => {
                let url = self.op_url(op);
                let why = if same_issued {
                    "the refresh response returned the same refresh token"
                } else {
                    "the previous refresh token was still accepted after a refresh"
                };
                self.violation(
                    &REFRESH_ROTATION,
                    url,
                    format!("Policy requires refresh-token rotation, but {why}."),
                    "",
                );
            }
            Ok(_) => self.pass(check, "refresh token rotated and old token rejected"),
            Err(e) => self.inconclusive(check, e),
        }
    }

    async fn check_logout(&mut self) {
        let check = "logout revocation";
        self.trace.clear();
        let sc = self.sc;
        let Some(op) = sc.steps.logout.as_ref() else {
            return self.inconclusive(check, "no `logout` step configured".into());
        };
        let s = match self.login().await {
            Ok(s) => s,
            Err(e) => return self.inconclusive(check, e),
        };
        let check_session = sc.policy.revoke_session_on_logout == Some(true);
        if check_session {
            match self.alive("session_check (before logout)", &s).await {
                Ok(true) => {}
                Ok(false) => {
                    return self
                        .inconclusive(check, "fresh session not accepted by session_check".into())
                }
                Err(e) => return self.inconclusive(check, e),
            }
        }
        if let Err(e) = self.run_op("logout", op, &mut s.clone()).await {
            return self.inconclusive(check, e.msg());
        }
        let url = self.op_url(op);
        if check_session {
            match self.alive("replay session (after logout)", &s).await {
                Ok(true) => self.violation(&LOGOUT_SESSION, url.clone(), "After a successful logout, replaying the logged-out session was still accepted by session_check.".into(), ""),
                Ok(false) => self.pass(check, "logged-out session rejected"),
                Err(e) => self.inconclusive(check, e),
            }
        }
        if sc.policy.refresh_revoked_on_logout == Some(true) {
            let Some(refresh) = sc.steps.refresh.as_ref() else {
                return self.inconclusive(check, "no `refresh` step configured".into());
            };
            match self.accepted("refresh (after logout)", refresh, &s).await {
                Ok(true) => self.violation(&LOGOUT_REFRESH, url, "After a successful logout, the session's refresh token still minted new tokens.".into(), ""),
                Ok(false) => self.pass(check, "refresh token rejected after logout"),
                Err(e) => self.inconclusive(check, e),
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Substitute `${var}` / `${env:NAME}`; a missing variable is an error.
fn render(tpl: &str, vars: &Vars) -> Result<String, String> {
    let mut out = String::with_capacity(tpl.len());
    let mut rest = tpl;
    while let Some(start) = rest.find("${") {
        out.push_str(&rest[..start]);
        let after = &rest[start + 2..];
        let end = after
            .find('}')
            .ok_or_else(|| "unterminated `${` in template".to_string())?;
        let name = &after[..end];
        let val = match name.strip_prefix("env:") {
            Some(env) => std::env::var(env)
                .map_err(|_| format!("environment variable `{env}` is not set"))?,
            None => vars
                .get(name)
                .cloned()
                .ok_or_else(|| format!("variable `{name}` is not set"))?,
        };
        out.push_str(&val);
        rest = &after[end + 1..];
    }
    out.push_str(rest);
    Ok(out)
}

fn is_secret_name(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    [
        "pass", "pwd", "token", "secret", "cookie", "csrf", "session", "sid", "key", "otp",
    ]
    .iter()
    .any(|s| n.contains(s))
}

fn success_matches(s: Option<&Success>, resp: &Resp) -> bool {
    let Some(s) = s else {
        return (200..400).contains(&resp.status);
    };
    let status_ok = if s.status.is_empty() {
        (200..400).contains(&resp.status)
    } else {
        s.status.contains(&resp.status)
    };
    status_ok
        && s.body_contains
            .as_deref()
            .is_none_or(|needle| resp.body.contains(needle))
}

fn extract(ex: &Extract, resp: &Resp) -> Option<String> {
    let v = match ex {
        Extract::Json(ptr) => {
            let json: Value = serde_json::from_str(&resp.body).ok()?;
            match json.pointer(ptr)? {
                Value::String(s) => s.clone(),
                Value::Null => return None,
                other => other.to_string(),
            }
        }
        Extract::Header(name) => resp.headers.get(name.as_str())?.to_str().ok()?.to_string(),
        Extract::Cookie(name) => resp
            .headers
            .get_all(reqwest::header::SET_COOKIE)
            .iter()
            .filter_map(|h| h.to_str().ok())
            .find_map(|c| {
                let (k, v) = c.split(';').next()?.split_once('=')?;
                (k.trim() == name.as_str()).then(|| v.trim().to_string())
            })?,
        Extract::Regex(pat) => {
            let caps = regex::Regex::new(pat).ok()?.captures(&resp.body)?;
            caps.get(1).or_else(|| caps.get(0))?.as_str().to_string()
        }
    };
    (!v.is_empty()).then_some(v)
}

/// A password visible in the response: a known password variable echoed
/// verbatim, or a non-trivial string under a `*password*` JSON key.
fn leaked_password(resp: &Resp, vars: &Vars) -> Option<String> {
    for k in ["new_password", "password"] {
        if let Some(p) = vars.get(k).filter(|p| p.len() >= 4) {
            if resp.body.contains(p.as_str()) {
                return Some(p.clone());
            }
        }
    }
    let json: Value = serde_json::from_str(&resp.body).ok()?;
    find_password_field(&json)
}

fn find_password_field(v: &Value) -> Option<String> {
    match v {
        Value::Object(m) => m.iter().find_map(|(k, val)| match val {
            Value::String(s) if is_password_key(k) && is_credential_like(s) => Some(s.clone()),
            other => find_password_field(other),
        }),
        Value::Array(a) => a.iter().find_map(find_password_field),
        _ => None,
    }
}

fn is_password_key(k: &str) -> bool {
    let k = k.to_ascii_lowercase();
    k.contains("password") || k.contains("passwd") || k == "pwd"
}

fn is_credential_like(s: &str) -> bool {
    let l = s.to_ascii_lowercase();
    s.len() >= 4
        && ![
            "true", "false", "changed", "updated", "reset", "success", "required",
        ]
        .contains(&l.as_str())
}

/// Copy of `op` whose final request drops (`empty=false`) or blanks
/// (`empty=true`) `field`, and whose success predicate is "any 2xx".
fn mutate_op(op: &Op, field: &str, empty: bool) -> Option<Op> {
    let mut reqs = op.requests().to_vec();
    let last = reqs.last_mut()?;
    let body = last.body.as_deref()?;
    let new_body = if let Ok(Value::Object(mut m)) = serde_json::from_str::<Value>(body) {
        if !m.contains_key(field) {
            return None;
        }
        if empty {
            m.insert(field.into(), Value::String(String::new()));
        } else {
            m.remove(field);
        }
        Value::Object(m).to_string()
    } else if body.split('&').any(|p| p.split('=').next() == Some(field)) {
        body.split('&')
            .filter_map(|p| match p.split('=').next() == Some(field) {
                true if empty => Some(format!("{field}=")),
                true => None,
                false => Some(p.to_string()),
            })
            .collect::<Vec<_>>()
            .join("&")
    } else {
        return None;
    };
    last.body = Some(new_body);
    last.extract.clear();
    last.success = Some(Success {
        status: (200..300).collect(),
        body_contains: None,
    });
    Some(Op::Many(reqs))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn render_substitutes_and_rejects_missing() {
        let mut v = Vars::new();
        v.insert("t".into(), "abc".into());
        assert_eq!(render("Bearer ${t}", &v).unwrap(), "Bearer abc");
        assert!(render("${missing}", &v).is_err());
    }

    #[test]
    fn mutate_op_json_and_form() {
        let spec = |body: &str| RequestSpec {
            method: "POST".into(),
            url: "/reset".into(),
            headers: BTreeMap::new(),
            body: Some(body.into()),
            follow_redirects: false,
            extract: BTreeMap::new(),
            success: None,
        };
        let op = Op::One(spec(r#"{"token":"${t}","new_password":"${p}"}"#));
        let Op::Many(r) = mutate_op(&op, "new_password", false).unwrap() else {
            panic!()
        };
        assert!(!r[0].body.as_ref().unwrap().contains("new_password"));
        let op = Op::One(spec("token=${t}&new_password=${p}"));
        let Op::Many(r) = mutate_op(&op, "new_password", true).unwrap() else {
            panic!()
        };
        assert_eq!(r[0].body.as_deref(), Some("token=${t}&new_password="));
        assert!(mutate_op(&op, "nope", true).is_none());
    }

    #[test]
    fn password_field_detection_ignores_status_words() {
        let j: Value =
            serde_json::from_str(r#"{"password_changed":"true","temp_password":"Xy9!abc"}"#)
                .unwrap();
        assert_eq!(find_password_field(&j).as_deref(), Some("Xy9!abc"));
    }
}
