//! Execution coverage (#41): which endpoint × method × plugin checks actually
//! ran, so "zero findings" is distinguishable from "check never completed".
//!
//! Request counts are observed through [`crate::safety::HttpSafetyGate`] via a
//! task-local [`ExecCounters`] that `ActiveScanner::scan_all` scopes around each
//! plugin run — plugins themselves are not instrumented.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};

/// Outcome of one check (plugin run against one endpoint/method).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    CompletedNoFinding,
    Finding,
    Inapplicable,
    AuthRequired,
    Throttled,
    Skipped,
    Error,
}

impl std::fmt::Display for Outcome {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = serde_json::to_value(self)
            .ok()
            .and_then(|v| v.as_str().map(str::to_string))
            .unwrap_or_default();
        f.write_str(&s)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutionRecord {
    pub endpoint: String,
    pub method: String,
    pub plugin: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity: Option<String>,
    pub requests_attempted: usize,
    pub requests_completed: usize,
    pub outcome: Outcome,
    /// Why the check did not complete cleanly. Non-empty for every outcome
    /// other than `completed_no_finding` / `finding`.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub reason: String,
}

/// Source-analysis limit that was hit (file walk or per-analyzer finding cap).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OmittedRecord {
    pub source: String,
    pub limit: usize,
    /// Items dropped, when known. `None` = the analyzer stopped early, so the
    /// remainder was never counted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub omitted: Option<usize>,
    pub reason: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScanStatus {
    Completed,
    Partial,
}

/// Outcome of one assessment input (#19): DAST, container image, dependencies.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InputOutcome {
    Assessed,
    /// The operator supplied no input for this part — it was NOT assessed.
    MissingInput,
    Skipped,
    Failed,
}

impl std::fmt::Display for InputOutcome {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            InputOutcome::Assessed => "assessed",
            InputOutcome::MissingInput => "missing_input",
            InputOutcome::Skipped => "skipped",
            InputOutcome::Failed => "failed",
        })
    }
}

/// What was (or was not) assessed for one input of a unified `scan`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AssessmentInput {
    /// `dast`, `image`, or `dependencies`.
    pub kind: String,
    pub outcome: InputOutcome,
    /// Image reference, lockfile path, imported JSON path, or target URL.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool: Option<String>,
    /// Exit code of the external tool when it ran and failed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exit_status: Option<i32>,
    /// Redacted reason for any outcome other than `assessed`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub diagnostic: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub image_digest: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub repository_revision: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vulnerability_db_updated_at: Option<String>,
    #[serde(default)]
    pub findings: usize,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Coverage {
    pub status: ScanStatus,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub records: Vec<ExecutionRecord>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub omitted: Vec<OmittedRecord>,
    /// Unified-assessment inputs (#19); absent on reports that predate it.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub inputs: Vec<AssessmentInput>,
}

impl Coverage {
    /// Status comes from execution records and omissions only — never from
    /// finding counts.
    pub fn new(records: Vec<ExecutionRecord>, omitted: Vec<OmittedRecord>) -> Self {
        let incomplete = records.iter().any(|r| match r.outcome {
            Outcome::AuthRequired | Outcome::Throttled | Outcome::Error => true,
            // Gate-blocked requests count as attempted; a config skip (e.g. the
            // no-query-string gate) sent nothing and is by design, not a gap.
            Outcome::Skipped => r.requests_attempted > 0,
            _ => false,
        });
        Coverage {
            status: if incomplete || !omitted.is_empty() {
                ScanStatus::Partial
            } else {
                ScanStatus::Completed
            },
            records,
            omitted,
            inputs: Vec::new(),
        }
    }

    /// Attach assessment inputs; a `failed` input makes the run `partial`.
    pub fn with_inputs(mut self, inputs: Vec<AssessmentInput>) -> Self {
        if inputs.iter().any(|i| i.outcome == InputOutcome::Failed) {
            self.status = ScanStatus::Partial;
        }
        self.inputs = inputs;
        self
    }

    pub fn outcome_counts(&self) -> BTreeMap<Outcome, usize> {
        let mut m = BTreeMap::new();
        for r in &self.records {
            *m.entry(r.outcome).or_insert(0) += 1;
        }
        m
    }

    /// One-line summary: `partial — completed_no_finding=3 error=1 …`.
    pub fn summary_line(&self) -> String {
        let status = match self.status {
            ScanStatus::Completed => "completed",
            ScanStatus::Partial => "partial",
        };
        let mut s = format!("{status} — {} check(s)", self.records.len());
        for (o, n) in self.outcome_counts() {
            s.push_str(&format!(" {o}={n}"));
        }
        if !self.omitted.is_empty() {
            s.push_str(&format!(" omitted_limits={}", self.omitted.len()));
        }
        s
    }
}

/// Per-plugin-run request counters, filled by `HttpSafetyGate`.
#[derive(Debug, Default)]
pub struct ExecCounters {
    attempted: AtomicUsize,
    blocked: AtomicUsize,
    completed: AtomicUsize,
    auth: AtomicUsize,
    throttled: AtomicUsize,
    block_reason: Mutex<Option<String>>,
}

tokio::task_local! {
    static EXEC: Arc<ExecCounters>;
}

/// Run `fut` with fresh counters; returns its output and the counters.
pub async fn with_counters<F: std::future::Future>(fut: F) -> (F::Output, Arc<ExecCounters>) {
    let c = Arc::new(ExecCounters::default());
    let out = EXEC.scope(c.clone(), fut).await;
    (out, c)
}

/// Gate hook: a request reached `before_*`; `blocked` holds the abort reason.
pub fn note_before(blocked: Option<String>) {
    let _ = EXEC.try_with(|c| {
        c.attempted.fetch_add(1, Ordering::SeqCst);
        if let Some(reason) = blocked {
            c.blocked.fetch_add(1, Ordering::SeqCst);
            if let Ok(mut r) = c.block_reason.lock() {
                r.get_or_insert(reason);
            }
        }
    });
}

/// Gate hook: a response arrived with `status`.
pub fn note_response(status: u16) {
    let _ = EXEC.try_with(|c| {
        c.completed.fetch_add(1, Ordering::SeqCst);
        match status {
            401 | 403 => c.auth.fetch_add(1, Ordering::SeqCst),
            // shortcut: the gate sees only the status, so 503+Retry-After is not
            // distinguishable from a plain 503; only 429 counts as throttling.
            429 => c.throttled.fetch_add(1, Ordering::SeqCst),
            _ => 0,
        };
    });
}

impl ExecCounters {
    /// Classify one plugin run. A finding wins; otherwise the first failure
    /// mode found (throttle, transport error, auth, gate skip) is reported.
    pub fn record(
        &self,
        endpoint: &str,
        method: &str,
        plugin: &str,
        found: bool,
    ) -> ExecutionRecord {
        let attempted = self.attempted.load(Ordering::SeqCst);
        let blocked = self.blocked.load(Ordering::SeqCst);
        let completed = self.completed.load(Ordering::SeqCst);
        let auth = self.auth.load(Ordering::SeqCst);
        let throttled = self.throttled.load(Ordering::SeqCst);
        // Passed the gate but never produced a response: transport error/timeout.
        let failed = attempted.saturating_sub(blocked + completed);
        let (outcome, reason) = if found {
            (Outcome::Finding, String::new())
        } else if throttled > 0 {
            (
                Outcome::Throttled,
                format!("{throttled} of {completed} response(s) were HTTP 429"),
            )
        } else if failed > 0 {
            (
                Outcome::Error,
                format!("{failed} of {attempted} request(s) failed (transport error or timeout)"),
            )
        } else if completed > 0 && auth == completed {
            (
                Outcome::AuthRequired,
                format!("all {completed} response(s) were HTTP 401/403"),
            )
        } else if blocked > 0 {
            let why = self
                .block_reason
                .lock()
                .ok()
                .and_then(|r| r.clone())
                .unwrap_or_default();
            (
                Outcome::Skipped,
                format!("{blocked} of {attempted} request(s) blocked by safety gate: {why}"),
            )
        } else if attempted == 0 {
            (
                Outcome::Inapplicable,
                "plugin sent no requests through the safety gate (nothing applicable to test)"
                    .to_string(),
            )
        } else {
            (Outcome::CompletedNoFinding, String::new())
        };
        ExecutionRecord {
            endpoint: endpoint.to_string(),
            method: method.to_string(),
            plugin: plugin.to_string(),
            identity: None,
            requests_attempted: attempted,
            requests_completed: completed,
            outcome,
            reason,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rec(outcome: Outcome, attempted: usize) -> ExecutionRecord {
        ExecutionRecord {
            endpoint: "http://x/".into(),
            method: "GET".into(),
            plugin: "active/xss".into(),
            identity: None,
            requests_attempted: attempted,
            requests_completed: 0,
            outcome,
            reason: "r".into(),
        }
    }

    #[test]
    fn status_ignores_findings_and_config_skips() {
        let c = Coverage::new(
            vec![rec(Outcome::Finding, 1), rec(Outcome::Skipped, 0)],
            vec![],
        );
        assert_eq!(c.status, ScanStatus::Completed);
        let c = Coverage::new(vec![rec(Outcome::Skipped, 2)], vec![]);
        assert_eq!(c.status, ScanStatus::Partial);
        let c = Coverage::new(vec![rec(Outcome::Error, 1)], vec![]);
        assert_eq!(c.status, ScanStatus::Partial);
        assert!(c.summary_line().starts_with("partial"));
    }

    #[tokio::test]
    async fn counters_classify_timeout_as_error() {
        let ((), c) = with_counters(async {
            note_before(None);
            note_before(None);
            note_response(200);
        })
        .await;
        let r = c.record("u", "GET", "p", false);
        assert_eq!(r.outcome, Outcome::Error);
        assert_eq!((r.requests_attempted, r.requests_completed), (2, 1));
        assert!(!r.reason.is_empty());
    }

    #[test]
    fn outcome_serializes_snake_case() {
        assert_eq!(Outcome::AuthRequired.to_string(), "auth_required");
        assert_eq!(
            serde_json::to_string(&Outcome::CompletedNoFinding).unwrap(),
            "\"completed_no_finding\""
        );
    }
}
