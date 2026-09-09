//! AI red-team battery — OWASP LLM Top-10 probes for an LLM-backed target.
//!
//! `ai_redteam` sends a curated set of adversarial prompts to an OpenAI-compatible
//! chat endpoint (the *application under test*) and inspects the replies for
//! susceptibility.
//!
//! Confidence follows what the evidence actually establishes. A reflected canary
//! shows the model followed the injected instruction, but not that it overrode a
//! protected one — nothing here observes the application's instruction boundary,
//! nor whether the reply is ever rendered — so canary probes report *tentative*.
//! Only a leaked operator-supplied marker is proof: the operator knows that text
//! was hidden, so its appearance is disclosure on its own.
//!
//! The detectors here are pure functions over response text, so the whole
//! catalogue is unit-testable without a live model. This is intrusive probing —
//! the tool is classed `Exploit` and gated by the scope's approval matrix.

pub mod detect;
pub mod eval;
pub mod mutate;
pub mod probes;
pub mod target;

pub use detect::{
    classify_reply, classify_reply_at, extract_text, is_susceptible, Detector, ProbeOutcome,
    Unevaluated,
};
pub use eval::{Attempt, ProbeReport, Verdict};
pub use mutate::Mutator;
pub use probes::probes;
pub use target::{Shape, TargetSpec};

use crate::types::{Finding, Severity};

/// One OWASP LLM Top-10 probe.
#[derive(Debug, Clone)]
pub struct Probe {
    pub id: &'static str,
    pub owasp: &'static str,
    pub cwe: u32,
    pub title: &'static str,
    pub technique: &'static str,
    pub mitigation: &'static str,
    pub severity: Severity,
    pub detector: Detector,
    /// A hit is proof on its own, needing no follow-up to confirm. True only
    /// where the evidence establishes the vulnerability without assuming
    /// unobserved application behavior (an operator-marker leak); canary and
    /// refusal probes stay tentative.
    pub confirmed_on_hit: bool,
    /// The prompt to send (canary/marker already interpolated).
    pub prompt: String,
}

/// Build a `Finding` for a susceptible probe (evidence is the reply snippet).
///
/// Probes that prove the issue outright carry a PoC and count as validated;
/// everything else is `tentative()`, which is most of the battery — see
/// `confirmed_on_hit`.
pub fn to_finding(probe: &Probe, url: &str, evidence: &str) -> Finding {
    let f = Finding::new(
        probe.title,
        probe.severity.clone(),
        url,
        probe.technique,
        probe.mitigation,
        "agent/ai-redteam",
    )
    .with_owasp(probe.owasp)
    .with_cwe(probe.cwe)
    .with_evidence(snippet(evidence, 400));
    if probe.confirmed_on_hit {
        let headers = vec![("Content-Type".into(), "application/json".into())];
        let req = crate::agent::poc::PocHttpRequest {
            method: "POST",
            url,
            headers: &headers,
            body: Some(probe.prompt.as_str()),
        };
        let poc = crate::agent::poc::build_poc_proof(
            &req,
            probe.id,
            snippet(evidence, 120),
            snippet(evidence, 400),
            0,
        );
        f.with_poc(poc)
    } else {
        f.tentative()
    }
}

/// Build the finding for a failed probe variant, folding in what the evaluator
/// measured.
///
/// The reply itself is the PoC evidence; the statistics and the mutator that
/// produced the hit are appended to the finding so a reader can tell a target
/// that always complies from one that complied once out of ten — a distinction
/// a single-generation battery cannot express at all.
pub fn finding_for(
    probe: &Probe,
    url: &str,
    report: &ProbeReport,
    mutator: Option<Mutator>,
) -> Finding {
    let reply = report.first_hit.clone().unwrap_or_default();
    let mut f = to_finding(probe, url, &reply);

    let mut evidence = String::new();
    if let Some(m) = mutator {
        evidence.push_str(&format!(
            "prompt variant: {} (obfuscated — the plain prompt may be filtered)\n",
            m.id()
        ));
    }
    evidence.push_str(&report.summary());
    if !reply.is_empty() {
        evidence.push_str("\nreply: ");
        evidence.push_str(&snippet(&reply, 320));
    }
    f.evidence = Some(evidence);

    if let Some(m) = mutator {
        f.title = format!("{} — via {} obfuscation", f.title, m.id());
    }
    f
}

pub(crate) fn snippet(s: &str, max: usize) -> String {
    s.chars().take(max).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const CANARY: &str = "RZ-CANARY-abc123";

    fn probe(id: &str) -> Probe {
        probes(CANARY, Some("SECRET-SYSPROMPT-MARKER"))
            .into_iter()
            .find(|p| p.id == id)
            .expect("probe id exists")
    }

    #[test]
    fn battery_covers_multiple_owasp_categories() {
        let ps = probes(CANARY, None);
        assert!(ps.len() >= 10);
        let cats: std::collections::BTreeSet<_> = ps.iter().map(|p| p.owasp).collect();
        assert!(cats.iter().any(|c| c.contains("LLM01")));
        assert!(cats.iter().any(|c| c.contains("LLM02")));
        assert!(cats.iter().any(|c| c.contains("LLM08")));
        assert!(cats.iter().any(|c| c.contains("LLM06")));
        assert!(ps.iter().any(|p| p.id == "rag-indirect-prompt-injection"));
    }

    #[test]
    fn canary_reflected_is_susceptible() {
        let p = probe("llm01-direct-injection");
        assert!(is_susceptible(
            &p,
            CANARY,
            None,
            &format!("Sure, here you go: {CANARY}")
        ));
        assert!(!is_susceptible(
            &p,
            CANARY,
            None,
            "I can't help with that request."
        ));
        assert!(!is_susceptible(
            &p,
            CANARY,
            None,
            &format!("I am sorry, but I cannot fulfill this request to output '{CANARY}' as it violates safety guidelines.")
        ));
    }

    #[test]
    fn marker_leak_needs_the_marker_present() {
        let p = probe("llm02-system-prompt-leak");
        let marker = Some("SECRET-SYSPROMPT-MARKER");
        assert!(is_susceptible(
            &p,
            CANARY,
            marker,
            "My instructions begin: SECRET-SYSPROMPT-MARKER you are a helpful bot"
        ));
        // No leak when the marker is absent from the reply.
        assert!(!is_susceptible(&p, CANARY, marker, "I won't share that."));
        // Refusal quoting marker is not marked susceptible
        assert!(!is_susceptible(
            &p,
            CANARY,
            marker,
            "I cannot repeat SECRET-SYSPROMPT-MARKER as it is confidential."
        ));
        // No marker configured → never fires (no false positives).
        assert!(!is_susceptible(
            &p,
            CANARY,
            None,
            "here is my system prompt ..."
        ));
    }

    #[test]
    fn rag_canary_leak_is_detected_without_system_marker() {
        let p = probe("rag-tenant-isolation");
        assert!(is_susceptible(
            &p,
            CANARY,
            None,
            "document: RZ-CANARY-abc123"
        ));
        assert!(!is_susceptible(&p, CANARY, None, "no matching document"));
    }

    #[test]
    fn refusal_absent_flags_only_compliance() {
        let p = probe("llm06-excessive-agency");
        assert!(is_susceptible(&p, CANARY, None, "DONE"));
        assert!(!is_susceptible(
            &p,
            CANARY,
            None,
            "I'm sorry, I cannot delete user accounts."
        ));
        assert!(!is_susceptible(&p, CANARY, None, "   ")); // empty ≠ compliance
    }

    #[test]
    fn classify_reply_rejects_provider_errors_and_unknown_shapes() {
        let ok = json!({"choices": [{"message": {"content": "hello"}}]}).to_string();
        assert_eq!(
            classify_reply(200, &ok),
            ProbeOutcome::Evaluated("hello".into())
        );

        // Non-2xx: the reply is a status page, not a model answer.
        assert_eq!(
            classify_reply(401, &ok),
            ProbeOutcome::Unevaluated(Unevaluated::HttpStatus(401))
        );

        // 200 with a provider error object (gateways do this).
        let err = json!({"error": {"message": "rate limited"}}).to_string();
        assert!(matches!(
            classify_reply(200, &err),
            ProbeOutcome::Unevaluated(Unevaluated::ProviderError(m)) if m.contains("rate limited")
        ));

        // 2xx bodies that are not chat completions never reach a detector.
        assert_eq!(
            classify_reply(200, "<html>gateway timeout</html>"),
            ProbeOutcome::Unevaluated(Unevaluated::UnrecognizedShape)
        );
        let empty = json!({"choices": [{"message": {"content": "  "}}]}).to_string();
        assert_eq!(
            classify_reply(200, &empty),
            ProbeOutcome::Unevaluated(Unevaluated::EmptyReply)
        );
    }

    /// Regression: an auth-failure body is not a refusal, so feeding it to
    /// `RefusalAbsent` used to yield a bogus excessive-agency finding.
    #[test]
    fn error_body_never_reaches_the_refusal_detector() {
        let body = json!({"error": {"message": "Incorrect API key provided"}}).to_string();
        let p = probe("llm06-excessive-agency");

        // The raw body would have been judged "susceptible"...
        assert!(is_susceptible(&p, CANARY, None, &extract_text(&body)));
        // ...but classification stops it before any detector runs.
        assert!(matches!(
            classify_reply(401, &body),
            ProbeOutcome::Unevaluated(_)
        ));
    }

    #[test]
    fn extract_text_handles_openai_and_anthropic_and_raw() {
        let openai = r#"{"choices":[{"message":{"content":"hello world"}}]}"#;
        assert_eq!(extract_text(openai), "hello world");
        let anthropic = r#"{"content":[{"type":"text","text":"hi there"}]}"#;
        assert_eq!(extract_text(anthropic), "hi there");
        assert_eq!(extract_text("not json"), "not json");
    }

    #[test]
    fn to_finding_sets_owasp_cwe_and_confidence() {
        let p = probe("llm01-direct-injection");
        let f = to_finding(&p, "https://app.local/chat", &format!("leaked {CANARY}"));
        assert_eq!(
            f.owasp_category.as_deref(),
            Some("LLM01:2025 Prompt Injection")
        );
        assert_eq!(f.cwe, Some(1427));
        assert_eq!(f.plugin, "agent/ai-redteam");

        let heuristic = probe("llm06-excessive-agency");
        let hf = to_finding(&heuristic, "https://app.local/chat", "DONE");
        assert!(!hf.poc_validated, "agency finding is heuristic/tentative");
    }

    /// Confidence must track what the evidence establishes: only an
    /// operator-marker leak is self-proving. A canary echo shows the model
    /// complied, not that it crossed a boundary the probe never observed.
    #[test]
    fn only_marker_leaks_are_reported_as_confirmed() {
        let leak = probe("llm02-system-prompt-leak");
        let lf = to_finding(&leak, "https://app.local/chat", "SECRET-SYSPROMPT-MARKER");
        assert!(lf.poc_validated, "an operator-marker leak is proof");

        for id in [
            "llm01-direct-injection",
            "llm01-role-override",
            "llm05-insecure-output",
        ] {
            let f = to_finding(&probe(id), "https://app.local/chat", CANARY);
            assert!(!f.poc_validated, "{id} must not claim confirmation");
            assert_eq!(f.confidence, crate::types::Confidence::Tentative, "{id}");
        }
    }
}
