//! Aggregate native + sibling-tool findings into `Report.static`.

use crate::report::{DetectionCheck, Inventory, RiskBreakdown, StaticAnalysis};
use crate::types::{Finding, Severity};

const NATIVE_CHECKS: &[(&str, &str)] = &[
    ("sast/inventory", "inventory"),
    ("sast/js-secrets", "js-secrets"),
    ("sast/js-urls", "js-urls"),
    ("sast/dom-sinks", "js-dom-sinks"),
    ("sast/js-cookies", "js-cookies"),
    ("sast/js-storage", "js-storage"),
    ("sast/js-postmessage", "js-postmessage"),
    ("sast/forms", "forms"),
    ("sast/params", "params"),
];

const SINK_PLUGINS: &[&str] = &[
    "sast/dom-sinks",
    "sast/js-cookies",
    "sast/js-storage",
    "sast/js-postmessage",
];

pub fn build_static_analysis(
    inventory: Inventory,
    findings: &[Finding],
    attack_plan: Vec<crate::report::AttackPlanEntry>,
) -> StaticAnalysis {
    let detection_checks = native_detection_checks(findings);
    let risk_breakdown = risk_breakdown(findings);
    let risk_score = sum_capped(&risk_breakdown);

    StaticAnalysis {
        inventory,
        risk_score,
        risk_breakdown,
        detection_checks,
        attack_plan,
    }
}

fn native_detection_checks(findings: &[Finding]) -> Vec<DetectionCheck> {
    NATIVE_CHECKS
        .iter()
        .map(|(plugin, id)| {
            let matched: Vec<_> = findings.iter().filter(|f| f.plugin == *plugin).collect();
            let count = matched.len();
            let severity = matched
                .iter()
                .map(|f| f.severity.clone())
                .max()
                .unwrap_or(Severity::Info);
            DetectionCheck {
                id: (*id).to_string(),
                triggered: count > 0,
                severity,
                count,
            }
        })
        .collect()
}

fn risk_breakdown(findings: &[Finding]) -> RiskBreakdown {
    let secrets = count_matching(findings, |f| {
        f.plugin == "sast/js-secrets" || f.plugin.starts_with("secrets/")
    });
    let sinks = count_matching(findings, |f| SINK_PLUGINS.iter().any(|p| f.plugin == *p));
    let config = count_matching(findings, |f| {
        f.plugin == "sast/forms" || f.plugin == "sast/params"
    });
    let sca = count_matching(findings, |f| f.plugin.starts_with("sca/"));
    let iac = count_matching(findings, |f| f.plugin.starts_with("iac/"));

    RiskBreakdown {
        secrets: weighted(secrets, 12, 40),
        sinks: weighted(sinks, 8, 30),
        config: weighted(config, 3, 15),
        sca: weighted(sca, 6, 20),
        iac: weighted(iac, 6, 20),
    }
}

fn count_matching(findings: &[Finding], pred: impl Fn(&Finding) -> bool) -> usize {
    findings.iter().filter(|f| pred(f)).count()
}

fn weighted(count: usize, per: u32, cap: u32) -> u32 {
    (count as u32).saturating_mul(per).min(cap)
}

fn sum_capped(b: &RiskBreakdown) -> u8 {
    b.secrets
        .saturating_add(b.sinks)
        .saturating_add(b.config)
        .saturating_add(b.sca)
        .saturating_add(b.iac)
        .min(100) as u8
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::report::Inventory;
    use crate::types::Finding;

    #[test]
    fn secrets_and_sinks_raise_score() {
        let findings = vec![
            Finding::new("s", Severity::High, "u", "d", "s", "sast/js-secrets"),
            Finding::new("k", Severity::Medium, "u", "d", "s", "sast/dom-sinks"),
            Finding::new("t", Severity::High, "u", "d", "s", "sca/trivy"),
        ];
        let st = build_static_analysis(Inventory::default(), &findings, vec![]);
        assert!(st.risk_score > 0);
        assert!(st.risk_breakdown.secrets > 0);
        assert!(st.risk_breakdown.sinks > 0);
        assert!(st.risk_breakdown.sca > 0);
        assert!(st
            .detection_checks
            .iter()
            .any(|c| c.id == "js-secrets" && c.triggered));
        assert!(st
            .detection_checks
            .iter()
            .any(|c| c.id == "js-dom-sinks" && c.triggered));
        assert!(st.detection_checks.iter().any(|c| c.id == "js-cookies"));
        assert!(st.detection_checks.iter().any(|c| c.id == "js-storage"));
        assert!(st.detection_checks.iter().any(|c| c.id == "js-postmessage"));
    }

    #[test]
    fn cookie_storage_postmessage_count_as_sinks() {
        let findings = vec![
            Finding::new("c", Severity::Medium, "u", "d", "s", "sast/js-cookies"),
            Finding::new("s", Severity::Medium, "u", "d", "s", "sast/js-storage"),
            Finding::new("p", Severity::Medium, "u", "d", "s", "sast/js-postmessage"),
        ];
        let st = build_static_analysis(Inventory::default(), &findings, vec![]);
        assert!(st.risk_breakdown.sinks > 0);
        assert!(st
            .detection_checks
            .iter()
            .any(|c| c.id == "js-cookies" && c.triggered && c.count == 1));
        assert!(st
            .detection_checks
            .iter()
            .any(|c| c.id == "js-storage" && c.triggered));
        assert!(st
            .detection_checks
            .iter()
            .any(|c| c.id == "js-postmessage" && c.triggered));
    }

    #[test]
    fn empty_findings_zero_score() {
        let st = build_static_analysis(Inventory::default(), &[], vec![]);
        assert_eq!(st.risk_score, 0);
        assert!(st.detection_checks.iter().all(|c| !c.triggered));
    }
}
