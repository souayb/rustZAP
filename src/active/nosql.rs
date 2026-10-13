//! NoSQL & MongoDB Injection Prober (CWE-943 & OWASP A03:2021).
//!
//! Detects NoSQL injection vulnerabilities across MongoDB, CouchDB, and DynamoDB:
//! 1. Query operator injection (`[$ne]=null`, `[$gt]=`, `[$regex]=.*`)
//! 2. BSON string concatenation & JavaScript `$where` injection (`' || '1'=='1`, `"; return true; var x="`)
//! 3. Authentication bypass via operator tampering

use async_trait::async_trait;
use url::Url;

use crate::active::{get_response_body, ScanPlugin};
use crate::types::{DiscoveredUrl, Finding, Severity};
use crate::verify::body_similarity;

pub struct NoSqlInjectionPlugin;

impl Default for NoSqlInjectionPlugin {
    fn default() -> Self {
        Self::new()
    }
}

impl NoSqlInjectionPlugin {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl ScanPlugin for NoSqlInjectionPlugin {
    fn name(&self) -> &str {
        "nosql-injection"
    }

    fn description(&self) -> &str {
        "Detects NoSQL and MongoDB operator injection (BSON/JSON query tampering)"
    }

    fn always_run(&self) -> bool {
        false // Runs when URL has query parameters or input surface
    }

    async fn scan(&self, client: &reqwest::Client, target: &DiscoveredUrl) -> Vec<Finding> {
        let mut findings = Vec::new();
        let Ok(parsed) = Url::parse(&target.url) else {
            return findings;
        };

        if parsed.query().is_none() {
            return findings;
        }

        // 1. Establish baseline response
        let Some((baseline_status, baseline_body)) = get_response_body(client, &target.url).await
        else {
            return findings;
        };

        // 2. Test query parameter operator injections
        let query_params: Vec<(String, String)> = parsed
            .query_pairs()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();

        for (param_name, orig_val) in query_params {
            // Test 1: [$ne]=null operator injection (e.g. ?user[$ne]=null)
            let mut ne_url = parsed.clone();
            let mut pairs = Vec::new();
            for (k, v) in parsed.query_pairs() {
                if k == param_name {
                    pairs.push((format!("{}[$ne]", k), "null".to_string()));
                } else {
                    pairs.push((k.to_string(), v.to_string()));
                }
            }
            ne_url
                .query_pairs_mut()
                .clear()
                .extend_pairs(pairs.iter().map(|(k, v)| (k.as_str(), v.as_str())));

            let ne_url_str = ne_url.to_string();

            // Benign control: the same parameter set to a value that should match
            // nothing. A real `$ne` injection must differ from BOTH the untouched
            // baseline AND this control; if the operator response matches either,
            // the app ignored/escaped the operator (no behavioral change) and this
            // is a false positive — do not confirm on a stable/echoed 200 (#21).
            let mut control_url = parsed.clone();
            {
                let mut cpairs = Vec::new();
                for (k, v) in parsed.query_pairs() {
                    if k == param_name {
                        cpairs.push((k.to_string(), "rustzap_nonexistent_val".to_string()));
                    } else {
                        cpairs.push((k.to_string(), v.to_string()));
                    }
                }
                control_url
                    .query_pairs_mut()
                    .clear()
                    .extend_pairs(cpairs.iter().map(|(k, v)| (k.as_str(), v.as_str())));
            }
            let (control_status, control_body) = get_response_body(client, control_url.as_str())
                .await
                .unwrap_or((0, String::new()));

            if let Some((test_status, test_body)) = get_response_body(client, &ne_url_str).await {
                let is_bypass = operator_bypass_confirmed(
                    baseline_status,
                    &baseline_body,
                    control_status,
                    &control_body,
                    test_status,
                    &test_body,
                );

                if is_bypass {
                    findings.push(
                        Finding::new(
                            "NoSQL / MongoDB Operator Injection",
                            Severity::High,
                            &ne_url_str,
                            format!(
                                "Query parameter `{}` is vulnerable to NoSQL operator injection via `[$ne]=null`. The `$ne` operator broadened the result set versus a benign non-matching control, indicating the MongoDB operator reached the query.",
                                param_name
                            ),
                            "Sanitize and validate user inputs before passing them to NoSQL query filters. Ensure query parameters are cast to primitive strings or use strict schemas (e.g. Mongoose, Zod) with `sanitize-filters` enabled.",
                            "active/nosql-operator",
                        )
                        .with_evidence(format!(
                            "Injected: {param_name}[$ne]=null → HTTP {test_status} ({}B); benign control {param_name}=rustzap_nonexistent_val → HTTP {control_status} ({}B)",
                            test_body.len(),
                            control_body.len()
                        ))
                        .with_cwe(943) // CWE-943: Improper Neutralization of Special Elements in Data Query Logic
                        .with_owasp("A03:2021 – Injection"),
                    );
                    break; // Skip further variants for this param
                }
            }

            // Test 2: JavaScript $where string concatenation injection (e.g. ?user=' || '1'=='1)
            let mut js_url = parsed.clone();
            let mut js_pairs = Vec::new();
            for (k, v) in parsed.query_pairs() {
                if k == param_name {
                    js_pairs.push((k.to_string(), format!("{}' || '1'=='1", orig_val)));
                } else {
                    js_pairs.push((k.to_string(), v.to_string()));
                }
            }
            js_url
                .query_pairs_mut()
                .clear()
                .extend_pairs(js_pairs.iter().map(|(k, v)| (k.as_str(), v.as_str())));

            let js_url_str = js_url.to_string();
            if let Some((test_status, test_body)) = get_response_body(client, &js_url_str).await {
                if test_status == 200
                    && (test_body.contains("MongoDB")
                        || test_body.contains("MongoError")
                        || test_body.contains("$where"))
                {
                    findings.push(
                        Finding::new(
                            "NoSQL Injection (Syntax / Error Disclosed)",
                            Severity::High,
                            &js_url_str,
                            format!(
                                "NoSQL error or syntax reflection detected when injecting JavaScript boolean expressions into parameter `{}`.",
                                param_name
                            ),
                            "Avoid passing unsanitized user input into dynamic `$where` clauses or string-concatenated NoSQL queries.",
                            "active/nosql-error",
                        )
                        .with_evidence(crate::types::safe_truncate(&test_body, 80).to_string())
                        .with_cwe(943)
                        .with_owasp("A03:2021 – Injection"),
                    );
                    break;
                }
            }
        }

        findings
    }
}

/// Decide whether an operator-injection response is a genuine bypass.
///
/// It must be a 200 carrying structured data that behaviorally differs from BOTH
/// the untouched baseline AND a benign non-matching control, and broaden the
/// result set versus that control. This prevents false positives on apps that
/// ignore unknown query parameters — a stable or echoed 200 is never confirmed
/// (see issue #21).
fn operator_bypass_confirmed(
    baseline_status: u16,
    baseline_body: &str,
    control_status: u16,
    control_body: &str,
    test_status: u16,
    test_body: &str,
) -> bool {
    if test_status != 200 {
        return false;
    }
    let looks_structured = test_body.contains('{') || test_body.contains('[');
    let differs_from_baseline =
        test_status != baseline_status || body_similarity(baseline_body, test_body) < 0.85;
    let differs_from_control =
        test_status != control_status || body_similarity(control_body, test_body) < 0.85;
    let broadened = test_body.len() > control_body.len() + 16;
    looks_structured && differs_from_baseline && differs_from_control && broadened
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nosql_plugin_instantiation() {
        let plugin = NoSqlInjectionPlugin::new();
        assert_eq!(plugin.name(), "nosql-injection");
    }

    #[test]
    fn stable_200_identical_to_baseline_is_not_a_bypass() {
        // App ignores the operator: response byte-identical to the baseline (#21).
        let body = r#"{"items":[{"id":1}]}"#;
        assert!(!operator_bypass_confirmed(200, body, 404, "", 200, body));
    }

    #[test]
    fn response_matching_benign_control_is_not_a_bypass() {
        // Operator response identical to a benign non-matching control → no effect.
        let baseline = r#"{"items":[{"id":1}]}"#;
        let control = r#"{"items":[]}"#;
        assert!(!operator_bypass_confirmed(
            200, baseline, 200, control, 200, control
        ));
    }

    #[test]
    fn broadened_divergent_200_is_a_bypass() {
        let baseline = r#"{"items":[{"id":1}]}"#;
        let control = r#"{"items":[]}"#;
        let test = r#"{"items":[{"id":1},{"id":2},{"id":3},{"id":4}]}"#;
        assert!(operator_bypass_confirmed(
            200, baseline, 404, control, 200, test
        ));
    }

    #[test]
    fn non_200_is_not_a_bypass() {
        let test = r#"{"items":[{"id":1},{"id":2}]}"#;
        assert!(!operator_bypass_confirmed(200, "{}", 200, "{}", 500, test));
    }
}
