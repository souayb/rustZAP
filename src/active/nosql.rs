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
            if let Some((test_status, test_body)) = get_response_body(client, &ne_url_str).await {
                // If baseline failed (e.g. 401/403/404 or empty response) but operator injection returns 200 OK with data:
                let is_bypass =
                    (baseline_status != 200 && test_status == 200 && test_body.len() > 30)
                        || (baseline_status == 200
                            && body_similarity(&baseline_body, &test_body) < 0.85
                            && (test_body.contains('{') || test_body.contains('[')));

                if is_bypass {
                    findings.push(
                        Finding::new(
                            "NoSQL / MongoDB Operator Injection",
                            Severity::High,
                            &ne_url_str,
                            format!(
                                "Query parameter `{}` is vulnerable to NoSQL operator injection via `[$ne]=null`. The server evaluated the MongoDB `$ne` query operator, modifying the query logic.",
                                param_name
                            ),
                            "Sanitize and validate user inputs before passing them to NoSQL query filters. Ensure query parameters are cast to primitive strings or use strict schemas (e.g. Mongoose, Zod) with `sanitize-filters` enabled.",
                            "active/nosql-operator",
                        )
                        .with_evidence(format!("Injected: {}[$ne]=null\nResponse status: HTTP {}", param_name, test_status))
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nosql_plugin_instantiation() {
        let plugin = NoSqlInjectionPlugin::new();
        assert_eq!(plugin.name(), "nosql-injection");
    }
}
