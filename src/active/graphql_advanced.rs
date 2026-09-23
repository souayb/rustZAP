//! Advanced GraphQL Security & DoS Prober (OWASP API4:2023 & CWE-400).
//!
//! Detects:
//! 1. Query Depth / Complexity Denial of Service (missing query depth limiters)
//! 2. Array Batching Query Abuse (batch processing rate limit / brute force bypass)
//! 3. Field Suggestion Information Disclosure (schema enumeration through Levenshtein suggestions)

use async_trait::async_trait;

use crate::active::{get_response_body, looks_like_graphql, post_response_body, ScanPlugin};
use crate::types::{DiscoveredUrl, Finding, Severity};

pub struct GraphqlAdvancedPlugin;

impl Default for GraphqlAdvancedPlugin {
    fn default() -> Self {
        Self::new()
    }
}

impl GraphqlAdvancedPlugin {
    pub fn new() -> Self {
        Self
    }
}

const DEEP_NESTED_QUERY: &str = r#"{"query":"query { __schema { types { fields { type { fields { type { fields { name } } } } } } } }"}"#;
const BATCH_QUERY_SAMPLE: &str = r#"[{"query":"{__typename}"},{"query":"{__typename}"},{"query":"{__typename}"},{"query":"{__typename}"},{"query":"{__typename}"}]"#;
const FIELD_SUGGESTION_QUERY: &str = r#"{"query":"query { __schema { typess } }"}"#;

#[async_trait]
impl ScanPlugin for GraphqlAdvancedPlugin {
    fn name(&self) -> &str {
        "graphql-advanced"
    }

    fn description(&self) -> &str {
        "Detects GraphQL Query Depth DoS, Batching Abuse, and Field Suggestion schema disclosure"
    }

    fn always_run(&self) -> bool {
        true
    }

    async fn scan(&self, client: &reqwest::Client, target: &DiscoveredUrl) -> Vec<Finding> {
        let mut findings = Vec::new();

        // Check if endpoint is GraphQL
        let probe = get_response_body(client, &target.url).await;
        let probe_ct = if probe.is_some() {
            Some("application/json")
        } else {
            None
        };

        if !looks_like_graphql(&target.url, probe_ct) {
            return findings;
        }

        // 1. Test Array Batching Abuse
        if let Some((status, body)) =
            post_response_body(client, &target.url, "application/json", BATCH_QUERY_SAMPLE).await
        {
            if status == 200 && body.trim().starts_with('[') && body.contains("__typename") {
                findings.push(
                    Finding::new(
                        "GraphQL Query Batching Enabled",
                        Severity::Medium,
                        &target.url,
                        "The GraphQL server permits multiple queries bundled in a single JSON array payload. Attackers can leverage batching to bypass per-request rate limiting, execute brute-force attacks, or amplify resource consumption.",
                        "Disable batch query execution or enforce strict rate limiting per individual operation within batch arrays.",
                        "active/graphql-batching",
                    )
                    .with_evidence("Payload: 5-query batch array -> Response: JSON array with 5 execution results".to_string())
                    .with_cwe(776)
                    .with_owasp("API4:2023 – Unrestricted Resource Consumption"),
                );
            }
        }

        // 2. Test Deep Query Complexity / Nested DoS
        if let Some((status, body)) =
            post_response_body(client, &target.url, "application/json", DEEP_NESTED_QUERY).await
        {
            if status == 200
                && body.contains("__schema")
                && body.contains("fields")
                && !body.contains("Query depth limit exceeded")
            {
                findings.push(
                    Finding::new(
                        "GraphQL Missing Query Depth Limiter (DoS Risk)",
                        Severity::High,
                        &target.url,
                        "The GraphQL server processed a deeply nested recursive query without depth enforcement. Attackers can issue exponentially complex queries to exhaust server CPU and memory.",
                        "Implement query depth limiting (e.g. max depth of 5-8 levels) and cost analysis middleware (e.g. `graphql-depth-limit` or `graphql-cost-analysis`).",
                        "active/graphql-depth-limit",
                    )
                    .with_evidence("Deeply nested recursive query executed with HTTP 200 OK".to_string())
                    .with_cwe(400) // CWE-400: Uncontrolled Resource Consumption
                    .with_owasp("API4:2023 – Unrestricted Resource Consumption"),
                );
            }
        }

        // 3. Test Field Suggestion Schema Enumeration
        if let Some((_, body)) = post_response_body(
            client,
            &target.url,
            "application/json",
            FIELD_SUGGESTION_QUERY,
        )
        .await
        {
            if body.contains("Did you mean") || body.contains("suggestions") {
                findings.push(
                    Finding::new(
                        "GraphQL Field Suggestions Enabled",
                        Severity::Low,
                        &target.url,
                        "The GraphQL server returns field suggestions in error messages when invalid field names are requested (e.g. `Did you mean 'types'?`). This allows attackers to enumerate hidden schema fields even when introspection is disabled.",
                        "Disable field suggestions in production environments (e.g. using `graphql-disable-resolve-field-suggestions`).",
                        "active/graphql-suggestions",
                    )
                    .with_evidence(crate::types::safe_truncate(&body, 80).to_string())
                    .with_cwe(200)
                    .with_owasp("A05:2021 – Security Misconfiguration"),
                );
            }
        }

        findings
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_graphql_advanced_instantiation() {
        let plugin = GraphqlAdvancedPlugin::new();
        assert_eq!(plugin.name(), "graphql-advanced");
        assert!(plugin.always_run());
    }
}
