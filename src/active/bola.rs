//! Broken Object Level Authorization (BOLA / IDOR) Plugin (OWASP API1:2023 & CWE-639).
//!
//! Actively detects authorization flaws where resource identifiers (numeric IDs,
//! UUIDs, account slugs) can be tampered with to access unauthorized objects.

use async_trait::async_trait;
use regex::Regex;
use url::Url;

use crate::active::{get_response_body, ScanPlugin};
use crate::types::{DiscoveredUrl, Finding, Severity};
use crate::verify::body_similarity;

pub struct BolaPlugin {
    id_param_regex: Regex,
    path_numeric_regex: Regex,
    uuid_regex: Regex,
}

impl Default for BolaPlugin {
    fn default() -> Self {
        Self::new()
    }
}

impl BolaPlugin {
    pub fn new() -> Self {
        Self {
            id_param_regex: Regex::new(r#"(?i)^(?:id|user_id|account_id|order_id|invoice_id|customer_id|doc_id|file_id|org_id|tenant_id|item_id|profile_id|uid)$"#).unwrap(),
            path_numeric_regex: Regex::new(r#"/(\d{1,10})(?:/|$|\?)"#).unwrap(),
            uuid_regex: Regex::new(r#"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"#).unwrap(),
        }
    }

    /// Extract candidate ID parameters from URL query string.
    fn extract_query_id_candidates(&self, parsed_url: &Url) -> Vec<(String, String)> {
        let mut candidates = Vec::new();
        for (key, val) in parsed_url.query_pairs() {
            if self.id_param_regex.is_match(&key)
                || val.parse::<u64>().is_ok()
                || self.uuid_regex.is_match(&val)
            {
                candidates.push((key.to_string(), val.to_string()));
            }
        }
        candidates
    }

    /// Generate modified/tampered IDs for testing authorization boundaries.
    fn generate_tampered_ids(&self, original_id: &str) -> Vec<String> {
        let mut variants = Vec::new();

        if let Ok(num) = original_id.parse::<i64>() {
            variants.push((num + 1).to_string());
            if num > 1 {
                variants.push((num - 1).to_string());
            }
            variants.push("1".to_string());
            variants.push("0".to_string());
            variants.push("100".to_string());
        } else if self.uuid_regex.is_match(original_id) {
            // Permute UUID by replacing first character or testing nil UUID
            variants.push("00000000-0000-0000-0000-000000000000".to_string());
            let mut permuted = original_id.to_string();
            if let Some(first_char) = permuted.chars().next() {
                let replacement = if first_char == 'a' { 'b' } else { 'a' };
                permuted.replace_range(..1, &replacement.to_string());
                variants.push(permuted);
            }
        } else {
            // String ID / Slug
            variants.push("admin".to_string());
            variants.push("root".to_string());
            variants.push("guest".to_string());
            variants.push("test".to_string());
        }

        variants
    }
}

#[async_trait]
impl ScanPlugin for BolaPlugin {
    fn name(&self) -> &str {
        "bola"
    }

    fn description(&self) -> &str {
        "Detects Broken Object Level Authorization (BOLA/IDOR) by mutating resource identifiers across objects"
    }

    fn always_run(&self) -> bool {
        true
    }

    async fn scan(&self, client: &reqwest::Client, target: &DiscoveredUrl) -> Vec<Finding> {
        let mut findings = Vec::new();
        let Ok(parsed) = Url::parse(&target.url) else {
            return findings;
        };

        // 1. Fetch baseline response
        let Some((baseline_status, baseline_body)) = get_response_body(client, &target.url).await
        else {
            return findings;
        };

        // 2. Test Query Parameter ID Tampering
        let query_candidates = self.extract_query_id_candidates(&parsed);
        for (param_name, original_val) in query_candidates {
            let tampered_values = self.generate_tampered_ids(&original_val);

            for tampered in tampered_values {
                let mut mutated_url = parsed.clone();
                let mut new_pairs = Vec::new();
                for (k, v) in parsed.query_pairs() {
                    if k == param_name {
                        new_pairs.push((k.to_string(), tampered.clone()));
                    } else {
                        new_pairs.push((k.to_string(), v.to_string()));
                    }
                }
                mutated_url
                    .query_pairs_mut()
                    .clear()
                    .extend_pairs(new_pairs.iter().map(|(k, v)| (k.as_str(), v.as_str())));

                let mutated_url_str = mutated_url.to_string();
                if let Some((test_status, test_body)) =
                    get_response_body(client, &mutated_url_str).await
                {
                    // Check if request succeeds (HTTP 200) and returns a distinct non-empty resource
                    if test_status == 200 && test_body.len() > 20 {
                        let similarity = body_similarity(&baseline_body, &test_body);

                        // If baseline was 200 and bodies are significantly different but both 200 OK with data
                        // or baseline was 403/404 and mutated is 200 OK:
                        let is_idor = if baseline_status == 200 {
                            // Returns a valid structured response (JSON/HTML) with different data content
                            similarity < 0.95
                                && (test_body.contains('{') || test_body.contains('<'))
                        } else {
                            baseline_status == 403
                                || baseline_status == 401
                                || baseline_status == 404
                        };

                        if is_idor {
                            let snippet = if test_body.len() > 80 {
                                format!("{}...[TRUNCATED]", &test_body[..80])
                            } else {
                                test_body.clone()
                            };

                            findings.push(
                                Finding::new(
                                    "Broken Object Level Authorization (BOLA / IDOR)",
                                    Severity::High,
                                    &mutated_url_str,
                                    format!(
                                        "Parameter '{}' was modified from '{}' to '{}', granting access to another resource (HTTP 200 OK).",
                                        param_name, original_val, tampered
                                    ),
                                    "Implement robust user authorization checks on the server side to ensure the authenticated user owns or is permitted to access the requested object ID.",
                                    "active/bola",
                                )
                                .with_evidence(format!("Parameter: {}={} -> {}\nResponse Snippet: {}", param_name, original_val, tampered, snippet))
                                .with_cwe(639) // CWE-639: Authorization Bypass Through User-Controlled Key
                                .with_owasp("API1:2023 – Broken Object Level Authorization"),
                            );
                            break; // Avoid spamming findings for same param
                        }
                    }
                }
            }
        }

        // 3. Test Path Segment ID Tampering (e.g. /api/v1/orders/123 -> /api/v1/orders/124)
        let path = parsed.path();
        if let Some(cap) = self.path_numeric_regex.captures(path) {
            if let Some(m) = cap.get(1) {
                let original_id = m.as_str();
                let tampered_ids = self.generate_tampered_ids(original_id);

                for tampered in tampered_ids {
                    let new_path =
                        format!("{}{}{}", &path[..m.start()], tampered, &path[m.end()..]);
                    let mut mutated_url = parsed.clone();
                    mutated_url.set_path(&new_path);
                    let mutated_url_str = mutated_url.to_string();

                    if let Some((test_status, test_body)) =
                        get_response_body(client, &mutated_url_str).await
                    {
                        if test_status == 200 && test_body.len() > 20 {
                            let similarity = body_similarity(&baseline_body, &test_body);
                            if (baseline_status == 200 && similarity < 0.95)
                                || (baseline_status == 403 || baseline_status == 404)
                            {
                                let snippet = if test_body.len() > 80 {
                                    format!("{}...[TRUNCATED]", &test_body[..80])
                                } else {
                                    test_body.clone()
                                };

                                findings.push(
                                    Finding::new(
                                        "Broken Object Level Authorization (BOLA / IDOR in Path)",
                                        Severity::High,
                                        &mutated_url_str,
                                        format!(
                                            "Path object identifier was modified from '{}' to '{}', successfully accessing an adjacent object (HTTP 200 OK).",
                                            original_id, tampered
                                        ),
                                        "Validate authorization on the server-side before resolving objects specified in URL paths.",
                                        "active/bola-path",
                                    )
                                    .with_evidence(format!("Path ID: {} -> {}\nResponse Snippet: {}", original_id, tampered, snippet))
                                    .with_cwe(639)
                                    .with_owasp("API1:2023 – Broken Object Level Authorization"),
                                );
                                break;
                            }
                        }
                    }
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
    fn test_bola_plugin_id_extraction() {
        let plugin = BolaPlugin::new();
        let url = Url::parse("https://example.com/api/user?user_id=1001&view=summary").unwrap();
        let candidates = plugin.extract_query_id_candidates(&url);
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].0, "user_id");
        assert_eq!(candidates[0].1, "1001");
    }

    #[test]
    fn test_bola_tampered_id_generation() {
        let plugin = BolaPlugin::new();
        let variants = plugin.generate_tampered_ids("42");
        assert!(variants.contains(&"43".to_string()));
        assert!(variants.contains(&"41".to_string()));
        assert!(variants.contains(&"1".to_string()));
    }
}
