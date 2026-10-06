//! Mass Assignment & HTTP Parameter Pollution (HPP) Prober (CWE-915 & OWASP API6:2023).
//!
//! Detects:
//! 1. Mass Assignment: Automatic binding of unwhitelisted privileged parameters (`isAdmin=true`, `role=admin`, `verified=true`)
//! 2. HTTP Parameter Pollution (HPP): Duplicate parameter handling vulnerabilities across front-end/back-end tiers

use async_trait::async_trait;
use url::Url;

use crate::active::{get_response_body, ScanPlugin};
use crate::types::{DiscoveredUrl, Finding, Severity};

pub struct MassAssignmentPlugin;

impl Default for MassAssignmentPlugin {
    fn default() -> Self {
        Self::new()
    }
}

impl MassAssignmentPlugin {
    pub fn new() -> Self {
        Self
    }
}

const PRIVILEGED_PARAMS: &[(&str, &str)] = &[
    ("isAdmin", "true"),
    ("is_admin", "1"),
    ("role", "admin"),
    ("roles", "[\"admin\"]"),
    ("verified", "true"),
    ("is_verified", "1"),
    ("plan", "enterprise"),
    ("account_type", "superuser"),
];

#[async_trait]
impl ScanPlugin for MassAssignmentPlugin {
    fn name(&self) -> &str {
        "mass-assignment"
    }

    fn description(&self) -> &str {
        "Detects Mass Assignment of privileged fields (role, isAdmin) and HTTP Parameter Pollution (HPP)"
    }

    fn always_run(&self) -> bool {
        true
    }

    async fn scan(&self, client: &reqwest::Client, target: &DiscoveredUrl) -> Vec<Finding> {
        let mut findings = Vec::new();
        let Ok(parsed) = Url::parse(&target.url) else {
            return findings;
        };

        // 1. Establish baseline
        let Some((_baseline_status, baseline_body)) = get_response_body(client, &target.url).await
        else {
            return findings;
        };

        // 2. Test Mass Assignment parameter injection
        for (param, val) in PRIVILEGED_PARAMS {
            let mut injected_url = parsed.clone();
            injected_url.query_pairs_mut().append_pair(param, val);
            let injected_url_str = injected_url.to_string();

            if let Some((test_status, test_body)) =
                get_response_body(client, &injected_url_str).await
            {
                // If response reflects the privileged parameter or indicates successful binding:
                if test_status == 200
                    && (test_body.contains(&format!("\"{}\":true", param))
                        || test_body.contains(&format!("\"{}\":\"admin\"", param))
                        || test_body.contains(&format!("\"{}\":1", param))
                        || (test_body.contains(param) && !baseline_body.contains(param)))
                {
                    findings.push(
                        Finding::new(
                            format!("Mass Assignment / Privileged Field Exposure (`{}`)", param),
                            Severity::High,
                            &injected_url_str,
                            format!(
                                "The application accepted and reflected the privileged parameter `{}=`{}. Unfiltered object binding allows attackers to modify sensitive properties such as user roles, administrative flags, or billing tiers.",
                                param, val
                            ),
                            "Implement strict Data Transfer Object (DTO) binding or explicit field whitelists (e.g. `strong_parameters` or `@Expose` annotations) to prevent binding of sensitive model properties.",
                            "active/mass-assignment",
                        )
                        .with_evidence(format!("Appended: {}={}\nResponse Snippet: {}", param, val, crate::types::safe_truncate(&test_body, 80)))
                        .with_cwe(915) // CWE-915: Improperly Controlled Modification of Dynamically-Determined Object Attributes
                        .with_owasp("API6:2023 – Server-Side Request Forgery / Unrestricted Resource Consumption"),
                    );
                    break;
                }
            }
        }

        // 3. Test HTTP Parameter Pollution (HPP)
        if parsed.query().is_some() {
            let mut hpp_url = parsed.clone();
            if let Some((first_k, _)) = parsed.query_pairs().next() {
                // Append duplicate parameter with different value
                hpp_url
                    .query_pairs_mut()
                    .append_pair(&first_k, "rz_hpp_test_value");
                let hpp_url_str = hpp_url.to_string();

                if let Some((status, body)) = get_response_body(client, &hpp_url_str).await {
                    if status == 200 && body.contains("rz_hpp_test_value") {
                        findings.push(
                            Finding::new(
                                format!("HTTP Parameter Pollution (HPP) on Parameter `{}`", first_k),
                                Severity::Medium,
                                &hpp_url_str,
                                format!(
                                    "The server accepted duplicate parameter occurrences of `{}` and processed the secondary value. In multi-tier environments, parameter precedence differences between front-end WAFs and back-end application servers can be leveraged to bypass security controls.",
                                    first_k
                                ),
                                "Normalize incoming query parameters at the API gateway or reject requests containing duplicate parameter keys.",
                                "active/hpp",
                            )
                            .with_evidence(format!("Duplicate parameter `{}` reflected in response body", first_k))
                            .with_cwe(20) // CWE-20: Improper Input Validation
                            .with_owasp("A05:2021 – Security Misconfiguration"),
                        );
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
    fn test_mass_assignment_instantiation() {
        let plugin = MassAssignmentPlugin::new();
        assert_eq!(plugin.name(), "mass-assignment");
        assert!(plugin.always_run());
    }
}
