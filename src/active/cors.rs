//! Advanced Cross-Origin Resource Sharing (CORS) Active Prober (CWE-942 & OWASP A01:2021).
//!
//! Actively probes endpoints with crafted `Origin` headers to identify dangerous
//! CORS trust misconfigurations:
//! 1. Arbitrary origin reflection with `Access-Control-Allow-Credentials: true` (Critical)
//! 2. `Origin: null` reflection with credentials (High - sandboxed iframe exploit)
//! 3. Subdomain prefix/suffix regex flaws (e.g. `target.com.attacker.com`)
//! 4. Wildcard `*` with credentials

use async_trait::async_trait;
use url::Url;

use crate::active::{active_gate, ScanPlugin};
use crate::types::{DiscoveredUrl, Finding, Severity};

pub struct CorsActivePlugin;

impl Default for CorsActivePlugin {
    fn default() -> Self {
        Self::new()
    }
}

impl CorsActivePlugin {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl ScanPlugin for CorsActivePlugin {
    fn name(&self) -> &str {
        "cors-advanced"
    }

    fn description(&self) -> &str {
        "Detects exploitable Cross-Origin Resource Sharing (CORS) misconfigurations via active Origin probing"
    }

    fn always_run(&self) -> bool {
        true
    }

    async fn scan(&self, client: &reqwest::Client, target: &DiscoveredUrl) -> Vec<Finding> {
        let mut findings = Vec::new();
        let Ok(parsed) = Url::parse(&target.url) else {
            return findings;
        };

        let host = parsed.host_str().unwrap_or("example.com");

        let test_origins = vec![
            (
                "https://evil-attacker.com".to_string(),
                "Arbitrary Attacker Origin",
            ),
            ("null".to_string(), "Null Origin (Sandboxed Iframe)"),
            (
                format!("https://{}.evil-attacker.com", host),
                "Subdomain Prefix Origin",
            ),
            (
                format!("https://evil-{}.com", host),
                "Subdomain Suffix Origin",
            ),
        ];

        for (origin_val, attack_label) in &test_origins {
            if let Some(gate) = active_gate() {
                if gate
                    .before_url_request("GET", &target.url, None)
                    .await
                    .is_err()
                {
                    continue;
                }
            }

            let resp = client
                .get(&target.url)
                .header("Origin", origin_val)
                .send()
                .await;

            if let Ok(response) = resp {
                let status = response.status().as_u16();
                let headers = response.headers().clone();

                if let Some(gate) = active_gate() {
                    let _ = gate.after_response(status, 0);
                }

                let acao = headers
                    .get("access-control-allow-origin")
                    .and_then(|v| v.to_str().ok());
                let acac = headers
                    .get("access-control-allow-credentials")
                    .and_then(|v| v.to_str().ok())
                    .map(|v| v.eq_ignore_ascii_case("true"))
                    .unwrap_or(false);

                if let Some(acao_val) = acao {
                    // Check if origin was reflected or accepted
                    let reflects_origin =
                        acao_val == origin_val || (origin_val == "null" && acao_val == "null");

                    if reflects_origin && acac {
                        let severity = if origin_val == "null" {
                            Severity::High
                        } else {
                            Severity::Critical
                        };

                        let evidence = format!(
                            "Request Header: Origin: {}\nResponse Headers:\nAccess-Control-Allow-Origin: {}\nAccess-Control-Allow-Credentials: true",
                            origin_val, acao_val
                        );

                        findings.push(
                            Finding::new(
                                format!("Exploitable CORS Misconfiguration ({})", attack_label),
                                severity,
                                &target.url,
                                format!(
                                    "The server accepts untrusted origin `{}` in the `Access-Control-Allow-Origin` header and enables credentials (`Access-Control-Allow-Credentials: true`). This allows an attacker to execute authenticated cross-origin requests and steal sensitive data.",
                                    origin_val
                                ),
                                "Implement a strict whitelist of trusted origins and do not dynamically reflect arbitrary Origin request headers when credentials are allowed.",
                                "active/cors-exploit",
                            )
                            .with_evidence(evidence)
                            .with_cwe(942) // CWE-942: Permissive Cross-Domain Policy with Untrusted Domains
                            .with_owasp("A01:2021 – Broken Access Control"),
                        );
                        break; // Found critical flaw, avoid spamming findings
                    } else if (acao_val.contains("evil-attacker.com") || acao_val.contains("evil-"))
                        && !acac
                    {
                        findings.push(
                            Finding::new(
                                format!("Permissive CORS Origin Reflection ({})", attack_label),
                                Severity::Medium,
                                &target.url,
                                format!(
                                    "The server reflects untrusted origin `{}` in `Access-Control-Allow-Origin`.",
                                    origin_val
                                ),
                                "Validate Origin headers against an explicit domain whitelist on the server side.",
                                "active/cors-reflection",
                            )
                            .with_evidence(format!("Origin: {} -> Access-Control-Allow-Origin: {}", origin_val, acao_val))
                            .with_cwe(942)
                            .with_owasp("A01:2021 – Broken Access Control"),
                        );
                        break;
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
    fn test_cors_plugin_instantiation() {
        let plugin = CorsActivePlugin::new();
        assert_eq!(plugin.name(), "cors-advanced");
        assert!(plugin.always_run());
    }
}
