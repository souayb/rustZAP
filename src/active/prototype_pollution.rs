//! Server-Side Prototype Pollution Active Prober (CWE-1321 & OWASP A03:2021).
//!
//! Detects Server-Side Prototype Pollution in Node.js and JavaScript backend runtimes:
//! 1. JSON body prototype mutation (`{"__proto__": {"rz_polluted": true}}`)
//! 2. Object constructor prototype mutation (`{"constructor": {"prototype": {"rz_polluted": true}}}`)
//! 3. Query string deep object parameter pollution (`?__proto__[rz_polluted]=true`)

use async_trait::async_trait;
use url::Url;

use crate::active::{get_response_body, post_response_body, ScanPlugin};
use crate::types::{DiscoveredUrl, Finding, Severity};

pub struct PrototypePollutionPlugin;

impl Default for PrototypePollutionPlugin {
    fn default() -> Self {
        Self::new()
    }
}

impl PrototypePollutionPlugin {
    pub fn new() -> Self {
        Self
    }
}

const POLLUTION_JSON_PAYLOADS: &[&str] = &[
    r#"{"__proto__":{"rz_polluted_canary":true}}"#,
    r#"{"constructor":{"prototype":{"rz_polluted_canary":true}}}"#,
];

#[async_trait]
impl ScanPlugin for PrototypePollutionPlugin {
    fn name(&self) -> &str {
        "prototype-pollution"
    }

    fn description(&self) -> &str {
        "Detects Server-Side Prototype Pollution in Node.js / JavaScript backend runtimes"
    }

    fn always_run(&self) -> bool {
        true
    }

    async fn scan(&self, client: &reqwest::Client, target: &DiscoveredUrl) -> Vec<Finding> {
        let mut findings = Vec::new();
        let Ok(parsed) = Url::parse(&target.url) else {
            return findings;
        };

        // 1. Test JSON POST Payload Prototype Pollution
        for payload in POLLUTION_JSON_PAYLOADS {
            if let Some((status, body)) =
                post_response_body(client, &target.url, "application/json", payload).await
            {
                if status == 200
                    && (body.contains("rz_polluted_canary")
                        || body.contains("\"rz_polluted_canary\":true"))
                {
                    findings.push(
                        Finding::new(
                            "Server-Side Prototype Pollution (JSON Body)",
                            Severity::Critical,
                            &target.url,
                            "The application processed and merged an object containing `__proto__` or `constructor.prototype` properties without sanitization. Prototype pollution can lead to Remote Code Execution (RCE), property injection, or authentication bypass.",
                            "Freeze the object prototype using `Object.freeze(Object.prototype)`, use `Object.create(null)` for map dictionaries, or use secure object merge libraries (e.g. `lodash.merge` >= 4.17.21).",
                            "active/prototype-pollution",
                        )
                        .with_evidence(format!("Payload: {}\nResponse contains polluted canary property", payload))
                        .with_cwe(1321) // CWE-1321: Improperly Controlled Modification of Object Prototype Attributes ('Prototype Pollution')
                        .with_owasp("A03:2021 – Injection"),
                    );
                    return findings; // Confirmed critical flaw
                }
            }
        }

        // 2. Test Query String Prototype Pollution (e.g. ?__proto__[rz_canary]=true)
        let mut query_url = parsed.clone();
        query_url
            .query_pairs_mut()
            .append_pair("__proto__[rz_polluted_canary]", "true");
        let query_url_str = query_url.to_string();

        if let Some((status, body)) = get_response_body(client, &query_url_str).await {
            if status == 200 && body.contains("rz_polluted_canary") {
                findings.push(
                    Finding::new(
                        "Server-Side Prototype Pollution (Query Parameter)",
                        Severity::High,
                        &query_url_str,
                        "Query parameter `__proto__[key]` was parsed as a nested object and mutated the prototype of backend object instances.",
                        "Disable prototype mutation in query string parser libraries (e.g. configure `qs` with `{ allowPrototypes: false }`).",
                        "active/prototype-pollution-query",
                    )
                    .with_evidence(format!("URL: {}\nResponse contains polluted canary property", query_url_str))
                    .with_cwe(1321)
                    .with_owasp("A03:2021 – Injection"),
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
    fn test_prototype_pollution_instantiation() {
        let plugin = PrototypePollutionPlugin::new();
        assert_eq!(plugin.name(), "prototype-pollution");
        assert!(plugin.always_run());
    }
}
