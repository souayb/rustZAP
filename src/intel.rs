//! C2 — Optional external intel hook.
//!
//! Reads API keys from the environment and, when set, enriches scan output
//! with open-port / known-CVE data from third-party services. Default
//! behaviour with no env vars: the module is a no-op. Currently wires
//! Shodan host lookup — other providers (Censys, VirusTotal) can hang off
//! the same `IntelConfig`.
//!
//! Env vars consumed (any subset):
//! - `SHODAN_API_KEY` — Shodan REST host lookup
//!
//! Legal note: per the platform agreement and FEATURE.md, only call these
//! services for hosts you are authorized to scan. The CLI keeps the keys
//! out of process arguments — they live in the environment.

use serde::Deserialize;
use std::time::Duration;

use crate::types::{Finding, Severity};

#[derive(Debug, Clone, Default)]
pub struct IntelConfig {
    pub shodan_api_key: Option<String>,
}

impl IntelConfig {
    /// Read every supported env var. Returns a default-empty config when
    /// none are set. Callers can short-circuit with `is_enabled`.
    pub fn from_env() -> Self {
        Self {
            shodan_api_key: std::env::var("SHODAN_API_KEY")
                .ok()
                .filter(|v| !v.trim().is_empty()),
        }
    }

    pub fn is_enabled(&self) -> bool {
        self.shodan_api_key.is_some()
    }
}

/// Canonical list of plugin ids this module can emit. Only meaningful when
/// at least one provider is enabled via `IntelConfig::is_enabled`.
pub fn known_plugin_names() -> &'static [&'static str] {
    &["intel/shodan-vulns", "intel/shodan-ports"]
}

/// Public entry-point. Iterates configured providers and produces findings.
pub async fn enrich_hosts(config: &IntelConfig, hosts: &[String]) -> Vec<Finding> {
    if !config.is_enabled() {
        return vec![];
    }

    let client = match reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .user_agent("RustZAP/0.1 Intel")
        .build()
    {
        Ok(c) => c,
        Err(_) => return vec![],
    };

    let mut findings = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for host in hosts {
        if !seen.insert(host.clone()) {
            continue;
        }
        if let Some(key) = &config.shodan_api_key {
            if let Some(resp) = fetch_shodan_host(&client, key, host).await {
                findings.extend(evaluate_shodan(host, &resp));
            }
        }
    }
    findings
}

#[derive(Debug, Deserialize, Default)]
#[allow(dead_code)] // `hostnames`, `org`, `country_code` are deserialized for downstream report consumers.
pub struct ShodanHost {
    #[serde(default)]
    pub ports: Vec<u16>,
    #[serde(default)]
    pub vulns: Vec<String>,
    #[serde(default)]
    pub hostnames: Vec<String>,
    #[serde(default)]
    pub org: Option<String>,
    #[serde(default)]
    pub country_code: Option<String>,
}

async fn fetch_shodan_host(
    client: &reqwest::Client,
    api_key: &str,
    host: &str,
) -> Option<ShodanHost> {
    // Shodan's /shodan/host/{ip} accepts IP, not hostname. We let the
    // platform handle DNS — if `host` isn't an IP, Shodan returns 404
    // which we silently drop.
    let url = format!("https://api.shodan.io/shodan/host/{}?key={}", host, api_key);
    let resp = client.get(&url).send().await.ok()?;
    if !resp.status().is_success() {
        return None;
    }
    resp.json::<ShodanHost>().await.ok()
}

/// Pure evaluator — separated for testing without network.
pub fn evaluate_shodan(host: &str, shodan: &ShodanHost) -> Vec<Finding> {
    let mut findings = Vec::new();
    let target = format!("https://{}", host);

    if !shodan.vulns.is_empty() {
        let preview = shodan.vulns.iter().take(10).cloned().collect::<Vec<_>>();
        findings.push(
            Finding::new(
                "Shodan-reported Known Vulnerabilities",
                Severity::High,
                &target,
                format!(
                    "Shodan associates {} with {} known CVE(s). The list reflects services exposed to the public internet.",
                    host,
                    shodan.vulns.len()
                ),
                "Patch the affected services. Cross-reference each CVE with the version banner before triaging.",
                "intel/shodan-vulns",
            )
            .with_evidence(preview.join(", "))
            .with_cwe(1395)
            .with_owasp("A06:2021 – Vulnerable and Outdated Components"),
        );
    }

    if shodan.ports.len() > 5 {
        findings.push(
            Finding::new(
                "Large Open-Port Surface (Shodan)",
                Severity::Low,
                &target,
                format!(
                    "Shodan reports {} open ports for {}. Each unnecessary service is an additional attack surface.",
                    shodan.ports.len(),
                    host
                ),
                "Audit exposed services. Block unused ports at the firewall.",
                "intel/shodan-ports",
            )
            .with_evidence(format!(
                "Ports: {}",
                shodan
                    .ports
                    .iter()
                    .map(|p| p.to_string())
                    .collect::<Vec<_>>()
                    .join(",")
            )),
        );
    }

    findings
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_disabled_when_no_env() {
        let cfg = IntelConfig::default();
        assert!(!cfg.is_enabled());
    }

    #[test]
    fn config_enabled_with_shodan_key() {
        let cfg = IntelConfig {
            shodan_api_key: Some("test".to_string()),
        };
        assert!(cfg.is_enabled());
    }

    #[test]
    fn evaluate_shodan_flags_vulns_as_high() {
        let s = ShodanHost {
            ports: vec![22, 80, 443],
            vulns: vec!["CVE-2023-1234".into(), "CVE-2024-5678".into()],
            ..Default::default()
        };
        let findings = evaluate_shodan("1.2.3.4", &s);
        assert!(findings.iter().any(|f| f.severity == Severity::High));
        assert!(findings
            .iter()
            .any(|f| f.title.contains("Known Vulnerabilities")));
    }

    #[test]
    fn evaluate_shodan_flags_large_port_surface() {
        let s = ShodanHost {
            ports: vec![22, 25, 80, 110, 143, 443, 8080],
            ..Default::default()
        };
        let findings = evaluate_shodan("1.2.3.4", &s);
        assert!(findings.iter().any(|f| f.title.contains("Open-Port")));
    }

    #[test]
    fn evaluate_shodan_quiet_when_clean() {
        let s = ShodanHost {
            ports: vec![443],
            ..Default::default()
        };
        let findings = evaluate_shodan("1.2.3.4", &s);
        assert!(findings.is_empty());
    }

    #[tokio::test]
    async fn enrich_hosts_disabled_returns_empty() {
        let cfg = IntelConfig::default();
        let out = enrich_hosts(&cfg, &["example.com".into()]).await;
        assert!(out.is_empty());
    }
}
