//! Canary Token Recognition & Honeypot / Tarpit Evasion Intelligence.
//!
//! Protects automated security agents and crawlers from triggering honeytokens,
//! alerting deception sensors, or getting trapped in recursive crawler traps / tarpits.

use regex::Regex;
use std::collections::HashSet;
use url::Url;

/// Classification of detected deception / honeypot artifacts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HoneypotType {
    CanaryDomain(String),
    CanaryPath(String),
    TrackingPixel,
    CanaryTokenCredential(String),
    CrawlerTarpit(String),
}

/// Honeypot and Canary token inspector.
pub struct HoneypotIntelligence {
    canary_domains: HashSet<&'static str>,
    canary_path_regex: Regex,
    canary_aws_regex: Regex,
}

impl Default for HoneypotIntelligence {
    fn default() -> Self {
        Self::new()
    }
}

impl HoneypotIntelligence {
    pub fn new() -> Self {
        let mut canary_domains = HashSet::new();
        canary_domains.insert("canarytokens.com");
        canary_domains.insert("canarytokens.org");
        canary_domains.insert("canarytokens.net");
        canary_domains.insert("thinkst.com");
        canary_domains.insert("dnslog.cn");
        canary_domains.insert("ceye.io");
        canary_domains.insert("oastify.com");
        canary_domains.insert("burpcollaborator.net");
        canary_domains.insert("interact.sh");
        canary_domains.insert("pingb.in");
        canary_domains.insert("canary.tools");

        Self {
            canary_domains,
            canary_path_regex: Regex::new(
                r#"(?i)(?:canary|honeytoken|honey-token|canarytoken|web_bug|tracker\.gif)"#,
            )
            .unwrap(),
            canary_aws_regex: Regex::new(r#"\b(?:AKIAIOSFODNN7EXAMPLE|AKIA[0-9A-Z]{16})\b"#)
                .unwrap(),
        }
    }

    /// Check if a URL belongs to a known canary domain or honeypot host.
    pub fn is_canary_domain(&self, url_str: &str) -> Option<String> {
        if let Ok(parsed) = Url::parse(url_str) {
            if let Some(host) = parsed.host_str() {
                let host_lower = host.to_ascii_lowercase();
                for domain in &self.canary_domains {
                    if host_lower == *domain || host_lower.ends_with(&format!(".{}", domain)) {
                        return Some((*domain).to_string());
                    }
                }
            }
        }
        None
    }

    /// Check if a URL pattern indicates a crawler trap / cyclic recursion.
    pub fn is_cyclic_tarpit(&self, url_str: &str) -> bool {
        if let Ok(parsed) = Url::parse(url_str) {
            let path = parsed.path();
            let segments: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
            if segments.len() > 10 {
                return true;
            }

            // Check if any segment appears 3 or more times
            let mut counts = std::collections::HashMap::new();
            for s in &segments {
                let count = counts.entry(*s).or_insert(0);
                *count += 1;
                if *count >= 3 && segments.len() >= 4 {
                    return true;
                }
            }
        }
        false
    }

    /// Check if a URL has suspicious honeypot path or web bug tokens.
    pub fn is_canary_url(&self, url_str: &str) -> Option<HoneypotType> {
        if let Some(domain) = self.is_canary_domain(url_str) {
            return Some(HoneypotType::CanaryDomain(domain));
        }

        if self.is_cyclic_tarpit(url_str) {
            return Some(HoneypotType::CrawlerTarpit("Cyclic path trap".to_string()));
        }

        if self.canary_path_regex.is_match(url_str) {
            return Some(HoneypotType::CanaryPath(
                "Canary token URL path".to_string(),
            ));
        }

        None
    }

    /// Check if an AWS key or credential matches known Canarytoken dummy patterns.
    pub fn is_canary_credential(&self, secret_text: &str) -> bool {
        if secret_text.contains("AKIAIOSFODNN7EXAMPLE") {
            return true;
        }
        if let Some(mat) = self.canary_aws_regex.find(secret_text) {
            if mat.as_str() == "AKIAIOSFODNN7EXAMPLE" {
                return true;
            }
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_canary_domain_detection() {
        let intel = HoneypotIntelligence::new();
        assert!(intel
            .is_canary_domain("https://abc123xyz.canarytokens.com/history")
            .is_some());
        assert!(intel
            .is_canary_domain("http://logger.oastify.com/p/1")
            .is_some());
        assert!(intel.is_canary_domain("https://example.com/api").is_none());
    }

    #[test]
    fn test_crawler_tarpit_cyclic_detection() {
        let intel = HoneypotIntelligence::new();
        let cyclic_url = "https://example.com/calendar/2026/01/calendar/2026/01/calendar/2026/01";
        assert!(intel.is_cyclic_tarpit(cyclic_url));

        let normal_url = "https://example.com/api/v1/users/123/orders";
        assert!(!intel.is_cyclic_tarpit(normal_url));
    }

    #[test]
    fn test_canary_credential_detection() {
        let intel = HoneypotIntelligence::new();
        assert!(intel.is_canary_credential("AWS_KEY=AKIAIOSFODNN7EXAMPLE"));
        assert!(!intel.is_canary_credential("AWS_KEY=AKIA1234567890ABCDEF"));
    }
}
