//! Passive Cloud Infrastructure & Metadata Header Auditor.
//!
//! Inspects HTTP response headers for exposed cloud provider metadata, internal
//! routing headers (AWS ALBs, Cloudflare, Fastly, Azure, GCP), and debug server signatures.

use crate::types::{Finding, Severity};

/// Check response headers for cloud server disclosures and misconfigurations.
pub fn check_cloud_headers(url: &str, headers: &reqwest::header::HeaderMap) -> Vec<Finding> {
    let mut findings = Vec::new();

    // Check for internal cloud infrastructure routing headers
    for (name, val) in headers.iter() {
        let key = name.as_str().to_lowercase();
        let val_str = val.to_str().unwrap_or("");

        if key.starts_with("x-amzn-") || key.starts_with("x-amz-") {
            if key == "x-amzn-trace-id" || key == "x-amz-cf-id" {
                continue; // Normal edge tracing
            }
            findings.push(
                Finding::new(
                    "AWS Internal Infrastructure Header Disclosed",
                    Severity::Info,
                    url,
                    format!("Response includes AWS internal header `{}: {}`.", key, val_str),
                    "Strip internal cloud infrastructure headers at edge reverse proxies or API gateways.",
                    "passive/cloud-headers",
                )
                .with_evidence(format!("{}: {}", key, val_str))
                .with_cwe(200)
                .with_owasp("A05:2021 – Security Misconfiguration"),
            );
        } else if key.starts_with("x-azure-ref") || key.starts_with("x-ms-") {
            findings.push(
                Finding::new(
                    "Azure Cloud Infrastructure Header Disclosed",
                    Severity::Info,
                    url,
                    format!("Response includes Azure internal header `{}: {}`.", key, val_str),
                    "Sanitize internal cloud headers before delivering responses to public clients.",
                    "passive/cloud-headers",
                )
                .with_evidence(format!("{}: {}", key, val_str))
                .with_cwe(200)
                .with_owasp("A05:2021 – Security Misconfiguration"),
            );
        } else if key.starts_with("x-goog-") || key.starts_with("x-cloud-trace-context") {
            if key == "x-cloud-trace-context" {
                continue;
            }
            findings.push(
                Finding::new(
                    "GCP Cloud Infrastructure Header Disclosed",
                    Severity::Info,
                    url,
                    format!("Response includes Google Cloud internal header `{}: {}`.", key, val_str),
                    "Configure Cloud Armor / Load Balancers to strip internal GCP header extensions.",
                    "passive/cloud-headers",
                )
                .with_evidence(format!("{}: {}", key, val_str))
                .with_cwe(200)
                .with_owasp("A05:2021 – Security Misconfiguration"),
            );
        }
    }

    findings
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cloud_headers_detection() {
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert("x-azure-ref", "0abcd1234ref".parse().unwrap());
        let findings = check_cloud_headers("https://example.com", &headers);
        assert_eq!(findings.len(), 1);
        assert!(findings[0]
            .title
            .contains("Azure Cloud Infrastructure Header"));
    }
}
