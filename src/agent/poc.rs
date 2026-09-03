//! PoC Synthesizer and Validation Engine (Strix-inspired).
//!
//! Generates standalone, reproducible Proof-of-Concept (PoC) scripts (curl / Python)
//! and records verifiable execution proof for confirmed security findings.

use crate::types::PocProof;

/// Synthesize a self-contained `curl` command that reproduces an exploit request.
pub fn synthesize_curl_poc(
    method: &str,
    url: &str,
    headers: &[(String, String)],
    body: Option<&str>,
) -> String {
    let mut parts = vec![format!("curl -s -k -X {}", method.to_uppercase())];

    for (k, v) in headers {
        if !k.eq_ignore_ascii_case("host") && !k.eq_ignore_ascii_case("content-length") {
            parts.push(format!("-H '{}: {}'", k, v.replace('\'', "'\\''")));
        }
    }

    if let Some(b) = body {
        if !b.is_empty() {
            parts.push(format!("-d '{}'", b.replace('\'', "'\\''")));
        }
    }

    parts.push(format!("'{}'", url.replace('\'', "'\\''")));
    parts.join(" ")
}

/// Synthesize a self-contained Python reproduction script.
pub fn synthesize_python_poc(
    method: &str,
    url: &str,
    headers: &[(String, String)],
    body: Option<&str>,
) -> String {
    let headers_json = serde_json::to_string_pretty(
        &headers
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect::<std::collections::HashMap<_, _>>(),
    )
    .unwrap_or_else(|_| "{}".to_string());

    let body_repr = match body {
        Some(b) => format!(
            "data = {}",
            serde_json::to_string(b).unwrap_or_else(|_| "\"\"".to_string())
        ),
        None => "data = None".to_string(),
    };

    format!(
        r#"#!/usr/bin/env python3
import requests
import urllib3
urllib3.disable_warnings()

url = {url:?}
method = {method:?}
headers = {headers_json}
{body_repr}

response = requests.request(
    method=method,
    url=url,
    headers=headers,
    data=data,
    verify=False,
    timeout=10
)

print(f"Status: {{response.status_code}}")
print("Response Snippet:")
print(response.text[:500])
"#,
        url = url,
        method = method.to_uppercase(),
        headers_json = headers_json,
        body_repr = body_repr,
    )
}

/// Construct a `PocProof` record from execution results.
pub fn build_poc_proof(
    method: &str,
    url: &str,
    headers: &[(String, String)],
    body: Option<&str>,
    canary_sent: impl Into<String>,
    canary_received: impl Into<String>,
    raw_response: impl Into<String>,
    execution_time_ms: u64,
) -> PocProof {
    let script_content = synthesize_curl_poc(method, url, headers, body);
    let raw_request = format!(
        "{} {}\n{}\n\n{}",
        method.to_uppercase(),
        url,
        headers
            .iter()
            .map(|(k, v)| format!("{k}: {v}"))
            .collect::<Vec<_>>()
            .join("\n"),
        body.unwrap_or_default()
    );

    PocProof {
        script_type: "curl".to_string(),
        script_content,
        canary_sent: canary_sent.into(),
        canary_received: canary_received.into(),
        raw_request,
        raw_response: raw_response.into(),
        execution_time_ms,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_synthesize_curl_poc() {
        let headers = vec![
            ("User-Agent".to_string(), "RustZAP".to_string()),
            ("Content-Type".to_string(), "application/json".to_string()),
        ];
        let curl = synthesize_curl_poc(
            "POST",
            "http://example.com/api",
            &headers,
            Some("{\"id\":1}"),
        );
        assert!(curl.contains("-X POST"));
        assert!(curl.contains("-H 'Content-Type: application/json'"));
        assert!(curl.contains("-d '{\"id\":1}'"));
        assert!(curl.contains("'http://example.com/api'"));
    }

    #[test]
    fn test_synthesize_python_poc() {
        let headers = vec![("Accept".to_string(), "application/json".to_string())];
        let py = synthesize_python_poc("GET", "http://example.com/api", &headers, None);
        assert!(py.contains("requests.request"));
        assert!(py.contains("http://example.com/api"));
    }
}
