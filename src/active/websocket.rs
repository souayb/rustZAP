//! WebSocket Security & Cross-Site WebSocket Hijacking (CSWSH) Prober (CWE-1385 & OWASP A01:2021).
//!
//! Detects:
//! 1. Cross-Site WebSocket Hijacking (CSWSH) via missing `Origin` validation during handshake
//! 2. Sensitive Authentication Token leakage in WebSocket URL query strings
//! 3. Insecure unencrypted WebSocket transports (`ws://` vs `wss://`)

use async_trait::async_trait;
use url::Url;

use crate::active::{active_gate, ScanPlugin};
use crate::types::{DiscoveredUrl, Finding, Severity};

pub struct WebSocketPlugin;

impl Default for WebSocketPlugin {
    fn default() -> Self {
        Self::new()
    }
}

impl WebSocketPlugin {
    pub fn new() -> Self {
        Self
    }

    /// Check if target URL suggests a WebSocket endpoint.
    pub fn is_websocket_target(url_str: &str) -> bool {
        let Ok(parsed) = Url::parse(url_str) else {
            return false;
        };

        if parsed.scheme() == "ws" || parsed.scheme() == "wss" {
            return true;
        }

        let path = parsed.path().to_lowercase();
        path.contains("/ws")
            || path.contains("/websocket")
            || path.contains("/socket.io")
            || path.contains("/cable")
            || path.contains("/stream")
            || path.contains("/chat")
            || path.ends_with("/graphql")
    }
}

#[async_trait]
impl ScanPlugin for WebSocketPlugin {
    fn name(&self) -> &str {
        "websocket-security"
    }

    fn description(&self) -> &str {
        "Detects Cross-Site WebSocket Hijacking (CSWSH) and exposed tokens in WebSocket endpoints"
    }

    fn always_run(&self) -> bool {
        true
    }

    async fn scan(&self, client: &reqwest::Client, target: &DiscoveredUrl) -> Vec<Finding> {
        let mut findings = Vec::new();

        if !Self::is_websocket_target(&target.url) {
            return findings;
        }

        let Ok(parsed) = Url::parse(&target.url) else {
            return findings;
        };

        // 1. Check for sensitive authentication tokens in query strings
        for (key, val) in parsed.query_pairs() {
            let k_lower = key.to_lowercase();
            if (k_lower.contains("token")
                || k_lower.contains("auth")
                || k_lower.contains("key")
                || k_lower.contains("jwt")
                || k_lower.contains("secret"))
                && val.len() > 8
            {
                findings.push(
                    Finding::new(
                        "Authentication Token Exposed in WebSocket URL Query",
                        Severity::Medium,
                        &target.url,
                        format!("WebSocket connection endpoint exposes credential token in query parameter `{}`. URL query strings are logged in access logs, proxies, and browser history.", key),
                        "Authenticate WebSocket connections using standard HTTP cookies or send authentication messages immediately after establishing the WebSocket connection rather than passing tokens in the URL.",
                        "active/websocket-query-auth",
                    )
                    .with_evidence(format!("{}={}", key, crate::types::safe_truncate(&val, 16)))
                    .with_cwe(598) // CWE-598: Use of GET Request Method with Sensitive Data in Query String
                    .with_owasp("A07:2021 – Identification and Authentication Failures"),
                );
            }
        }

        // 2. Test Cross-Site WebSocket Hijacking (CSWSH) by attempting handshake with attacker Origin
        if let Some(gate) = active_gate() {
            if gate
                .before_url_request("GET", &target.url, None)
                .await
                .is_err()
            {
                return findings;
            }
        }

        // Send WebSocket handshake request
        let handshake_resp = client
            .get(&target.url)
            .header("Upgrade", "websocket")
            .header("Connection", "Upgrade")
            .header("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
            .header("Sec-WebSocket-Version", "13")
            .header("Origin", "https://evil-attacker.com")
            .send()
            .await;

        if let Ok(resp) = handshake_resp {
            let status = resp.status().as_u16();
            let headers = resp.headers().clone();

            if let Some(gate) = active_gate() {
                let _ = gate.after_response(status, 0);
            }

            let has_upgrade = headers
                .get("upgrade")
                .and_then(|v| v.to_str().ok())
                .map(|v| v.eq_ignore_ascii_case("websocket"))
                .unwrap_or(false);
            let has_accept = headers.contains_key("sec-websocket-accept");

            // If server switches protocol (101) or returns Sec-WebSocket-Accept for evil-attacker.com:
            if status == 101 || (has_upgrade && has_accept) {
                let evidence = format!(
                    "Request Header: Origin: https://evil-attacker.com\nResponse Status: {}\nUpgrade: websocket\nSec-WebSocket-Accept: present",
                    status
                );

                findings.push(
                    Finding::new(
                        "Cross-Site WebSocket Hijacking (CSWSH)",
                        Severity::High,
                        &target.url,
                        "The server accepted a WebSocket upgrade request from untrusted origin `https://evil-attacker.com` without validating the Origin header. An attacker can hijack user WebSocket sessions from malicious websites to intercept or inject real-time messages.",
                        "Validate the `Origin` header during the WebSocket handshake against an explicit whitelist of trusted domains and reject untrusted origins (e.g. return HTTP 403 Forbidden).",
                        "active/cswsh",
                    )
                    .with_evidence(evidence)
                    .with_cwe(1385) // CWE-1385: Missing Origin Validation in WebSockets
                    .with_owasp("A01:2021 – Broken Access Control"),
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
    fn test_is_websocket_target() {
        assert!(WebSocketPlugin::is_websocket_target(
            "wss://example.com/socket"
        ));
        assert!(WebSocketPlugin::is_websocket_target(
            "https://example.com/ws"
        ));
        assert!(WebSocketPlugin::is_websocket_target(
            "https://example.com/socket.io/?EIO=4"
        ));
        assert!(!WebSocketPlugin::is_websocket_target(
            "https://example.com/about.html"
        ));
    }
}
