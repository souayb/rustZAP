//! Opt-in: Web Cache Deception + Web Cache Poisoning probes.
//!
//! Both require a shared cache (CDN, reverse proxy) in front of the target to
//! actually matter, and both carry a higher false-positive risk than the rest
//! of the active suite (see FEATURE.md / CLAUDE.md). Neither plugin is part
//! of the default `--plugins` set — enable explicitly with
//! `--plugins cache-deception,cache-poisoning` (or `all`) against a target you
//! are authorized to test.

use std::collections::HashSet;

use async_trait::async_trait;
use tokio::sync::Mutex;
use url::Url;

use crate::active::{get_with_headers, ScanPlugin};
use crate::types::{DiscoveredUrl, Finding, Severity};

/// True when response headers carry a recognizable cache-HIT signal from a
/// CDN/reverse proxy (Cloudflare, Varnish, Akamai, Fastly, generic `X-Cache`).
fn header_indicates_cache_hit(headers: &reqwest::header::HeaderMap) -> bool {
    if let Some(v) = headers.get("cf-cache-status").and_then(|v| v.to_str().ok()) {
        if v.eq_ignore_ascii_case("hit") {
            return true;
        }
    }
    if let Some(v) = headers.get("x-cache").and_then(|v| v.to_str().ok()) {
        if v.to_lowercase().contains("hit") {
            return true;
        }
    }
    if let Some(v) = headers.get("x-varnish-cache").and_then(|v| v.to_str().ok()) {
        if v.eq_ignore_ascii_case("hit") {
            return true;
        }
    }
    if let Some(v) = headers.get("age").and_then(|v| v.to_str().ok()) {
        if v.trim().parse::<u64>().map(|n| n > 0).unwrap_or(false) {
            return true;
        }
    }
    false
}

// ─────────────────────────────────────────────────────────────────────────────
// Web Cache Deception
// ─────────────────────────────────────────────────────────────────────────────

/// Appends a static-looking suffix (`/rustzap-cache-deception.css`) to a
/// dynamic path. If a shared cache stores the result under that suffixed key
/// — despite the response still being the original dynamic (often
/// user-specific) content — a follow-up request returns the same body with a
/// cache-HIT indicator, meaning any other client requesting that same
/// suffixed path would be served the *first* client's cached response.
pub struct CacheDeceptionPlugin {
    seen_urls: Mutex<HashSet<String>>,
}

impl CacheDeceptionPlugin {
    pub fn new() -> Self {
        Self {
            seen_urls: Mutex::new(HashSet::new()),
        }
    }
}

impl Default for CacheDeceptionPlugin {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl ScanPlugin for CacheDeceptionPlugin {
    fn name(&self) -> &str {
        "cache-deception"
    }
    fn description(&self) -> &str {
        "Opt-in: Web Cache Deception — static-suffix path caching of dynamic/personalized content"
    }

    fn always_run(&self) -> bool {
        true
    }

    async fn scan(&self, client: &reqwest::Client, target: &DiscoveredUrl) -> Vec<Finding> {
        let mut findings = Vec::new();

        {
            let mut seen = self.seen_urls.lock().await;
            if !seen.insert(target.url.clone()) {
                return findings;
            }
        }

        let Ok(parsed) = Url::parse(&target.url) else {
            return findings;
        };
        if parsed.path() == "/" {
            return findings;
        }

        let Some((base_status, _base_headers, base_body)) =
            get_with_headers(client, &target.url, &[]).await
        else {
            return findings;
        };
        // Only worth testing a real, non-trivial 200 response.
        if base_status != 200 || base_body.len() < 32 {
            return findings;
        }

        let mut variant = parsed.clone();
        let new_path = format!(
            "{}/rustzap-cache-deception.css",
            parsed.path().trim_end_matches('/')
        );
        variant.set_path(&new_path);
        let variant_url = variant.to_string();

        // First request primes a cache (if any); the second checks for a HIT.
        let _ = get_with_headers(client, &variant_url, &[]).await;
        let Some((variant_status, variant_headers, variant_body)) =
            get_with_headers(client, &variant_url, &[]).await
        else {
            return findings;
        };
        if variant_status != 200 {
            return findings;
        }

        let cache_hit = header_indicates_cache_hit(&variant_headers);
        let similarity = crate::verify::body_similarity(&base_body, &variant_body);

        if cache_hit && similarity > 0.85 {
            findings.push(
                Finding::new(
                    "Web Cache Deception",
                    Severity::High,
                    &target.url,
                    format!(
                        "Appending a static-looking suffix to this dynamic path (`{}`) returned the original page content with a cache-HIT indicator, meaning a shared cache stored and will replay this response — potentially including session-specific content — to other requesters of that same suffixed URL.",
                        new_path
                    ),
                    "Configure the cache/CDN to key on the full request path and never cache a path that doesn't map to a real static file. Reject or normalize requests where a static extension is appended after a dynamic path segment.",
                    "active/cache-deception",
                )
                .with_evidence(format!(
                    "GET {} → HTTP {} with a cache-HIT indicator, {:.0}% similar to the original dynamic response",
                    variant_url,
                    variant_status,
                    similarity * 100.0
                ))
                .with_cwe(524)
                .with_owasp("A05:2021 – Security Misconfiguration")
                .tentative(),
            );
        }

        findings
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Web Cache Poisoning
// ─────────────────────────────────────────────────────────────────────────────

/// Sends a request carrying an unkeyed header (`X-Forwarded-Host` /
/// `X-Forwarded-Scheme`) that some origins reflect into the response without
/// including it in the cache key, then re-requests the same URL as a plain
/// client. If the plain response still carries the injected marker, the
/// cache stored the poisoned variant and is replaying it to everyone.
pub struct CachePoisoningPlugin;

#[async_trait]
impl ScanPlugin for CachePoisoningPlugin {
    fn name(&self) -> &str {
        "cache-poisoning"
    }
    fn description(&self) -> &str {
        "Opt-in: Web Cache Poisoning — unkeyed header (X-Forwarded-Host) reflected into a cached response"
    }

    fn always_run(&self) -> bool {
        true
    }

    async fn scan(&self, client: &reqwest::Client, target: &DiscoveredUrl) -> Vec<Finding> {
        let mut findings = Vec::new();

        let token = crate::verify::rand_token(8);
        let evil_host = format!("rustzap-cp-{}.example", token);
        let evil_lower = evil_host.to_lowercase();

        // "Attacker" request carrying the unkeyed header.
        let poison_headers = [
            ("X-Forwarded-Host", evil_host.as_str()),
            ("X-Forwarded-Scheme", "http"),
        ];
        if get_with_headers(client, &target.url, &poison_headers)
            .await
            .is_none()
        {
            return findings;
        }

        // "Victim" request — plain GET, no special headers.
        let Some((status, headers, body)) = get_with_headers(client, &target.url, &[]).await else {
            return findings;
        };

        let reflected = body.to_lowercase().contains(&evil_lower)
            || headers
                .get("location")
                .and_then(|v| v.to_str().ok())
                .map(|l| l.to_lowercase().contains(&evil_lower))
                .unwrap_or(false);

        if reflected {
            let cache_hit = header_indicates_cache_hit(&headers);
            let finding = Finding::new(
                "Web Cache Poisoning",
                Severity::High,
                &target.url,
                "A request carrying an unkeyed header (X-Forwarded-Host) was reflected into the origin's response, and a follow-up plain request without that header still shows the injected value — consistent with a shared cache having stored and replayed the poisoned response to subsequent requesters.",
                "Ensure the cache key includes every header the origin's response depends on (or stop trusting unkeyed headers like X-Forwarded-Host/X-Forwarded-Scheme when building absolute URLs, canonical links, or redirects).",
                "active/cache-poisoning",
            )
            .with_evidence(format!(
                "Follow-up plain GET (HTTP {}) still reflects the injected X-Forwarded-Host `{}`{}",
                status,
                evil_host,
                if cache_hit { " — cache-HIT indicator present" } else { "" }
            ))
            .with_cwe(444)
            .with_owasp("A05:2021 – Security Misconfiguration");

            findings.push(if cache_hit {
                finding.confirmed()
            } else {
                finding.tentative()
            });
        }

        findings
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use reqwest::header::{HeaderMap, HeaderName, HeaderValue};

    fn headers_from(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut h = HeaderMap::new();
        for (k, v) in pairs {
            h.insert(
                HeaderName::from_bytes(k.as_bytes()).unwrap(),
                HeaderValue::from_str(v).unwrap(),
            );
        }
        h
    }

    #[test]
    fn cache_hit_detected_via_cf_header() {
        assert!(header_indicates_cache_hit(&headers_from(&[(
            "cf-cache-status",
            "HIT"
        )])));
        assert!(!header_indicates_cache_hit(&headers_from(&[(
            "cf-cache-status",
            "MISS"
        )])));
    }

    #[test]
    fn cache_hit_detected_via_age_header() {
        assert!(header_indicates_cache_hit(&headers_from(&[("age", "42")])));
        assert!(!header_indicates_cache_hit(&headers_from(&[("age", "0")])));
    }

    #[test]
    fn cache_hit_detected_via_generic_x_cache() {
        assert!(header_indicates_cache_hit(&headers_from(&[(
            "x-cache",
            "Hit from cloudfront"
        )])));
        assert!(!header_indicates_cache_hit(&HeaderMap::new()));
    }
}
