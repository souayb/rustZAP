//! Opt-in: missing-rate-limiting detection.
//!
//! This is a **detection probe, not a load/DoS attack**. It sends a small,
//! fixed-size burst of GET requests (`BURST_SIZE`, currently 15) to the same
//! endpoint through the exact same `HttpSafetyGate` every other active
//! plugin goes through (`--max-rps`, circuit breaker on 5xx/latency), and
//! simply checks whether the target ever responds with `429`/`503` or a
//! `Retry-After` header. If it never does, that is worth reporting: an
//! endpoint with no rate limiting is exposed to brute-force,
//! credential-stuffing, and resource-exhaustion abuse — which is the class of
//! bug this plugin targets.
//!
//! Real load/stress testing (sustained high-rate traffic against a target you
//! control) is a **separate, already-opt-in subcommand**: `rustzap stress`
//! (`src/stress.rs`). This plugin never sends more than `BURST_SIZE`
//! requests and is not a substitute for it.
//!
//! Not part of the default `--plugins` set — enable explicitly with
//! `--plugins rate-limit-missing` (or `all`) against a target you are
//! authorized to test.

use std::collections::HashSet;

use async_trait::async_trait;
use tokio::sync::Mutex;
use url::Url;

use crate::active::{get_with_headers, ScanPlugin};
use crate::types::{DiscoveredUrl, Finding, Severity};

const BURST_SIZE: usize = 15;

pub struct RateLimitMissingPlugin {
    seen_paths: Mutex<HashSet<String>>,
}

impl RateLimitMissingPlugin {
    pub fn new() -> Self {
        Self {
            seen_paths: Mutex::new(HashSet::new()),
        }
    }
}

impl Default for RateLimitMissingPlugin {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl ScanPlugin for RateLimitMissingPlugin {
    fn name(&self) -> &str {
        "rate-limit-missing"
    }
    fn description(&self) -> &str {
        "Opt-in: bounded 15-request burst through the safety gate to detect missing rate limiting (not a load/DoS attack — see `rustzap stress`)"
    }

    fn always_run(&self) -> bool {
        true
    }

    async fn scan(&self, client: &reqwest::Client, target: &DiscoveredUrl) -> Vec<Finding> {
        let mut findings = Vec::new();

        let path_key = match Url::parse(&target.url) {
            Ok(u) => format!(
                "{}://{}{}",
                u.scheme(),
                u.host_str().unwrap_or(""),
                u.path()
            ),
            Err(_) => return findings,
        };
        {
            let mut seen = self.seen_paths.lock().await;
            if !seen.insert(path_key) {
                return findings;
            }
        }

        let mut statuses = Vec::with_capacity(BURST_SIZE);
        let mut saw_throttle = false;
        for _ in 0..BURST_SIZE {
            let Some((status, headers, _body)) = get_with_headers(client, &target.url, &[]).await
            else {
                break;
            };
            statuses.push(status);
            if status == 429 || status == 503 || headers.contains_key("retry-after") {
                saw_throttle = true;
                break;
            }
        }

        if saw_throttle {
            return findings; // rate limiting is present — nothing to report
        }

        // Not enough signal (safety gate likely throttled/aborted us, or the
        // target errored transport-side) — don't report either way.
        if statuses.len() < BURST_SIZE / 2 {
            return findings;
        }

        findings.push(
            Finding::new(
                "No Rate Limiting Detected",
                Severity::Low,
                &target.url,
                format!(
                    "Sent {} consecutive requests to this endpoint and never observed a 429/503 or Retry-After response, suggesting no rate limiting is enforced.",
                    statuses.len()
                ),
                "Add rate limiting (per-IP and, where applicable, per-account) to this endpoint — especially if it handles authentication, password reset, MFA, or other sensitive/high-cost actions.",
                "active/rate-limit-missing",
            )
            .with_evidence(format!(
                "{} consecutive GETs, statuses: {:?}",
                statuses.len(),
                statuses
            ))
            .with_cwe(799)
            .with_owasp("A04:2021 – Insecure Design")
            .tentative(),
        );

        findings
    }
}
