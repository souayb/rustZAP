//! Deterministic HTTP Capture Replay Engine for CI/CD regression testing.
//!
//! Replays serialized HTTP transactions (from previous scans or proxy dumps)
//! to verify whether vulnerabilities remain present or have been remediated.

use crate::types::HttpTransaction;
use anyhow::{Context, Result};
use colored::*;
use std::path::Path;

/// Replay execution options.
#[derive(Debug, Clone, Default)]
pub struct ReplayConfig {
    /// Optional target host override (e.g. `http://localhost:8080`)
    pub target_override: Option<String>,
    /// Request timeout in seconds
    pub timeout_secs: u64,
    /// Verbose per-transaction diff logging
    pub verbose: bool,
}

/// Result of a capture replay run.
#[derive(Debug, Clone, Default)]
pub struct ReplaySummary {
    pub total: usize,
    pub successful: usize,
    pub failed: usize,
    pub status_matched: usize,
    pub status_diverged: usize,
}

/// Run replay on a JSON capture file.
pub async fn run_replay_file(file_path: &Path, config: &ReplayConfig) -> Result<ReplaySummary> {
    let content = std::fs::read_to_string(file_path)
        .with_context(|| format!("Failed to read capture file {}", file_path.display()))?;
    let transactions: Vec<HttpTransaction> = serde_json::from_str(&content)
        .with_context(|| format!("Failed to parse capture file {}", file_path.display()))?;

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(config.timeout_secs.max(5)))
        .danger_accept_invalid_certs(true)
        .build()?;

    let mut summary = ReplaySummary {
        total: transactions.len(),
        ..Default::default()
    };

    println!(
        "{} {} transactions from {}",
        "▶ Replaying".bright_white().bold(),
        transactions.len().to_string().bright_cyan(),
        file_path.display().to_string().bright_yellow()
    );

    for (idx, txn) in transactions.iter().enumerate() {
        let mut target_url = txn.request.url.clone();
        if let Some(ref base) = config.target_override {
            if let Ok(parsed) = url::Url::parse(&txn.request.url) {
                if let Ok(base_url) = url::Url::parse(base) {
                    let mut modified = parsed.clone();
                    let _ = modified.set_scheme(base_url.scheme());
                    let _ = modified.set_host(base_url.host_str());
                    let _ = modified.set_port(base_url.port());
                    target_url = modified.to_string();
                }
            }
        }

        let method = reqwest::Method::from_bytes(txn.request.method.as_bytes())
            .unwrap_or(reqwest::Method::GET);
        let mut req = client.request(method.clone(), &target_url);

        for (k, v) in &txn.request.headers {
            if !k.eq_ignore_ascii_case("host") && !k.eq_ignore_ascii_case("content-length") {
                req = req.header(k, v);
            }
        }

        if let Some(ref body) = txn.request.body {
            req = req.body(body.clone());
        }

        match req.send().await {
            Ok(resp) => {
                let status = resp.status().as_u16();
                summary.successful += 1;
                let expected_status = txn.response.as_ref().map(|r| r.status).unwrap_or(200);

                if status == expected_status {
                    summary.status_matched += 1;
                    println!(
                        "  [{}/{}] {} {} → status {}",
                        idx + 1,
                        transactions.len(),
                        method.to_string().bright_cyan(),
                        target_url.dimmed(),
                        status.to_string().bright_green()
                    );
                } else {
                    summary.status_diverged += 1;
                    println!(
                        "  [{}/{}] {} {} → status {} (expected {})",
                        idx + 1,
                        transactions.len(),
                        method.to_string().bright_cyan(),
                        target_url.dimmed(),
                        status.to_string().bright_yellow(),
                        expected_status.to_string().bright_white()
                    );
                }
            }
            Err(e) => {
                summary.failed += 1;
                println!(
                    "  [{}/{}] {} {} → {}",
                    idx + 1,
                    transactions.len(),
                    method.to_string().bright_cyan(),
                    target_url.dimmed(),
                    format!("ERROR: {e}").bright_red()
                );
            }
        }
    }

    println!("\n{}", "Replay Summary".bright_white().bold());
    println!("{}", "─".repeat(40).dimmed());
    println!("  Total transactions : {}", summary.total);
    println!(
        "  Successful         : {}",
        summary.successful.to_string().bright_green()
    );
    println!(
        "  Failed             : {}",
        summary.failed.to_string().bright_red()
    );
    println!(
        "  Status matched     : {}",
        summary.status_matched.to_string().bright_green()
    );
    println!(
        "  Status diverged    : {}",
        summary.status_diverged.to_string().bright_yellow()
    );

    Ok(summary)
}
