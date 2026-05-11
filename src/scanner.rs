use std::sync::Arc;
use std::time::Instant;
use base64::Engine;

use anyhow::Result;
use colored::*;
use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
use tokio::sync::Mutex;

use crate::active::ActiveScanner;
use crate::passive::PassiveScanner;
use crate::report::Report;
use crate::spider::Spider;
use crate::types::{DiscoveredUrl, Finding};

/// Full scan configuration
#[derive(Debug, Clone)]
pub struct ScanConfig {
    pub target_url: String,
    pub max_depth: usize,
    pub concurrency: usize,
    pub passive_only: bool,
    pub output_file: String,
    pub timeout_secs: u64,
    pub user_agent: Option<String>,
    pub cookies: Option<String>,
    pub auth_header: Option<String>,
    pub api_key: Option<String>,
    pub basic_auth: Option<String>,
    pub insecure: bool,
    pub plugins: Vec<String>,
}

/// Shared HTTP client factory
pub fn build_client(config: &ScanConfig) -> Result<reqwest::Client> {
    let mut builder = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(config.timeout_secs))
        .danger_accept_invalid_certs(config.insecure)
        .cookie_store(true)
        .redirect(reqwest::redirect::Policy::limited(10));

    let ua = config
        .user_agent
        .clone()
        .unwrap_or_else(|| "RustZAP/0.1 (Security Scanner)".to_string());
    builder = builder.user_agent(ua);

    let mut default_headers = reqwest::header::HeaderMap::new();

    if let Some(cookies) = &config.cookies {
        default_headers.insert(
            reqwest::header::COOKIE,
            reqwest::header::HeaderValue::from_str(cookies)?,
        );
    }

    if let Some(auth) = &config.auth_header {
        default_headers.insert(
            reqwest::header::AUTHORIZATION,
            reqwest::header::HeaderValue::from_str(auth)?,
        );
    }

    if let Some(api_key) = &config.api_key {
        // Assume format is "Header-Name: Value"
        if let Some((k, v)) = api_key.split_once(':') {
            if let Ok(key) = reqwest::header::HeaderName::from_bytes(k.trim().as_bytes()) {
                if let Ok(val) = reqwest::header::HeaderValue::from_str(v.trim()) {
                    default_headers.insert(key, val);
                }
            }
        }
    }

    if let Some(basic_auth) = &config.basic_auth {
        // basic_auth expected as "username:password"
        let encoded = base64::engine::general_purpose::STANDARD.encode(basic_auth);
        let auth_val = format!("Basic {}", encoded);
        if let Ok(val) = reqwest::header::HeaderValue::from_str(&auth_val) {
            default_headers.insert(
                reqwest::header::AUTHORIZATION,
                val,
            );
        }
    }

    if !default_headers.is_empty() {
        builder = builder.default_headers(default_headers);
    }

    Ok(builder.build()?)
}

/// Entry point for a full scan
pub async fn run_scan(config: ScanConfig) -> Result<()> {
    let start = Instant::now();

    println!(
        "{} {}",
        "▶ Target:".bright_white().bold(),
        config.target_url.bright_cyan()
    );
    println!(
        "{} depth={} concurrency={} passive_only={}",
        "▶ Config:".bright_white().bold(),
        config.max_depth,
        config.concurrency,
        config.passive_only
    );
    if !config.passive_only {
        println!(
            "{} {}",
            "▶ Plugins:".bright_white().bold(),
            config.plugins.join(", ").bright_magenta()
        );
    }
    println!();

    let client = Arc::new(build_client(&config)?);
    let findings: Arc<Mutex<Vec<Finding>>> = Arc::new(Mutex::new(Vec::new()));
    let mp = MultiProgress::new();

    // ─── Phase 1: Spider ──────────────────────────────────────────
    let spider_pb = mp.add(ProgressBar::new_spinner());
    spider_pb.set_style(
        ProgressStyle::default_spinner()
            .template("{spinner:.cyan} {prefix:.bold} {msg}")
            .unwrap(),
    );
    spider_pb.set_prefix("SPIDER");
    spider_pb.set_message("Crawling...");
    spider_pb.enable_steady_tick(std::time::Duration::from_millis(100));

    let spider = Spider::new(
        client.clone(),
        config.target_url.clone(),
        config.max_depth,
        config.concurrency,
    );

    let discovered = spider.crawl(&spider_pb).await?;
    spider_pb.finish_with_message(format!(
        "✓ Discovered {} URLs",
        discovered.len()
    ));

    // ─── Phase 2: Passive Scanning ────────────────────────────────
    let passive_pb = mp.add(ProgressBar::new(discovered.len() as u64));
    passive_pb.set_style(
        ProgressStyle::default_bar()
            .template("{prefix:.bold} [{bar:40.green/white}] {pos}/{len} {msg}")
            .unwrap()
            .progress_chars("█▉▊▋▌▍▎▏  "),
    );
    passive_pb.set_prefix("PASSIVE");

    let passive_scanner = PassiveScanner::new(client.clone());
    let passive_findings = passive_scanner
        .scan_all(&discovered, &passive_pb)
        .await?;

    {
        let mut f = findings.lock().await;
        f.extend(passive_findings.clone());
    }
    passive_pb.finish_with_message(format!(
        "✓ {} findings",
        passive_findings.len()
    ));

    // ─── Phase 3: Active Scanning ─────────────────────────────────
    if !config.passive_only {
        let active_pb = mp.add(ProgressBar::new(discovered.len() as u64));
        active_pb.set_style(
            ProgressStyle::default_bar()
                .template("{prefix:.bold} [{bar:40.red/white}] {pos}/{len} {msg}")
                .unwrap()
                .progress_chars("█▉▊▋▌▍▎▏  "),
        );
        active_pb.set_prefix("ACTIVE ");

        let active_scanner = ActiveScanner::new(client.clone(), config.plugins.clone(), config.concurrency);
        let af = active_scanner
            .scan_all(&discovered, &active_pb)
            .await?;

        {
            let mut f = findings.lock().await;
            f.extend(af.clone());
        }
        active_pb.finish_with_message(format!("✓ {} findings", af.len()));
    }

    // ─── Phase 4: Report ──────────────────────────────────────────
    let elapsed = start.elapsed();
    let all_findings = findings.lock().await.clone();

    print_summary(&discovered, &all_findings, elapsed);

    let report = Report::new(
        &config.target_url,
        discovered.clone(),
        all_findings,
        elapsed,
    );

    if config.output_file.ends_with(".csv") {
        report.save_csv(&config.output_file).await?;
    } else if config.output_file.ends_with(".html") {
        report.save_html(&config.output_file).await?;
    } else {
        report.save_json(&config.output_file).await?;
    }

    println!(
        "\n{} {}",
        "✓ Report saved to:".bright_green().bold(),
        config.output_file.bright_cyan()
    );

    Ok(())
}

fn print_summary(urls: &[DiscoveredUrl], findings: &[Finding], elapsed: std::time::Duration) {
    use crate::types::Severity;

    println!("\n{}", "─".repeat(60).dimmed());
    println!("{}", "  SCAN SUMMARY".bright_white().bold());
    println!("{}", "─".repeat(60).dimmed());

    println!(
        "  {:<25} {}",
        "URLs discovered:".bright_white(),
        urls.len().to_string().bright_cyan()
    );
    println!(
        "  {:<25} {}",
        "Total findings:".bright_white(),
        findings.len().to_string().bright_yellow()
    );

    let counts = [
        Severity::Critical,
        Severity::High,
        Severity::Medium,
        Severity::Low,
        Severity::Info,
    ];
    for sev in &counts {
        let count = findings.iter().filter(|f| &f.severity == sev).count();
        if count > 0 {
            println!(
                "    {:<23} {}",
                sev.color_str(),
                count.to_string().bright_white()
            );
        }
    }

    println!(
        "  {:<25} {:.1}s",
        "Elapsed:".bright_white(),
        elapsed.as_secs_f64()
    );
    println!("{}", "─".repeat(60).dimmed());

    if !findings.is_empty() {
        println!("\n{}", "  FINDINGS".bright_white().bold());
        println!("{}", "─".repeat(60).dimmed());
        let mut sorted = findings.to_vec();
        sorted.sort_by(|a, b| b.severity.cmp(&a.severity));

        for f in &sorted {
            println!(
                "  {} {}",
                f.severity.color_str(),
                f.title.bright_white()
            );
            println!("    URL: {}", f.url.dimmed());
            if let Some(param) = &f.parameter {
                println!("    Param: {}", param.bright_magenta());
            }
            if let Some(ev) = &f.evidence {
                let truncated = if ev.len() > 80 { &ev[..80] } else { ev };
                println!("    Evidence: {}", truncated.yellow());
            }
            println!();
        }
    }
}
