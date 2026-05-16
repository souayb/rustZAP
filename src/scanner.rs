use base64::Engine;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Result;
use colored::*;
use indicatif::{MultiProgress, ProgressBar, ProgressDrawTarget, ProgressStyle};
use tokio::sync::Mutex;

use crate::active::ActiveScanner;
use crate::events::{ScanEvent, ScanPhase};
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
            default_headers.insert(reqwest::header::AUTHORIZATION, val);
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
    spider_pb.finish_with_message(format!("✓ Discovered {} URLs", discovered.len()));

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
    let passive_findings = passive_scanner.scan_all(&discovered, &passive_pb).await?;

    {
        let mut f = findings.lock().await;
        f.extend(passive_findings.clone());
    }
    passive_pb.finish_with_message(format!("✓ {} findings", passive_findings.len()));

    // ─── Phase 3: Active Scanning ─────────────────────────────────
    let mut active_module_names: Vec<String> = Vec::new();
    if !config.passive_only {
        let active_pb = mp.add(ProgressBar::new(discovered.len() as u64));
        active_pb.set_style(
            ProgressStyle::default_bar()
                .template("{prefix:.bold} [{bar:40.red/white}] {pos}/{len} {msg}")
                .unwrap()
                .progress_chars("█▉▊▋▌▍▎▏  "),
        );
        active_pb.set_prefix("ACTIVE ");

        let active_scanner =
            ActiveScanner::new(client.clone(), config.plugins.clone(), config.concurrency);
        active_module_names = active_scanner.enabled_module_names();
        let af = active_scanner.scan_all(&discovered, &active_pb).await?;

        {
            let mut f = findings.lock().await;
            f.extend(af.clone());
        }
        active_pb.finish_with_message(format!("✓ {} findings", af.len()));
    }

    // ─── Phase 3.5: Transport + intel ─────────────────────────────
    // Per-host TLS probe + optional Shodan enrichment. Both are silent on
    // success (no findings) and best-effort on failure.
    let hosts = unique_hosts(&discovered);
    let mut intel_enabled = false;
    if !hosts.is_empty() {
        let tls_findings = crate::tls::check_hosts(&hosts).await;
        let intel_cfg = crate::intel::IntelConfig::from_env();
        intel_enabled = intel_cfg.is_enabled();
        let intel_findings = crate::intel::enrich_hosts(&intel_cfg, &hosts).await;
        let mut f = findings.lock().await;
        f.extend(tls_findings);
        f.extend(intel_findings);
    }

    // ─── Phase 4: Report ──────────────────────────────────────────
    let elapsed = start.elapsed();
    let all_findings = findings.lock().await.clone();

    print_summary(&discovered, &all_findings, elapsed);
    print_module_summary(
        &all_findings,
        &active_module_names,
        !hosts.is_empty(),
        intel_enabled,
    );

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

/// TUI-friendly scan: identical phases to `run_scan`, but emits events through
/// an mpsc channel instead of printing to stdout. Used by the interactive TUI.
pub async fn run_scan_with_events(
    config: ScanConfig,
    tx: tokio::sync::mpsc::UnboundedSender<ScanEvent>,
) -> Result<()> {
    let start = Instant::now();

    let _ = tx.send(ScanEvent::Started {
        target: config.target_url.clone(),
    });
    let _ = tx.send(ScanEvent::Log(format!(
        "depth={} concurrency={} passive_only={} plugins=[{}]",
        config.max_depth,
        config.concurrency,
        config.passive_only,
        config.plugins.join(",")
    )));

    let client = Arc::new(build_client(&config)?);

    // ── Phase 1: Spider ────────────────────────────────────────────
    let _ = tx.send(ScanEvent::PhaseStarted {
        phase: ScanPhase::Spider,
        total: None,
    });

    let spider_pb = ProgressBar::with_draw_target(Some(0), ProgressDrawTarget::hidden());
    let spider = Spider::new(
        client.clone(),
        config.target_url.clone(),
        config.max_depth,
        config.concurrency,
    );

    // Tick task forwards spider progress as it crawls
    let tick_tx = tx.clone();
    let tick_pb = spider_pb.clone();
    let spider_tick = tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_millis(250)).await;
            let _ = tick_tx.send(ScanEvent::SpiderProgress {
                discovered: tick_pb.position() as usize,
            });
            if tick_pb.is_finished() {
                break;
            }
        }
    });

    let discovered = spider.crawl(&spider_pb).await?;
    spider_pb.finish();
    let _ = spider_tick.await;

    let _ = tx.send(ScanEvent::SpiderProgress {
        discovered: discovered.len(),
    });

    // ── Phase 2: Passive ───────────────────────────────────────────
    let _ = tx.send(ScanEvent::PhaseStarted {
        phase: ScanPhase::Passive,
        total: Some(discovered.len()),
    });

    let passive_pb =
        ProgressBar::with_draw_target(Some(discovered.len() as u64), ProgressDrawTarget::hidden());
    let total = discovered.len();
    let tick_tx = tx.clone();
    let tick_pb = passive_pb.clone();
    let passive_tick = tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_millis(200)).await;
            let _ = tick_tx.send(ScanEvent::PassiveProgress {
                done: tick_pb.position() as usize,
                total,
            });
            if tick_pb.is_finished() {
                break;
            }
        }
    });

    let passive_scanner = PassiveScanner::new(client.clone());
    let passive_findings = passive_scanner.scan_all(&discovered, &passive_pb).await?;
    passive_pb.finish();
    let _ = passive_tick.await;

    for f in &passive_findings {
        let _ = tx.send(ScanEvent::Finding(f.clone()));
    }
    let _ = tx.send(ScanEvent::PassiveProgress {
        done: discovered.len(),
        total: discovered.len(),
    });
    emit_module_events(&tx, &passive_findings, crate::passive::known_plugin_names());

    let mut all_findings = passive_findings;

    // ── Phase 3: Active ────────────────────────────────────────────
    if !config.passive_only {
        let _ = tx.send(ScanEvent::PhaseStarted {
            phase: ScanPhase::Active,
            total: Some(discovered.len()),
        });

        let active_pb = ProgressBar::with_draw_target(
            Some(discovered.len() as u64),
            ProgressDrawTarget::hidden(),
        );
        let total = discovered.len();
        let tick_tx = tx.clone();
        let tick_pb = active_pb.clone();
        let active_tick = tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_millis(200)).await;
                let _ = tick_tx.send(ScanEvent::ActiveProgress {
                    done: tick_pb.position() as usize,
                    total,
                });
                if tick_pb.is_finished() {
                    break;
                }
            }
        });

        let active_scanner =
            ActiveScanner::new(client.clone(), config.plugins.clone(), config.concurrency);
        let active_modules: Vec<String> = active_scanner.enabled_module_names();
        let active_findings = active_scanner.scan_all(&discovered, &active_pb).await?;
        active_pb.finish();
        let _ = active_tick.await;

        for f in &active_findings {
            let _ = tx.send(ScanEvent::Finding(f.clone()));
        }
        let _ = tx.send(ScanEvent::ActiveProgress {
            done: discovered.len(),
            total: discovered.len(),
        });
        let active_module_refs: Vec<&str> = active_modules.iter().map(|s| s.as_str()).collect();
        emit_module_events(&tx, &active_findings, &active_module_refs);
        all_findings.extend(active_findings);
    }

    // ── Phase 3.5: Transport + intel ───────────────────────────────
    let hosts = unique_hosts(&discovered);
    if !hosts.is_empty() {
        let tls_findings = crate::tls::check_hosts(&hosts).await;
        let intel_cfg = crate::intel::IntelConfig::from_env();
        let intel_findings = crate::intel::enrich_hosts(&intel_cfg, &hosts).await;
        for f in tls_findings.iter().chain(intel_findings.iter()) {
            let _ = tx.send(ScanEvent::Finding(f.clone()));
        }
        emit_module_events(&tx, &tls_findings, crate::tls::known_plugin_names());
        if intel_cfg.is_enabled() {
            emit_module_events(&tx, &intel_findings, crate::intel::known_plugin_names());
        }
        all_findings.extend(tls_findings);
        all_findings.extend(intel_findings);
    }

    // ── Phase 4: Report ────────────────────────────────────────────
    let _ = tx.send(ScanEvent::PhaseStarted {
        phase: ScanPhase::Done,
        total: None,
    });

    let elapsed = start.elapsed();
    let report = Report::new(
        &config.target_url,
        discovered.clone(),
        all_findings,
        elapsed,
    );

    let total_findings = report.summary.total_findings;
    let risk_score = report.summary.risk_score;

    if config.output_file.ends_with(".csv") {
        report.save_csv(&config.output_file).await?;
    } else if config.output_file.ends_with(".html") {
        report.save_html(&config.output_file).await?;
    } else {
        report.save_json(&config.output_file).await?;
    }

    let _ = tx.send(ScanEvent::Completed {
        duration_secs: elapsed.as_secs_f64(),
        total_findings,
        risk_score,
        report_path: config.output_file,
    });

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
            println!("  {} {}", f.severity.color_str(), f.title.bright_white());
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

/// Print the per-module roll-up below the main scan summary. Format
/// matches SDD §9.1 — non-quiet modules first (sorted by max severity),
/// quiet modules last.
fn print_module_summary(
    findings: &[Finding],
    active_modules: &[String],
    transport_ran: bool,
    intel_enabled: bool,
) {
    let mut known: Vec<&str> = Vec::new();
    known.extend(crate::passive::known_plugin_names());
    known.extend(active_modules.iter().map(|s| s.as_str()));
    if transport_ran {
        known.extend(crate::tls::known_plugin_names());
    }
    if intel_enabled {
        known.extend(crate::intel::known_plugin_names());
    }

    let summaries = crate::types::summarize_modules(findings, &known);
    if summaries.is_empty() {
        return;
    }

    println!("\n{}", "  MODULES".bright_white().bold());
    println!("{}", "─".repeat(60).dimmed());
    for s in &summaries {
        let marker = if s.quiet {
            "·".dimmed()
        } else {
            "✓".bright_green()
        };
        let sev_label = match &s.max_severity {
            Some(sev) => sev.color_str().to_string(),
            None => "(quiet)".dimmed().to_string(),
        };
        let count = if s.findings == 0 {
            String::new()
        } else if s.findings == 1 {
            "1 finding ".to_string()
        } else {
            format!("{} findings ", s.findings)
        };
        println!(
            "  {} {:<36} {}{}",
            marker,
            s.name.bright_white(),
            count.dimmed(),
            sev_label
        );
    }
    println!("{}", "─".repeat(60).dimmed());
}

/// Emit one `ScanEvent::ModuleRan` per known module after a phase finishes.
/// Modules with zero findings are still emitted (quiet) so the TUI can show
/// them folded in the module tree — see SDD §9.1.
fn emit_module_events(
    tx: &tokio::sync::mpsc::UnboundedSender<ScanEvent>,
    findings: &[Finding],
    known_modules: &[&str],
) {
    let summaries = crate::types::summarize_modules(findings, known_modules);
    for s in summaries {
        let _ = tx.send(ScanEvent::ModuleRan {
            name: s.name,
            findings: s.findings,
        });
    }
}

/// Collect unique hostnames from the discovered URL list (HTTPS only —
/// TLS probe requires it and IPs/localhost aren't useful for cert checks).
fn unique_hosts(discovered: &[DiscoveredUrl]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for du in discovered {
        let Ok(u) = url::Url::parse(&du.url) else {
            continue;
        };
        if u.scheme() != "https" {
            continue;
        }
        let Some(host) = u.host_str() else { continue };
        if host.parse::<std::net::IpAddr>().is_ok() {
            continue;
        }
        if seen.insert(host.to_string()) {
            out.push(host.to_string());
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::UrlSource;

    fn du(url: &str) -> DiscoveredUrl {
        DiscoveredUrl {
            url: url.into(),
            method: "GET".into(),
            parameters: vec![],
            source: UrlSource::Seed,
        }
    }

    #[test]
    fn unique_hosts_dedupes_and_filters_non_https() {
        let urls = vec![
            du("https://example.com/a"),
            du("https://example.com/b"),
            du("http://example.com/c"),
            du("https://api.example.com/"),
            du("https://192.168.1.1/"),
        ];
        let hosts = unique_hosts(&urls);
        assert_eq!(hosts, vec!["example.com", "api.example.com"]);
    }
}
