use base64::Engine;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Result;
use colored::*;
use indicatif::{ProgressBar, ProgressDrawTarget};
use tokio::sync::Mutex;

use crate::active::ActiveScanner;
use crate::events::{ScanEvent, ScanPhase};
use crate::passive::PassiveScanner;
use crate::report::Report;
use crate::spider::Spider;
use crate::types::{DiscoveredUrl, Finding, ModuleSummary};

/// Result of an in-process scan (no file I/O).
pub struct ScanCollected {
    pub discovered: Vec<DiscoveredUrl>,
    pub findings: Vec<Finding>,
    pub modules: Vec<ModuleSummary>,
}

/// Full scan configuration
#[derive(Debug, Clone)]
pub struct ScanConfig {
    pub target_url: String,
    pub max_depth: usize,
    pub concurrency: usize,
    pub passive_only: bool,
    pub output_file: String,
    /// Emit SARIF 2.1 in addition to `--output`, or alongside JSON/CSV/HTML.
    pub sarif_out: Option<String>,
    pub timeout_secs: u64,
    pub user_agent: Option<String>,
    pub cookies: Option<String>,
    pub auth_header: Option<String>,
    pub api_key: Option<String>,
    pub basic_auth: Option<String>,
    pub insecure: bool,
    pub plugins: Vec<String>,
    /// Local OpenAPI 3.x JSON path (optional).
    pub openapi_path: Option<String>,
    /// Fetch OpenAPI JSON from this URL once (optional).
    pub openapi_url: Option<String>,
    /// HAR recording path; same-origin requests become scan seeds (optional).
    pub har_path: Option<String>,
    /// Opt-in: spawn ProjectDiscovery Nuclei against the target.
    pub nuclei: bool,
    /// Opt-in: parse existing Nuclei `-jsonl` output (no spawn).
    pub nuclei_jsonl: Option<String>,
    /// Opt-in: run active plugins on URLs without query parameters too
    /// (path-based injection). Higher traffic — off by default.
    pub active_all_paths: bool,
    /// Opt-in: run passive checks on non-GET discovered requests too.
    pub passive_all_methods: bool,
    /// Do-no-harm / attack-mode / RPS policy for active HTTP.
    pub safety: crate::safety::SafetyPolicy,
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

/// Run spider → passive → active → transport/intel without writing a report.
pub async fn collect_scan(config: ScanConfig) -> Result<ScanCollected> {
    let client = Arc::new(build_client(&config)?);
    let findings: Arc<Mutex<Vec<Finding>>> = Arc::new(Mutex::new(Vec::new()));

    let spider_pb = ProgressBar::with_draw_target(Some(0), ProgressDrawTarget::hidden());
    let spider = Spider::new(
        client.clone(),
        config.target_url.clone(),
        config.max_depth,
        config.concurrency,
    );
    let response_cache = crate::types::HttpResponseCache::new();
    let mut discovered = spider
        .crawl_with_cache(&spider_pb, Some(&response_cache))
        .await?;
    spider_pb.finish();

    // Phase 3: OpenAPI / HAR surface expansion (merged into discovered set).
    let mut openapi_imported = false;
    if let Some(ref path) = config.openapi_path {
        let (urls, info) = crate::openapi::load_openapi_file(path, &config.target_url)?;
        merge_discovered(&mut discovered, urls);
        findings.lock().await.push(info);
        openapi_imported = true;
    }
    if let Some(ref oas_url) = config.openapi_url {
        let (urls, info) =
            crate::openapi::load_openapi_url(&client, oas_url, &config.target_url).await?;
        merge_discovered(&mut discovered, urls);
        findings.lock().await.push(info);
        openapi_imported = true;
    }
    if let Some(ref har_path) = config.har_path {
        let urls = crate::har::load_har_file(har_path, &config.target_url)?;
        merge_discovered(&mut discovered, urls);
    }

    let passive_pb =
        ProgressBar::with_draw_target(Some(discovered.len() as u64), ProgressDrawTarget::hidden());
    let passive_scanner =
        PassiveScanner::new(client.clone()).with_all_methods(config.passive_all_methods);
    let passive_findings = passive_scanner
        .scan_all_with_cache(&discovered, &passive_pb, Some(&response_cache))
        .await?;
    passive_pb.finish();
    {
        let mut f = findings.lock().await;
        f.extend(passive_findings);
    }

    let mut active_module_names: Vec<String> = Vec::new();
    if !config.passive_only {
        let active_pb = ProgressBar::with_draw_target(
            Some(discovered.len() as u64),
            ProgressDrawTarget::hidden(),
        );
        let active_scanner = ActiveScanner::new(
            client.clone(),
            config.plugins.clone(),
            config.concurrency,
            config.active_all_paths,
            config.safety.clone(),
        );
        active_module_names = active_scanner.enabled_module_names();
        let af = active_scanner.scan_all(&discovered, &active_pb).await?;
        active_pb.finish();
        let mut f = findings.lock().await;
        f.extend(af);
    }

    // Opt-in Nuclei (never default-on).
    let mut nuclei_ran = false;
    if let Some(ref jsonl) = config.nuclei_jsonl {
        let nf = crate::nuclei::parse_nuclei_jsonl_file(jsonl)?;
        findings.lock().await.extend(nf);
        nuclei_ran = true;
    } else if config.nuclei {
        let nf = crate::nuclei::run_nuclei(&config.target_url, true).await?;
        findings.lock().await.extend(nf);
        nuclei_ran = true;
    }

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

    let all_findings = findings.lock().await.clone();
    let modules = compute_module_summaries(
        &all_findings,
        &active_module_names,
        !hosts.is_empty(),
        intel_enabled,
        openapi_imported,
        nuclei_ran,
    );

    Ok(ScanCollected {
        discovered,
        findings: all_findings,
        modules,
    })
}

/// Deduping merge of imported URLs into the spider result set.
fn merge_discovered(into: &mut Vec<DiscoveredUrl>, extra: Vec<DiscoveredUrl>) {
    let mut seen: std::collections::HashSet<String> = into
        .iter()
        .map(|d| format!("{} {}", d.method, d.url))
        .collect();
    for du in extra {
        let key = format!("{} {}", du.method, du.url);
        if seen.insert(key) {
            into.push(du);
        }
    }
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

    let collected = collect_scan(config.clone()).await?;
    let elapsed = start.elapsed();

    print_summary(&collected.discovered, &collected.findings, elapsed);
    print_module_summary_from_modules(&collected.modules);

    let report = Report::new(
        &config.target_url,
        collected.modules,
        collected.discovered.clone(),
        collected.findings,
        elapsed,
    );

    if config.output_file.ends_with(".sarif") {
        crate::sarif::write_sarif(&report, &config.output_file)?;
    } else if config.output_file.ends_with(".csv") {
        report.save_csv(&config.output_file).await?;
    } else if config.output_file.ends_with(".html") {
        report.save_html(&config.output_file).await?;
    } else {
        report.save_json(&config.output_file).await?;
    }

    if let Some(ref sarif_path) = config.sarif_out {
        if sarif_path != &config.output_file {
            crate::sarif::write_sarif(&report, sarif_path)?;
        }
    }

    println!(
        "\n{} {}",
        "✓ Report saved to:".bright_green().bold(),
        config.output_file.bright_cyan()
    );
    if let Some(ref sarif_path) = config.sarif_out {
        if sarif_path != &config.output_file {
            println!(
                "{} {}",
                "✓ SARIF saved to:".bright_green().bold(),
                sarif_path.bright_cyan()
            );
        }
    }

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

    let mut discovered = spider.crawl(&spider_pb).await?;
    spider_pb.finish();
    let _ = spider_tick.await;

    let mut import_findings: Vec<Finding> = Vec::new();
    let mut openapi_imported = false;
    if let Some(ref path) = config.openapi_path {
        match crate::openapi::load_openapi_file(path, &config.target_url) {
            Ok((urls, info)) => {
                merge_discovered(&mut discovered, urls);
                let _ = tx.send(ScanEvent::Finding(Box::new(info.clone())));
                import_findings.push(info);
                openapi_imported = true;
            }
            Err(e) => {
                let _ = tx.send(ScanEvent::Log(format!("OpenAPI import failed: {e}")));
            }
        }
    }
    if let Some(ref oas_url) = config.openapi_url {
        match crate::openapi::load_openapi_url(&client, oas_url, &config.target_url).await {
            Ok((urls, info)) => {
                merge_discovered(&mut discovered, urls);
                let _ = tx.send(ScanEvent::Finding(Box::new(info.clone())));
                import_findings.push(info);
                openapi_imported = true;
            }
            Err(e) => {
                let _ = tx.send(ScanEvent::Log(format!("OpenAPI URL import failed: {e}")));
            }
        }
    }
    if let Some(ref har_path) = config.har_path {
        match crate::har::load_har_file(har_path, &config.target_url) {
            Ok(urls) => {
                let n = urls.len();
                merge_discovered(&mut discovered, urls);
                let _ = tx.send(ScanEvent::Log(format!(
                    "HAR imported {n} same-origin request(s)"
                )));
            }
            Err(e) => {
                let _ = tx.send(ScanEvent::Log(format!("HAR import failed: {e}")));
            }
        }
    }

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

    let passive_scanner =
        PassiveScanner::new(client.clone()).with_all_methods(config.passive_all_methods);
    let passive_findings = passive_scanner.scan_all(&discovered, &passive_pb).await?;
    passive_pb.finish();
    let _ = passive_tick.await;

    for f in &passive_findings {
        let _ = tx.send(ScanEvent::Finding(Box::new(f.clone())));
    }
    let _ = tx.send(ScanEvent::PassiveProgress {
        done: discovered.len(),
        total: discovered.len(),
    });
    emit_module_events(&tx, &passive_findings, crate::passive::known_plugin_names());

    let mut all_findings = import_findings;
    all_findings.extend(passive_findings);
    let mut active_module_names: Vec<String> = Vec::new();
    let mut transport_ran = false;
    let mut intel_enabled = false;
    let mut nuclei_ran = false;

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

        let active_scanner = ActiveScanner::new(
            client.clone(),
            config.plugins.clone(),
            config.concurrency,
            config.active_all_paths,
            config.safety.clone(),
        );
        active_module_names = active_scanner.enabled_module_names();
        let active_findings = active_scanner.scan_all(&discovered, &active_pb).await?;
        active_pb.finish();
        let _ = active_tick.await;

        for f in &active_findings {
            let _ = tx.send(ScanEvent::Finding(Box::new(f.clone())));
        }
        let _ = tx.send(ScanEvent::ActiveProgress {
            done: discovered.len(),
            total: discovered.len(),
        });
        let active_module_refs: Vec<&str> =
            active_module_names.iter().map(|s| s.as_str()).collect();
        emit_module_events(&tx, &active_findings, &active_module_refs);
        all_findings.extend(active_findings);
    }

    // Opt-in Nuclei
    if let Some(ref jsonl) = config.nuclei_jsonl {
        match crate::nuclei::parse_nuclei_jsonl_file(jsonl) {
            Ok(nf) => {
                for f in &nf {
                    let _ = tx.send(ScanEvent::Finding(Box::new(f.clone())));
                }
                all_findings.extend(nf);
                nuclei_ran = true;
            }
            Err(e) => {
                let _ = tx.send(ScanEvent::Log(format!("Nuclei JSONL parse failed: {e}")));
            }
        }
    } else if config.nuclei {
        match crate::nuclei::run_nuclei(&config.target_url, true).await {
            Ok(nf) => {
                for f in &nf {
                    let _ = tx.send(ScanEvent::Finding(Box::new(f.clone())));
                }
                all_findings.extend(nf);
                nuclei_ran = true;
            }
            Err(e) => {
                let _ = tx.send(ScanEvent::Log(format!("Nuclei failed: {e}")));
            }
        }
    }

    // ── Phase 3.5: Transport + intel ───────────────────────────────
    let hosts = unique_hosts(&discovered);
    if !hosts.is_empty() {
        transport_ran = true;
        let tls_findings = crate::tls::check_hosts(&hosts).await;
        let intel_cfg = crate::intel::IntelConfig::from_env();
        intel_enabled = intel_cfg.is_enabled();
        let intel_findings = crate::intel::enrich_hosts(&intel_cfg, &hosts).await;
        for f in tls_findings.iter().chain(intel_findings.iter()) {
            let _ = tx.send(ScanEvent::Finding(Box::new(f.clone())));
        }
        emit_module_events(&tx, &tls_findings, crate::tls::known_plugin_names());
        if intel_enabled {
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
    let modules = compute_module_summaries(
        &all_findings,
        &active_module_names,
        transport_ran,
        intel_enabled,
        openapi_imported,
        nuclei_ran,
    );
    let report = Report::new(
        &config.target_url,
        modules,
        discovered.clone(),
        all_findings,
        elapsed,
    );

    let total_findings = report.summary.total_findings;
    let risk_score = report.summary.risk_score;

    if config.output_file.ends_with(".sarif") {
        crate::sarif::write_sarif(&report, &config.output_file)?;
    } else if config.output_file.ends_with(".csv") {
        report.save_csv(&config.output_file).await?;
    } else if config.output_file.ends_with(".html") {
        report.save_html(&config.output_file).await?;
    } else {
        report.save_json(&config.output_file).await?;
    }

    if let Some(ref sarif_path) = config.sarif_out {
        if sarif_path != &config.output_file {
            crate::sarif::write_sarif(&report, sarif_path)?;
        }
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
fn print_module_summary_from_modules(summaries: &[ModuleSummary]) {
    if summaries.is_empty() {
        return;
    }

    println!("\n{}", "  MODULES".bright_white().bold());
    println!("{}", "─".repeat(60).dimmed());
    for s in summaries {
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

/// Compute the module roll-up contract for both:
/// - CLI `MODULES` printing
/// - JSON `Report.modules[]` serialization
fn compute_module_summaries(
    findings: &[Finding],
    active_modules: &[String],
    transport_ran: bool,
    intel_enabled: bool,
    openapi_imported: bool,
    nuclei_ran: bool,
) -> Vec<ModuleSummary> {
    let mut known: Vec<&str> = Vec::new();
    known.extend(crate::passive::known_plugin_names());
    known.extend(active_modules.iter().map(|s| s.as_str()));
    if transport_ran {
        known.extend(crate::tls::known_plugin_names());
    }
    if intel_enabled {
        known.extend(crate::intel::known_plugin_names());
    }
    if openapi_imported {
        known.push("passive/openapi-import");
    }
    if nuclei_ran {
        // Quiet placeholder; concrete active/nuclei/<id> still appear via findings.
        known.push("active/nuclei");
    }
    crate::types::summarize_modules(findings, &known)
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
        DiscoveredUrl::new(url, "GET", UrlSource::Seed)
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
