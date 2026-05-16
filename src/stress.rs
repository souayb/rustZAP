use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Result;
use chrono::Utc;
use colored::*;
use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
use serde::{Deserialize, Serialize};
use tokio::sync::{Mutex, Semaphore};

// ─────────────────────────────────────────────────────────────────────────────
// Config
// ─────────────────────────────────────────────────────────────────────────────

/// Stress test configuration
#[derive(Debug, Clone)]
pub struct StressConfig {
    /// Base URL to hammer
    pub target: String,
    /// Test mode
    pub mode: StressMode,
    /// HTTP method
    pub method: String,
    /// Optional request body
    pub body: Option<String>,
    /// Additional headers (key:value)
    pub headers: Vec<(String, String)>,
    /// Per-request timeout
    pub timeout_secs: u64,
    /// Output report path
    pub output: String,
    /// Skip TLS verification
    pub insecure: bool,
    /// Cookie string
    pub cookies: Option<String>,
    /// Auth header
    pub auth: Option<String>,
    /// Expected HTTP status (assertions)
    pub expect_status: Option<u16>,
    /// String that must appear in body (assertion)
    #[allow(dead_code)]
    pub expect_body: Option<String>,
}

#[derive(Debug, Clone)]
pub enum StressMode {
    /// Constant load: N concurrent users for D seconds
    Constant { users: usize, duration_secs: u64 },
    /// Ramp-up: linearly increase from `start` to `peak` users over `ramp_secs`,
    /// hold at peak for `hold_secs`
    Ramp {
        start_users: usize,
        peak_users: usize,
        ramp_secs: u64,
        hold_secs: u64,
    },
    /// Spike: idle → sudden spike → back to idle
    Spike {
        base_users: usize,
        spike_users: usize,
        spike_at_secs: u64,
        spike_duration_secs: u64,
        total_secs: u64,
    },
    /// Soak: long-running constant load to detect memory leaks / degradation
    Soak { users: usize, duration_secs: u64 },
    /// Fixed request count (ignores time)
    Requests { total: usize, concurrency: usize },
}

// ─────────────────────────────────────────────────────────────────────────────
// Per-request result
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestResult {
    pub timestamp_ms: u64,
    pub latency_ms: u64,
    pub status: Option<u16>,
    pub success: bool,
    pub error: Option<String>,
    pub bytes: usize,
}

// ─────────────────────────────────────────────────────────────────────────────
// Live stats (lock-free atomics where possible)
// ─────────────────────────────────────────────────────────────────────────────

struct LiveStats {
    total: AtomicU64,
    success: AtomicU64,
    errors: AtomicU64,
    total_bytes: AtomicU64,
    total_latency_ms: AtomicU64,
    min_latency_ms: AtomicU64,
    max_latency_ms: AtomicU64,
    // Fine-grained latency histogram buckets (ms): 0-10,10-25,25-50,50-100,100-250,250-500,500-1000,1000+
    hist: [AtomicU64; 8],
}

impl LiveStats {
    fn new() -> Self {
        LiveStats {
            total: AtomicU64::new(0),
            success: AtomicU64::new(0),
            errors: AtomicU64::new(0),
            total_bytes: AtomicU64::new(0),
            total_latency_ms: AtomicU64::new(0),
            min_latency_ms: AtomicU64::new(u64::MAX),
            max_latency_ms: AtomicU64::new(0),
            hist: Default::default(),
        }
    }

    fn record(&self, latency_ms: u64, success: bool, bytes: usize) {
        self.total.fetch_add(1, Ordering::Relaxed);
        if success {
            self.success.fetch_add(1, Ordering::Relaxed);
        } else {
            self.errors.fetch_add(1, Ordering::Relaxed);
        }
        self.total_bytes.fetch_add(bytes as u64, Ordering::Relaxed);
        self.total_latency_ms
            .fetch_add(latency_ms, Ordering::Relaxed);

        // CAS min/max
        let mut cur_min = self.min_latency_ms.load(Ordering::Relaxed);
        while latency_ms < cur_min {
            match self.min_latency_ms.compare_exchange_weak(
                cur_min,
                latency_ms,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(v) => cur_min = v,
            }
        }
        let mut cur_max = self.max_latency_ms.load(Ordering::Relaxed);
        while latency_ms > cur_max {
            match self.max_latency_ms.compare_exchange_weak(
                cur_max,
                latency_ms,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(v) => cur_max = v,
            }
        }

        // Histogram bucket
        let bucket = match latency_ms {
            0..=10 => 0,
            11..=25 => 1,
            26..=50 => 2,
            51..=100 => 3,
            101..=250 => 4,
            251..=500 => 5,
            501..=1000 => 6,
            _ => 7,
        };
        self.hist[bucket].fetch_add(1, Ordering::Relaxed);
    }

    fn snapshot(&self) -> StatsSnapshot {
        let total = self.total.load(Ordering::Relaxed);
        let success = self.success.load(Ordering::Relaxed);
        let errors = self.errors.load(Ordering::Relaxed);
        let bytes = self.total_bytes.load(Ordering::Relaxed);
        let total_lat = self.total_latency_ms.load(Ordering::Relaxed);
        let min_lat = self.min_latency_ms.load(Ordering::Relaxed);
        let max_lat = self.max_latency_ms.load(Ordering::Relaxed);
        let hist: Vec<u64> = self
            .hist
            .iter()
            .map(|b| b.load(Ordering::Relaxed))
            .collect();

        StatsSnapshot {
            total,
            success,
            errors,
            bytes,
            avg_latency_ms: if total > 0 { total_lat / total } else { 0 },
            min_latency_ms: if min_lat == u64::MAX { 0 } else { min_lat },
            max_latency_ms: max_lat,
            hist,
        }
    }
}

#[derive(Debug, Clone)]
struct StatsSnapshot {
    total: u64,
    success: u64,
    errors: u64,
    bytes: u64,
    avg_latency_ms: u64,
    min_latency_ms: u64,
    max_latency_ms: u64,
    hist: Vec<u64>,
}

// ─────────────────────────────────────────────────────────────────────────────
// Report types
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Serialize, Deserialize)]
pub struct StressReport {
    pub meta: StressReportMeta,
    pub summary: StressSummary,
    pub percentiles: Percentiles,
    pub histogram: LatencyHistogram,
    pub timeline: Vec<TimelinePoint>,
    pub errors: Vec<ErrorEntry>,
}

#[derive(Serialize, Deserialize)]
pub struct StressReportMeta {
    pub scanner: String,
    pub target: String,
    pub mode: String,
    pub method: String,
    pub start_time: String,
    pub end_time: String,
    pub duration_secs: f64,
}

#[derive(Serialize, Deserialize)]
pub struct StressSummary {
    pub total_requests: u64,
    pub successful: u64,
    pub failed: u64,
    pub error_rate_pct: f64,
    pub throughput_rps: f64,
    pub avg_latency_ms: u64,
    pub min_latency_ms: u64,
    pub max_latency_ms: u64,
    pub total_bytes_received: u64,
    pub throughput_kbps: f64,
}

#[derive(Serialize, Deserialize)]
pub struct Percentiles {
    pub p50_ms: u64,
    pub p75_ms: u64,
    pub p90_ms: u64,
    pub p95_ms: u64,
    pub p99_ms: u64,
    pub p999_ms: u64,
}

#[derive(Serialize, Deserialize)]
pub struct LatencyHistogram {
    pub buckets: Vec<HistogramBucket>,
}

#[derive(Serialize, Deserialize)]
pub struct HistogramBucket {
    pub label: String,
    pub count: u64,
    pub pct: f64,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct TimelinePoint {
    pub elapsed_secs: u64,
    pub rps: f64,
    pub avg_latency_ms: u64,
    pub active_users: usize,
    pub errors: u64,
}

#[derive(Serialize, Deserialize)]
pub struct ErrorEntry {
    pub count: u64,
    pub message: String,
}

// ─────────────────────────────────────────────────────────────────────────────
// Main runner
// ─────────────────────────────────────────────────────────────────────────────

pub async fn run_stress(config: StressConfig) -> Result<()> {
    let mode_name = mode_display_name(&config.mode);

    println!(
        "{} {} {}",
        "▶ Stress Test:".bright_white().bold(),
        config.target.bright_cyan(),
        format!("[{}]", mode_name).bright_magenta()
    );
    println!(
        "  {} {}  timeout={}s",
        config.method.bright_yellow(),
        config.target.dimmed(),
        config.timeout_secs,
    );
    print_mode_info(&config.mode);
    println!();

    let client = build_stress_client(&config)?;
    let stats = Arc::new(LiveStats::new());
    let results: Arc<Mutex<Vec<RequestResult>>> = Arc::new(Mutex::new(Vec::new()));
    let timeline: Arc<Mutex<Vec<TimelinePoint>>> = Arc::new(Mutex::new(Vec::new()));
    let errors: Arc<Mutex<std::collections::HashMap<String, u64>>> =
        Arc::new(Mutex::new(std::collections::HashMap::new()));
    let running = Arc::new(AtomicBool::new(true));

    let start = Instant::now();
    let start_ts = Utc::now();

    // Live display bar
    let mp = MultiProgress::new();
    let status_bar = mp.add(ProgressBar::new_spinner());
    status_bar.set_style(
        ProgressStyle::default_spinner()
            .template("{spinner:.cyan} {msg}")
            .unwrap(),
    );
    status_bar.enable_steady_tick(Duration::from_millis(200));

    // ── Timeline sampler ──────────────────────────────────────────
    {
        let stats_clone = stats.clone();
        let timeline_clone = timeline.clone();
        let running_clone = running.clone();
        tokio::spawn(async move {
            let mut prev_total = 0u64;
            let mut prev_errors = 0u64;
            let mut elapsed = 0u64;
            let users = 0usize;

            while running_clone.load(Ordering::Relaxed) {
                tokio::time::sleep(Duration::from_secs(1)).await;
                elapsed += 1;

                let snap = stats_clone.snapshot();
                let delta_req = snap.total - prev_total;
                let delta_err = snap.errors - prev_errors;

                timeline_clone.lock().await.push(TimelinePoint {
                    elapsed_secs: elapsed,
                    rps: delta_req as f64,
                    avg_latency_ms: snap.avg_latency_ms,
                    active_users: users,
                    errors: delta_err,
                });

                prev_total = snap.total;
                prev_errors = snap.errors;
            }
        });
    }

    // ── Status updater ────────────────────────────────────────────
    {
        let stats_clone = stats.clone();
        let running_clone = running.clone();
        let bar = status_bar.clone();
        tokio::spawn(async move {
            while running_clone.load(Ordering::Relaxed) {
                tokio::time::sleep(Duration::from_millis(500)).await;
                let snap = stats_clone.snapshot();
                let elapsed = start.elapsed().as_secs_f64();
                let rps = if elapsed > 0.0 {
                    snap.total as f64 / elapsed
                } else {
                    0.0
                };
                let err_pct = if snap.total > 0 {
                    snap.errors as f64 / snap.total as f64 * 100.0
                } else {
                    0.0
                };

                bar.set_message(format!(
                    "reqs={} rps={:.1} avg={}ms min={}ms max={}ms err={:.1}%",
                    snap.total.to_string().bright_white(),
                    rps,
                    snap.avg_latency_ms.to_string().bright_cyan(),
                    snap.min_latency_ms.to_string().bright_green(),
                    snap.max_latency_ms.to_string().bright_red(),
                    err_pct,
                ));
            }
        });
    }

    // ── Dispatch by mode ──────────────────────────────────────────
    match config.mode.clone() {
        StressMode::Constant {
            users,
            duration_secs,
        } => {
            run_constant_load(
                &client,
                &config,
                users,
                duration_secs,
                stats.clone(),
                results.clone(),
                errors.clone(),
            )
            .await?;
        }
        StressMode::Ramp {
            start_users,
            peak_users,
            ramp_secs,
            hold_secs,
        } => {
            run_ramp_load(
                &client,
                &config,
                start_users,
                peak_users,
                ramp_secs,
                hold_secs,
                stats.clone(),
                results.clone(),
                errors.clone(),
            )
            .await?;
        }
        StressMode::Spike {
            base_users,
            spike_users,
            spike_at_secs,
            spike_duration_secs,
            total_secs,
        } => {
            run_spike_load(
                &client,
                &config,
                base_users,
                spike_users,
                spike_at_secs,
                spike_duration_secs,
                total_secs,
                stats.clone(),
                results.clone(),
                errors.clone(),
            )
            .await?;
        }
        StressMode::Soak {
            users,
            duration_secs,
        } => {
            run_soak_load(
                &client,
                &config,
                users,
                duration_secs,
                stats.clone(),
                results.clone(),
                errors.clone(),
            )
            .await?;
        }
        StressMode::Requests { total, concurrency } => {
            run_fixed_requests(
                &client,
                &config,
                total,
                concurrency,
                stats.clone(),
                results.clone(),
                errors.clone(),
            )
            .await?;
        }
    }

    running.store(false, Ordering::Relaxed);
    status_bar.finish_and_clear();

    let elapsed = start.elapsed();
    let end_ts = Utc::now();

    // ── Gather all results for percentile computation ─────────────
    let all_results = results.lock().await.clone();
    let all_errors = errors.lock().await.clone();
    let tl = timeline.lock().await.clone();
    let snap = stats.snapshot();

    let percentiles = compute_percentiles(&all_results);
    let histogram = build_histogram(&snap.hist, snap.total);
    let error_entries: Vec<ErrorEntry> = all_errors
        .into_iter()
        .map(|(msg, count)| ErrorEntry {
            message: msg,
            count,
        })
        .collect();

    // ── Print results ─────────────────────────────────────────────
    print_stress_results(&snap, &percentiles, &histogram, elapsed);

    // ── Save report ───────────────────────────────────────────────
    let rps = if elapsed.as_secs_f64() > 0.0 {
        snap.total as f64 / elapsed.as_secs_f64()
    } else {
        0.0
    };
    let err_rate = if snap.total > 0 {
        snap.errors as f64 / snap.total as f64 * 100.0
    } else {
        0.0
    };
    let kbps = if elapsed.as_secs_f64() > 0.0 {
        snap.bytes as f64 / elapsed.as_secs_f64() / 1024.0
    } else {
        0.0
    };

    let report = StressReport {
        meta: StressReportMeta {
            scanner: "RustZAP".to_string(),
            target: config.target.clone(),
            mode: mode_display_name(&config.mode).to_string(),
            method: config.method.clone(),
            start_time: start_ts.to_rfc3339(),
            end_time: end_ts.to_rfc3339(),
            duration_secs: elapsed.as_secs_f64(),
        },
        summary: StressSummary {
            total_requests: snap.total,
            successful: snap.success,
            failed: snap.errors,
            error_rate_pct: err_rate,
            throughput_rps: rps,
            avg_latency_ms: snap.avg_latency_ms,
            min_latency_ms: snap.min_latency_ms,
            max_latency_ms: snap.max_latency_ms,
            total_bytes_received: snap.bytes,
            throughput_kbps: kbps,
        },
        percentiles,
        histogram,
        timeline: tl,
        errors: error_entries,
    };

    let json = serde_json::to_string_pretty(&report)?;
    tokio::fs::write(&config.output, json).await?;
    println!(
        "\n{} {}",
        "✓ Report saved to:".bright_green().bold(),
        config.output.bright_cyan()
    );

    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// Load drivers
// ─────────────────────────────────────────────────────────────────────────────

async fn run_constant_load(
    client: &reqwest::Client,
    config: &StressConfig,
    users: usize,
    duration_secs: u64,
    stats: Arc<LiveStats>,
    results: Arc<Mutex<Vec<RequestResult>>>,
    errors: Arc<Mutex<std::collections::HashMap<String, u64>>>,
) -> Result<()> {
    let sem = Arc::new(Semaphore::new(users));
    let deadline = Instant::now() + Duration::from_secs(duration_secs);

    println!(
        "  {} users={} duration={}s",
        "MODE constant".bright_magenta(),
        users,
        duration_secs
    );

    let mut handles = Vec::new();
    while Instant::now() < deadline {
        let permit = sem.clone().acquire_owned().await?;
        let client = client.clone();
        let config = config.clone();
        let stats = stats.clone();
        let results = results.clone();
        let errors = errors.clone();

        let h = tokio::spawn(async move {
            let r = fire_request(&client, &config).await;
            record_result(r, &stats, &results, &errors).await;
            drop(permit);
        });
        handles.push(h);

        // Tiny yield to avoid hot spin
        tokio::task::yield_now().await;
    }

    for h in handles {
        let _ = h.await;
    }
    Ok(())
}

async fn run_ramp_load(
    client: &reqwest::Client,
    config: &StressConfig,
    start_users: usize,
    peak_users: usize,
    ramp_secs: u64,
    hold_secs: u64,
    stats: Arc<LiveStats>,
    results: Arc<Mutex<Vec<RequestResult>>>,
    errors: Arc<Mutex<std::collections::HashMap<String, u64>>>,
) -> Result<()> {
    println!(
        "  {} {}→{} users over {}s, hold {}s",
        "MODE ramp".bright_magenta(),
        start_users,
        peak_users,
        ramp_secs,
        hold_secs
    );

    let total_secs = ramp_secs + hold_secs;
    let start = Instant::now();

    let sem = Arc::new(Semaphore::new(peak_users));
    let mut handles = Vec::new();

    loop {
        let elapsed = start.elapsed().as_secs_f64();
        if elapsed >= total_secs as f64 {
            break;
        }

        // Compute current target concurrency
        let _current_users = if elapsed < ramp_secs as f64 {
            let t = elapsed / ramp_secs as f64;
            (start_users as f64 + t * (peak_users - start_users) as f64) as usize
        } else {
            peak_users
        };
        // TODO: Use _current_users to dynamically adjust concurrency

        // Acquire slot up to current users
        if let Ok(permit) = sem.clone().try_acquire_owned() {
            let client = client.clone();
            let config = config.clone();
            let stats = stats.clone();
            let results = results.clone();
            let errors = errors.clone();
            let h = tokio::spawn(async move {
                let r = fire_request(&client, &config).await;
                record_result(r, &stats, &results, &errors).await;
                drop(permit);
            });
            handles.push(h);
        }

        tokio::task::yield_now().await;
    }

    for h in handles {
        let _ = h.await;
    }
    Ok(())
}

async fn run_spike_load(
    client: &reqwest::Client,
    config: &StressConfig,
    base_users: usize,
    spike_users: usize,
    spike_at_secs: u64,
    spike_duration_secs: u64,
    total_secs: u64,
    stats: Arc<LiveStats>,
    results: Arc<Mutex<Vec<RequestResult>>>,
    errors: Arc<Mutex<std::collections::HashMap<String, u64>>>,
) -> Result<()> {
    println!(
        "  {} base={} spike={} at={}s for {}s total={}s",
        "MODE spike".bright_magenta(),
        base_users,
        spike_users,
        spike_at_secs,
        spike_duration_secs,
        total_secs
    );

    let start = Instant::now();
    let max_sem = Arc::new(Semaphore::new(spike_users));
    let mut handles = Vec::new();

    loop {
        let elapsed_secs = start.elapsed().as_secs();
        if elapsed_secs >= total_secs {
            break;
        }

        let in_spike =
            elapsed_secs >= spike_at_secs && elapsed_secs < spike_at_secs + spike_duration_secs;

        let target = if in_spike { spike_users } else { base_users };

        // Only fire if under target
        let available = max_sem.available_permits();
        if available > spike_users.saturating_sub(target) {
            if let Ok(permit) = max_sem.clone().try_acquire_owned() {
                let client = client.clone();
                let config = config.clone();
                let stats = stats.clone();
                let results = results.clone();
                let errors = errors.clone();
                let h = tokio::spawn(async move {
                    let r = fire_request(&client, &config).await;
                    record_result(r, &stats, &results, &errors).await;
                    drop(permit);
                });
                handles.push(h);
            }
        }

        tokio::task::yield_now().await;
    }

    for h in handles {
        let _ = h.await;
    }
    Ok(())
}

async fn run_soak_load(
    client: &reqwest::Client,
    config: &StressConfig,
    users: usize,
    duration_secs: u64,
    stats: Arc<LiveStats>,
    results: Arc<Mutex<Vec<RequestResult>>>,
    errors: Arc<Mutex<std::collections::HashMap<String, u64>>>,
) -> Result<()> {
    println!(
        "  {} users={} duration={}s ({:.1}min)",
        "MODE soak".bright_magenta(),
        users,
        duration_secs,
        duration_secs as f64 / 60.0
    );
    // Soak is just a long constant load — reuse
    run_constant_load(client, config, users, duration_secs, stats, results, errors).await
}

async fn run_fixed_requests(
    client: &reqwest::Client,
    config: &StressConfig,
    total: usize,
    concurrency: usize,
    stats: Arc<LiveStats>,
    results: Arc<Mutex<Vec<RequestResult>>>,
    errors: Arc<Mutex<std::collections::HashMap<String, u64>>>,
) -> Result<()> {
    println!(
        "  {} total={} concurrency={}",
        "MODE requests".bright_magenta(),
        total,
        concurrency
    );

    let sem = Arc::new(Semaphore::new(concurrency));
    let mut handles = Vec::new();

    for _ in 0..total {
        let permit = sem.clone().acquire_owned().await?;
        let client = client.clone();
        let config = config.clone();
        let stats = stats.clone();
        let results = results.clone();
        let errors = errors.clone();

        let h = tokio::spawn(async move {
            let r = fire_request(&client, &config).await;
            record_result(r, &stats, &results, &errors).await;
            drop(permit);
        });
        handles.push(h);
    }

    for h in handles {
        let _ = h.await;
    }
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// Single request execution
// ─────────────────────────────────────────────────────────────────────────────

async fn fire_request(client: &reqwest::Client, config: &StressConfig) -> RequestResult {
    let t_start = Instant::now();
    let timestamp_ms = chrono::Utc::now().timestamp_millis() as u64;

    let mut req = match config.method.to_uppercase().as_str() {
        "POST" => client.post(&config.target),
        "PUT" => client.put(&config.target),
        "DELETE" => client.delete(&config.target),
        "PATCH" => client.patch(&config.target),
        "HEAD" => client.head(&config.target),
        _ => client.get(&config.target),
    };

    for (k, v) in &config.headers {
        req = req.header(k.as_str(), v.as_str());
    }

    if let Some(body) = &config.body {
        req = req.body(body.clone());
    }

    match req.send().await {
        Ok(resp) => {
            let status = resp.status().as_u16();
            let bytes = resp.bytes().await.map(|b| b.len()).unwrap_or(0);
            let latency_ms = t_start.elapsed().as_millis() as u64;

            // Assertion checks
            let status_ok = config.expect_status.map(|s| s == status).unwrap_or(true);

            RequestResult {
                timestamp_ms,
                latency_ms,
                status: Some(status),
                success: status < 400 && status_ok,
                error: if !status_ok {
                    Some(format!(
                        "Expected status {} got {}",
                        config.expect_status.unwrap(),
                        status
                    ))
                } else if status >= 400 {
                    Some(format!("HTTP {}", status))
                } else {
                    None
                },
                bytes,
            }
        }
        Err(e) => {
            let latency_ms = t_start.elapsed().as_millis() as u64;
            RequestResult {
                timestamp_ms,
                latency_ms,
                status: None,
                success: false,
                error: Some(truncate_error(&e.to_string())),
                bytes: 0,
            }
        }
    }
}

fn truncate_error(e: &str) -> String {
    // Normalize connection errors to group them in error map
    if e.contains("connection refused") {
        "Connection refused".to_string()
    } else if e.contains("timed out") || e.contains("timeout") {
        "Request timeout".to_string()
    } else if e.contains("dns") || e.contains("resolve") {
        "DNS resolution failed".to_string()
    } else if e.contains("reset") {
        "Connection reset".to_string()
    } else {
        e.chars().take(80).collect()
    }
}

async fn record_result(
    result: RequestResult,
    stats: &Arc<LiveStats>,
    results: &Arc<Mutex<Vec<RequestResult>>>,
    errors: &Arc<Mutex<std::collections::HashMap<String, u64>>>,
) {
    stats.record(result.latency_ms, result.success, result.bytes);

    if let Some(ref err) = result.error {
        let mut em = errors.lock().await;
        *em.entry(err.clone()).or_insert(0) += 1;
    }

    results.lock().await.push(result);
}

// ─────────────────────────────────────────────────────────────────────────────
// Percentile calculation (HDR-style from sorted latencies)
// ─────────────────────────────────────────────────────────────────────────────

fn compute_percentiles(results: &[RequestResult]) -> Percentiles {
    if results.is_empty() {
        return Percentiles {
            p50_ms: 0,
            p75_ms: 0,
            p90_ms: 0,
            p95_ms: 0,
            p99_ms: 0,
            p999_ms: 0,
        };
    }

    let mut latencies: Vec<u64> = results.iter().map(|r| r.latency_ms).collect();
    latencies.sort_unstable();
    let n = latencies.len();

    let pct = |p: f64| -> u64 {
        let idx = ((p / 100.0) * n as f64) as usize;
        latencies[idx.min(n - 1)]
    };

    Percentiles {
        p50_ms: pct(50.0),
        p75_ms: pct(75.0),
        p90_ms: pct(90.0),
        p95_ms: pct(95.0),
        p99_ms: pct(99.0),
        p999_ms: pct(99.9),
    }
}

fn build_histogram(hist: &[u64], total: u64) -> LatencyHistogram {
    let labels = [
        "0-10ms",
        "10-25ms",
        "25-50ms",
        "50-100ms",
        "100-250ms",
        "250-500ms",
        "500-1000ms",
        "1000ms+",
    ];
    let buckets = hist
        .iter()
        .enumerate()
        .map(|(i, &count)| HistogramBucket {
            label: labels[i].to_string(),
            count,
            pct: if total > 0 {
                count as f64 / total as f64 * 100.0
            } else {
                0.0
            },
        })
        .collect();
    LatencyHistogram { buckets }
}

// ─────────────────────────────────────────────────────────────────────────────
// Console output
// ─────────────────────────────────────────────────────────────────────────────

fn print_stress_results(
    snap: &StatsSnapshot,
    pct: &Percentiles,
    hist: &LatencyHistogram,
    elapsed: Duration,
) {
    let rps = if elapsed.as_secs_f64() > 0.0 {
        snap.total as f64 / elapsed.as_secs_f64()
    } else {
        0.0
    };
    let err_rate = if snap.total > 0 {
        snap.errors as f64 / snap.total as f64 * 100.0
    } else {
        0.0
    };
    let kbps = if elapsed.as_secs_f64() > 0.0 {
        snap.bytes as f64 / elapsed.as_secs_f64() / 1024.0
    } else {
        0.0
    };

    println!("\n{}", "─".repeat(64).dimmed());
    println!("{}", "  STRESS TEST RESULTS".bright_white().bold());
    println!("{}", "─".repeat(64).dimmed());

    // Summary
    println!("\n  {}", "Summary".bright_white().underline());
    println!(
        "  {:<30} {}",
        "Total Requests:".dimmed(),
        snap.total.to_string().bright_white()
    );
    println!(
        "  {:<30} {}",
        "Successful:".dimmed(),
        snap.success.to_string().bright_green()
    );
    println!(
        "  {:<30} {}",
        "Failed:".dimmed(),
        snap.errors.to_string().bright_red()
    );
    println!("  {:<30} {:.2}%", "Error Rate:".dimmed(), err_rate);
    println!("  {:<30} {:.1} req/s", "Throughput:".dimmed(), rps);
    println!("  {:<30} {:.1} KB/s", "Data Rate:".dimmed(), kbps);
    println!(
        "  {:<30} {:.1}s",
        "Duration:".dimmed(),
        elapsed.as_secs_f64()
    );

    // Latency
    println!("\n  {}", "Latency".bright_white().underline());
    println!(
        "  {:<30} {}ms",
        "Average:".dimmed(),
        snap.avg_latency_ms.to_string().bright_cyan()
    );
    println!(
        "  {:<30} {}ms",
        "Min:".dimmed(),
        snap.min_latency_ms.to_string().bright_green()
    );
    println!(
        "  {:<30} {}ms",
        "Max:".dimmed(),
        snap.max_latency_ms.to_string().bright_red()
    );
    println!("  {:<30} {}ms", "p50 (median):".dimmed(), pct.p50_ms);
    println!("  {:<30} {}ms", "p75:".dimmed(), pct.p75_ms);
    println!("  {:<30} {}ms", "p90:".dimmed(), pct.p90_ms);
    println!("  {:<30} {}ms", "p95:".dimmed(), pct.p95_ms);
    println!(
        "  {:<30} {}",
        "p99:".dimmed(),
        format!("{}ms", pct.p99_ms).bright_yellow()
    );
    println!(
        "  {:<30} {}",
        "p99.9:".dimmed(),
        format!("{}ms", pct.p999_ms).bright_red()
    );

    // Histogram (ASCII bar chart)
    println!("\n  {}", "Latency Distribution".bright_white().underline());
    let max_count = hist
        .buckets
        .iter()
        .map(|b| b.count)
        .max()
        .unwrap_or(1)
        .max(1);
    for b in &hist.buckets {
        if b.count == 0 {
            continue;
        }
        let bar_len = (b.count as f64 / max_count as f64 * 30.0) as usize;
        let bar = "█".repeat(bar_len);
        println!(
            "  {:>10}  {:>6} {:5.1}%  {}",
            b.label.dimmed(),
            b.count.to_string().bright_white(),
            b.pct,
            bar.bright_cyan()
        );
    }

    // Verdict
    println!("\n  {}", "Verdict".bright_white().underline());
    let verdict = if err_rate == 0.0 && pct.p99_ms < 500 {
        "✓ PASS — no errors, p99 latency within 500ms".bright_green()
    } else if err_rate < 1.0 && pct.p99_ms < 2000 {
        "⚠ WARN — low error rate, latency acceptable".bright_yellow()
    } else {
        "✗ FAIL — high error rate or elevated latency".bright_red()
    };
    println!("  {}", verdict);
    println!("{}", "─".repeat(64).dimmed());
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

fn build_stress_client(config: &StressConfig) -> Result<reqwest::Client> {
    let mut builder = reqwest::Client::builder()
        .timeout(Duration::from_secs(config.timeout_secs))
        .danger_accept_invalid_certs(config.insecure)
        .pool_max_idle_per_host(512)
        .tcp_keepalive(Duration::from_secs(30))
        .connection_verbose(false);

    if let Some(cookies) = &config.cookies {
        let mut hm = reqwest::header::HeaderMap::new();
        hm.insert(
            reqwest::header::COOKIE,
            reqwest::header::HeaderValue::from_str(cookies)?,
        );
        builder = builder.default_headers(hm);
    }

    if let Some(auth) = &config.auth {
        let mut hm = reqwest::header::HeaderMap::new();
        hm.insert(
            reqwest::header::AUTHORIZATION,
            reqwest::header::HeaderValue::from_str(auth)?,
        );
        builder = builder.default_headers(hm);
    }

    Ok(builder.user_agent("RustZAP-Stress/0.1").build()?)
}

fn mode_display_name(mode: &StressMode) -> &'static str {
    match mode {
        StressMode::Constant { .. } => "constant",
        StressMode::Ramp { .. } => "ramp",
        StressMode::Spike { .. } => "spike",
        StressMode::Soak { .. } => "soak",
        StressMode::Requests { .. } => "requests",
    }
}

fn print_mode_info(mode: &StressMode) {
    match mode {
        StressMode::Constant {
            users,
            duration_secs,
        } => println!(
            "  {} {} concurrent users for {}s",
            "▸".dimmed(),
            users,
            duration_secs
        ),
        StressMode::Ramp {
            start_users,
            peak_users,
            ramp_secs,
            hold_secs,
        } => println!(
            "  {} ramp {}→{} users over {}s, hold {}s",
            "▸".dimmed(),
            start_users,
            peak_users,
            ramp_secs,
            hold_secs
        ),
        StressMode::Spike {
            base_users,
            spike_users,
            spike_at_secs,
            spike_duration_secs,
            total_secs,
        } => println!(
            "  {} base={} spike={} at={}s for {}s (total {}s)",
            "▸".dimmed(),
            base_users,
            spike_users,
            spike_at_secs,
            spike_duration_secs,
            total_secs
        ),
        StressMode::Soak {
            users,
            duration_secs,
        } => println!(
            "  {} {} users for {}s ({:.1}min)",
            "▸".dimmed(),
            users,
            duration_secs,
            *duration_secs as f64 / 60.0
        ),
        StressMode::Requests { total, concurrency } => println!(
            "  {} {} total requests at concurrency={}",
            "▸".dimmed(),
            total,
            concurrency
        ),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// CLI entry point (called from main.rs)
// ─────────────────────────────────────────────────────────────────────────────

pub async fn run_stress_cli(args: StressCliArgs) -> Result<()> {
    let mode = match args.mode.as_str() {
        "constant" => StressMode::Constant {
            users: args.users,
            duration_secs: args.duration,
        },
        "ramp" => StressMode::Ramp {
            start_users: args.start_users.unwrap_or(1),
            peak_users: args.users,
            ramp_secs: args.ramp_secs.unwrap_or(30),
            hold_secs: args.duration.saturating_sub(args.ramp_secs.unwrap_or(30)),
        },
        "spike" => StressMode::Spike {
            base_users: args.start_users.unwrap_or(5),
            spike_users: args.users,
            spike_at_secs: args.spike_at.unwrap_or(10),
            spike_duration_secs: args.spike_duration.unwrap_or(10),
            total_secs: args.duration,
        },
        "soak" => StressMode::Soak {
            users: args.users,
            duration_secs: args.duration,
        },
        "requests" => StressMode::Requests {
            total: args.requests.unwrap_or(1000),
            concurrency: args.users,
        },
        other => {
            anyhow::bail!(
                "Unknown stress mode '{}'. Use: constant|ramp|spike|soak|requests",
                other
            );
        }
    };

    // Parse extra headers
    let headers: Vec<(String, String)> = args
        .headers
        .iter()
        .filter_map(|h| {
            let mut parts = h.splitn(2, ':');
            let k = parts.next()?.trim().to_string();
            let v = parts.next()?.trim().to_string();
            Some((k, v))
        })
        .collect();

    let config = StressConfig {
        target: args.target,
        mode,
        method: args.method.to_uppercase(),
        body: args.body,
        headers,
        timeout_secs: args.timeout,
        output: args.output,
        insecure: args.insecure,
        cookies: args.cookies,
        auth: args.auth,
        expect_status: args.expect_status,
        expect_body: args.expect_body,
    };

    run_stress(config).await
}

/// Flat struct for clap args — easier than nested enums in derive macros
#[derive(Debug, Clone)]
pub struct StressCliArgs {
    pub target: String,
    pub mode: String,
    pub users: usize,
    pub duration: u64,
    pub method: String,
    pub body: Option<String>,
    pub headers: Vec<String>,
    pub timeout: u64,
    pub output: String,
    pub insecure: bool,
    pub cookies: Option<String>,
    pub auth: Option<String>,
    pub expect_status: Option<u16>,
    pub expect_body: Option<String>,
    // ramp options
    pub start_users: Option<usize>,
    pub ramp_secs: Option<u64>,
    // spike options
    pub spike_at: Option<u64>,
    pub spike_duration: Option<u64>,
    // requests mode
    pub requests: Option<usize>,
}
