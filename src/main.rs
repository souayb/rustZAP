mod scanner;
mod proxy;
mod spider;
mod passive;
mod active;
mod report;
mod stress;
mod types;
mod tui;

use clap::{Parser, Subcommand};
use colored::*;
use tracing_subscriber::EnvFilter;

use crate::scanner::ScanConfig;
use crate::stress::StressCliArgs;

/// RustZAP - OWASP ZAP-inspired web security scanner written in Rust
#[derive(Parser)]
#[command(
    name = "rustzap",
    about = "A fast, fearless web application security scanner",
    version = "0.1.0",
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    /// Verbosity level (-v, -vv, -vvv)
    #[arg(short, long, action = clap::ArgAction::Count, global = true)]
    verbose: u8,
}

#[derive(Subcommand)]
enum Commands {
    /// Run a full scan (spider + passive + active)
    Scan {
        #[arg(short, long)]
        target: String,
        #[arg(short, long, default_value = "5")]
        depth: usize,
        #[arg(short = 'j', long, default_value = "10")]
        concurrency: usize,
        #[arg(long)]
        passive_only: bool,
        #[arg(short, long, default_value = "rustzap-report.json")]
        output: String,
        #[arg(long, default_value = "10")]
        timeout: u64,
        #[arg(long)]
        user_agent: Option<String>,
        #[arg(long)]
        cookies: Option<String>,
        #[arg(long)]
        auth: Option<String>,
        #[arg(long)]
        api_key: Option<String>,
        #[arg(long)]
        basic_auth: Option<String>,
        #[arg(long)]
        insecure: bool,
        #[arg(long, default_value = "xss,sqli,path-traversal,open-redirect,ssrf,xxe,cmd-injection,ssti")]
        plugins: String,
    },

    /// Run spider only
    Spider {
        #[arg(short, long)]
        target: String,
        #[arg(short, long, default_value = "5")]
        depth: usize,
        #[arg(short, long)]
        output: Option<String>,
    },

    /// Start intercepting proxy
    Proxy {
        #[arg(short, long, default_value = "127.0.0.1:8080")]
        listen: String,
        #[arg(short, long)]
        dump: Option<String>,
        #[arg(long)]
        passive: bool,
    },

    /// Run passive analysis
    Passive {
        #[arg(short, long)]
        input: String,
        #[arg(short, long, default_value = "passive-report.json")]
        output: String,
    },

    /// List available scan plugins
    Plugins,

    /// Stress test / load test an API endpoint
    ///
    /// Modes:
    ///   constant  — N users hammering for D seconds
    ///   ramp      — linearly ramp from start_users to peak users, then hold
    ///   spike     — baseline users, sudden spike burst, back to baseline
    ///   soak      — long-duration constant load (find leaks/degradation)
    ///   requests  — send exactly N requests at given concurrency
    Stress {
        /// Target URL
        /// Target URL
        #[arg(short, long)]
        target: String,

        /// Mode: constant | ramp | spike | soak | requests
        #[arg(short, long, default_value = "constant")]
        mode: String,

        /// Concurrent users (peak for ramp/spike)
        #[arg(short, long, default_value = "10")]
        users: usize,

        /// Duration in seconds (not used in 'requests' mode)
        #[arg(short, long, default_value = "30")]
        duration: u64,

        /// HTTP method
        #[arg(long, default_value = "GET")]
        method: String,

        /// Request body (for POST/PUT)
        #[arg(long)]
        body: Option<String>,

        /// Extra headers: "Key: Value" (repeatable)
        #[arg(long = "header", short = 'H')]
        headers: Vec<String>,

        /// Per-request timeout in seconds
        #[arg(long, default_value = "10")]
        timeout: u64,

        /// Output JSON report
        #[arg(short, long, default_value = "stress-report.json")]
        output: String,

        /// Skip TLS verification
        #[arg(long)]
        insecure: bool,

        /// Cookie string
        #[arg(long)]
        cookies: Option<String>,

        /// Authorization header
        #[arg(long)]
        auth: Option<String>,

        /// Assert response status equals this value
        #[arg(long)]
        expect_status: Option<u16>,

        /// Assert response body contains this string
        #[arg(long)]
        expect_body: Option<String>,

        /// [ramp] Starting user count
        #[arg(long)]
        start_users: Option<usize>,

        /// [ramp] Ramp-up duration in seconds
        #[arg(long)]
        ramp_secs: Option<u64>,

        /// [spike] Second at which spike begins
        #[arg(long)]
        spike_at: Option<u64>,

        /// [spike] Spike duration in seconds
        #[arg(long)]
        spike_duration: Option<u64>,

        /// [requests] Total request count to fire
        #[arg(long)]
        requests: Option<usize>,
    },

    /// Launch the interactive terminal UI (TUI)
    Tui,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    let level = match cli.verbose {
        0 => "warn",
        1 => "info",
        2 => "debug",
        _ => "trace",
    };
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::new(format!("rustzap={}", level)))
        .with_target(false)
        .init();

    print_banner();

    match cli.command {
        Commands::Scan {
            target, depth, concurrency, passive_only, output,
            timeout, user_agent, cookies, auth, api_key, basic_auth, insecure, plugins,
        } => {
            let config = ScanConfig {
                target_url: target,
                max_depth: depth,
                concurrency,
                passive_only,
                output_file: output,
                timeout_secs: timeout,
                user_agent,
                cookies,
                auth_header: auth,
                api_key,
                basic_auth,
                insecure,
                plugins: plugins.split(',').map(|s| s.trim().to_string()).collect(),
            };
            scanner::run_scan(config).await?;
        }

        Commands::Spider { target, depth, output } => {
            spider::run_spider_cli(&target, depth, output).await?;
        }

        Commands::Proxy { listen, dump, passive } => {
            proxy::run_proxy(&listen, dump, passive).await?;
        }

        Commands::Passive { input, output } => {
            passive::run_passive_cli(&input, &output).await?;
        }

        Commands::Plugins => {
            active::list_plugins();
        }

        Commands::Tui => {
            tui::run_tui().await.expect("TUI error");
        }

        Commands::Stress {
            target, mode, users, duration, method, body, headers,
            timeout, output, insecure, cookies, auth,
            expect_status, expect_body,
            start_users, ramp_secs, spike_at, spike_duration, requests,
        } => {
            let args = StressCliArgs {
                target, mode, users, duration, method, body, headers,
                timeout, output, insecure, cookies, auth,
                expect_status, expect_body,
                start_users, ramp_secs, spike_at, spike_duration, requests,
            };
            stress::run_stress_cli(args).await?;
        }
    }

    Ok(())
}

fn print_banner() {
    println!("{}", r#"
██████╗ ██╗   ██╗███████╗████████╗███████╗ █████╗ ██████╗ 
██╔══██╗██║   ██║██╔════╝╚══██╔══╝╚════██║██╔══██╗██╔══██╗
██████╔╝██║   ██║███████╗   ██║       ██╔╝███████║██████╔╝
██╔══██╗██║   ██║╚════██║   ██║      ██╔╝ ██╔══██║██╔═══╝ 
██║  ██║╚██████╔╝███████║   ██║      ██║  ██║  ██║██║     
╚═╝  ╚═╝ ╚═════╝ ╚══════╝   ╚═╝      ╚═╝  ╚═╝  ╚═╝╚═╝     
"#.bright_red());
    println!("{}", "  Rust Web Application Security Scanner v0.1.0".bright_yellow());
    println!("{}", "  Inspired by OWASP ZAP — Use responsibly!\n".dimmed());
}
