mod active;
mod analyze;
mod correlate;
mod events;
mod installer;
mod intel;
mod passive;
mod proxy;
mod report;
mod sarif;
mod scanner;
mod sensitive_paths;
mod spider;
mod sqli_advanced;
mod stress;
mod tls;
mod tools;
mod tui;
mod types;

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
    version = "0.1.0"
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,

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
        /// Additional SARIF 2.1 file (GitHub Code Scanning). `--output foo.sarif` also works.
        #[arg(long)]
        sarif_out: Option<String>,
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
        #[arg(
            long,
            default_value = "xss,sqli,nosql,path-traversal,open-redirect,ssrf,xxe,cmd-injection,ssti,graphql-introspection,http-methods,redirect-chain"
        )]
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

    /// Run static analysis on a local repository
    Analyze {
        /// Path to a local repository to analyze
        #[arg(short, long, default_value = ".")]
        repo: String,

        /// Tools to run: semgrep,trivy,gitleaks
        #[arg(long, default_value = "semgrep")]
        tools: String,

        /// Optional Semgrep JSON input file (skip running Semgrep)
        #[arg(long)]
        semgrep_json: Option<String>,

        /// Optional Trivy JSON input file (skip running Trivy)
        #[arg(long)]
        trivy_json: Option<String>,

        /// Optional Gitleaks JSON input file (skip running Gitleaks)
        #[arg(long)]
        gitleaks_json: Option<String>,

        /// Correlate static + dynamic findings when both are present
        #[arg(long)]
        correlate: bool,

        /// Output JSON report path
        #[arg(short, long, default_value = "analyze-report.json")]
        output: String,

        /// Optional SARIF export path
        #[arg(long)]
        sarif_out: Option<String>,
    },

    /// Unified audit: static analysis + optional DAST scan
    Audit {
        #[arg(short, long, default_value = ".")]
        repo: String,

        /// Optional live target URL for DAST (spider + passive + active)
        #[arg(short, long)]
        target: Option<String>,

        #[arg(long, default_value = "semgrep,trivy,gitleaks")]
        tools: String,

        #[arg(long)]
        semgrep_json: Option<String>,

        #[arg(long)]
        trivy_json: Option<String>,

        #[arg(long)]
        gitleaks_json: Option<String>,

        #[arg(long)]
        correlate: bool,

        #[arg(short, long, default_value = "audit-report.json")]
        output: String,

        #[arg(long)]
        sarif_out: Option<String>,

        #[arg(long)]
        passive_only: bool,

        #[arg(short, long, default_value = "3")]
        depth: usize,

        #[arg(short = 'j', long, default_value = "5")]
        concurrency: usize,

        #[arg(long, default_value = "10")]
        timeout: u64,

        #[arg(long)]
        insecure: bool,

        #[arg(
            long,
            default_value = "xss,sqli,nosql,path-traversal,open-redirect,ssrf,xxe,cmd-injection,ssti,graphql-introspection,http-methods,redirect-chain"
        )]
        plugins: String,
    },

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

    /// Launch the interactive terminal UI (TUI). Aliases: `ui`, `console`.
    #[command(alias = "ui", alias = "console")]
    Tui,

    /// Install SDD companion tools (Semgrep, Trivy, Gitleaks, …) for this OS.
    ///
    /// Detects macOS / Debian / Fedora / Arch / Alpine and dispatches to the
    /// right package manager. Aliases: `setup`.
    #[command(alias = "setup")]
    Install {
        /// Print the plan without running anything
        #[arg(long)]
        dry_run: bool,
        /// List supported tools + install commands for the detected OS
        #[arg(short, long)]
        list: bool,
        /// Install only the named tool (e.g. semgrep, trivy, gitleaks)
        #[arg(long)]
        tool: Option<String>,
        /// Assume yes — non-interactive
        #[arg(short, long)]
        yes: bool,
    },
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

    // Bare `rustzap` (no subcommand) → drop straight into the interactive TUI.
    let Some(command) = cli.command else {
        tui::run_tui().await.expect("TUI error");
        return Ok(());
    };

    print_banner();

    match command {
        Commands::Scan {
            target,
            depth,
            concurrency,
            passive_only,
            output,
            sarif_out,
            timeout,
            user_agent,
            cookies,
            auth,
            api_key,
            basic_auth,
            insecure,
            plugins,
        } => {
            let config = ScanConfig {
                target_url: target,
                max_depth: depth,
                concurrency,
                passive_only,
                output_file: output,
                sarif_out,
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

        Commands::Spider {
            target,
            depth,
            output,
        } => {
            spider::run_spider_cli(&target, depth, output).await?;
        }

        Commands::Proxy {
            listen,
            dump,
            passive,
        } => {
            proxy::run_proxy(&listen, dump, passive).await?;
        }

        Commands::Passive { input, output } => {
            passive::run_passive_cli(&input, &output).await?;
        }

        Commands::Plugins => {
            active::list_plugins();
        }

        Commands::Analyze {
            repo,
            tools,
            semgrep_json,
            trivy_json,
            gitleaks_json,
            correlate,
            output,
            sarif_out,
        } => {
            analyze::run_analyze_cli(
                repo,
                tools,
                semgrep_json,
                trivy_json,
                gitleaks_json,
                correlate,
                output,
                sarif_out,
            )
            .await?;
        }

        Commands::Audit {
            repo,
            target,
            tools,
            semgrep_json,
            trivy_json,
            gitleaks_json,
            correlate,
            output,
            sarif_out,
            passive_only,
            depth,
            concurrency,
            timeout,
            insecure,
            plugins,
        } => {
            analyze::run_audit_cli(
                repo,
                target,
                tools,
                semgrep_json,
                trivy_json,
                gitleaks_json,
                correlate,
                output,
                sarif_out,
                passive_only,
                depth,
                concurrency,
                plugins,
                timeout,
                insecure,
            )
            .await?;
        }

        Commands::Tui => {
            tui::run_tui().await.expect("TUI error");
        }

        Commands::Install {
            dry_run,
            list,
            tool,
            yes,
        } => {
            installer::run(dry_run, tool, yes, list).await?;
        }

        Commands::Stress {
            target,
            mode,
            users,
            duration,
            method,
            body,
            headers,
            timeout,
            output,
            insecure,
            cookies,
            auth,
            expect_status,
            expect_body,
            start_users,
            ramp_secs,
            spike_at,
            spike_duration,
            requests,
        } => {
            let args = StressCliArgs {
                target,
                mode,
                users,
                duration,
                method,
                body,
                headers,
                timeout,
                output,
                insecure,
                cookies,
                auth,
                expect_status,
                expect_body,
                start_users,
                ramp_secs,
                spike_at,
                spike_duration,
                requests,
            };
            stress::run_stress_cli(args).await?;
        }
    }

    Ok(())
}

fn print_banner() {
    println!(
        "{}",
        r#"
██████╗ ██╗   ██╗███████╗████████╗███████╗ █████╗ ██████╗ 
██╔══██╗██║   ██║██╔════╝╚══██╔══╝╚════██║██╔══██╗██╔══██╗
██████╔╝██║   ██║███████╗   ██║       ██╔╝███████║██████╔╝
██╔══██╗██║   ██║╚════██║   ██║      ██╔╝ ██╔══██║██╔═══╝ 
██║  ██║╚██████╔╝███████║   ██║      ██║  ██║  ██║██║     
╚═╝  ╚═╝ ╚═════╝ ╚══════╝   ╚═╝      ╚═╝  ╚═╝  ╚═╝╚═╝     
"#
        .bright_red()
    );
    println!(
        "{}",
        "  Rust Web Application Security Scanner v0.1.0".bright_yellow()
    );
    println!(
        "{}",
        "  Inspired by OWASP ZAP — Use responsibly!\n".dimmed()
    );
}
