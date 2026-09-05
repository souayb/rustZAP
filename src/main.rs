use anyhow::Context;
use clap::{Parser, Subcommand};
use colored::*;
use rustzap::scanner::ScanConfig;
use rustzap::stress::StressCliArgs;
use rustzap::{
    active, ad, agent, analyze, installer, mcp, passive, proxy, replay, safety, scanner, spider,
    stress, tui,
};
use tracing_subscriber::EnvFilter;

/// RustZAP - OWASP ZAP-inspired web security scanner written in Rust
#[derive(Parser)]
#[command(
    name = "rustzap",
    about = "A fast, fearless web application security scanner",
    version = env!("CARGO_PKG_VERSION")
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
        /// Enable aggressive Attack Mode for dedicated lab/dev testing (intrusive mutations)
        #[arg(long, visible_alias = "attack-mode")]
        attack: bool,
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
        /// Import OpenAPI 3.x JSON from a local file (expands paths into scan surface)
        #[arg(long)]
        openapi_path: Option<String>,
        /// Fetch OpenAPI 3.x JSON from a URL once
        #[arg(long)]
        openapi_url: Option<String>,
        /// Import same-origin requests from a HAR recording
        #[arg(long)]
        har_path: Option<String>,
        /// Opt-in: run ProjectDiscovery Nuclei against the target (requires `nuclei` on PATH)
        #[arg(long)]
        nuclei: bool,
        /// Opt-in: parse existing Nuclei `-jsonl` output (no spawn)
        #[arg(long)]
        nuclei_jsonl: Option<String>,
        /// Opt-in: run active plugins on URLs without query params too (more traffic)
        #[arg(long)]
        active_all_paths: bool,
        /// Opt-in: run passive checks on non-GET discovered requests too
        #[arg(long)]
        passive_all_methods: bool,
        /// Block mutating HTTP verbs (POST/PUT/DELETE/PATCH) during active scan
        #[arg(long)]
        read_only_safe: bool,
        /// Cap outbound HTTP requests per second (0 = unlimited). Default 50.
        #[arg(long)]
        max_rps: Option<u32>,
        /// Exit with non-zero status code if findings at or above this severity are detected (info, low, medium, high, critical)
        #[arg(long, value_name = "SEVERITY")]
        fail_on: Option<String>,
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
        /// Repository path (overrides --repo)
        #[arg(value_name = "REPO")]
        path: Option<String>,

        /// Path to a local repository (used when REPO is omitted)
        #[arg(short, long)]
        repo: Option<String>,

        /// Tools to run: semgrep,trivy,gitleaks,native,checkov [default: semgrep]
        #[arg(long)]
        tools: Option<String>,

        /// Optional Semgrep JSON input file (skip running Semgrep)
        #[arg(long)]
        semgrep_json: Option<String>,

        /// Optional Trivy JSON input file (skip running Trivy)
        #[arg(long)]
        trivy_json: Option<String>,

        /// Optional Gitleaks JSON input file (skip running Gitleaks)
        #[arg(long)]
        gitleaks_json: Option<String>,

        /// Optional Checkov JSON input file (skip running Checkov)
        #[arg(long)]
        checkov_json: Option<String>,

        /// Correlate static + dynamic findings when both are present
        #[arg(long)]
        correlate: bool,

        /// Output JSON report path
        #[arg(short, long, default_value = "analyze-report.json")]
        output: String,

        /// Optional SARIF export path
        #[arg(long)]
        sarif_out: Option<String>,

        /// Assume yes — skip the interactive repo-access prompt (required in CI / non-TTY)
        #[arg(short = 'y', long)]
        yes: bool,

        /// Also scan paths excluded by .gitignore / .rustzapignore (full-tree coverage)
        #[arg(long)]
        include_ignored: bool,

        /// Follow symlinked files and directories (cycle-protected)
        #[arg(long)]
        follow_symlinks: bool,
    },

    /// Unified audit: static analysis + optional DAST scan
    Audit {
        /// Repository path (overrides --repo)
        #[arg(value_name = "REPO")]
        path: Option<String>,

        /// Path to a local repository (used when REPO is omitted)
        #[arg(short, long)]
        repo: Option<String>,

        /// Optional live target URL for DAST (spider + passive + active)
        #[arg(short, long)]
        target: Option<String>,

        /// Tools to run: semgrep,trivy,gitleaks,native,checkov [default: semgrep,trivy,gitleaks]
        #[arg(long)]
        tools: Option<String>,

        #[arg(long)]
        semgrep_json: Option<String>,

        #[arg(long)]
        trivy_json: Option<String>,

        #[arg(long)]
        gitleaks_json: Option<String>,

        #[arg(long)]
        checkov_json: Option<String>,

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

        /// Assume yes — skip the interactive repo-access prompt (required in CI / non-TTY)
        #[arg(short = 'y', long)]
        yes: bool,

        /// Also scan paths excluded by .gitignore / .rustzapignore (full-tree coverage)
        #[arg(long)]
        include_ignored: bool,

        /// Follow symlinked files and directories (cycle-protected)
        #[arg(long)]
        follow_symlinks: bool,

        /// Opt-in: run active plugins on URLs without query params too (more traffic)
        #[arg(long)]
        active_all_paths: bool,

        /// Opt-in: run passive checks on non-GET discovered requests too
        #[arg(long)]
        passive_all_methods: bool,

        /// Enable aggressive Attack Mode for dedicated lab/dev testing (intrusive mutations)
        #[arg(long, visible_alias = "attack-mode")]
        attack: bool,

        /// Block mutating HTTP verbs during DAST portion of audit
        #[arg(long)]
        read_only_safe: bool,

        /// Cap outbound HTTP requests per second (0 = unlimited)
        #[arg(long)]
        max_rps: Option<u32>,
    },

    /// Detect Active Directory / NTLM-relay attack vectors (LDAP + SPN + NTLM).
    ///
    /// Detection only: enumerates the directory and reads relay posture; it never
    /// generates a relay-target list or triggers coercion. Intrusive — requires
    /// authorization consent (TTY prompt, or --yes in CI). Only scan AD you own or
    /// are explicitly authorized to test.
    Ad {
        /// AD domain FQDN, e.g. corp.local
        #[arg(long)]
        domain: String,

        /// Domain controller IP (used for LDAP bind + domain DNS)
        #[arg(long)]
        dc_ip: String,

        /// Explicit target host(s); repeat for several. Defaults to the DC.
        #[arg(short = 't', long = "target")]
        targets: Vec<String>,

        /// File of target hosts, one per line
        #[arg(short = 'f', long)]
        targets_file: Option<String>,

        /// Username for an authenticated bind (UPN built as user@domain)
        #[arg(short = 'u', long)]
        username: Option<String>,

        /// Env var holding the bind password (never pass the password on argv)
        #[arg(long, default_value = "RZ_AD_PASS")]
        password_env: String,

        /// Unauthenticated (anonymous) bind
        #[arg(long)]
        null_auth: bool,

        /// Use Kerberos authentication (reserved; not yet wired for Tier A)
        #[arg(short = 'k', long)]
        kerberos: bool,

        /// Enumerate domain computers from AD and scan each (needs creds)
        #[arg(long)]
        audit: bool,

        /// Which check families to run: all, or a comma list of ldap,spn,ntlm
        #[arg(long, default_value = "all")]
        checks: String,

        /// Skip TLS verification for LDAPS / WinRM probes
        #[arg(long)]
        insecure: bool,

        /// Output report path (.json/.sarif/.csv/.html by extension)
        #[arg(short, long, default_value = "ad-report.json")]
        output: String,

        /// Also write a SARIF report to this path
        #[arg(long)]
        sarif_out: Option<String>,

        /// Confirm authorization non-interactively (CI)
        #[arg(short, long)]
        yes: bool,
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

    /// Agentic tester (scope-gated; Phase 5). An LLM (or scripted) brain drives
    /// RustZAP's scanners/verification under a mandatory scope file.
    Agent {
        /// Scope/config file (YAML/JSON) — REQUIRED. Allowed hosts/schemes,
        /// rate + budget caps, autonomy mode, approval classes, model config.
        #[arg(long, required_unless_present = "init_scope")]
        scope: Option<String>,
        /// Write a documented starter scope file to PATH and exit (won't overwrite).
        #[arg(long, value_name = "PATH")]
        init_scope: Option<String>,
        /// Natural-language goal (derived from target/repo when omitted)
        #[arg(long)]
        goal: Option<String>,
        /// Live target URL for DAST
        #[arg(short, long)]
        target: Option<String>,
        /// Local repository path for SAST
        #[arg(short, long)]
        repo: Option<String>,
        /// Override the scope file's autonomy: assisted | semi | auto
        #[arg(long)]
        autonomy: Option<String>,
        /// Non-interactive (CI): approval gates are auto-denied, never prompted
        #[arg(short = 'n', long)]
        non_interactive: bool,
        /// Deterministic brain: a JSON file of scripted steps (no live LLM)
        #[arg(long)]
        script: Option<String>,
        /// LLM model id (e.g. qwen2.5-coder, gpt-4o-mini, claude-3-5-sonnet). Overrides scope.
        #[arg(long)]
        model: Option<String>,
        /// OpenAI-compatible base URL. Default: http://localhost:11434/v1 (Ollama). Overrides scope.
        #[arg(long)]
        base_url: Option<String>,
        /// Env var holding the API key (omit for keyless local servers). Overrides scope.
        #[arg(long)]
        api_key_env: Option<String>,
        /// Force strict JSON output (response_format) — helps some open-source models.
        #[arg(long)]
        json_mode: bool,
        /// Privacy tokenization: redact real hosts/secrets/emails/IPs before they
        /// reach the LLM, restore locally before tools run. Overrides scope.
        #[arg(long)]
        privacy: bool,
        /// Run the OWASP LLM Top-10 red-team battery directly against --target
        /// (no LLM brain). --model/--api-key-env name the target's model/key.
        #[arg(long)]
        ai_redteam: bool,
        /// A phrase known to be in the target's system prompt; enables leak
        /// detection in --ai-redteam mode (no effect otherwise).
        #[arg(long)]
        ai_redteam_marker: Option<String>,
        #[arg(short, long, default_value = "agent-report.json")]
        output: String,
        #[arg(long)]
        sarif_out: Option<String>,
        #[arg(long, default_value = "agent-trace.jsonl")]
        trace: String,
        /// Enable aggressive Attack Mode for dedicated lab/dev testing
        #[arg(long, visible_alias = "attack-mode")]
        attack: bool,
        /// Block mutating HTTP verbs (POST/PUT/DELETE/PATCH) in agent probes
        #[arg(long)]
        read_only_safe: bool,
        /// Cap outbound HTTP requests per second (0 = unlimited). Default 50.
        #[arg(long)]
        max_rps: Option<u32>,
        /// Directory for autofix prompt/patch exports (optional)
        #[arg(long)]
        autofix_dir: Option<String>,
    },

    /// Export autofix prompts from a JSON report (findings with file locations)
    Autofix {
        /// Path to a rustzap JSON report
        #[arg(long)]
        report: String,
        /// Output directory for `{finding-id}.md` prompt files
        #[arg(short, long, default_value = "patches")]
        out: String,
    },

    /// Run as an MCP server on stdio, exposing RustZAP's tools to external
    /// agents (Claude Code, Cursor, …). Network tools require `--scope`.
    Mcp {
        /// Scope file for network-touching tools (without it, only local analysis is allowed)
        #[arg(long)]
        scope: Option<String>,
        #[arg(long, default_value = "agent-trace.jsonl")]
        trace: String,
    },

    /// Replay an HTTP transaction capture file for CI/CD regression verification
    Replay {
        /// Path to captured transactions JSON file
        #[arg(value_name = "CAPTURE_FILE")]
        file: String,

        /// Override target host (e.g. http://localhost:8080)
        #[arg(short, long)]
        target: Option<String>,

        /// Request timeout in seconds
        #[arg(long, default_value = "10")]
        timeout: u64,

        /// Verbose diff output
        #[arg(short, long)]
        verbose: bool,
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
        // Logs go to stderr so stdout stays clean (required for MCP stdio).
        .with_writer(std::io::stderr)
        .init();

    // Bare `rustzap` (no subcommand) → drop straight into the interactive TUI.
    let Some(command) = cli.command else {
        tui::run_tui().await.expect("TUI error");
        return Ok(());
    };

    // The MCP server owns stdout as its protocol channel — no banner there.
    if !matches!(command, Commands::Mcp { .. }) {
        print_banner();
    }

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
            openapi_path,
            openapi_url,
            har_path,
            nuclei,
            nuclei_jsonl,
            active_all_paths,
            passive_all_methods,
            attack,
            read_only_safe,
            max_rps,
            fail_on,
        } => {
            if attack && !read_only_safe {
                safety::print_attack_mode_warning(&target);
            }
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
                openapi_path,
                openapi_url,
                har_path,
                nuclei,
                nuclei_jsonl,
                active_all_paths,
                passive_all_methods,
                safety: safety::SafetyPolicy::from_flags(attack, read_only_safe, max_rps),
            };
            let report = scanner::run_scan(config).await?;

            if let Some(ref fail_severity) = fail_on {
                if let Ok(threshold) = fail_severity.parse::<rustzap::types::Severity>() {
                    let matching = report
                        .findings
                        .iter()
                        .filter(|f| f.severity >= threshold)
                        .count();
                    if matching > 0 {
                        eprintln!(
                            "\n{} CI/CD Gate Failed: Detected {} finding(s) with severity >= {:?}",
                            "❌".bright_red(),
                            matching,
                            threshold
                        );
                        std::process::exit(1);
                    }
                } else {
                    eprintln!("Warning: unknown --fail-on severity value '{fail_severity}'");
                }
            }
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
            path,
            repo,
            tools,
            semgrep_json,
            trivy_json,
            gitleaks_json,
            checkov_json,
            correlate,
            output,
            sarif_out,
            yes,
            include_ignored,
            follow_symlinks,
        } => {
            let tools_explicit = tools.is_some();
            let tools = tools.unwrap_or_else(|| analyze::DEFAULT_ANALYZE_TOOLS.to_string());
            let repo = analyze::resolve_repo_path(path, repo, yes)?;
            analyze::run_analyze_cli(
                repo,
                tools,
                semgrep_json,
                trivy_json,
                gitleaks_json,
                checkov_json,
                correlate,
                output,
                sarif_out,
                yes,
                tools_explicit,
                include_ignored,
                follow_symlinks,
            )
            .await?;
        }

        Commands::Audit {
            path,
            repo,
            target,
            tools,
            semgrep_json,
            trivy_json,
            gitleaks_json,
            checkov_json,
            correlate,
            output,
            sarif_out,
            passive_only,
            depth,
            concurrency,
            timeout,
            insecure,
            plugins,
            yes,
            include_ignored,
            follow_symlinks,
            active_all_paths,
            passive_all_methods,
            attack,
            read_only_safe,
            max_rps,
        } => {
            if attack && !read_only_safe {
                if let Some(ref t) = target {
                    safety::print_attack_mode_warning(t);
                }
            }
            let tools_explicit = tools.is_some();
            let tools = tools.unwrap_or_else(|| analyze::DEFAULT_AUDIT_TOOLS.to_string());
            let repo = analyze::resolve_repo_path(path, repo, yes)?;
            analyze::run_audit_cli(
                repo,
                target,
                tools,
                semgrep_json,
                trivy_json,
                gitleaks_json,
                checkov_json,
                correlate,
                output,
                sarif_out,
                passive_only,
                depth,
                concurrency,
                plugins,
                timeout,
                insecure,
                yes,
                tools_explicit,
                include_ignored,
                follow_symlinks,
                active_all_paths,
                passive_all_methods,
                safety::SafetyPolicy::from_flags(attack, read_only_safe, max_rps),
            )
            .await?;
        }

        Commands::Agent {
            scope,
            init_scope,
            goal,
            target,
            repo,
            autonomy,
            non_interactive,
            script,
            model,
            base_url,
            api_key_env,
            json_mode,
            privacy,
            ai_redteam,
            ai_redteam_marker,
            output,
            sarif_out,
            trace,
            attack,
            read_only_safe,
            max_rps,
            autofix_dir,
        } => {
            if attack && !read_only_safe {
                let target_str = target.as_deref().unwrap_or("configured target");
                safety::print_attack_mode_warning(target_str);
            }
            if let Some(path) = init_scope {
                let p = std::path::Path::new(&path);
                agent::scope::write_template(p)?;
                println!(
                    "Wrote starter scope → {path}\nEdit `allowed_hosts`, then run: rustzap agent --scope {path} --target <URL>"
                );
                return Ok(());
            }
            let scope = scope.expect("clap requires --scope unless --init-scope is set");
            let llm = agent::LlmOverrides {
                base_url,
                model,
                api_key_env,
                json_mode,
                privacy,
            };
            agent::run_agent_cli(
                scope,
                goal,
                target,
                repo,
                output,
                sarif_out,
                trace,
                autonomy,
                non_interactive,
                script,
                llm,
                ai_redteam,
                ai_redteam_marker,
                safety::SafetyPolicy::from_flags(attack, read_only_safe, max_rps),
                autofix_dir,
            )
            .await?;
        }

        Commands::Autofix { report, out } => {
            agent::autofix::export_from_report(&report, &out)?;
            println!("Wrote autofix prompts → {out}");
        }

        Commands::Mcp { scope, trace } => {
            mcp::run_mcp_stdio(scope, trace).await?;
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

        Commands::Ad {
            domain,
            dc_ip,
            targets,
            targets_file,
            username,
            password_env,
            null_auth,
            kerberos,
            audit,
            checks,
            insecure,
            output,
            sarif_out,
            yes,
        } => {
            let mut targets = targets;
            if let Some(file) = targets_file {
                let contents = std::fs::read_to_string(&file)
                    .with_context(|| format!("read targets file {file}"))?;
                targets.extend(
                    contents
                        .lines()
                        .map(|l| l.trim())
                        .filter(|l| !l.is_empty() && !l.starts_with('#'))
                        .map(|l| l.to_string()),
                );
            }
            let password = if null_auth {
                None
            } else {
                std::env::var(&password_env).ok().filter(|v| !v.is_empty())
            };
            if username.is_some() && !null_auth && password.is_none() {
                anyhow::bail!(
                    "No password found in ${password_env}. Set it (e.g. `export {password_env}=...`) or use --null-auth."
                );
            }
            let config = ad::AdConfig {
                domain,
                dc_ip,
                targets,
                username,
                password,
                null_auth,
                kerberos,
                audit,
                checks: ad::AdChecks::parse(&checks),
                insecure,
                output,
                sarif_out,
                assume_yes: yes,
            };
            ad::run_ad_cli(config).await?;
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
        Commands::Replay {
            file,
            target,
            timeout,
            verbose,
        } => {
            let config = replay::ReplayConfig {
                target_override: target,
                timeout_secs: timeout,
                verbose,
            };
            let summary = replay::run_replay_file(std::path::Path::new(&file), &config).await?;
            if summary.failed > 0 || summary.status_diverged > 0 {
                std::process::exit(1);
            }
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
