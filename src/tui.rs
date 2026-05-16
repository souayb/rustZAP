//! Interactive multi-tab TUI for the unified DevSecOps platform.
//!
//! Tabs:
//!   1·Dashboard — target, risk score, severity distribution, recent findings
//!   2·Scan      — edit config inline, launch scans, watch live phase progress
//!   3·Findings  — browse, severity-filter, drill into details
//!   4·Tools     — detect SDD tools (Semgrep/Trivy/Gitleaks/Checkov/Nmap/…) and run them
//!   5·Logs      — live event stream from scans and tool runs

use std::collections::{BTreeMap, HashSet, VecDeque};
use std::time::{Duration, Instant};

use anyhow::Result;
use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyModifiers},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{BarChart, Block, Borders, Gauge, List, ListItem, ListState, Paragraph, Tabs, Wrap},
    Frame, Terminal,
};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

use crate::events::{ScanEvent, ScanPhase};
use crate::scanner::{run_scan_with_events, ScanConfig};
use crate::tools::{detect_tools, run_tool, ExternalTool, ToolEvent};
use crate::types::{Finding, Severity};

const TAB_TITLES: &[&str] = &["1·Dashboard", "2·Scan", "3·Findings", "4·Tools", "5·Logs"];

/// State for one module group in the Findings-tab tree (SDD §9.1).
/// `ran` is set when a `ScanEvent::ModuleRan` arrives; it differentiates
/// modules that executed from those merely seen via a `Finding` event.
/// `folded` controls collapsed/expanded rendering.
#[derive(Debug, Clone)]
struct ModuleNode {
    ran: bool,
    folded: bool,
}

impl Default for ModuleNode {
    fn default() -> Self {
        Self {
            ran: false,
            folded: true,
        }
    }
}

/// One visible row in the flattened module tree. The findings tab navigates
/// this list; selecting a `Header` and pressing Enter toggles its fold.
#[derive(Debug, Clone)]
enum TreeRow {
    Header {
        module: String,
        finding_count: usize,
        max_severity: Option<Severity>,
        folded: bool,
        quiet: bool,
    },
    Finding {
        module: String,
        index: usize,
    },
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Tab {
    Dashboard,
    Scan,
    Findings,
    Tools,
    Logs,
}

impl Tab {
    fn index(&self) -> usize {
        match self {
            Tab::Dashboard => 0,
            Tab::Scan => 1,
            Tab::Findings => 2,
            Tab::Tools => 3,
            Tab::Logs => 4,
        }
    }

    fn from_index(i: usize) -> Tab {
        match i {
            0 => Tab::Dashboard,
            1 => Tab::Scan,
            2 => Tab::Findings,
            3 => Tab::Tools,
            _ => Tab::Logs,
        }
    }

    fn next(&self) -> Tab {
        Tab::from_index((self.index() + 1) % TAB_TITLES.len())
    }

    fn prev(&self) -> Tab {
        Tab::from_index((self.index() + TAB_TITLES.len() - 1) % TAB_TITLES.len())
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum InputMode {
    Normal,
    EditTarget,
    EditPlugins,
    EditOutput,
}

#[derive(Clone)]
struct ConfigForm {
    target: String,
    depth: usize,
    concurrency: usize,
    plugins: String,
    output: String,
    passive_only: bool,
    insecure: bool,
}

impl Default for ConfigForm {
    fn default() -> Self {
        Self {
            target: "https://example.com".to_string(),
            depth: 3,
            concurrency: 10,
            plugins: "xss,sqli,nosql,path-traversal,open-redirect,ssrf,xxe,cmd-injection,ssti,graphql-introspection,http-methods,redirect-chain".to_string(),
            output: "rustzap-report.json".to_string(),
            passive_only: false,
            insecure: false,
        }
    }
}

impl ConfigForm {
    fn to_scan_config(&self) -> ScanConfig {
        ScanConfig {
            target_url: self.target.clone(),
            max_depth: self.depth,
            concurrency: self.concurrency,
            passive_only: self.passive_only,
            output_file: self.output.clone(),
            timeout_secs: 10,
            user_agent: None,
            cookies: None,
            auth_header: None,
            api_key: None,
            basic_auth: None,
            insecure: self.insecure,
            plugins: self
                .plugins
                .split(',')
                .map(|s| s.trim().to_string())
                .collect(),
        }
    }
}

enum ScanStatus {
    Idle,
    Running {
        phase: ScanPhase,
        spider_count: usize,
        passive: (usize, usize),
        active: (usize, usize),
        started_at: Instant,
    },
    Completed {
        findings: usize,
        risk_score: u8,
        duration_secs: f64,
        report_path: String,
    },
    Failed {
        error: String,
    },
}

const MAX_LOGS: usize = 500;

struct App {
    tab: Tab,
    config: ConfigForm,
    input_mode: InputMode,
    input_buffer: String,

    scan_status: ScanStatus,
    scan_handle: Option<JoinHandle<Result<()>>>,
    scan_rx: Option<mpsc::UnboundedReceiver<ScanEvent>>,

    findings: Vec<Finding>,
    findings_state: ListState,
    severity_filter: HashSet<Severity>,
    detail_scroll: u16,
    /// Module tree state (SDD §9.1). Keyed by plugin id (e.g. `active/sqli`).
    modules: BTreeMap<String, ModuleNode>,

    tools: Vec<ExternalTool>,
    tools_state: ListState,
    tool_rx: Option<mpsc::UnboundedReceiver<ToolEvent>>,
    tool_handle: Option<JoinHandle<Result<()>>>,
    active_tool: Option<String>,

    logs: VecDeque<String>,
    log_scroll: u16,

    started: Instant,
    should_quit: bool,
}

impl App {
    fn new() -> Self {
        let mut findings_state = ListState::default();
        findings_state.select(Some(0));
        let mut tools_state = ListState::default();
        tools_state.select(Some(0));

        let mut app = Self {
            tab: Tab::Dashboard,
            config: ConfigForm::default(),
            input_mode: InputMode::Normal,
            input_buffer: String::new(),

            scan_status: ScanStatus::Idle,
            scan_handle: None,
            scan_rx: None,

            findings: Vec::new(),
            findings_state,
            severity_filter: HashSet::new(),
            detail_scroll: 0,
            modules: BTreeMap::new(),

            tools: detect_tools(),
            tools_state,
            tool_rx: None,
            tool_handle: None,
            active_tool: None,

            logs: VecDeque::with_capacity(MAX_LOGS),
            log_scroll: 0,

            started: Instant::now(),
            should_quit: false,
        };

        // Pre-load any existing report so the dashboard isn't empty on first run.
        for path in ["report.json", "rustzap-report.json"] {
            if let Ok(contents) = std::fs::read_to_string(path) {
                if let Ok(parsed) = serde_json::from_str::<crate::report::Report>(&contents) {
                    app.findings = parsed.findings;
                    app.log(format!(
                        "Loaded {} findings from {}",
                        app.findings.len(),
                        path
                    ));
                    break;
                }
            }
        }
        app.log("RustZAP TUI ready. Press '?' for help, 'q' to quit.".into());
        app
    }

    fn log(&mut self, line: String) {
        if self.logs.len() >= MAX_LOGS {
            self.logs.pop_front();
        }
        let ts = chrono::Utc::now().format("%H:%M:%S");
        self.logs.push_back(format!("[{}] {}", ts, line));
    }

    /// Build the flattened module tree shown in the Findings tab (SDD §9.1).
    /// Severity filter only hides findings; module headers always appear so
    /// the operator sees coverage even when the filter is restrictive.
    fn tree_rows(&self) -> Vec<TreeRow> {
        // Bucket finding indices by their `plugin` field.
        let mut by_module: BTreeMap<String, Vec<usize>> = BTreeMap::new();
        for (i, f) in self.findings.iter().enumerate() {
            if !self.severity_filter.is_empty() && !self.severity_filter.contains(&f.severity) {
                continue;
            }
            by_module.entry(f.plugin.clone()).or_default().push(i);
        }
        // Make sure every known/registered module appears even if 0 findings.
        for k in self.modules.keys() {
            by_module.entry(k.clone()).or_default();
        }

        // Per-module max severity (highest first).
        let mut headers: Vec<(String, Vec<usize>, Option<Severity>)> = by_module
            .into_iter()
            .map(|(name, idxs)| {
                let max_sev = idxs
                    .iter()
                    .map(|&i| self.findings[i].severity.clone())
                    .max();
                (name, idxs, max_sev)
            })
            .collect();
        // Non-quiet first (by max severity descending), then quiet (alphabetical).
        headers.sort_by(|a, b| {
            let a_quiet = a.1.is_empty();
            let b_quiet = b.1.is_empty();
            match (a_quiet, b_quiet) {
                (false, true) => std::cmp::Ordering::Less,
                (true, false) => std::cmp::Ordering::Greater,
                _ => b.2.cmp(&a.2).then_with(|| a.0.cmp(&b.0)),
            }
        });

        let mut rows = Vec::new();
        for (name, idxs, max_sev) in headers {
            let node = self.modules.get(&name);
            let folded = node.map(|n| n.folded).unwrap_or(idxs.is_empty());
            let quiet = idxs.is_empty();
            rows.push(TreeRow::Header {
                module: name.clone(),
                finding_count: idxs.len(),
                max_severity: max_sev,
                folded,
                quiet,
            });
            if !folded {
                for i in idxs {
                    rows.push(TreeRow::Finding {
                        module: name.clone(),
                        index: i,
                    });
                }
            }
        }
        rows
    }

    /// Toggle the folded state of the module under the focused row. If the
    /// focused row is a finding, fold its parent module.
    fn toggle_focused_module(&mut self) {
        let rows = self.tree_rows();
        let sel = self
            .findings_state
            .selected()
            .unwrap_or(0)
            .min(rows.len().saturating_sub(1));
        let module = match rows.get(sel) {
            Some(TreeRow::Header { module, .. }) => module.clone(),
            Some(TreeRow::Finding { module, .. }) => module.clone(),
            None => return,
        };
        let entry = self.modules.entry(module).or_default();
        entry.folded = !entry.folded;
    }

    fn set_all_modules_folded(&mut self, folded: bool) {
        // Make sure every observed module has a state entry first.
        let plugins: Vec<String> = self.findings.iter().map(|f| f.plugin.clone()).collect();
        for p in plugins {
            self.modules.entry(p).or_default();
        }
        for node in self.modules.values_mut() {
            node.folded = folded;
        }
    }

    fn start_scan(&mut self) {
        if matches!(self.scan_status, ScanStatus::Running { .. }) {
            self.log("A scan is already running. Press 'x' to cancel first.".into());
            return;
        }
        let config = self.config.to_scan_config();
        let (tx, rx) = mpsc::unbounded_channel();
        self.scan_rx = Some(rx);
        self.scan_status = ScanStatus::Running {
            phase: ScanPhase::Spider,
            spider_count: 0,
            passive: (0, 0),
            active: (0, 0),
            started_at: Instant::now(),
        };
        self.findings.clear();
        self.findings_state.select(Some(0));
        self.log(format!("Launching scan on {}", config.target_url));
        let handle = tokio::spawn(async move { run_scan_with_events(config, tx).await });
        self.scan_handle = Some(handle);
        self.tab = Tab::Scan;
    }

    fn cancel_scan(&mut self) {
        if let Some(handle) = self.scan_handle.take() {
            handle.abort();
            self.log("Scan cancelled by user.".into());
            self.scan_status = ScanStatus::Failed {
                error: "Cancelled".to_string(),
            };
        }
        self.scan_rx = None;
    }

    fn run_selected_tool(&mut self) {
        let Some(idx) = self.tools_state.selected() else {
            return;
        };
        let Some(tool) = self.tools.get(idx).cloned() else {
            return;
        };
        if self.tool_handle.is_some() {
            self.log("A tool is already running. Wait for it to finish.".into());
            return;
        }
        let target = if tool.needs_target {
            Some(self.config.target.clone())
        } else {
            None
        };
        let (tx, rx) = mpsc::unbounded_channel();
        self.tool_rx = Some(rx);
        self.active_tool = Some(tool.name.clone());
        let handle = tokio::spawn(async move { run_tool(tool, target, tx).await });
        self.tool_handle = Some(handle);
        self.tab = Tab::Logs;
    }

    fn drain_events(&mut self) {
        // Drain scan events
        if let Some(rx) = &mut self.scan_rx {
            for _ in 0..256 {
                match rx.try_recv() {
                    Ok(ev) => Self::apply_scan_event(
                        &mut self.scan_status,
                        &mut self.findings,
                        &mut self.logs,
                        &mut self.modules,
                        ev,
                    ),
                    Err(mpsc::error::TryRecvError::Empty) => break,
                    Err(mpsc::error::TryRecvError::Disconnected) => {
                        self.scan_rx = None;
                        break;
                    }
                }
            }
        }
        // Reap scan handle if done
        if let Some(handle) = &self.scan_handle {
            if handle.is_finished() {
                let handle = self.scan_handle.take().unwrap();
                tokio::spawn(async move {
                    let _ = handle.await;
                });
            }
        }

        // Drain tool events
        if let Some(rx) = &mut self.tool_rx {
            for _ in 0..256 {
                match rx.try_recv() {
                    Ok(ev) => Self::apply_tool_event(&mut self.logs, &mut self.active_tool, ev),
                    Err(mpsc::error::TryRecvError::Empty) => break,
                    Err(mpsc::error::TryRecvError::Disconnected) => {
                        self.tool_rx = None;
                        break;
                    }
                }
            }
        }
        if let Some(handle) = &self.tool_handle {
            if handle.is_finished() {
                let handle = self.tool_handle.take().unwrap();
                tokio::spawn(async move {
                    let _ = handle.await;
                });
                self.active_tool = None;
            }
        }
    }

    fn apply_scan_event(
        status: &mut ScanStatus,
        findings: &mut Vec<Finding>,
        logs: &mut VecDeque<String>,
        modules: &mut BTreeMap<String, ModuleNode>,
        ev: ScanEvent,
    ) {
        let push_log = |logs: &mut VecDeque<String>, msg: String| {
            if logs.len() >= MAX_LOGS {
                logs.pop_front();
            }
            let ts = chrono::Utc::now().format("%H:%M:%S");
            logs.push_back(format!("[{}] {}", ts, msg));
        };

        match ev {
            ScanEvent::Started { target } => {
                push_log(logs, format!("Scan started: {}", target));
            }
            ScanEvent::PhaseStarted { phase, total } => {
                push_log(
                    logs,
                    format!(
                        "Phase {} started{}",
                        phase.label(),
                        total.map(|t| format!(" ({} URLs)", t)).unwrap_or_default()
                    ),
                );
                if let ScanStatus::Running { phase: p, .. } = status {
                    *p = phase;
                }
            }
            ScanEvent::SpiderProgress { discovered, .. } => {
                if let ScanStatus::Running { spider_count, .. } = status {
                    *spider_count = discovered;
                }
            }
            ScanEvent::PassiveProgress { done, total } => {
                if let ScanStatus::Running { passive, .. } = status {
                    *passive = (done, total);
                }
            }
            ScanEvent::ActiveProgress { done, total } => {
                if let ScanStatus::Running { active, .. } = status {
                    *active = (done, total);
                }
            }
            ScanEvent::Finding(f) => {
                push_log(
                    logs,
                    format!("Finding [{}] {} @ {}", f.severity, f.title, f.url),
                );
                // Register the module group on first finding so it shows up
                // in the tree even before ModuleRan arrives.
                let entry = modules.entry(f.plugin.clone()).or_default();
                // Auto-expand groups that have findings — quiet defaults to folded.
                if !entry.ran {
                    entry.folded = false;
                }
                findings.push(f);
            }
            ScanEvent::Log(msg) => push_log(logs, msg),
            ScanEvent::Error(msg) => push_log(logs, format!("ERROR: {}", msg)),
            ScanEvent::ModuleRan { name, findings: n } => {
                let marker = if n == 0 { "·" } else { "✓" };
                push_log(
                    logs,
                    format!(
                        "{} module {} ({})",
                        marker,
                        name,
                        if n == 0 {
                            "quiet".to_string()
                        } else if n == 1 {
                            "1 finding".to_string()
                        } else {
                            format!("{} findings", n)
                        }
                    ),
                );
                modules.entry(name).or_default().ran = true;
            }
            ScanEvent::Completed {
                duration_secs,
                total_findings,
                risk_score,
                report_path,
            } => {
                push_log(
                    logs,
                    format!(
                        "Scan complete: {} findings, risk={}, duration={:.1}s, report={}",
                        total_findings, risk_score, duration_secs, report_path
                    ),
                );
                *status = ScanStatus::Completed {
                    findings: total_findings,
                    risk_score,
                    duration_secs,
                    report_path,
                };
            }
        }
    }

    fn apply_tool_event(
        logs: &mut VecDeque<String>,
        active_tool: &mut Option<String>,
        ev: ToolEvent,
    ) {
        let push_log = |logs: &mut VecDeque<String>, msg: String| {
            if logs.len() >= MAX_LOGS {
                logs.pop_front();
            }
            let ts = chrono::Utc::now().format("%H:%M:%S");
            logs.push_back(format!("[{}] {}", ts, msg));
        };

        match ev {
            ToolEvent::Started { tool, cmdline } => {
                push_log(logs, format!("[{}] $ {}", tool, cmdline));
                *active_tool = Some(tool);
            }
            ToolEvent::Output { tool, line } => {
                push_log(logs, format!("[{}] {}", tool, line));
            }
            ToolEvent::Completed { tool, exit_code } => {
                push_log(logs, format!("[{}] exited with code {}", tool, exit_code));
            }
            ToolEvent::Error { tool, error } => {
                push_log(logs, format!("[{}] ERROR: {}", tool, error));
            }
        }
    }
}

pub async fn run_tui() -> anyhow::Result<()> {
    enable_raw_mode()?;
    let mut stdout = std::io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let mut app = App::new();
    let res = event_loop(&mut terminal, &mut app).await;

    disable_raw_mode()?;
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture
    )?;
    terminal.show_cursor()?;

    res
}

async fn event_loop(
    terminal: &mut Terminal<CrosstermBackend<std::io::Stdout>>,
    app: &mut App,
) -> anyhow::Result<()> {
    loop {
        app.drain_events();
        terminal.draw(|f| draw(f, app))?;

        if event::poll(Duration::from_millis(80))? {
            if let Event::Key(key) = event::read()? {
                handle_key(app, key.code, key.modifiers);
            }
        }
        if app.should_quit {
            // Make sure any background scan is aborted before we leave.
            if let Some(h) = app.scan_handle.take() {
                h.abort();
            }
            if let Some(h) = app.tool_handle.take() {
                h.abort();
            }
            return Ok(());
        }
    }
}

fn handle_key(app: &mut App, code: KeyCode, mods: KeyModifiers) {
    // Editing modes intercept most keys.
    if app.input_mode != InputMode::Normal {
        match code {
            KeyCode::Esc => {
                app.input_buffer.clear();
                app.input_mode = InputMode::Normal;
            }
            KeyCode::Enter => {
                let value = std::mem::take(&mut app.input_buffer);
                match app.input_mode {
                    InputMode::EditTarget => {
                        app.config.target = value;
                        app.log(format!("Target set to {}", app.config.target));
                    }
                    InputMode::EditPlugins => {
                        app.config.plugins = value;
                        app.log("Active plugins updated".into());
                    }
                    InputMode::EditOutput => {
                        app.config.output = value;
                        app.log(format!("Output file set to {}", app.config.output));
                    }
                    InputMode::Normal => {}
                }
                app.input_mode = InputMode::Normal;
            }
            KeyCode::Backspace => {
                app.input_buffer.pop();
            }
            KeyCode::Char(c) => {
                if !(mods.contains(KeyModifiers::CONTROL) && c == 'c') {
                    app.input_buffer.push(c);
                }
            }
            _ => {}
        }
        return;
    }

    // Normal-mode global keys
    match code {
        KeyCode::Char('q') => app.should_quit = true,
        KeyCode::Char('Q') => app.should_quit = true,
        KeyCode::Tab => app.tab = app.tab.next(),
        KeyCode::BackTab => app.tab = app.tab.prev(),
        KeyCode::Char('1') => app.tab = Tab::Dashboard,
        KeyCode::Char('2') => app.tab = Tab::Scan,
        KeyCode::Char('3') => app.tab = Tab::Findings,
        KeyCode::Char('4') => app.tab = Tab::Tools,
        KeyCode::Char('5') => app.tab = Tab::Logs,
        _ => match app.tab {
            Tab::Dashboard => {}
            Tab::Scan => handle_scan_keys(app, code),
            Tab::Findings => handle_findings_keys(app, code),
            Tab::Tools => handle_tools_keys(app, code),
            Tab::Logs => handle_logs_keys(app, code),
        },
    }
}

fn handle_scan_keys(app: &mut App, code: KeyCode) {
    match code {
        KeyCode::Char('t') => {
            app.input_buffer = app.config.target.clone();
            app.input_mode = InputMode::EditTarget;
        }
        KeyCode::Char('P') => {
            app.input_buffer = app.config.plugins.clone();
            app.input_mode = InputMode::EditPlugins;
        }
        KeyCode::Char('o') => {
            app.input_buffer = app.config.output.clone();
            app.input_mode = InputMode::EditOutput;
        }
        KeyCode::Char('p') => app.config.passive_only = !app.config.passive_only,
        KeyCode::Char('i') => app.config.insecure = !app.config.insecure,
        KeyCode::Char('+') | KeyCode::Char('=') => {
            app.config.depth = (app.config.depth + 1).min(20);
        }
        KeyCode::Char('-') | KeyCode::Char('_') => {
            app.config.depth = app.config.depth.saturating_sub(1).max(1);
        }
        KeyCode::Char(']') => {
            app.config.concurrency = (app.config.concurrency + 1).min(200);
        }
        KeyCode::Char('[') => {
            app.config.concurrency = app.config.concurrency.saturating_sub(1).max(1);
        }
        KeyCode::Char('s') => app.start_scan(),
        KeyCode::Char('x') => app.cancel_scan(),
        _ => {}
    }
}

fn handle_findings_keys(app: &mut App, code: KeyCode) {
    // Navigate the module tree (headers + visible findings) rather than a
    // flat list. Fold state is mutable from here too.
    let len = app.tree_rows().len();
    if len == 0 {
        return;
    }
    let selected = app.findings_state.selected().unwrap_or(0).min(len - 1);
    match code {
        KeyCode::Down | KeyCode::Char('j') => {
            let next = if selected + 1 >= len { 0 } else { selected + 1 };
            app.findings_state.select(Some(next));
            app.detail_scroll = 0;
        }
        KeyCode::Up | KeyCode::Char('k') => {
            let next = if selected == 0 { len - 1 } else { selected - 1 };
            app.findings_state.select(Some(next));
            app.detail_scroll = 0;
        }
        KeyCode::Enter | KeyCode::Char(' ') => {
            app.toggle_focused_module();
            app.detail_scroll = 0;
        }
        KeyCode::Char('o') => {
            app.set_all_modules_folded(false);
        }
        KeyCode::Char('O') => {
            app.set_all_modules_folded(true);
        }
        KeyCode::PageDown => app.detail_scroll = app.detail_scroll.saturating_add(5),
        KeyCode::PageUp => app.detail_scroll = app.detail_scroll.saturating_sub(5),
        KeyCode::Char('f') => {
            // Cycle: empty -> Critical -> High -> Medium -> Low -> Info -> empty
            let next = match app.severity_filter.iter().next().cloned() {
                None => Some(Severity::Critical),
                Some(Severity::Critical) => Some(Severity::High),
                Some(Severity::High) => Some(Severity::Medium),
                Some(Severity::Medium) => Some(Severity::Low),
                Some(Severity::Low) => Some(Severity::Info),
                Some(Severity::Info) => None,
            };
            app.severity_filter.clear();
            if let Some(s) = next {
                app.severity_filter.insert(s);
            }
            app.findings_state.select(Some(0));
        }
        KeyCode::Char('c') => {
            app.severity_filter.clear();
            app.findings_state.select(Some(0));
        }
        _ => {}
    }
}

fn handle_tools_keys(app: &mut App, code: KeyCode) {
    let len = app.tools.len();
    if len == 0 {
        return;
    }
    let selected = app.tools_state.selected().unwrap_or(0).min(len - 1);
    match code {
        KeyCode::Down | KeyCode::Char('j') => {
            let next = if selected + 1 >= len { 0 } else { selected + 1 };
            app.tools_state.select(Some(next));
        }
        KeyCode::Up | KeyCode::Char('k') => {
            let next = if selected == 0 { len - 1 } else { selected - 1 };
            app.tools_state.select(Some(next));
        }
        KeyCode::Char('r') | KeyCode::Enter => app.run_selected_tool(),
        KeyCode::Char('R') => {
            app.tools = detect_tools();
            app.log("Re-detected tools on PATH".into());
        }
        _ => {}
    }
}

fn handle_logs_keys(app: &mut App, code: KeyCode) {
    match code {
        KeyCode::Down | KeyCode::Char('j') => app.log_scroll = app.log_scroll.saturating_add(1),
        KeyCode::Up | KeyCode::Char('k') => app.log_scroll = app.log_scroll.saturating_sub(1),
        KeyCode::PageDown => app.log_scroll = app.log_scroll.saturating_add(10),
        KeyCode::PageUp => app.log_scroll = app.log_scroll.saturating_sub(10),
        KeyCode::Char('G') => app.log_scroll = u16::MAX,
        KeyCode::Char('c') => {
            app.logs.clear();
            app.log_scroll = 0;
        }
        _ => {}
    }
}

// ─── Rendering ──────────────────────────────────────────────────────

fn draw(f: &mut Frame, app: &App) {
    let outer = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(1),
            Constraint::Length(3),
        ])
        .split(f.area());

    draw_tabs(f, app, outer[0]);

    match app.tab {
        Tab::Dashboard => draw_dashboard(f, app, outer[1]),
        Tab::Scan => draw_scan(f, app, outer[1]),
        Tab::Findings => draw_findings(f, app, outer[1]),
        Tab::Tools => draw_tools(f, app, outer[1]),
        Tab::Logs => draw_logs(f, app, outer[1]),
    }

    draw_status_bar(f, app, outer[2]);
}

fn draw_tabs(f: &mut Frame, app: &App, area: Rect) {
    let titles: Vec<Line> = TAB_TITLES
        .iter()
        .map(|t| Line::from(Span::styled(*t, Style::default().fg(Color::White))))
        .collect();

    let tabs = Tabs::new(titles)
        .block(Block::default().borders(Borders::ALL).title(Span::styled(
            " RustZAP · Unified DevSecOps Pentesting Console ",
            Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
        )))
        .select(app.tab.index())
        .highlight_style(
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD | Modifier::REVERSED),
        )
        .divider("│");

    f.render_widget(tabs, area);
}

fn severity_color(sev: &Severity) -> Color {
    match sev {
        Severity::Critical => Color::Magenta,
        Severity::High => Color::Red,
        Severity::Medium => Color::Yellow,
        Severity::Low => Color::Cyan,
        Severity::Info => Color::Blue,
    }
}

fn count_by_severity(findings: &[Finding]) -> [u64; 5] {
    let mut counts = [0u64; 5];
    for f in findings {
        let i = match f.severity {
            Severity::Critical => 0,
            Severity::High => 1,
            Severity::Medium => 2,
            Severity::Low => 3,
            Severity::Info => 4,
        };
        counts[i] += 1;
    }
    counts
}

fn risk_score(findings: &[Finding]) -> u8 {
    let c = count_by_severity(findings);
    ((c[0] * 20 + c[1] * 10 + c[2] * 5 + c[3] * 2 + c[4]) as f64).min(100.0) as u8
}

fn draw_dashboard(f: &mut Frame, app: &App, area: Rect) {
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(7),
            Constraint::Length(11),
            Constraint::Min(1),
        ])
        .split(area);

    // Top: summary cards
    let cards = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage(34),
            Constraint::Percentage(33),
            Constraint::Percentage(33),
        ])
        .split(rows[0]);

    let target_card = Paragraph::new(vec![
        Line::from(Span::styled(
            &app.config.target,
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        )),
        Line::from(format!(
            "depth={} concurrency={}",
            app.config.depth, app.config.concurrency
        )),
        Line::from(format!(
            "passive_only={} insecure={}",
            app.config.passive_only, app.config.insecure
        )),
    ])
    .block(
        Block::default()
            .borders(Borders::ALL)
            .title(" Target ")
            .title_alignment(Alignment::Left),
    )
    .wrap(Wrap { trim: true });
    f.render_widget(target_card, cards[0]);

    let score = risk_score(&app.findings);
    let score_color = match score {
        0..=24 => Color::Green,
        25..=49 => Color::Yellow,
        50..=74 => Color::LightRed,
        _ => Color::Magenta,
    };
    let score_card = Paragraph::new(vec![
        Line::from(""),
        Line::from(Span::styled(
            format!("  {} / 100", score),
            Style::default()
                .fg(score_color)
                .add_modifier(Modifier::BOLD),
        )),
        Line::from(""),
        Line::from(Span::styled(
            risk_label(score),
            Style::default().fg(score_color),
        )),
    ])
    .block(Block::default().borders(Borders::ALL).title(" Risk Score "))
    .alignment(Alignment::Center);
    f.render_widget(score_card, cards[1]);

    let status_text = match &app.scan_status {
        ScanStatus::Idle => Line::from(Span::styled(
            "Idle — press 's' on Scan tab to begin",
            Style::default().fg(Color::Gray),
        )),
        ScanStatus::Running {
            phase, started_at, ..
        } => Line::from(vec![
            Span::styled(
                format!("RUNNING [{}]", phase.label()),
                Style::default()
                    .fg(Color::Green)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw(format!(" · {:.0}s", started_at.elapsed().as_secs_f64())),
        ]),
        ScanStatus::Completed {
            findings,
            duration_secs,
            ..
        } => Line::from(Span::styled(
            format!("Completed · {} findings · {:.1}s", findings, duration_secs),
            Style::default().fg(Color::Green),
        )),
        ScanStatus::Failed { error } => Line::from(Span::styled(
            format!("Failed: {}", error),
            Style::default().fg(Color::Red),
        )),
    };
    let status_card = Paragraph::new(vec![
        Line::from(format!("Findings: {}", app.findings.len())),
        Line::from(format!(
            "Tools detected: {}",
            app.tools.iter().filter(|t| t.installed).count()
        )),
        Line::from(format!(
            "Uptime: {:.0}s",
            app.started.elapsed().as_secs_f64()
        )),
        status_text,
    ])
    .block(Block::default().borders(Borders::ALL).title(" Status "));
    f.render_widget(status_card, cards[2]);

    // Middle: severity bar chart
    let counts = count_by_severity(&app.findings);
    let data = [
        ("CRIT", counts[0]),
        ("HIGH", counts[1]),
        ("MED", counts[2]),
        ("LOW", counts[3]),
        ("INFO", counts[4]),
    ];
    let bars = BarChart::default()
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(" Severity distribution "),
        )
        .data(&data)
        .bar_width(8)
        .bar_gap(2)
        .bar_style(Style::default().fg(Color::Red))
        .value_style(
            Style::default()
                .bg(Color::Red)
                .fg(Color::White)
                .add_modifier(Modifier::BOLD),
        );
    f.render_widget(bars, rows[1]);

    // Bottom: recent findings (top 10 by severity desc)
    let mut sorted = app.findings.clone();
    sorted.sort_by(|a, b| b.severity.cmp(&a.severity));
    let items: Vec<ListItem> = sorted
        .iter()
        .take(20)
        .map(|fnd| {
            ListItem::new(Line::from(vec![
                Span::styled(
                    format!("[{:<8}]", fnd.severity),
                    Style::default().fg(severity_color(&fnd.severity)),
                ),
                Span::raw(" "),
                Span::styled(&fnd.title, Style::default().add_modifier(Modifier::BOLD)),
                Span::raw("  "),
                Span::styled(&fnd.url, Style::default().fg(Color::DarkGray)),
            ]))
        })
        .collect();
    let list = List::new(items).block(
        Block::default()
            .borders(Borders::ALL)
            .title(" Recent findings (top by severity) "),
    );
    f.render_widget(list, rows[2]);
}

fn risk_label(score: u8) -> &'static str {
    match score {
        0..=24 => "● LOW RISK",
        25..=49 => "● MODERATE",
        50..=74 => "● HIGH RISK",
        _ => "● CRITICAL",
    }
}

fn draw_scan(f: &mut Frame, app: &App, area: Rect) {
    let cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(45), Constraint::Percentage(55)])
        .split(area);

    // Left: configuration form
    let mut lines: Vec<Line> = vec![
        Line::from(Span::styled(
            " Scan Configuration",
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        )),
        Line::from(""),
        Line::from(vec![
            Span::styled("  [t] Target      ", Style::default().fg(Color::Cyan)),
            Span::raw(app.config.target.clone()),
        ]),
        Line::from(vec![
            Span::styled("  [+/-] Depth     ", Style::default().fg(Color::Cyan)),
            Span::raw(app.config.depth.to_string()),
        ]),
        Line::from(vec![
            Span::styled("  [[/]] Concurrent ", Style::default().fg(Color::Cyan)),
            Span::raw(app.config.concurrency.to_string()),
        ]),
        Line::from(vec![
            Span::styled("  [P] Plugins     ", Style::default().fg(Color::Cyan)),
            Span::raw(app.config.plugins.clone()),
        ]),
        Line::from(vec![
            Span::styled("  [o] Output      ", Style::default().fg(Color::Cyan)),
            Span::raw(app.config.output.clone()),
        ]),
        Line::from(vec![
            Span::styled("  [p] Passive only ", Style::default().fg(Color::Cyan)),
            Span::raw(if app.config.passive_only { "ON" } else { "OFF" }),
        ]),
        Line::from(vec![
            Span::styled("  [i] Insecure TLS ", Style::default().fg(Color::Cyan)),
            Span::raw(if app.config.insecure { "ON" } else { "OFF" }),
        ]),
        Line::from(""),
        Line::from(Span::styled(
            "  [s] Start scan    [x] Cancel scan",
            Style::default()
                .fg(Color::Green)
                .add_modifier(Modifier::BOLD),
        )),
    ];

    if app.input_mode != InputMode::Normal {
        let label = match app.input_mode {
            InputMode::EditTarget => "Editing target URL",
            InputMode::EditPlugins => "Editing plugins (comma-separated)",
            InputMode::EditOutput => "Editing output path (.json/.csv/.html)",
            InputMode::Normal => "",
        };
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            format!(" ▶ {}", label),
            Style::default().fg(Color::Yellow),
        )));
        lines.push(Line::from(vec![
            Span::styled(" › ", Style::default().fg(Color::Yellow)),
            Span::styled(
                app.input_buffer.clone() + "▌",
                Style::default()
                    .fg(Color::White)
                    .bg(Color::DarkGray)
                    .add_modifier(Modifier::BOLD),
            ),
        ]));
        lines.push(Line::from(Span::styled(
            "   Enter: commit · Esc: cancel",
            Style::default().fg(Color::DarkGray),
        )));
    }

    let form = Paragraph::new(lines)
        .block(Block::default().borders(Borders::ALL).title(" Config "))
        .wrap(Wrap { trim: false });
    f.render_widget(form, cols[0]);

    // Right: phase progress + status
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Length(3),
            Constraint::Length(3),
            Constraint::Length(3),
            Constraint::Min(1),
        ])
        .split(cols[1]);

    let (spider_ratio, passive_ratio, active_ratio, header) = match &app.scan_status {
        ScanStatus::Idle => (
            0.0,
            0.0,
            0.0,
            "Idle — configure on the left and press 's' to start".to_string(),
        ),
        ScanStatus::Running {
            spider_count,
            passive,
            active,
            started_at,
            phase,
        } => {
            let spider_done = match phase {
                ScanPhase::Spider => 0.4_f64.min(0.1 + (*spider_count as f64) / 200.0),
                _ => 1.0,
            };
            let passive_ratio = if passive.1 == 0 {
                0.0
            } else {
                (passive.0 as f64) / (passive.1 as f64)
            };
            let active_ratio = if active.1 == 0 {
                0.0
            } else {
                (active.0 as f64) / (active.1 as f64)
            };
            (
                spider_done.clamp(0.0, 1.0),
                passive_ratio.clamp(0.0, 1.0),
                active_ratio.clamp(0.0, 1.0),
                format!(
                    "Scanning · phase={} · elapsed={:.1}s · findings={}",
                    phase.label(),
                    started_at.elapsed().as_secs_f64(),
                    app.findings.len()
                ),
            )
        }
        ScanStatus::Completed {
            findings,
            duration_secs,
            risk_score,
            report_path,
        } => (
            1.0,
            1.0,
            1.0,
            format!(
                "Completed · {} findings · risk={} · {:.1}s · → {}",
                findings, risk_score, duration_secs, report_path
            ),
        ),
        ScanStatus::Failed { error } => (0.0, 0.0, 0.0, format!("Failed: {}", error)),
    };

    let title = Paragraph::new(header).block(
        Block::default()
            .borders(Borders::ALL)
            .title(" Live status "),
    );
    f.render_widget(title, rows[0]);

    let spider = Gauge::default()
        .block(Block::default().borders(Borders::ALL).title(" Spider "))
        .gauge_style(Style::default().fg(Color::Cyan))
        .ratio(spider_ratio);
    f.render_widget(spider, rows[1]);

    let passive = Gauge::default()
        .block(Block::default().borders(Borders::ALL).title(" Passive "))
        .gauge_style(Style::default().fg(Color::Green))
        .ratio(passive_ratio);
    f.render_widget(passive, rows[2]);

    let active = Gauge::default()
        .block(Block::default().borders(Borders::ALL).title(" Active "))
        .gauge_style(Style::default().fg(Color::Red))
        .ratio(active_ratio);
    f.render_widget(active, rows[3]);

    // Live findings preview
    let preview_items: Vec<ListItem> = app
        .findings
        .iter()
        .rev()
        .take(50)
        .map(|fnd| {
            ListItem::new(Line::from(vec![
                Span::styled(
                    format!("[{:<8}]", fnd.severity),
                    Style::default().fg(severity_color(&fnd.severity)),
                ),
                Span::raw(" "),
                Span::raw(&fnd.title),
            ]))
        })
        .collect();
    let preview = List::new(preview_items).block(
        Block::default()
            .borders(Borders::ALL)
            .title(" Live findings "),
    );
    f.render_widget(preview, rows[4]);
}

fn draw_findings(f: &mut Frame, app: &App, area: Rect) {
    let cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(45), Constraint::Percentage(55)])
        .split(area);

    let rows = app.tree_rows();
    let total_findings = app.findings.len();
    let modules_ran = rows
        .iter()
        .filter(|r| matches!(r, TreeRow::Header { .. }))
        .count();
    let quiet_count = rows
        .iter()
        .filter(|r| matches!(r, TreeRow::Header { quiet: true, .. }))
        .count();

    let filter_label = if app.severity_filter.is_empty() {
        "Filter: all".to_string()
    } else {
        let names: Vec<String> = app.severity_filter.iter().map(|s| s.to_string()).collect();
        format!("Filter: {}", names.join(","))
    };

    let items: Vec<ListItem> = rows
        .iter()
        .map(|row| match row {
            TreeRow::Header {
                module,
                finding_count,
                max_severity,
                folded,
                quiet,
            } => {
                let caret = if *quiet {
                    "·"
                } else if *folded {
                    "▶"
                } else {
                    "▼"
                };
                let sev_style = max_severity
                    .as_ref()
                    .map(severity_color)
                    .map(|c| Style::default().fg(c))
                    .unwrap_or_else(|| Style::default().fg(Color::DarkGray));
                let sev_label = match max_severity {
                    Some(s) => format!("[{}]", s),
                    None => "(quiet)".to_string(),
                };
                let count_label = if *quiet {
                    String::new()
                } else if *finding_count == 1 {
                    "  1 finding ".to_string()
                } else {
                    format!("  {} findings ", finding_count)
                };
                ListItem::new(Line::from(vec![
                    Span::styled(
                        format!("{} ", caret),
                        Style::default().fg(if *quiet { Color::DarkGray } else { Color::Cyan }),
                    ),
                    Span::styled(
                        module.clone(),
                        Style::default()
                            .fg(if *quiet {
                                Color::DarkGray
                            } else {
                                Color::White
                            })
                            .add_modifier(if *quiet {
                                Modifier::DIM
                            } else {
                                Modifier::BOLD
                            }),
                    ),
                    Span::styled(count_label, Style::default().fg(Color::DarkGray)),
                    Span::styled(sev_label, sev_style),
                ]))
            }
            TreeRow::Finding { index, .. } => {
                let fnd = &app.findings[*index];
                ListItem::new(Line::from(vec![
                    Span::raw("    "),
                    Span::styled(
                        format!("[{:<8}]", fnd.severity),
                        Style::default().fg(severity_color(&fnd.severity)),
                    ),
                    Span::raw(" "),
                    Span::raw(fnd.title.clone()),
                ]))
            }
        })
        .collect();

    let mut state = app.findings_state.clone();
    if !rows.is_empty() {
        let cur = state.selected().unwrap_or(0).min(rows.len() - 1);
        state.select(Some(cur));
    }

    let title = format!(
        " Modules ({} ran · {} quiet · {} findings) · {} ",
        modules_ran.saturating_sub(quiet_count),
        quiet_count,
        total_findings,
        filter_label
    );
    let list = List::new(items)
        .block(Block::default().borders(Borders::ALL).title(title))
        .highlight_style(
            Style::default()
                .bg(Color::DarkGray)
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol("▶ ");
    f.render_stateful_widget(list, cols[0], &mut state);

    // Detail pane — module-level info when a header is selected, full
    // finding detail when a finding row is selected.
    let sel = app
        .findings_state
        .selected()
        .unwrap_or(0)
        .min(rows.len().saturating_sub(1));
    let detail_text = if rows.is_empty() {
        "No findings yet. Run a scan from the Scan tab.".to_string()
    } else {
        match &rows[sel] {
            TreeRow::Header {
                module,
                finding_count,
                max_severity,
                folded,
                quiet,
            } => {
                format!(
                    "Module:      {}\nStatus:      {}\nFindings:    {}\nMax severity:{}\nFolded:      {}\n\nPress Enter / Space to {} this group.\n'o' opens all module groups, 'O' collapses all.",
                    module,
                    if *quiet { "Ran (quiet)" } else { "Ran" },
                    finding_count,
                    max_severity
                        .as_ref()
                        .map(|s| format!(" {}", s))
                        .unwrap_or_else(|| " —".into()),
                    if *folded { "yes" } else { "no" },
                    if *folded { "expand" } else { "collapse" },
                )
            }
            TreeRow::Finding { index, .. } => {
                let fnd = &app.findings[*index];
                format!(
                    "Title:       {}\nSeverity:    {}\nPlugin:      {}\nURL:         {}\nParameter:   {}\nCWE:         {}\nOWASP:       {}\nFound at:    {}\n\nDescription\n────────────\n{}\n\nEvidence\n────────────\n{}\n\nSolution\n────────────\n{}\n",
                    fnd.title,
                    fnd.severity,
                    fnd.plugin,
                    fnd.url,
                    fnd.parameter.as_deref().unwrap_or("—"),
                    fnd.cwe
                        .map(|c| format!("CWE-{}", c))
                        .unwrap_or_else(|| "—".into()),
                    fnd.owasp_category.as_deref().unwrap_or("—"),
                    fnd.found_at,
                    fnd.description,
                    fnd.evidence.as_deref().unwrap_or("—"),
                    fnd.solution,
                )
            }
        }
    };

    let detail = Paragraph::new(detail_text)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(" Finding details (PgUp/PgDn) "),
        )
        .wrap(Wrap { trim: false })
        .scroll((app.detail_scroll, 0));
    f.render_widget(detail, cols[1]);
}

fn draw_tools(f: &mut Frame, app: &App, area: Rect) {
    let cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(55), Constraint::Percentage(45)])
        .split(area);

    let items: Vec<ListItem> = app
        .tools
        .iter()
        .map(|t| {
            let badge = if t.installed { "✓" } else { "·" };
            let badge_color = if t.installed {
                Color::Green
            } else {
                Color::DarkGray
            };
            let name_color = if t.installed {
                Color::White
            } else {
                Color::DarkGray
            };
            ListItem::new(Line::from(vec![
                Span::styled(format!(" {} ", badge), Style::default().fg(badge_color)),
                Span::styled(
                    format!("{:<18}", t.name),
                    Style::default().fg(name_color).add_modifier(Modifier::BOLD),
                ),
                Span::styled(
                    format!("[{}] ", t.category),
                    Style::default().fg(Color::Yellow),
                ),
                Span::styled(t.role, Style::default().fg(Color::Gray)),
            ]))
        })
        .collect();

    let mut state = app.tools_state.clone();
    let list = List::new(items)
        .block(Block::default().borders(Borders::ALL).title(format!(
            " Integrated Tools — {}/{} installed ",
            app.tools.iter().filter(|t| t.installed).count(),
            app.tools.len()
        )))
        .highlight_style(
            Style::default()
                .bg(Color::DarkGray)
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol("▶ ");
    f.render_stateful_widget(list, cols[0], &mut state);

    let detail_lines = if let Some(idx) = app.tools_state.selected() {
        if let Some(tool) = app.tools.get(idx) {
            let mut lines = vec![
                Line::from(Span::styled(
                    tool.name.clone(),
                    Style::default()
                        .fg(Color::Yellow)
                        .add_modifier(Modifier::BOLD),
                )),
                Line::from(""),
                Line::from(format!("Command  : {}", tool.command)),
                Line::from(format!("Category : {}", tool.category)),
                Line::from(format!("Role     : {}", tool.role)),
                Line::from(format!(
                    "Status   : {}",
                    if tool.installed {
                        "installed on PATH"
                    } else {
                        "not installed"
                    }
                )),
                Line::from(format!(
                    "Needs    : {}",
                    if tool.needs_target {
                        "target URL/host"
                    } else {
                        "no target"
                    }
                )),
                Line::from(""),
                Line::from(format!(
                    "Default  : {} {}{}",
                    tool.command,
                    tool.default_args.join(" "),
                    if tool.needs_target {
                        format!(" {}", app.config.target)
                    } else {
                        String::new()
                    }
                )),
                Line::from(""),
                Line::from(Span::styled(
                    "  [r/Enter] Run    [R] Re-detect    [j/k] Navigate",
                    Style::default().fg(Color::Green),
                )),
            ];
            if let Some(active) = &app.active_tool {
                lines.push(Line::from(""));
                lines.push(Line::from(Span::styled(
                    format!("● Currently running: {}", active),
                    Style::default()
                        .fg(Color::Green)
                        .add_modifier(Modifier::BOLD),
                )));
                lines.push(Line::from(Span::styled(
                    "  Switch to Logs tab to watch output",
                    Style::default().fg(Color::DarkGray),
                )));
            }
            lines
        } else {
            vec![Line::from("No tool selected.")]
        }
    } else {
        vec![Line::from("No tool selected.")]
    };

    let detail = Paragraph::new(detail_lines)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(" Tool detail "),
        )
        .wrap(Wrap { trim: true });
    f.render_widget(detail, cols[1]);
}

fn draw_logs(f: &mut Frame, app: &App, area: Rect) {
    let total = app.logs.len() as u16;
    let height = area.height.saturating_sub(2);
    let max_scroll = total.saturating_sub(height);
    let scroll = app.log_scroll.min(max_scroll);

    let text: Vec<Line> = app
        .logs
        .iter()
        .map(|l| {
            let style = if l.contains("ERROR") {
                Style::default().fg(Color::Red)
            } else if l.contains("Finding [") {
                Style::default().fg(Color::Yellow)
            } else {
                Style::default().fg(Color::White)
            };
            Line::from(Span::styled(l.clone(), style))
        })
        .collect();

    let p = Paragraph::new(text)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(format!(" Logs ({} lines) ", total)),
        )
        .scroll((scroll, 0))
        .wrap(Wrap { trim: false });
    f.render_widget(p, area);
}

fn draw_status_bar(f: &mut Frame, app: &App, area: Rect) {
    let hints = match app.tab {
        Tab::Dashboard => "1-5/Tab: switch · q: quit",
        Tab::Scan => "t/P/o: edit · p/i: toggle · +/-/[/]: tune · s: start · x: cancel",
        Tab::Findings => {
            "j/k: nav · Enter/Space: fold · o: open-all · O: close-all · f: filter · c: clear"
        }
        Tab::Tools => "j/k: navigate · r/Enter: run · R: re-detect",
        Tab::Logs => "j/k/PgUp/PgDn: scroll · G: bottom · c: clear",
    };

    let mode_label = match app.input_mode {
        InputMode::Normal => "NORMAL",
        InputMode::EditTarget | InputMode::EditPlugins | InputMode::EditOutput => "EDIT",
    };

    let scan_label = match &app.scan_status {
        ScanStatus::Idle => "scan:idle".to_string(),
        ScanStatus::Running { phase, .. } => format!("scan:running[{}]", phase.label()),
        ScanStatus::Completed { .. } => "scan:complete".to_string(),
        ScanStatus::Failed { .. } => "scan:failed".to_string(),
    };

    let line = Line::from(vec![
        Span::styled(
            format!(" {} ", mode_label),
            Style::default()
                .fg(Color::Black)
                .bg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw("  "),
        Span::styled(
            scan_label,
            Style::default()
                .fg(Color::Green)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw("  "),
        Span::styled(hints, Style::default().fg(Color::DarkGray)),
    ]);

    let bar =
        Paragraph::new(line).block(Block::default().borders(Borders::ALL).title(" Controls "));
    f.render_widget(bar, area);
}
