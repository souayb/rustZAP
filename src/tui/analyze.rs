//! TUI repo analysis — equivalent to `rustzap analyze --repo PATH --tools native`.
//!
//! The CLI default `--tools` is `semgrep` (with native fallback when Semgrep is
//! missing). The TUI defaults to **`native`** so analysis works without extra
//! binaries. Operators can still type `semgrep,trivy,gitleaks,checkov,native`.

use std::path::Path;
use std::time::Instant;

use anyhow::Result;
use ratatui::{
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Clear, Gauge, List, ListItem, Paragraph, Wrap},
    Frame,
};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

use crate::analyze::{self, parse_tools};
use crate::report::Report;
use crate::types::{Finding, Severity};

/// TUI default `--tools` (CLI `DEFAULT_ANALYZE_TOOLS` remains `semgrep`).
pub const DEFAULT_TUI_ANALYZE_TOOLS: &str = "native";
/// Default JSON/CSV/HTML path for TUI-launched analysis.
pub const DEFAULT_ANALYZE_OUTPUT: &str = "analyze-report.json";

/// Form fields on the Analyze tab.
#[derive(Clone)]
pub struct AnalyzeForm {
    pub repo: String,
    pub tools: String,
    pub output: String,
    /// Empty string means no SARIF export.
    pub sarif_out: String,
    pub correlate: bool,
}

impl Default for AnalyzeForm {
    fn default() -> Self {
        Self {
            repo: ".".to_string(),
            tools: DEFAULT_TUI_ANALYZE_TOOLS.to_string(),
            output: DEFAULT_ANALYZE_OUTPUT.to_string(),
            sarif_out: String::new(),
            correlate: false,
        }
    }
}

impl AnalyzeForm {
    pub fn normalized_repo(&self) -> String {
        analyze::normalize_repo_input(&self.repo)
    }

    pub fn sarif_out_opt(&self) -> Option<String> {
        let t = self.sarif_out.trim();
        if t.is_empty() {
            None
        } else {
            Some(t.to_string())
        }
    }

    /// `None` when `--tools` would be rejected by the CLI parser.
    pub fn validate_tools(&self) -> Result<()> {
        parse_tools(&self.tools).map(|_| ())
    }
}

/// Live status of a TUI-launched `analyze` run (independent of DAST `ScanStatus`).
#[derive(Clone, Default)]
pub enum AnalyzeStatus {
    #[default]
    Idle,
    Running {
        repo: String,
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

impl AnalyzeStatus {
    pub fn is_running(&self) -> bool {
        matches!(self, AnalyzeStatus::Running { .. })
    }

    pub fn short_label(&self) -> String {
        match self {
            AnalyzeStatus::Idle => "analyze:idle".to_string(),
            AnalyzeStatus::Running { .. } => "analyze:running".to_string(),
            AnalyzeStatus::Completed { .. } => "analyze:complete".to_string(),
            AnalyzeStatus::Failed { .. } => "analyze:failed".to_string(),
        }
    }
}

/// Events from the background analyze task → TUI.
pub enum AnalyzeEvent {
    Started {
        repo: String,
    },
    Log(String),
    Finding(Box<Finding>),
    ModuleRan {
        name: String,
        findings: usize,
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

/// One-line consent copy shown in the TUI dialog (replaces CLI `Proceed? [y/N]`).
pub fn consent_dialog_text(abs_path: &str) -> String {
    format!("RustZAP will read files under `{abs_path}`. Only analyze repos you own. [Y]es / [N]o")
}

/// Absolute path shown in the consent dialog (same resolution as the CLI).
pub fn consent_abs_path(repo_input: &str) -> String {
    let repo = analyze::normalize_repo_input(repo_input);
    analyze::absolute_repo_path(Path::new(&repo))
        .display()
        .to_string()
}

/// `Some(true)` = proceed, `Some(false)` = cancel, `None` = ignore key.
pub fn consent_key_decision(code: crossterm::event::KeyCode) -> Option<bool> {
    match code {
        crossterm::event::KeyCode::Char('y') | crossterm::event::KeyCode::Char('Y') => Some(true),
        crossterm::event::KeyCode::Char('n')
        | crossterm::event::KeyCode::Char('N')
        | crossterm::event::KeyCode::Esc => Some(false),
        _ => None,
    }
}

/// Spawn `run_analyze` with `assume_yes: true` (caller must have accepted the dialog).
pub fn spawn_analyze(
    form: &AnalyzeForm,
    tx: mpsc::UnboundedSender<AnalyzeEvent>,
) -> JoinHandle<Result<()>> {
    let repo = form.normalized_repo();
    let tools = form.tools.clone();
    let output = form.output.clone();
    let sarif_out = form.sarif_out_opt();
    let correlate = form.correlate;

    tokio::spawn(async move {
        let started = Instant::now();
        let abs = analyze::absolute_repo_path(Path::new(&repo));
        let repo_display = abs.to_string_lossy().to_string();
        let _ = tx.send(AnalyzeEvent::Started {
            repo: repo_display.clone(),
        });
        let _ = tx.send(AnalyzeEvent::Log(format!(
            "Analyzing {repo_display} with tools {tools} (TUI default is native)"
        )));

        match analyze::run_analyze(
            repo,
            tools,
            None,
            None,
            None,
            None,
            correlate,
            output.clone(),
            sarif_out,
            true,
            true,
        )
        .await
        {
            Ok(report) => {
                emit_report_events(&tx, report, output, started.elapsed().as_secs_f64());
                Ok(())
            }
            Err(err) => {
                let msg = format!("{err:#}");
                let _ = tx.send(AnalyzeEvent::Failed { error: msg });
                Err(err)
            }
        }
    })
}

fn emit_report_events(
    tx: &mpsc::UnboundedSender<AnalyzeEvent>,
    report: Report,
    report_path: String,
    duration_secs: f64,
) {
    let findings_n = report.findings.len();
    let risk_score = report.summary.risk_score;
    for f in report.findings {
        let _ = tx.send(AnalyzeEvent::Finding(Box::new(f)));
    }
    for m in &report.modules {
        let _ = tx.send(AnalyzeEvent::ModuleRan {
            name: m.name.clone(),
            findings: m.findings,
        });
    }
    let _ = tx.send(AnalyzeEvent::Completed {
        findings: findings_n,
        risk_score,
        duration_secs,
        report_path,
    });
}

fn sev_color(sev: &Severity) -> Color {
    match sev {
        Severity::Critical => Color::Magenta,
        Severity::High => Color::Red,
        Severity::Medium => Color::Yellow,
        Severity::Low => Color::Cyan,
        Severity::Info => Color::Blue,
    }
}

/// Analyze tab: config form (left) + live status (right).
pub fn draw_analyze(
    f: &mut Frame,
    area: Rect,
    form: &AnalyzeForm,
    status: &AnalyzeStatus,
    findings: &[Finding],
    edit: Option<(&str, &str)>,
) {
    let cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(48), Constraint::Percentage(52)])
        .split(area);

    let correlate_label = if form.correlate { "ON" } else { "OFF" };
    let sarif_label = if form.sarif_out.trim().is_empty() {
        "(none)".to_string()
    } else {
        form.sarif_out.clone()
    };

    let mut lines: Vec<Line> = vec![
        Line::from(Span::styled(
            " Analyze repository",
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        )),
        Line::from(Span::styled(
            " Equivalent to: rustzap analyze --repo PATH --tools native --yes",
            Style::default().fg(Color::DarkGray),
        )),
        Line::from(""),
        Line::from(vec![
            Span::styled("  [r] Repo path   ", Style::default().fg(Color::Cyan)),
            Span::raw(form.repo.clone()),
        ]),
        Line::from(vec![
            Span::styled("  [t] Tools       ", Style::default().fg(Color::Cyan)),
            Span::raw(form.tools.clone()),
        ]),
        Line::from(vec![
            Span::styled("  [o] Output      ", Style::default().fg(Color::Cyan)),
            Span::raw(form.output.clone()),
        ]),
        Line::from(vec![
            Span::styled("  [S] SARIF out   ", Style::default().fg(Color::Cyan)),
            Span::raw(sarif_label),
        ]),
        Line::from(vec![
            Span::styled("  [c] Correlate   ", Style::default().fg(Color::Cyan)),
            Span::raw(correlate_label),
        ]),
        Line::from(""),
        Line::from(Span::styled(
            "  Tools: native (default), semgrep, trivy, gitleaks, checkov",
            Style::default().fg(Color::DarkGray),
        )),
        Line::from(""),
        Line::from(Span::styled(
            "  [s] Start analyze    [x] Cancel",
            Style::default()
                .fg(Color::Green)
                .add_modifier(Modifier::BOLD),
        )),
    ];

    if let Some((label, buffer)) = edit {
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            format!(" ▶ {label}"),
            Style::default().fg(Color::Yellow),
        )));
        lines.push(Line::from(vec![
            Span::styled(" › ", Style::default().fg(Color::Yellow)),
            Span::styled(
                format!("{buffer}▌"),
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

    let form_widget = Paragraph::new(lines)
        .block(Block::default().borders(Borders::ALL).title(" Config "))
        .wrap(Wrap { trim: false });
    f.render_widget(form_widget, cols[0]);

    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(5),
            Constraint::Length(3),
            Constraint::Min(1),
        ])
        .split(cols[1]);

    let (ratio, header) = match status {
        AnalyzeStatus::Idle => (
            0.0,
            "Idle — set repo path and press 's' (consent dialog before walk)".to_string(),
        ),
        AnalyzeStatus::Running { repo, started_at } => {
            let elapsed = started_at.elapsed().as_secs_f64();
            (
                (elapsed / 45.0).clamp(0.05, 0.9),
                format!("Analyzing {repo} · elapsed={elapsed:.1}s"),
            )
        }
        AnalyzeStatus::Completed {
            findings,
            duration_secs,
            risk_score,
            report_path,
        } => (
            1.0,
            format!("Completed · {findings} findings · risk={risk_score} · {duration_secs:.1}s · → {report_path}"),
        ),
        AnalyzeStatus::Failed { error } => (0.0, format!("Failed: {error}")),
    };

    let title = Paragraph::new(header).wrap(Wrap { trim: true }).block(
        Block::default()
            .borders(Borders::ALL)
            .title(" Live status "),
    );
    f.render_widget(title, rows[0]);

    let gauge = Gauge::default()
        .block(Block::default().borders(Borders::ALL).title(" Progress "))
        .gauge_style(Style::default().fg(Color::Yellow))
        .ratio(ratio);
    f.render_widget(gauge, rows[1]);

    let preview_items: Vec<ListItem> = findings
        .iter()
        .rev()
        .take(50)
        .map(|fnd| {
            ListItem::new(Line::from(vec![
                Span::styled(
                    format!("[{:<8}]", fnd.severity),
                    Style::default().fg(sev_color(&fnd.severity)),
                ),
                Span::raw(" "),
                Span::raw(fnd.title.clone()),
            ]))
        })
        .collect();
    let preview = List::new(preview_items).block(
        Block::default()
            .borders(Borders::ALL)
            .title(" Findings (this run) "),
    );
    f.render_widget(preview, rows[2]);
}

/// Modal confirmation before walking the repo (replaces stdin `y/N`).
pub fn draw_consent_dialog(f: &mut Frame, abs_path: &str) {
    let area = centered_rect(72, 36, f.area());
    f.render_widget(Clear, area);
    let text = vec![
        Line::from(""),
        Line::from(Span::styled(
            consent_dialog_text(abs_path),
            Style::default().fg(Color::White),
        )),
        Line::from(""),
        Line::from("Inventory, secret/sink heuristics, and any selected tools will run."),
        Line::from(""),
        Line::from(Span::styled(
            "[Y]es, proceed          [N]o / Esc cancel",
            Style::default()
                .fg(Color::Green)
                .add_modifier(Modifier::BOLD),
        )),
    ];
    let p = Paragraph::new(text)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Yellow))
                .title(" Repo access "),
        )
        .wrap(Wrap { trim: true })
        .alignment(Alignment::Center);
    f.render_widget(p, area);
}

fn centered_rect(percent_x: u16, percent_y: u16, r: Rect) -> Rect {
    let popup_layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage((100 - percent_y) / 2),
            Constraint::Percentage(percent_y),
            Constraint::Percentage((100 - percent_y) / 2),
        ])
        .split(r);
    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - percent_x) / 2),
            Constraint::Percentage(percent_x),
            Constraint::Percentage((100 - percent_x) / 2),
        ])
        .split(popup_layout[1])[1]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyze::AnalyzeTool;
    use crossterm::event::KeyCode;

    #[test]
    fn default_form_matches_tui_native_contract() {
        let form = AnalyzeForm::default();
        assert_eq!(form.repo, ".");
        assert_eq!(form.tools, "native");
        assert_eq!(form.output, "analyze-report.json");
        assert!(form.sarif_out.is_empty());
        assert!(!form.correlate);
        assert!(form.sarif_out_opt().is_none());
        form.validate_tools().expect("native is a valid tool spec");
        let tools = parse_tools(&form.tools).expect("parse");
        assert_eq!(tools, vec![AnalyzeTool::Native]);
    }

    #[test]
    fn empty_repo_normalizes_to_dot() {
        let form = AnalyzeForm {
            repo: "  ".into(),
            ..AnalyzeForm::default()
        };
        assert_eq!(form.normalized_repo(), ".");
    }

    #[test]
    fn sarif_out_opt_trims_and_skips_empty() {
        let blank = AnalyzeForm {
            sarif_out: "  ".into(),
            ..AnalyzeForm::default()
        };
        assert!(blank.sarif_out_opt().is_none());
        let set = AnalyzeForm {
            sarif_out: " out.sarif ".into(),
            ..AnalyzeForm::default()
        };
        assert_eq!(set.sarif_out_opt().as_deref(), Some("out.sarif"));
    }

    #[test]
    fn reject_unknown_tools() {
        let form = AnalyzeForm {
            tools: "not-a-tool".into(),
            ..AnalyzeForm::default()
        };
        assert!(form.validate_tools().is_err());
    }

    #[test]
    fn consent_text_includes_path_and_yes_no() {
        let text = consent_dialog_text("/abs/repo");
        assert!(text.contains("/abs/repo"));
        assert!(text.contains("[Y]es"));
        assert!(text.contains("[N]o"));
        assert!(text.contains("own"));
    }

    #[test]
    fn consent_abs_path_is_absolute() {
        let p = consent_abs_path(".");
        assert!(
            std::path::Path::new(&p).is_absolute(),
            "expected absolute path, got {p}"
        );
    }

    #[test]
    fn consent_keys_yes_no_esc() {
        assert_eq!(consent_key_decision(KeyCode::Char('y')), Some(true));
        assert_eq!(consent_key_decision(KeyCode::Char('Y')), Some(true));
        assert_eq!(consent_key_decision(KeyCode::Char('n')), Some(false));
        assert_eq!(consent_key_decision(KeyCode::Char('N')), Some(false));
        assert_eq!(consent_key_decision(KeyCode::Esc), Some(false));
        assert_eq!(consent_key_decision(KeyCode::Char('s')), None);
        assert_eq!(consent_key_decision(KeyCode::Enter), None);
    }

    #[test]
    fn analyze_status_running_flag() {
        assert!(!AnalyzeStatus::Idle.is_running());
        assert!(AnalyzeStatus::Running {
            repo: "/tmp".into(),
            started_at: Instant::now(),
        }
        .is_running());
        assert_eq!(AnalyzeStatus::Idle.short_label(), "analyze:idle");
    }
}
