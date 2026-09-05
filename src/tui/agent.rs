//! TUI agentic tester — a front-end for `rustzap agent`.
//!
//! The CLI agent drives an LLM (or scripted) brain under a mandatory scope file.
//! A raw-mode TUI cannot service the CLI's interactive approval prompt, so this
//! tab runs **non-interactively** with a deterministic scripted brain in one of
//! two modes — Recon (scan + static analysis) or Red-team (OWASP LLM Top-10) —
//! each gated by a consent dialog. The LLM brain stays CLI/MCP-only.

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
use serde_json::json;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

use crate::agent::brain::{AgentAction, AgentBrain, ScriptedBrain};
use crate::agent::scope::{Autonomy, ScopeConfig};
use crate::agent::{run_agent, AgentConfig};
use crate::report::Report;
use crate::types::{Finding, Severity};

/// Default report path for TUI-launched agent runs.
pub const DEFAULT_AGENT_OUTPUT: &str = "agent-report.json";
/// Trace file for TUI-launched agent runs.
pub const AGENT_TRACE_PATH: &str = "agent-trace.jsonl";

/// The scripted brain the TUI runs (no live LLM; that stays CLI/MCP-only).
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum BrainKind {
    /// scan_target (if target) + analyze_repo/get_attack_plan (if repo).
    Recon,
    /// ai_redteam OWASP LLM Top-10 battery against the target chat endpoint.
    Redteam,
}

impl BrainKind {
    pub fn label(self) -> &'static str {
        match self {
            BrainKind::Recon => "recon (scan + analyze)",
            BrainKind::Redteam => "red-team (OWASP LLM Top-10)",
        }
    }

    pub fn next(self) -> BrainKind {
        match self {
            BrainKind::Recon => BrainKind::Redteam,
            BrainKind::Redteam => BrainKind::Recon,
        }
    }
}

/// Cycle the autonomy mode for the toggle key.
pub fn autonomy_next(a: Autonomy) -> Autonomy {
    match a {
        Autonomy::Assisted => Autonomy::Semi,
        Autonomy::Semi => Autonomy::Auto,
        Autonomy::Auto => Autonomy::Assisted,
    }
}

pub fn autonomy_label(a: Autonomy) -> &'static str {
    match a {
        Autonomy::Assisted => "assisted",
        Autonomy::Semi => "semi",
        Autonomy::Auto => "auto",
    }
}

/// Form fields on the Agent tab.
#[derive(Clone)]
pub struct AgentForm {
    pub scope: String,
    pub target: String,
    pub repo: String,
    pub autonomy: Autonomy,
    pub brain: BrainKind,
    pub output: String,
}

impl Default for AgentForm {
    fn default() -> Self {
        Self {
            scope: "scope.yaml".to_string(),
            target: String::new(),
            repo: String::new(),
            autonomy: Autonomy::Assisted,
            brain: BrainKind::Recon,
            output: DEFAULT_AGENT_OUTPUT.to_string(),
        }
    }
}

impl AgentForm {
    fn opt(s: &str) -> Option<String> {
        let t = s.trim();
        if t.is_empty() {
            None
        } else {
            Some(t.to_string())
        }
    }

    pub fn target_opt(&self) -> Option<String> {
        Self::opt(&self.target)
    }

    pub fn repo_opt(&self) -> Option<String> {
        Self::opt(&self.repo)
    }

    /// Reject a form that can't produce a run (mirrors the CLI's requirements).
    pub fn validate(&self) -> Result<()> {
        if self.scope.trim().is_empty() {
            anyhow::bail!("a scope file is required (press 'c' to set it)");
        }
        match self.brain {
            BrainKind::Recon if self.target_opt().is_none() && self.repo_opt().is_none() => {
                anyhow::bail!("recon needs a target URL or a repo path")
            }
            BrainKind::Redteam if self.target_opt().is_none() => {
                anyhow::bail!("red-team needs a target chat-completions URL")
            }
            _ => Ok(()),
        }
    }
}

/// Live status of a TUI-launched agent run.
#[derive(Clone, Default)]
pub enum AgentStatus {
    #[default]
    Idle,
    Running {
        label: String,
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

impl AgentStatus {
    pub fn is_running(&self) -> bool {
        matches!(self, AgentStatus::Running { .. })
    }

    pub fn short_label(&self) -> String {
        match self {
            AgentStatus::Idle => "agent:idle".to_string(),
            AgentStatus::Running { .. } => "agent:running".to_string(),
            AgentStatus::Completed { .. } => "agent:complete".to_string(),
            AgentStatus::Failed { .. } => "agent:failed".to_string(),
        }
    }
}

/// Events from the background agent task → TUI.
pub enum AgentEvent {
    Started {
        label: String,
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

/// One-line consent copy shown before an agent run (the agent touches the
/// network / reads a repo, so consent is explicit — as on the Analyze tab).
pub fn consent_dialog_text(form: &AgentForm) -> String {
    let dest = form
        .target_opt()
        .or_else(|| form.repo_opt())
        .unwrap_or_else(|| "the scope".to_string());
    format!(
        "RustZAP agent [{}] will act against `{dest}` under scope `{}` (autonomy={}). \
         Only test assets you own. [Y]es / [N]o",
        form.brain.label(),
        form.scope,
        autonomy_label(form.autonomy),
    )
}

/// Build the scripted plan for a brain kind (empty if the form is unusable).
fn plan_for(brain: BrainKind, target: Option<&str>, repo: Option<&str>) -> Vec<AgentAction> {
    let mut steps = Vec::new();
    match brain {
        BrainKind::Recon => {
            if let Some(t) = target {
                steps.push(AgentAction::CallTool {
                    tool: "scan_target".into(),
                    args: json!({ "target": t }),
                });
            }
            if let Some(r) = repo {
                steps.push(AgentAction::CallTool {
                    tool: "analyze_repo".into(),
                    args: json!({ "path": r, "tools": "native" }),
                });
                steps.push(AgentAction::CallTool {
                    tool: "get_attack_plan".into(),
                    args: json!({ "path": r }),
                });
            }
            steps.push(AgentAction::Finish {
                summary: "recon complete".into(),
            });
        }
        BrainKind::Redteam => {
            if let Some(t) = target {
                steps.push(AgentAction::CallTool {
                    tool: "ai_redteam".into(),
                    args: json!({ "endpoint": t }),
                });
            }
            steps.push(AgentAction::Finish {
                summary: "red-team battery complete".into(),
            });
        }
    }
    steps
}

/// Spawn the agent run (caller must have accepted the consent dialog).
pub fn spawn_agent(
    form: &AgentForm,
    tx: mpsc::UnboundedSender<AgentEvent>,
) -> JoinHandle<Result<()>> {
    let scope_path = form.scope.trim().to_string();
    let target = form.target_opt();
    let repo = form.repo_opt();
    let autonomy = form.autonomy;
    let brain_kind = form.brain;
    let output = form.output.clone();
    let label = brain_kind.label().to_string();

    tokio::spawn(async move {
        let started = Instant::now();
        let _ = tx.send(AgentEvent::Started {
            label: label.clone(),
        });

        let mut scope = match ScopeConfig::load(Path::new(&scope_path)) {
            Ok(s) => s,
            Err(err) => {
                let _ = tx.send(AgentEvent::Failed {
                    error: format!("scope file: {err:#}"),
                });
                return Err(err);
            }
        };
        scope.set_autonomy(autonomy);

        let steps = plan_for(brain_kind, target.as_deref(), repo.as_deref());
        // Red-team is an Exploit-class action; selecting that mode + accepting
        // the consent dialog IS the approval (same rule as the CLI --ai-redteam).
        let auto_approve = brain_kind == BrainKind::Redteam;
        let brain: Box<dyn AgentBrain> = Box::new(ScriptedBrain::new(steps));

        let _ = tx.send(AgentEvent::Log(format!(
            "agent [{label}] scope={scope_path} autonomy={}",
            autonomy_label(autonomy)
        )));

        let cfg = AgentConfig {
            scope,
            goal: format!("TUI agent run ({label})"),
            target,
            repo,
            output: output.clone(),
            sarif_out: None,
            trace_path: AGENT_TRACE_PATH.to_string(),
            non_interactive: true,
            auto_approve,
            safety: crate::safety::SafetyPolicy::default(),
            autofix_dir: None,
        };

        match run_agent(cfg, brain).await {
            Ok(report) => {
                emit_report_events(&tx, report, output, started.elapsed().as_secs_f64());
                Ok(())
            }
            Err(err) => {
                let _ = tx.send(AgentEvent::Failed {
                    error: format!("{err:#}"),
                });
                Err(err)
            }
        }
    })
}

fn emit_report_events(
    tx: &mpsc::UnboundedSender<AgentEvent>,
    report: Report,
    report_path: String,
    duration_secs: f64,
) {
    let findings_n = report.findings.len();
    let risk_score = report.summary.risk_score;
    for f in report.findings {
        let _ = tx.send(AgentEvent::Finding(Box::new(f)));
    }
    for m in &report.modules {
        let _ = tx.send(AgentEvent::ModuleRan {
            name: m.name.clone(),
            findings: m.findings,
        });
    }
    let _ = tx.send(AgentEvent::Completed {
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

/// Agent tab: config form (left) + live status (right).
pub fn draw_agent(
    f: &mut Frame,
    area: Rect,
    form: &AgentForm,
    status: &AgentStatus,
    findings: &[Finding],
    edit: Option<(&str, &str)>,
) {
    let cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(48), Constraint::Percentage(52)])
        .split(area);

    let target_label = if form.target.trim().is_empty() {
        "(none)".to_string()
    } else {
        form.target.clone()
    };
    let repo_label = if form.repo.trim().is_empty() {
        "(none)".to_string()
    } else {
        form.repo.clone()
    };

    let mut lines: Vec<Line> = vec![
        Line::from(Span::styled(
            " Agentic tester",
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        )),
        Line::from(Span::styled(
            " Scope-gated agent · non-interactive · scripted brain (LLM brain is CLI/MCP)",
            Style::default().fg(Color::DarkGray),
        )),
        Line::from(""),
        Line::from(vec![
            Span::styled("  [c] Scope file  ", Style::default().fg(Color::Cyan)),
            Span::raw(form.scope.clone()),
        ]),
        Line::from(vec![
            Span::styled("  [t] Target URL  ", Style::default().fg(Color::Cyan)),
            Span::raw(target_label),
        ]),
        Line::from(vec![
            Span::styled("  [r] Repo path   ", Style::default().fg(Color::Cyan)),
            Span::raw(repo_label),
        ]),
        Line::from(vec![
            Span::styled("  [b] Brain       ", Style::default().fg(Color::Cyan)),
            Span::raw(form.brain.label().to_string()),
        ]),
        Line::from(vec![
            Span::styled("  [u] Autonomy    ", Style::default().fg(Color::Cyan)),
            Span::raw(autonomy_label(form.autonomy).to_string()),
        ]),
        Line::from(vec![
            Span::styled("  [o] Output      ", Style::default().fg(Color::Cyan)),
            Span::raw(form.output.clone()),
        ]),
        Line::from(""),
        Line::from(Span::styled(
            "  Recon → scan_target + analyze_repo · Red-team → OWASP LLM Top-10",
            Style::default().fg(Color::DarkGray),
        )),
        Line::from(""),
        Line::from(Span::styled(
            "  [s] Start agent    [x] Cancel",
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
        AgentStatus::Idle => (
            0.0,
            "Idle — set scope + target/repo and press 's' (consent dialog first)".to_string(),
        ),
        AgentStatus::Running { label, started_at } => {
            let elapsed = started_at.elapsed().as_secs_f64();
            (
                (elapsed / 45.0).clamp(0.05, 0.9),
                format!("Running {label} · elapsed={elapsed:.1}s"),
            )
        }
        AgentStatus::Completed {
            findings,
            duration_secs,
            risk_score,
            report_path,
        } => (
            1.0,
            format!("Completed · {findings} findings · risk={risk_score} · {duration_secs:.1}s · → {report_path}"),
        ),
        AgentStatus::Failed { error } => (0.0, format!("Failed: {error}")),
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

/// Modal confirmation before an agent run (mirrors the Analyze consent dialog).
pub fn draw_consent_dialog(f: &mut Frame, form: &AgentForm) {
    let area = centered_rect(74, 38, f.area());
    f.render_widget(Clear, area);
    let text = vec![
        Line::from(""),
        Line::from(Span::styled(
            consent_dialog_text(form),
            Style::default().fg(Color::White),
        )),
        Line::from(""),
        Line::from("The run is scope-gated and non-interactive; gated actions are auto-denied"),
        Line::from("unless autonomy allows them (red-team is pre-approved by this dialog)."),
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
                .title(" Agent run "),
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

    #[test]
    fn default_form_is_recon_assisted() {
        let form = AgentForm::default();
        assert_eq!(form.scope, "scope.yaml");
        assert!(form.target.is_empty());
        assert_eq!(form.output, "agent-report.json");
        assert!(matches!(form.brain, BrainKind::Recon));
        assert!(matches!(form.autonomy, Autonomy::Assisted));
    }

    #[test]
    fn validate_requires_scope_and_a_destination() {
        // Recon with neither target nor repo is invalid.
        let mut form = AgentForm::default();
        assert!(form.validate().is_err());
        form.repo = ".".into();
        assert!(form.validate().is_ok());

        // Red-team needs a target endpoint specifically.
        form.repo.clear();
        form.brain = BrainKind::Redteam;
        assert!(form.validate().is_err());
        form.target = "http://localhost:3000/v1/chat/completions".into();
        assert!(form.validate().is_ok());

        // Empty scope always fails.
        form.scope = "  ".into();
        assert!(form.validate().is_err());
    }

    #[test]
    fn autonomy_and_brain_cycle() {
        assert!(matches!(autonomy_next(Autonomy::Assisted), Autonomy::Semi));
        assert!(matches!(autonomy_next(Autonomy::Semi), Autonomy::Auto));
        assert!(matches!(autonomy_next(Autonomy::Auto), Autonomy::Assisted));
        assert!(matches!(BrainKind::Recon.next(), BrainKind::Redteam));
        assert!(matches!(BrainKind::Redteam.next(), BrainKind::Recon));
    }

    #[test]
    fn recon_plan_reflects_target_and_repo() {
        // target-only → scan_target + finish
        let steps = plan_for(BrainKind::Recon, Some("http://x"), None);
        assert_eq!(steps.len(), 2);
        assert!(matches!(&steps[0], AgentAction::CallTool { tool, .. } if tool == "scan_target"));

        // repo-only → analyze_repo + get_attack_plan + finish
        let steps = plan_for(BrainKind::Recon, None, Some("."));
        assert_eq!(steps.len(), 3);
        assert!(matches!(&steps[0], AgentAction::CallTool { tool, .. } if tool == "analyze_repo"));

        // both → scan + analyze + attack_plan + finish
        let steps = plan_for(BrainKind::Recon, Some("http://x"), Some("."));
        assert_eq!(steps.len(), 4);
    }

    #[test]
    fn redteam_plan_calls_ai_redteam() {
        let steps = plan_for(BrainKind::Redteam, Some("http://x/v1"), None);
        assert!(matches!(&steps[0], AgentAction::CallTool { tool, .. } if tool == "ai_redteam"));
        assert!(matches!(steps.last(), Some(AgentAction::Finish { .. })));
    }

    #[test]
    fn consent_text_names_target_scope_and_brain() {
        let form = AgentForm {
            target: "http://app.local".into(),
            ..AgentForm::default()
        };
        let text = consent_dialog_text(&form);
        assert!(text.contains("http://app.local"));
        assert!(text.contains("scope.yaml"));
        assert!(text.contains("recon"));
        assert!(text.contains("[Y]es"));
    }

    #[test]
    fn status_running_flag_and_label() {
        assert!(!AgentStatus::Idle.is_running());
        assert!(AgentStatus::Running {
            label: "recon".into(),
            started_at: Instant::now(),
        }
        .is_running());
        assert_eq!(AgentStatus::Idle.short_label(), "agent:idle");
    }
}
