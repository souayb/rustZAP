//! TUI agentic tester — a front-end for `rustzap agent`.
//!
//! Live LLM and scripted workflows share the same scope-gated agent loop.
//! API keys entered here stay in memory and are passed directly to the HTTP
//! client. They are never added to prompts, command arguments, or saved config.

use std::path::Path;
use std::time::Instant;

use anyhow::{Context, Result};
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

use crate::agent::brain::{AgentAction, AgentBrain, LlmBrain, ScriptedBrain};
use crate::agent::scope::{Autonomy, ScopeConfig};
use crate::agent::{run_agent, AgentConfig};
use crate::report::Report;
use crate::types::{Finding, Severity};

/// Default report path for TUI-launched agent runs.
pub const DEFAULT_AGENT_OUTPUT: &str = "agent-report.json";
/// Trace file for TUI-launched agent runs.
pub const AGENT_TRACE_PATH: &str = "agent-trace.jsonl";

/// Available agent workflows.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum BrainKind {
    Llm,
    /// scan_target (if target) + analyze_repo/get_attack_plan (if repo).
    Recon,
    /// ai_redteam OWASP LLM Top-10 battery against the target chat endpoint.
    Redteam,
}

impl BrainKind {
    pub fn label(self) -> &'static str {
        match self {
            BrainKind::Llm => "LLM (live)",
            BrainKind::Recon => "recon (scan + analyze)",
            BrainKind::Redteam => "red-team (OWASP LLM Top-10)",
        }
    }

    pub fn next(self) -> BrainKind {
        match self {
            BrainKind::Llm => BrainKind::Recon,
            BrainKind::Recon => BrainKind::Redteam,
            BrainKind::Redteam => BrainKind::Llm,
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
    pub goal: String,
    pub model: String,
    pub base_url: String,
    /// Session-only credential. Deliberately no Debug/Serialize implementation.
    pub api_key: String,
    /// Model name the *target* application is asked to run (red-team only).
    /// Distinct from `model`, which is the agent's own brain.
    pub target_model: String,
    /// Name of the environment variable holding the *target's* bearer token.
    /// The name, never the secret: `ai_redteam` resolves it at request time, so
    /// a target credential is never held in the form alongside the agent's.
    pub target_key_env: String,
    /// Operator-known phrase from the target's system prompt. Without it the
    /// leak probes — the only self-proving ones — cannot fire.
    pub target_marker: String,
    /// Times to repeat each probe variant. Above 1 the run reports an attack
    /// success rate instead of a single pass/fail.
    pub generations: u32,
    /// Prompt mutators to also try, comma-separated or `all`. Empty by default:
    /// each one multiplies the request volume against an intrusive endpoint.
    pub mutators: String,
}

impl Default for AgentForm {
    fn default() -> Self {
        Self {
            scope: "scope.yaml".to_string(),
            target: String::new(),
            repo: String::new(),
            autonomy: Autonomy::Assisted,
            brain: BrainKind::Llm,
            output: DEFAULT_AGENT_OUTPUT.to_string(),
            goal: String::new(),
            model: String::new(),
            base_url: String::new(),
            api_key: String::new(),
            target_model: String::new(),
            target_key_env: String::new(),
            target_marker: String::new(),
            generations: 1,
            mutators: String::new(),
        }
    }
}

/// Sample sizes offered by the generations toggle. Small on purpose: every
/// generation is a live request against someone's application.
const GENERATION_STEPS: [u32; 4] = [1, 3, 5, 10];

/// Next sample size in the cycle.
pub fn generations_next(current: u32) -> u32 {
    let idx = GENERATION_STEPS.iter().position(|g| *g == current);
    match idx {
        Some(i) => GENERATION_STEPS[(i + 1) % GENERATION_STEPS.len()],
        None => GENERATION_STEPS[0],
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
            BrainKind::Recon | BrainKind::Llm
                if self.target_opt().is_none() && self.repo_opt().is_none() =>
            {
                anyhow::bail!("agent needs a target URL or a repo path")
            }
            BrainKind::Redteam if self.target_opt().is_none() => {
                anyhow::bail!("red-team needs a target chat-completions URL")
            }
            BrainKind::Redteam => {
                if let Some(list) = Self::opt(&self.mutators) {
                    crate::agent::redteam::Mutator::parse_list(&list)
                        .map_err(|e| anyhow::anyhow!(e))?;
                }
                self.validate_target_key()
            }
            _ => Ok(()),
        }
    }

    /// A key env var that resolves to nothing yields a run where every probe is
    /// unevaluated; fail now with the reason instead.
    fn validate_target_key(&self) -> Result<()> {
        match Self::opt(&self.target_key_env) {
            Some(name)
                if std::env::var(&name)
                    .ok()
                    .filter(|v| !v.trim().is_empty())
                    .is_none() =>
            {
                anyhow::bail!(
                    "target key env var `{name}` is unset or empty \
                     (export it before starting, or clear it with [A])"
                )
            }
            _ => Ok(()),
        }
    }
}

/// Resolve UI overrides before scope defaults. Never persist the supplied key.
fn llm_brain(form: &AgentForm, scope: &ScopeConfig) -> Result<LlmBrain> {
    let model = AgentForm::opt(&form.model)
        .or_else(|| scope.model.model.clone())
        .context("Set the LLM model with [m], or model.model in the scope file")?;
    let base = AgentForm::opt(&form.base_url)
        .or_else(|| scope.model.base_url.clone())
        .unwrap_or_else(|| crate::agent::DEFAULT_LLM_BASE_URL.into());
    let parsed = url::Url::parse(&base).context("Invalid LLM API URL; edit it with [e]")?;
    anyhow::ensure!(
        matches!(parsed.scheme(), "http" | "https") && parsed.host_str().is_some(),
        "LLM API URL must use http or https"
    );
    let key = match AgentForm::opt(&form.api_key) {
        Some(key) => Some(key),
        None => match scope.model.api_key_env.as_deref() {
            Some(name) => Some(
                std::env::var(name)
                    .ok()
                    .filter(|s| !s.trim().is_empty())
                    .context(
                    "The scope's API-key environment variable is unavailable; enter a key with [k]",
                )?,
            ),
            None => None,
        },
    };
    let vault = crate::agent::build_vault(
        scope.privacy,
        &scope.allowed_hosts,
        form.target_opt().as_deref(),
    );
    Ok(
        LlmBrain::with_vault(&base, &model, key, scope.model.json_mode, vault)
            .with_options(scope.model.limits.clone())?
            .with_token_budget(scope.budget.max_tokens),
    )
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
fn plan_for(form: &AgentForm) -> Vec<AgentAction> {
    let brain = form.brain;
    let target = form.target_opt();
    let target = target.as_deref();
    let repo = form.repo_opt();
    let repo = repo.as_deref();
    let mut steps = Vec::new();
    match brain {
        BrainKind::Llm => {}
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
                // Target-side config: model, credential env var, and the system
                // marker. Omitting any of these silently weakens the battery,
                // so they are forwarded whenever the operator supplied them.
                let mut args = json!({ "endpoint": t });
                if let Some(m) = AgentForm::opt(&form.target_model) {
                    args["model"] = json!(m);
                }
                if let Some(e) = AgentForm::opt(&form.target_key_env) {
                    args["api_key_env"] = json!(e);
                }
                if let Some(m) = AgentForm::opt(&form.target_marker) {
                    args["system_marker"] = json!(m);
                }
                if form.generations > 1 {
                    args["generations"] = json!(form.generations);
                }
                if let Some(m) = AgentForm::opt(&form.mutators) {
                    args["mutators"] = json!(m);
                }
                steps.push(AgentAction::CallTool {
                    tool: "ai_redteam".into(),
                    args,
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
    let form = form.clone();
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

        let steps = plan_for(&form);
        // Red-team is an Exploit-class action; selecting that mode + accepting
        // the consent dialog IS the approval (same rule as the CLI --ai-redteam).
        let auto_approve = brain_kind == BrainKind::Redteam;
        let brain: Box<dyn AgentBrain> = if brain_kind == BrainKind::Llm {
            match llm_brain(&form, &scope) {
                Ok(brain) => Box::new(brain),
                Err(error) => {
                    let _ = tx.send(AgentEvent::Failed {
                        error: error.to_string(),
                    });
                    return Err(error);
                }
            }
        } else {
            Box::new(ScriptedBrain::new(steps))
        };

        let _ = tx.send(AgentEvent::Log(format!(
            "agent [{label}] scope={scope_path} autonomy={}",
            autonomy_label(autonomy)
        )));

        let cfg = AgentConfig {
            scope,
            goal: AgentForm::opt(&form.goal).unwrap_or_else(|| {
                format!(
                    "Assess {} for security issues",
                    target
                        .as_deref()
                        .or(repo.as_deref())
                        .unwrap_or("the supplied scope")
                )
            }),
            target,
            repo,
            output: output.clone(),
            sarif_out: None,
            trace_path: Path::new(&output)
                .parent()
                .unwrap_or_else(|| Path::new("."))
                .join(AGENT_TRACE_PATH)
                .to_string_lossy()
                .into_owned(),
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
    edit: Option<(&str, &str, bool)>,
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

    let inherited = |value: &str| {
        if value.trim().is_empty() {
            "(from scope)".to_string()
        } else {
            value.to_string()
        }
    };
    let mut lines = vec![Line::from(Span::styled(
        " Agentic tester",
        Style::default()
            .fg(Color::Yellow)
            .add_modifier(Modifier::BOLD),
    ))];
    for (label, value) in [
        ("[c] Scope", form.scope.clone()),
        ("[t] Target", target_label),
        ("[r] Repo", repo_label),
        ("[b] Brain", form.brain.label().into()),
        ("[u] Autonomy", autonomy_label(form.autonomy).into()),
        (
            "[g] Goal",
            if form.goal.is_empty() {
                "Assess target/repo".into()
            } else {
                form.goal.clone()
            },
        ),
        (
            "[e] Agent API URL",
            if form.base_url.is_empty() {
                "Scope / local Ollama".into()
            } else {
                form.base_url.clone()
            },
        ),
        ("[m] Agent model", inherited(&form.model)),
        (
            "[k] Agent API key",
            if form.api_key.is_empty() {
                "Scope env / keyless".into()
            } else {
                "******** (set)".into()
            },
        ),
        ("[o] Output", form.output.clone()),
    ] {
        lines.push(Line::from(vec![
            Span::styled(format!(" {label:<18}"), Style::default().fg(Color::Cyan)),
            Span::raw(value),
        ]));
    }

    // The application under test is configured separately from the agent's own
    // brain: a different model, a different credential, its own system prompt.
    if form.brain == BrainKind::Redteam {
        lines.push(Line::from(Span::styled(
            " Target AI application",
            Style::default().fg(Color::Yellow),
        )));
        for (label, value) in [
            (
                "[M] Target model",
                if form.target_model.is_empty() {
                    "Tool default (gpt-4o-mini)".into()
                } else {
                    form.target_model.clone()
                },
            ),
            (
                "[A] Target key env",
                if form.target_key_env.is_empty() {
                    "Keyless".into()
                } else {
                    format!("${}", form.target_key_env)
                },
            ),
            (
                "[P] System marker",
                if form.target_marker.is_empty() {
                    "Unset — leak probes disabled".into()
                } else {
                    "******** (set)".into()
                },
            ),
            (
                "[G] Generations",
                if form.generations > 1 {
                    format!("{} (reports success rate)", form.generations)
                } else {
                    "1 (single pass/fail)".into()
                },
            ),
            (
                "[X] Mutators",
                if form.mutators.is_empty() {
                    "None (plain prompts only)".into()
                } else {
                    form.mutators.clone()
                },
            ),
        ] {
            lines.push(Line::from(vec![
                Span::styled(format!(" {label:<18}"), Style::default().fg(Color::Cyan)),
                Span::raw(value),
            ]));
        }
    }
    lines.push(Line::from(Span::styled(
        " Key: session only · [K] clear",
        Style::default().fg(Color::DarkGray),
    )));
    lines.push(Line::from(Span::styled(
        " [s] Start agent · [x] Cancel",
        Style::default().fg(Color::Green),
    )));

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
    if let Some((label, buffer, secret)) = edit {
        let area = centered_rect(85, 40, f.area());
        f.render_widget(Clear, area);
        let text = if secret {
            "*".repeat(buffer.chars().count())
        } else {
            buffer.to_string()
        };
        let visible: String = text
            .chars()
            .rev()
            .take(area.width.saturating_sub(6) as usize)
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
            .collect();
        let mut lines = vec![
            Line::from(format!(" {visible}▌")),
            Line::from(""),
            Line::from(" Enter: save · Esc: cancel · Ctrl+U: clear"),
        ];
        if secret {
            lines.push(Line::from(" Kept in memory for this session only."));
        }
        f.render_widget(
            Paragraph::new(lines)
                .block(Block::default().borders(Borders::ALL).title(label))
                .wrap(Wrap { trim: false }),
            area,
        );
    }
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
    fn default_form_is_llm_assisted() {
        let form = AgentForm::default();
        assert_eq!(form.scope, "scope.yaml");
        assert!(form.target.is_empty());
        assert_eq!(form.output, "agent-report.json");
        assert!(matches!(form.brain, BrainKind::Llm));
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
        assert!(matches!(BrainKind::Redteam.next(), BrainKind::Llm));
        assert!(matches!(BrainKind::Llm.next(), BrainKind::Recon));
    }

    fn form_for(brain: BrainKind, target: Option<&str>, repo: Option<&str>) -> AgentForm {
        AgentForm {
            brain,
            target: target.unwrap_or_default().into(),
            repo: repo.unwrap_or_default().into(),
            ..AgentForm::default()
        }
    }

    #[test]
    fn recon_plan_reflects_target_and_repo() {
        // target-only → scan_target + finish
        let steps = plan_for(&form_for(BrainKind::Recon, Some("http://x"), None));
        assert_eq!(steps.len(), 2);
        assert!(matches!(&steps[0], AgentAction::CallTool { tool, .. } if tool == "scan_target"));

        // repo-only → analyze_repo + get_attack_plan + finish
        let steps = plan_for(&form_for(BrainKind::Recon, None, Some(".")));
        assert_eq!(steps.len(), 3);
        assert!(matches!(&steps[0], AgentAction::CallTool { tool, .. } if tool == "analyze_repo"));

        // both → scan + analyze + attack_plan + finish
        let steps = plan_for(&form_for(BrainKind::Recon, Some("http://x"), Some(".")));
        assert_eq!(steps.len(), 4);
    }

    #[test]
    fn redteam_plan_calls_ai_redteam() {
        let steps = plan_for(&form_for(BrainKind::Redteam, Some("http://x/v1"), None));
        assert!(matches!(&steps[0], AgentAction::CallTool { tool, .. } if tool == "ai_redteam"));
        assert!(matches!(steps.last(), Some(AgentAction::Finish { .. })));
    }

    /// The TUI used to send only the endpoint, so a target needing a key, a
    /// specific model, or marker-based leak probes was untestable from the UI.
    #[test]
    fn redteam_plan_forwards_target_configuration() {
        let mut form = form_for(BrainKind::Redteam, Some("http://x/v1"), None);
        form.target_model = "llama3.1".into();
        form.target_key_env = "TARGET_APP_KEY".into();
        form.target_marker = "SECRET-MARKER".into();

        let steps = plan_for(&form);
        let AgentAction::CallTool { tool, args } = &steps[0] else {
            panic!("expected a tool call");
        };
        assert_eq!(tool, "ai_redteam");
        assert_eq!(args["endpoint"], json!("http://x/v1"));
        assert_eq!(args["model"], json!("llama3.1"));
        assert_eq!(args["api_key_env"], json!("TARGET_APP_KEY"));
        assert_eq!(args["system_marker"], json!("SECRET-MARKER"));

        // Unset target fields stay absent so the tool keeps its own defaults.
        let bare = plan_for(&form_for(BrainKind::Redteam, Some("http://x/v1"), None));
        let AgentAction::CallTool { args, .. } = &bare[0] else {
            panic!("expected a tool call");
        };
        assert!(args.get("model").is_none());
        assert!(args.get("api_key_env").is_none());
        assert!(args.get("system_marker").is_none());
    }

    #[test]
    fn redteam_plan_forwards_generations_and_mutators() {
        let mut form = form_for(BrainKind::Redteam, Some("http://x/v1"), None);
        form.generations = 5;
        form.mutators = "base64,rot13".into();

        let steps = plan_for(&form);
        let AgentAction::CallTool { args, .. } = &steps[0] else {
            panic!("expected a tool call");
        };
        assert_eq!(args["generations"], json!(5));
        assert_eq!(args["mutators"], json!("base64,rot13"));

        // The defaults keep the request volume of the original battery.
        let bare = plan_for(&form_for(BrainKind::Redteam, Some("http://x/v1"), None));
        let AgentAction::CallTool { args, .. } = &bare[0] else {
            panic!("expected a tool call");
        };
        assert!(args.get("generations").is_none());
        assert!(args.get("mutators").is_none());
    }

    #[test]
    fn generations_toggle_cycles_useful_sample_sizes() {
        assert_eq!(generations_next(1), 3);
        assert_eq!(generations_next(3), 5);
        assert_eq!(generations_next(5), 10);
        assert_eq!(generations_next(10), 1, "the cycle returns to a cheap run");
        assert_eq!(
            generations_next(7),
            1,
            "an off-cycle value restarts cleanly"
        );
    }

    /// A mistyped mutator must stop the run, not quietly test less than asked.
    #[test]
    fn redteam_validation_rejects_an_unknown_mutator() {
        let mut form = form_for(BrainKind::Redteam, Some("http://x/v1"), None);
        form.mutators = "base64,rot-13".into();
        let err = form.validate().unwrap_err().to_string();
        assert!(err.contains("unknown mutator 'rot-13'"), "{err}");

        form.mutators = "all".into();
        assert!(form.validate().is_ok());
    }

    /// The agent's own credential must never stand in for the target's.
    #[test]
    fn agent_key_is_not_reused_as_the_target_credential() {
        let mut form = form_for(BrainKind::Redteam, Some("http://x/v1"), None);
        form.api_key = "agent-brain-secret".into();

        let steps = plan_for(&form);
        let AgentAction::CallTool { args, .. } = &steps[0] else {
            panic!("expected a tool call");
        };
        let rendered = args.to_string();
        assert!(
            !rendered.contains("agent-brain-secret"),
            "the agent's key must not leak into target probe arguments"
        );
    }

    #[test]
    fn redteam_validation_rejects_an_unresolvable_target_key_env() {
        let mut form = form_for(BrainKind::Redteam, Some("http://x/v1"), None);
        form.target_key_env = format!("RUSTZAP_UNSET_{}", crate::types::uuid_v4());
        let err = form.validate().unwrap_err().to_string();
        assert!(err.contains("unset or empty"), "{err}");

        // Cleared → valid again (keyless targets are legitimate).
        form.target_key_env.clear();
        assert!(form.validate().is_ok());
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
        assert!(text.contains("LLM"));
        assert!(text.contains("[Y]es"));
    }

    #[test]
    fn llm_configuration_reports_missing_model_and_missing_env_key() {
        let scope: ScopeConfig = serde_yaml::from_str("allowed_hosts: []").unwrap();
        let mut form = AgentForm::default();
        assert!(llm_brain(&form, &scope)
            .err()
            .unwrap()
            .to_string()
            .contains("[m]"));
        form.model = "test-model".into();
        assert!(
            llm_brain(&form, &scope).is_ok(),
            "keyless local models remain supported"
        );
        form.base_url = "file:///tmp/invalid".into();
        assert!(llm_brain(&form, &scope).is_err());
        form.base_url.clear();
        let mut scope = scope;
        scope.model.api_key_env = Some(format!("RUSTZAP_UNSET_{}", crate::types::uuid_v4()));
        assert!(llm_brain(&form, &scope)
            .err()
            .unwrap()
            .to_string()
            .contains("[k]"));
        form.api_key = "session-test-key".into();
        assert!(
            llm_brain(&form, &scope).is_ok(),
            "typed key overrides scope env"
        );
    }

    #[tokio::test]
    async fn live_tui_uses_entered_credentials_without_persisting_them() {
        use hyper::{
            service::{make_service_fn, service_fn},
            Body, Response, Server,
        };
        let captured = std::sync::Arc::new(std::sync::Mutex::new(None));
        let requests = captured.clone();
        let service = make_service_fn(move |_| {
            let requests = requests.clone();
            async move {
                Ok::<_, std::convert::Infallible>(service_fn(
                    move |request: hyper::Request<Body>| {
                        let requests = requests.clone();
                        async move {
                            let auth = request
                                .headers()
                                .get("authorization")
                                .unwrap()
                                .to_str()
                                .unwrap()
                                .to_owned();
                            let body: serde_json::Value = serde_json::from_slice(
                                &hyper::body::to_bytes(request.into_body()).await.unwrap(),
                            )
                            .unwrap();
                            *requests.lock().unwrap() = Some((auth, body));
                            let response = json!({"choices":[{"message":{"content":r#"{"finish":"No work requested","evidence_ids":[]}"#}}]});
                            Ok::<_, std::convert::Infallible>(Response::new(Body::from(
                                response.to_string(),
                            )))
                        }
                    },
                ))
            }
        });
        let server = Server::bind(&([127, 0, 0, 1], 0).into()).serve(service);
        let addr = server.local_addr();
        let server = tokio::spawn(async move {
            let _ = server.await;
        });
        let dir = std::env::temp_dir().join(format!("rustzap-tui-llm-{}", crate::types::uuid_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let scope_path = dir.join("scope.yaml");
        let original_scope = "allowed_hosts: []\nmodel:\n  base_url: http://127.0.0.1:1/v1\n  model: scope-model\n  api_key_env: RUSTZAP_TEST_UNSET_SCOPE_KEY\n";
        std::fs::write(&scope_path, original_scope).unwrap();
        let secret = "entered-session-credential-EXAMPLE";
        let form = AgentForm {
            scope: scope_path.to_string_lossy().into_owned(),
            target: "http://example.invalid".into(),
            base_url: format!("http://{addr}/v1"),
            model: "ui-model".into(),
            api_key: secret.into(),
            goal: "Do no work and finish immediately".into(),
            output: dir.join("report.json").to_string_lossy().into_owned(),
            ..AgentForm::default()
        };
        let (tx, mut rx) = mpsc::unbounded_channel();
        spawn_agent(&form, tx).await.unwrap().unwrap();
        let (auth, body) = captured.lock().unwrap().take().unwrap();
        assert_eq!(auth, format!("Bearer {secret}"));
        assert_eq!(body["model"], "ui-model");
        assert!(body.to_string().contains(&form.goal));
        assert!(!body.to_string().contains(secret));
        let mut completed = false;
        while let Ok(event) = rx.try_recv() {
            match event {
                AgentEvent::Completed { .. } => completed = true,
                AgentEvent::Log(text) | AgentEvent::Failed { error: text } => {
                    assert!(!text.contains(secret))
                }
                _ => {}
            }
        }
        assert!(completed);
        assert_eq!(
            std::fs::read_to_string(&scope_path).unwrap(),
            original_scope
        );
        for entry in std::fs::read_dir(&dir).unwrap() {
            assert!(!std::fs::read_to_string(entry.unwrap().path())
                .unwrap()
                .contains(secret));
        }
        assert!(!consent_dialog_text(&form).contains(secret));
        server.abort();
        std::fs::remove_dir_all(dir).unwrap();
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
