use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::{Backend, CrosstermBackend},
    layout::{Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, ListState, Paragraph},
    Terminal,
};
use std::{error::Error, fs, io};

use crate::report::Report;

struct AppState {
    report: Option<Report>,
    list_state: ListState,
}

impl AppState {
    fn new() -> Self {
        let mut app = Self {
            report: None,
            list_state: ListState::default(),
        };

        // Try to load report.json or rustzap-report.json
        if let Ok(contents) = fs::read_to_string("report.json") {
            if let Ok(report) = serde_json::from_str(&contents) {
                app.report = Some(report);
            }
        } else if let Ok(contents) = fs::read_to_string("rustzap-report.json") {
            if let Ok(report) = serde_json::from_str(&contents) {
                app.report = Some(report);
            }
        }

        if let Some(r) = &app.report {
            if !r.findings.is_empty() {
                app.list_state.select(Some(0));
            }
        }

        app
    }

    fn next(&mut self) {
        if let Some(r) = &self.report {
            let i = match self.list_state.selected() {
                Some(i) => {
                    if i >= r.findings.len() - 1 {
                        0
                    } else {
                        i + 1
                    }
                }
                None => 0,
            };
            self.list_state.select(Some(i));
        }
    }

    fn previous(&mut self) {
        if let Some(r) = &self.report {
            let i = match self.list_state.selected() {
                Some(i) => {
                    if i == 0 {
                        r.findings.len() - 1
                    } else {
                        i - 1
                    }
                }
                None => 0,
            };
            self.list_state.select(Some(i));
        }
    }
}

pub async fn run_tui() -> Result<(), Box<dyn Error>> {
    // Setup terminal
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let mut app = AppState::new();

    // Run app loop
    let res = run_app(&mut terminal, &mut app);

    // Restore terminal
    disable_raw_mode()?;
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture
    )?;
    terminal.show_cursor()?;

    if let Err(err) = res {
        println!("{:?}", err)
    }

    Ok(())
}

fn run_app<B: Backend>(terminal: &mut Terminal<B>, app: &mut AppState) -> Result<(), Box<dyn Error>>
where
    Box<dyn Error>: From<<B as Backend>::Error>,
{
    loop {
        terminal.draw(|f| ui(f, app))?;

        if let Event::Key(key) = event::read()? {
            match key.code {
                KeyCode::Char('q') => return Ok(()),
                KeyCode::Down | KeyCode::Char('j') => app.next(),
                KeyCode::Up | KeyCode::Char('k') => app.previous(),
                _ => {}
            }
        }
    }
}

fn ui(f: &mut ratatui::Frame, app: &mut AppState) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .margin(1)
        .constraints(
            [
                Constraint::Length(3),
                Constraint::Min(0),
                Constraint::Length(3),
            ]
            .as_ref(),
        )
        .split(f.area());

    let main_content_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(40), Constraint::Percentage(60)].as_ref())
        .split(chunks[1]);

    let title_text = if let Some(r) = &app.report {
        format!(" RustZAP | Target: {} | Findings: {} | Score: {}", r.meta.target, r.summary.total_findings, r.summary.risk_score)
    } else {
        " RustZAP | Unified DevSecOps TUI (No report found)".to_string()
    };

    let title = Paragraph::new(Line::from(vec![
        Span::styled(title_text, Style::default().fg(Color::Red).add_modifier(Modifier::BOLD)),
    ]))
    .block(Block::default().borders(Borders::ALL).title("Overview"));
    f.render_widget(title, chunks[0]);

    let mut list_items = Vec::new();
    if let Some(r) = &app.report {
        for (i, finding) in r.findings.iter().enumerate() {
            let color = match finding.severity {
                crate::types::Severity::Critical => Color::Magenta,
                crate::types::Severity::High => Color::Red,
                crate::types::Severity::Medium => Color::Yellow,
                crate::types::Severity::Low => Color::Cyan,
                crate::types::Severity::Info => Color::Blue,
            };

            let content = format!("{}. [{}] {}", i + 1, finding.severity, finding.title);
            list_items.push(ListItem::new(Span::styled(content, Style::default().fg(color))));
        }
    } else {
        list_items.push(ListItem::new("No findings loaded. Run a scan first."));
    }

    let findings_list = List::new(list_items)
        .block(Block::default().borders(Borders::ALL).title("Active Findings"))
        .highlight_style(Style::default().bg(Color::DarkGray).add_modifier(Modifier::BOLD))
        .highlight_symbol(">> ");

    f.render_stateful_widget(findings_list, main_content_chunks[0], &mut app.list_state);

    // Detail view
    let detail_text = if let (Some(r), Some(selected)) = (&app.report, app.list_state.selected()) {
        if let Some(finding) = r.findings.get(selected) {
            format!(
                "Title: {}\nSeverity: {}\nURL: {}\nParameter: {:?}\n\nDescription:\n{}\n\nSolution:\n{}\n\nEvidence:\n{}",
                finding.title,
                finding.severity,
                finding.url,
                finding.parameter.as_deref().unwrap_or("None"),
                finding.description,
                finding.solution,
                finding.evidence.as_deref().unwrap_or("None")
            )
        } else {
            "".to_string()
        }
    } else {
        "Select a finding to view details.".to_string()
    };

    let detail_view = Paragraph::new(detail_text)
        .block(Block::default().borders(Borders::ALL).title("Finding Details"))
        .wrap(ratatui::widgets::Wrap { trim: true });

    f.render_widget(detail_view, main_content_chunks[1]);

    let status = Paragraph::new("Use ↑/↓ or j/k to navigate. Press 'q' to quit.")
        .block(Block::default().borders(Borders::ALL).title("Controls"));
    f.render_widget(status, chunks[2]);
}
