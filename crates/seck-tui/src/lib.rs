//! Terminal UI: three-pane viewer for a seck report. Keymap: q (quit),
//! j/k or arrows (move), Enter (expand finding), g/G (top/bottom).
//! Deliberately no mouse to keep the OSC 8 / mouse-event surface zero.
//! All text routes through `seck-report::sanitize` before rendering.

use crossterm::{
    event::{self, Event, KeyCode},
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use ratatui::{
    Frame, Terminal,
    backend::CrosstermBackend,
    layout::{Constraint, Layout},
    text::{Line, Span, Text},
    widgets::{Block, Borders, Paragraph, Widget},
};
use seck_report::{sanitize::sanitize, schema::Report};
use std::collections::HashSet;
use std::io::stdout;

#[derive(Default)]
pub struct AppState {
    pub report: Option<Report>,
    pub selected: usize,
    pub expanded: HashSet<String>,
}

impl AppState {
    pub fn new(report: Report) -> Self {
        Self {
            report: Some(report),
            selected: 0,
            expanded: HashSet::new(),
        }
    }
}

pub fn run(report_path: &std::path::Path) -> anyhow::Result<()> {
    let body = std::fs::read(report_path)?;
    let report: Report = serde_json::from_slice(&body)?;
    let mut state = AppState::new(report);

    enable_raw_mode()?;
    let mut out = stdout();
    execute!(out, EnterAlternateScreen)?;
    let mut term = Terminal::new(CrosstermBackend::new(out))?;
    // Deliberately do NOT enable mouse capture.

    let res = event_loop(&mut term, &mut state);

    disable_raw_mode()?;
    execute!(std::io::stdout(), LeaveAlternateScreen)?;
    res
}

fn event_loop<B>(term: &mut Terminal<B>, state: &mut AppState) -> anyhow::Result<()>
where
    B: ratatui::backend::Backend,
    B::Error: Send + Sync + 'static,
{
    loop {
        term.draw(|f| draw(f, state))
            .map_err(|e| anyhow::anyhow!("draw: {e}"))?;
        if let Event::Key(k) = event::read()? {
            match k.code {
                KeyCode::Char('q') | KeyCode::Esc => break,
                KeyCode::Char('j') | KeyCode::Down => {
                    if let Some(r) = &state.report {
                        if state.selected + 1 < r.findings.len() {
                            state.selected += 1;
                        }
                    }
                }
                KeyCode::Char('k') | KeyCode::Up => {
                    state.selected = state.selected.saturating_sub(1);
                }
                KeyCode::Char('g') => state.selected = 0,
                KeyCode::Char('G') => {
                    if let Some(r) = &state.report {
                        state.selected = r.findings.len().saturating_sub(1);
                    }
                }
                KeyCode::Enter => {
                    if let Some(r) = &state.report {
                        if let Some(f) = r.findings.get(state.selected) {
                            if state.expanded.contains(&f.id) {
                                state.expanded.remove(&f.id);
                            } else {
                                state.expanded.insert(f.id.clone());
                            }
                        }
                    }
                }
                _ => {}
            }
        }
    }
    Ok(())
}

fn draw(f: &mut Frame, s: &AppState) {
    let area = f.area();
    let cols = Layout::horizontal([
        Constraint::Length(28),
        Constraint::Length(28),
        Constraint::Min(40),
    ])
    .split(area);
    if let Some(r) = &s.report {
        render_files(cols[0], f, r);
        render_meta(cols[1], f, r);
        render_findings(cols[2], f, r, s);
    }
}

fn safe_line(s: &str) -> Line<'static> {
    Line::from(Span::raw(sanitize(s)))
}

fn render_files(area: ratatui::layout::Rect, f: &mut Frame, r: &Report) {
    let lines: Vec<Line> = r.inputs.iter().map(|i| safe_line(&i.path)).collect();
    Paragraph::new(Text::from(lines))
        .block(Block::default().borders(Borders::ALL).title("Files"))
        .render(area, f.buffer_mut());
}

fn render_meta(area: ratatui::layout::Rect, f: &mut Frame, r: &Report) {
    let lines = vec![
        safe_line(&format!("sandbox: {}", r.invocation.sandbox_mode)),
        safe_line(&format!("backend: {}", r.invocation.backend)),
        safe_line(&format!("temp: {}", r.invocation.temperature)),
        safe_line(&format!("deterministic: {}", r.invocation.deterministic)),
    ];
    Paragraph::new(Text::from(lines))
        .block(Block::default().borders(Borders::ALL).title("Pipeline"))
        .render(area, f.buffer_mut());
}

fn render_findings(area: ratatui::layout::Rect, f: &mut Frame, r: &Report, s: &AppState) {
    let mut lines = Vec::new();
    for (i, fnd) in r.findings.iter().enumerate() {
        let prefix = if i == s.selected { "▶" } else { " " };
        lines.push(safe_line(&format!("{prefix} [{}] {}", fnd.id, fnd.summary)));
        if s.expanded.contains(&fnd.id) {
            lines.push(safe_line(&format!(
                "    {}/{} — {}",
                fnd.category, fnd.confidence, fnd.evidence_quote
            )));
        }
    }
    Paragraph::new(Text::from(lines))
        .block(Block::default().borders(Borders::ALL).title("Findings"))
        .render(area, f.buffer_mut());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn state_constructs_and_navigates() {
        let report = seck_report::schema::Report {
            version: "0.1.0".into(),
            invocation: seck_report::schema::Invocation {
                nonce_sha3_256: "0".repeat(64),
                started_at: "".into(),
                finished_at: "".into(),
                sandbox_mode: "A".into(),
                backend: "stub".into(),
                model: "".into(),
                model_sha3_256: "".into(),
                temperature: 0.0,
                seed: 1,
                deterministic: true,
            },
            inputs: vec![],
            findings: vec![],
            sandbox_attestation: seck_report::schema::Attestation {
                platform: "x".into(),
                sandbox_mode: "A".into(),
                profile_sha3_256: "0".repeat(64),
                binary_sha3_256: "".into(),
            },
        };
        let mut s = AppState::new(report);
        assert_eq!(s.selected, 0);
        s.selected = s.selected.saturating_sub(1);
        assert_eq!(s.selected, 0);
    }

    #[test]
    fn safe_line_strips_ansi() {
        let l = safe_line("\x1b[31mred\x1b[0m");
        let s = format!("{:?}", l);
        assert!(!s.contains("\x1b"), "ANSI escape NOT in line: {s}");
    }
}
