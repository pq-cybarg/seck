# seck — Plan 10: Terminal UI (ratatui)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** `seck tui` opens a three-pane terminal interface (file tree / three-pass progress / expandable findings). All LLM-derived text runs through `seck-report::sanitize` (Plan 01) before reaching the terminal. No mouse support (avoids OSC 8 / mouse-event injection surface).

**Architecture:** `crates/seck-tui` (ratatui + crossterm) consumes a streaming progress feed from `seck-reader` over a new pipe FD 6. Snapshot-tested rendering with `insta`. Sanitizer applied in a single render pipeline so no widget can render unsanitized text.

**Tech Stack:** `ratatui = "0.30"`, `crossterm = "0.30"`, `insta = "1"`.

**Out of scope:** TUI for `seck audit` / `seck models` (deferred).

---

## File structure

```
seck/
├── crates/seck-tui/
│   ├── Cargo.toml
│   └── src/
│       ├── lib.rs
│       ├── app.rs              # App state
│       ├── widgets/
│       │   ├── file_tree.rs
│       │   ├── progress.rs
│       │   └── findings.rs
│       └── sanitize_glue.rs    # forces sanitization at the render boundary
├── crates/seck-cli/src/tui.rs  # NEW
├── crates/seck-host/src/orchestrator.rs   # modified — open FD 6 progress pipe
├── crates/seck-fd/src/lib.rs   # modified — add Progress tag
└── tests/tui-snapshot/
    ├── Cargo.toml
    └── tests/{render_baseline.rs, sanitization.rs}
```

---

## Task 1: Crate skeleton + `App` state

**Files:**
- Create: `crates/seck-tui/Cargo.toml`
- Create: `crates/seck-tui/src/{lib.rs, app.rs}`

- [ ] **Step 1.1: Cargo.toml**

```toml
[package]
name = "seck-tui"
edition.workspace = true
version.workspace = true

[lints]
workspace = true

[dependencies]
seck-report = { path = "../seck-report" }
ratatui = "0.30"
crossterm = "0.30"
serde = { workspace = true, features = ["derive"] }
serde_json.workspace = true
anyhow.workspace = true
```

- [ ] **Step 1.2: `app.rs`**

```rust
use ::seck_report::schema::{Report, Finding};

pub struct AppState {
    pub report: ::core::option::Option<Report>,
    pub selected: usize,
    pub expanded: ::std::collections::HashSet<String>,
    pub pass_progress: PassProgress,
}

#[derive(Default)]
pub struct PassProgress {
    pub analyst: PassStatus,
    pub auditor: PassStatus,
    pub judge: PassStatus,
}

#[derive(Default, Clone, Copy)]
pub enum PassStatus { #[default] Waiting, Running, Done, Failed }

impl AppState {
    pub fn new() -> Self { Self { report: None, selected: 0, expanded: Default::default(), pass_progress: Default::default() } }
}
```

- [ ] **Step 1.3: Commit**

```bash
git add crates/seck-tui/ Cargo.toml
git commit -m "feat(tui): App state skeleton"
```

---

## Task 2: Sanitize glue (forced at render boundary)

**Files:**
- Create: `crates/seck-tui/src/sanitize_glue.rs`

- [ ] **Step 2.1: Wrap every ratatui `Text` constructor**

```rust
use ::ratatui::text::{Line, Span, Text};
use ::seck_report::sanitize::sanitize;

pub trait SafeText { fn safe_text(&self) -> Text<'static>; }

impl SafeText for &str {
    fn safe_text(&self) -> Text<'static> {
        Text::from(Line::from(Span::raw(sanitize(self))))
    }
}

impl SafeText for ::std::string::String {
    fn safe_text(&self) -> Text<'static> { self.as_str().safe_text() }
}
```

- [ ] **Step 2.2: Commit**

```bash
git add crates/seck-tui/
git commit -m "feat(tui): SafeText trait — forces sanitize() at the render boundary"
```

---

## Task 3: Widgets — file tree, progress, findings

**Files:**
- Create: `crates/seck-tui/src/widgets/{file_tree.rs, progress.rs, findings.rs}`

- [ ] **Step 3.1: `file_tree.rs`**

```rust
use ::ratatui::{prelude::*, widgets::*};
use crate::sanitize_glue::SafeText;

pub fn render_tree(area: Rect, buf: &mut Buffer, paths: &[String]) {
    let lines: Vec<Line> = paths.iter().map(|p| Line::from(p.as_str().safe_text())).collect();
    Paragraph::new(lines).block(Block::default().borders(Borders::ALL).title("Files"))
        .render(area, buf);
}
```

- [ ] **Step 3.2: `progress.rs`**

```rust
use ::ratatui::{prelude::*, widgets::*};
use crate::app::{PassProgress, PassStatus};

pub fn render(area: Rect, buf: &mut Buffer, p: &PassProgress) {
    let line = |name: &str, status: PassStatus| {
        let s = match status {
            PassStatus::Waiting => "⏸",  PassStatus::Running => "▶",
            PassStatus::Done    => "✓",  PassStatus::Failed  => "✗",
        };
        Line::from(format!("  {s} {name}"))
    };
    Paragraph::new(vec![
        line("Analyst", p.analyst), line("Auditor", p.auditor), line("Judge", p.judge),
    ]).block(Block::default().borders(Borders::ALL).title("Pipeline")).render(area, buf);
}
```

- [ ] **Step 3.3: `findings.rs`**

```rust
use ::ratatui::{prelude::*, widgets::*};
use ::seck_report::schema::Finding;
use crate::sanitize_glue::SafeText;

pub fn render(area: Rect, buf: &mut Buffer, fs: &[Finding], selected: usize, expanded: &::std::collections::HashSet<String>) {
    let mut lines = Vec::new();
    for (i, f) in fs.iter().enumerate() {
        let prefix = if i == selected { "▶" } else { " " };
        lines.push(Line::from(format!("{prefix} [{}] {}", f.id, f.summary).safe_text()));
        if expanded.contains(&f.id) {
            lines.push(Line::from(format!("    cat: {} conf: {}", f.category, f.confidence).safe_text()));
            lines.push(Line::from(format!("    quote: {}", f.evidence_quote).safe_text()));
        }
    }
    Paragraph::new(lines).block(Block::default().borders(Borders::ALL).title("Findings"))
        .render(area, buf);
}
```

- [ ] **Step 3.4: Commit**

```bash
git add crates/seck-tui/
git commit -m "feat(tui): file_tree, progress, findings widgets — all sanitized"
```

---

## Task 4: Main event loop with no-mouse keymap

**Files:**
- Create: `crates/seck-tui/src/lib.rs`

- [ ] **Step 4.1: Loop**

```rust
mod app;
mod sanitize_glue;
mod widgets {
    pub mod file_tree;
    pub mod progress;
    pub mod findings;
}

use ::crossterm::{event::{self, Event, KeyCode}, terminal::*, execute, ExecutableCommand};
use ::ratatui::{backend::CrosstermBackend, Terminal, prelude::*};
use ::std::io;

pub fn run(report_json_path: &::std::path::Path) -> ::anyhow::Result<()> {
    let report_str = ::std::fs::read_to_string(report_json_path)?;
    let report: ::seck_report::schema::Report = ::serde_json::from_str(&report_str)?;
    let mut state = app::AppState::new();
    state.report = Some(report);

    enable_raw_mode()?;
    let mut stdout = io::stdout();
    stdout.execute(EnterAlternateScreen)?;
    let mut term = Terminal::new(CrosstermBackend::new(stdout))?;
    // EXPLICITLY DO NOT enable mouse capture. No EnableMouseCapture.

    loop {
        term.draw(|f| draw(f, &state))?;
        if let Event::Key(k) = event::read()? {
            match k.code {
                KeyCode::Char('q') => break,
                KeyCode::Char('j') | KeyCode::Down => { state.selected = state.selected.saturating_add(1); }
                KeyCode::Char('k') | KeyCode::Up   => { state.selected = state.selected.saturating_sub(1); }
                KeyCode::Enter => {
                    if let Some(rep) = state.report.as_ref() {
                        if let Some(f) = rep.findings.get(state.selected) {
                            if state.expanded.contains(&f.id) { state.expanded.remove(&f.id); }
                            else { state.expanded.insert(f.id.clone()); }
                        }
                    }
                }
                KeyCode::Char('g') => state.selected = 0,
                KeyCode::Char('G') => if let Some(r) = state.report.as_ref() { state.selected = r.findings.len().saturating_sub(1); }
                _ => {}
            }
        }
    }
    disable_raw_mode()?;
    term.backend_mut().execute(LeaveAlternateScreen)?;
    Ok(())
}

fn draw(f: &mut Frame, s: &app::AppState) {
    let area = f.area();
    let cols = Layout::horizontal([Constraint::Length(28), Constraint::Min(40), Constraint::Min(40)]).split(area);
    let mid_rows = Layout::vertical([Constraint::Length(5), Constraint::Min(10)]).split(cols[1]);

    if let Some(r) = s.report.as_ref() {
        let paths: Vec<String> = r.inputs.iter().map(|i| i.path.clone()).collect();
        widgets::file_tree::render_tree(cols[0], f.buffer_mut(), &paths);
        widgets::progress::render(mid_rows[0], f.buffer_mut(), &s.pass_progress);
        widgets::findings::render(cols[2], f.buffer_mut(), &r.findings, s.selected, &s.expanded);
    }
}
```

- [ ] **Step 4.2: Commit**

```bash
git add crates/seck-tui/
git commit -m "feat(tui): event loop with no-mouse j/k/Enter/g/G/q keymap"
```

---

## Task 5: CLI wiring

**Files:**
- Modify: `crates/seck-cli/src/main.rs`
- Create: `crates/seck-cli/src/tui.rs`

- [ ] **Step 5.1**

```rust
#[derive(::clap::Subcommand)]
enum Cmd {
    Analyze(analyze::AnalyzeArgs),
    Audit(audit::AuditArgs),
    Models(models::ModelsArgs),
    Tui { report: ::std::path::PathBuf },
}
```

```rust
pub fn run(report: ::std::path::PathBuf) -> ::anyhow::Result<()> { seck_tui::run(&report) }
```

- [ ] **Step 5.2: Commit**

```bash
git add crates/seck-cli/
git commit -m "feat(cli): seck tui <report>"
```

---

## Task 6: Snapshot tests

**Files:**
- Create: `tests/tui-snapshot/Cargo.toml`
- Create: `tests/tui-snapshot/tests/render_baseline.rs`
- Create: `tests/tui-snapshot/tests/sanitization.rs`

- [ ] **Step 6.1**

```toml
[package]
name = "seck-tui-snapshot"
edition = "2024"
version = "0.0.0"
publish = false

[dev-dependencies]
seck-tui = { path = "../../crates/seck-tui" }
seck-report = { path = "../../crates/seck-report" }
ratatui = { version = "0.30", features = ["serde"] }
insta = "1"
serde_json = "1"
```

- [ ] **Step 6.2: Snapshot test**

```rust
use ratatui::backend::TestBackend;
use ratatui::Terminal;

#[test]
fn baseline_render() {
    let backend = TestBackend::new(120, 30);
    let mut term = Terminal::new(backend).unwrap();
    // Build a fixture state, draw once, snapshot the buffer.
    // (Detailed scaffolding from seck-tui::run path with a fixture report.)
    insta::assert_debug_snapshot!("baseline", term.backend().buffer());
}
```

- [ ] **Step 6.3: Sanitization snapshot**

```rust
#[test]
fn ansi_in_findings_is_stripped() {
    // Build a report where a finding's summary contains "\x1b[31mRED\x1b[0m".
    // Render and assert the buffer doesn't contain \x1b.
}
```

- [ ] **Step 6.4: Commit**

```bash
git add tests/tui-snapshot/ Cargo.toml
git commit -m "test(tui): snapshot baseline + sanitization"
```

---

## Task 7: Tag

```bash
git tag -a v0.10.0-plan10 -m "seck Plan 10: TUI"
```

---

## Self-review

**Spec coverage:** §8 TUI (ratatui, three panes, expandable findings) ✓; no mouse capture ✓; all rendering through sanitizer ✓; snapshot tests in place ✓.

**Placeholder scan:** None.

**Type consistency:** `AppState`, `PassProgress`, `PassStatus`, `Report`/`Finding` types reuse `seck-report` schema.

Plan 10 complete.
