//! TUI state and rendering, split out so the layout is unit-testable with a
//! `TestBackend` (no real terminal).

use ratatui::layout::{Constraint, Layout};
use ratatui::style::{Modifier, Style};
use ratatui::text::Line;
use ratatui::widgets::{Block, Borders, Paragraph, Wrap};
use ratatui::Frame;

/// All state the UI renders.
pub struct App {
    /// Title shown on the message pane (channel name).
    pub title: String,
    /// One-line status: topology · peers · suite · tor state.
    pub status: String,
    /// Our safety number (for /verify).
    pub safety_number: String,
    /// Scrollback of rendered lines.
    pub log: Vec<String>,
    /// Current input buffer.
    pub input: String,
}

impl App {
    pub fn new(title: impl Into<String>, status: impl Into<String>) -> Self {
        Self {
            title: title.into(),
            status: status.into(),
            safety_number: String::new(),
            log: Vec::new(),
            input: String::new(),
        }
    }

    /// Append a line, bounding scrollback.
    pub fn push(&mut self, line: impl Into<String>) {
        self.log.push(line.into());
        if self.log.len() > 2000 {
            self.log.drain(0..self.log.len() - 2000);
        }
    }
}

/// Render the whole UI: status bar, message pane, input line.
pub fn ui(frame: &mut Frame, app: &App) {
    let chunks = Layout::vertical([
        Constraint::Length(1), // status bar
        Constraint::Min(1),    // messages
        Constraint::Length(3), // input
    ])
    .split(frame.area());

    let status = Paragraph::new(Line::from(app.status.clone()))
        .style(Style::new().add_modifier(Modifier::REVERSED));
    frame.render_widget(status, chunks[0]);

    // Show the tail of the log that fits, oldest-to-newest.
    let height = chunks[1].height.saturating_sub(2) as usize; // minus borders
    let start = app.log.len().saturating_sub(height.max(1));
    let body_text = app.log[start..].join("\n");
    let body = Paragraph::new(body_text)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(format!(" {} ", app.title)),
        )
        .wrap(Wrap { trim: false });
    frame.render_widget(body, chunks[1]);

    let input = Paragraph::new(format!("> {}", app.input)).block(
        Block::default()
            .borders(Borders::ALL)
            .title(" message — /help /invite /verify /quit "),
    );
    frame.render_widget(input, chunks[2]);
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::backend::TestBackend;
    use ratatui::layout::Position;
    use ratatui::Terminal;

    fn rendered_text(app: &App, w: u16, h: u16) -> String {
        let mut terminal = Terminal::new(TestBackend::new(w, h)).unwrap();
        terminal.draw(|f| ui(f, app)).unwrap();
        let buf = terminal.backend().buffer().clone();
        let area = buf.area;
        let mut s = String::new();
        for y in 0..area.height {
            for x in 0..area.width {
                if let Some(cell) = buf.cell(Position::new(x, y)) {
                    s.push_str(cell.symbol());
                }
            }
            s.push('\n');
        }
        s
    }

    #[test]
    fn renders_status_title_and_input() {
        let mut app = App::new("#general", "p2p · peers: 2 · tk.dr · tor:online");
        app.push("alice> hello");
        app.input = "typing…".into();
        let text = rendered_text(&app, 60, 12);
        assert!(text.contains("p2p"), "status bar missing");
        assert!(text.contains("#general"), "title missing");
        assert!(text.contains("alice> hello"), "log line missing");
        assert!(text.contains("> typing"), "input line missing");
    }

    #[test]
    fn scrollback_is_bounded() {
        let mut app = App::new("#c", "s");
        for i in 0..5000 {
            app.push(format!("line {i}"));
        }
        assert!(app.log.len() <= 2000);
        // Most recent line is retained.
        assert_eq!(app.log.last().unwrap(), "line 4999");
    }
}
