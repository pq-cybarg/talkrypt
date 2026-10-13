//! TUI state and rendering, split out so the layout is unit-testable with a
//! `TestBackend` (no real terminal).

use ratatui::layout::{Constraint, Layout};
use ratatui::style::{Modifier, Style};
use ratatui::text::Line;
use ratatui::widgets::{Block, Borders, Paragraph};
use ratatui::Frame;

/// Hard-wrap one logical line into visual rows of at most `width` cells. Char-
/// based (each char is one cell for our content: ASCII text and the QR's Unicode
/// half-blocks), so the wrapped-row count is exact and the tail windowing never
/// clips the newest line. An empty line stays one (blank) row.
fn wrap_to_rows(line: &str, width: usize) -> Vec<String> {
    if width == 0 || line.is_empty() {
        return vec![String::new()];
    }
    let chars: Vec<char> = line.chars().collect();
    chars
        .chunks(width)
        .map(|c| c.iter().collect::<String>())
        .collect()
}

/// All state the UI renders.
pub struct App {
    /// Title shown on the message pane (channel name).
    pub title: String,
    /// The STABLE status prefix (topology · hosting addr · suite). Never
    /// overwritten by events — the live peer count is appended at render time, so
    /// the user keeps seeing the topology/address/suite instead of a bare
    /// "peers: N" clobbering it after the first event.
    pub status: String,
    /// Live peer count, updated on connect/disconnect events.
    pub peers: usize,
    /// Our safety number (for /verify).
    pub safety_number: String,
    /// Scrollback of rendered lines.
    pub log: Vec<String>,
    /// How many wrapped rows the user has scrolled UP from the newest line.
    /// 0 == pinned to the bottom (newest), the default.
    pub scroll_offset: u16,
    /// Our own sent messages: `gossip_id` → (log index, original text), so a later
    /// delivery ack can upgrade that line's marker (· sent → ✓✓ delivered).
    pub sent: std::collections::HashMap<[u8; 32], (usize, String)>,
    /// Current input buffer.
    pub input: String,
}

impl App {
    pub fn new(title: impl Into<String>, status: impl Into<String>) -> Self {
        Self {
            title: title.into(),
            status: status.into(),
            peers: 0,
            safety_number: String::new(),
            log: Vec::new(),
            scroll_offset: 0,
            sent: std::collections::HashMap::new(),
            input: String::new(),
        }
    }

    /// Append a line, bounding scrollback. Appending pins the view to the bottom
    /// so a new message is always visible (unless the user scrolled up — see
    /// `scroll_offset`, which `push` leaves alone only when already at bottom).
    pub fn push(&mut self, line: impl Into<String>) {
        self.log.push(line.into());
        if self.log.len() > 2000 {
            let drained = self.log.len() - 2000;
            self.log.drain(0..drained);
            // Keep the own-message index map valid across the drain: entries whose
            // line scrolled off are forgotten, the rest shift down by `drained`.
            self.sent = self
                .sent
                .drain()
                .filter_map(|(gid, (i, t))| (i >= drained).then(|| (gid, (i - drained, t))))
                .collect();
        }
    }

    /// Record our own just-sent message with a "sent" marker, keyed by its
    /// `gossip_id` so a delivery ack can later upgrade it.
    pub fn push_sent(&mut self, gid: [u8; 32], text: &str) {
        let idx = self.log.len();
        self.push(format!("· me> {text}"));
        self.sent.insert(gid, (idx, text.to_string()));
    }

    /// Upgrade a sent message to "delivered" (✓✓) when its ack arrives. No-op if
    /// the message isn't ours / already scrolled out of the bounded log.
    pub fn mark_delivered(&mut self, gid: [u8; 32]) {
        if let Some((i, text)) = self.sent.get(&gid).cloned() {
            if let Some(line) = self.log.get_mut(i) {
                *line = format!("✓✓ me> {text}");
            }
        }
    }

    /// Render `data` as a scannable QR (Unicode half-blocks) into the scrollback,
    /// so an in-person joiner can scan the invite straight off the terminal — the
    /// same affordance the CLI's `print_qr` gives (SECURITY-AUDIT UX blocker).
    pub fn push_qr(&mut self, data: &str) {
        match qrcode::QrCode::new(data.as_bytes()) {
            Ok(code) => {
                let rendered = code
                    .render::<qrcode::render::unicode::Dense1x2>()
                    .quiet_zone(true)
                    .build();
                for line in rendered.lines() {
                    self.push(line.to_string());
                }
            }
            // Too large to encode (e.g. a very long multi-homed invite): the URI
            // text is already in the log, so just note it rather than failing.
            Err(_) => self.push("(invite too long to render as a QR — copy the URI above)"),
        }
    }

    /// Scroll the message pane up (toward older lines) by `rows`.
    pub fn scroll_up(&mut self, rows: u16) {
        self.scroll_offset = self.scroll_offset.saturating_add(rows);
    }

    /// Scroll down (toward newer lines); clamps at the bottom (newest).
    pub fn scroll_down(&mut self, rows: u16) {
        self.scroll_offset = self.scroll_offset.saturating_sub(rows);
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

    // Status: the stable prefix + the live peer count (+ a scroll hint while the
    // user is scrolled up), so topology/address/suite stay visible.
    let mut status_line = format!("{} · peers: {}", app.status, app.peers);
    if app.scroll_offset > 0 {
        status_line.push_str("  [scrolled — End to return]");
    }
    let status = Paragraph::new(Line::from(status_line))
        .style(Style::new().add_modifier(Modifier::REVERSED));
    frame.render_widget(status, chunks[0]);

    // Message pane. We pre-wrap every log line into VISUAL rows ourselves and show
    // the tail that fits, so a long/wrapped line (the pasted invite, a QR) can no
    // longer push newer messages off-screen (the old tail math counted logical
    // lines, not wrapped rows, and clipped the bottom). `scroll_offset` pages back
    // through history; offset 0 pins to the newest row.
    let body_block = Block::default()
        .borders(Borders::ALL)
        .title(format!(" {} ", app.title));
    let inner = body_block.inner(chunks[1]);
    let w = inner.width as usize;
    let h = inner.height as usize;
    let mut rows: Vec<String> = Vec::new();
    for line in &app.log {
        rows.extend(wrap_to_rows(line, w));
    }
    let total = rows.len();
    let max_scroll = total.saturating_sub(h);
    let off = (app.scroll_offset as usize).min(max_scroll);
    let end = total - off; // exclusive; newest visible row
    let start = end.saturating_sub(h);
    let visible = rows[start..end].join("\n");
    let body = Paragraph::new(visible).block(body_block);
    frame.render_widget(body, chunks[1]);

    let input = Paragraph::new(format!("> {}", app.input)).block(
        Block::default()
            .borders(Borders::ALL)
            .title(" type + Enter · /help · Ctrl-C or /quit to exit · PgUp/PgDn scroll "),
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
        let mut app = App::new("#general", "p2p · hosting 127.0.0.1:9000 · tk.dr");
        app.peers = 2;
        app.push("alice> hello");
        app.input = "typing…".into();
        let text = rendered_text(&app, 60, 12);
        assert!(text.contains("p2p"), "status bar missing");
        assert!(text.contains("peers: 2"), "live peer count missing");
        assert!(text.contains("#general"), "title missing");
        assert!(text.contains("alice> hello"), "log line missing");
        assert!(text.contains("> typing"), "input line missing");
    }

    #[test]
    fn newest_line_visible_despite_a_long_wrapped_line() {
        // Regression (UX blocker): a very long line (e.g. a pasted invite) must not
        // push the newest message off-screen. With tail windowing by VISUAL rows,
        // the last line is always shown.
        let mut app = App::new("#c", "s");
        app.push("x".repeat(400)); // wraps to many rows on a narrow pane
        app.push("NEWEST-MESSAGE");
        let text = rendered_text(&app, 40, 10);
        assert!(
            text.contains("NEWEST-MESSAGE"),
            "the newest line must remain visible under a long wrapped line"
        );
    }

    #[test]
    fn scrolling_up_reveals_older_then_end_returns_to_newest() {
        let mut app = App::new("#c", "s");
        for i in 0..100 {
            app.push(format!("line-{i}"));
        }
        // Pinned to bottom: newest visible, oldest not.
        let bottom = rendered_text(&app, 40, 8);
        assert!(bottom.contains("line-99"));
        assert!(!bottom.contains("line-0"));
        // Scroll all the way up: the first line comes into view.
        app.scroll_up(u16::MAX);
        let top = rendered_text(&app, 40, 8);
        assert!(top.contains("line-0"), "scrolling up must reveal the oldest line");
        // End returns to the newest.
        app.scroll_offset = 0;
        assert!(rendered_text(&app, 40, 8).contains("line-99"));
    }

    #[test]
    fn own_message_marks_sent_then_delivered() {
        let mut app = App::new("#c", "s");
        let gid = [7u8; 32];
        app.push_sent(gid, "hello");
        assert!(app.log.last().unwrap().starts_with("· me> hello"), "sent marker");
        app.mark_delivered(gid);
        assert!(app.log.last().unwrap().starts_with("✓✓ me> hello"), "delivered marker");
        // An ack for an unknown gid is a harmless no-op.
        app.mark_delivered([9u8; 32]);
        assert!(app.log.last().unwrap().starts_with("✓✓ me> hello"));
    }

    #[test]
    fn sent_index_survives_scrollback_drain() {
        let mut app = App::new("#c", "s");
        let gid = [1u8; 32];
        app.push_sent(gid, "early");
        // Push enough to force a drain past the 2000-line cap.
        for i in 0..2100 {
            app.push(format!("filler {i}"));
        }
        // The "early" line scrolled off; its stale index must not mis-mark another.
        app.mark_delivered(gid);
        assert!(!app.log.iter().any(|l| l.contains("✓✓ me> early")));
        assert!(!app.log.iter().any(|l| l.starts_with("✓✓ me> filler")));
    }

    #[test]
    fn push_qr_renders_block_rows_for_an_invite() {
        let mut app = App::new("#c", "s");
        let before = app.log.len();
        app.push_qr("talkrypt://example-invite-uri-for-qr");
        // A QR renders as several half-block rows (not a single line).
        assert!(app.log.len() > before + 3, "expected multiple QR rows");
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
