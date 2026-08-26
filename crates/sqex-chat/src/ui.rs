//! Rendering, and nothing else.
//!
//! No I/O, no network, no clock: [`App`] is a plain struct and [`draw`] is a
//! function of it. That is what lets the interesting parts be tested without a
//! terminal, and it keeps the decisions about *what to say* — which are the
//! ones with judgement in them — out of the drawing code.
//!
//! Three of those decisions come from the SIPs rather than from taste, and all
//! three are about refusing to show an empty screen where something is wrong:
//!
//! - an entry we hold and cannot open is reported, not skipped (SIP-19);
//! - being unable to decrypt the current epoch reads as *nobody sent you the
//!   key*, not as a conversation with nothing in it (SIP-17);
//! - a `since` below the exchange's oldest entry is a gap we can never fill,
//!   and presenting what remains as the whole conversation would be a lie
//!   (SIP-16).

use ratatui::Frame;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, List, ListItem, Paragraph, Wrap};
use sqnr_core::PubKey;

/// One row in the conversation list.
pub struct Row {
    pub account: PubKey,
    pub label: String,
    pub unread: usize,
    /// They have never run a client, so nothing can be sealed to them yet.
    pub waiting: bool,
}

/// One line of conversation, already resolved to what the reader should see.
pub struct Said {
    pub who: String,
    pub mine: bool,
    pub text: String,
    pub at: u64,
    pub edited: bool,
}

/// What the status line has to say, in the order it says it.
#[derive(Default)]
pub struct Trouble {
    /// Entries held and not openable.
    pub unreadable: usize,
    /// The current epoch, when we hold no key for it.
    pub no_key: Option<u32>,
    /// History older than the retention window, gone for good.
    pub gap: bool,
    /// Anything else — a refusal, a dropped connection.
    pub message: Option<String>,
}

impl Trouble {
    pub fn is_quiet(&self) -> bool {
        self.unreadable == 0 && self.no_key.is_none() && !self.gap && self.message.is_none()
    }

    /// The status line, worst first.
    ///
    /// Worst first because the line is short and the reader gets whichever
    /// fits: "you have no key" explains an empty conversation and "3 unreadable"
    /// does not.
    pub fn line(&self) -> String {
        let mut parts = Vec::new();
        if let Some(epoch) = self.no_key {
            parts.push(format!(
                "no key for epoch {epoch} — nobody has sent you one, so this cannot be read"
            ));
        }
        if self.gap {
            parts.push(
                "older messages have passed the retention window and are gone".to_string(),
            );
        }
        if self.unreadable > 0 {
            parts.push(format!(
                "{} message{} could not be opened",
                self.unreadable,
                if self.unreadable == 1 { "" } else { "s" }
            ));
        }
        if let Some(m) = &self.message {
            parts.push(m.clone());
        }
        parts.join(" · ")
    }
}

/// Everything on screen.
#[derive(Default)]
pub struct App {
    pub me: String,
    pub rows: Vec<Row>,
    pub selected: usize,
    pub said: Vec<Said>,
    pub input: String,
    pub trouble: Trouble,
    pub peer_typing: bool,
    /// The "add a contact" prompt, when it is open.
    pub adding: Option<String>,
    pub should_quit: bool,
}

impl App {
    pub fn selected_row(&self) -> Option<&Row> {
        self.rows.get(self.selected)
    }

    pub fn select_next(&mut self) {
        if !self.rows.is_empty() {
            self.selected = (self.selected + 1) % self.rows.len();
        }
    }

    pub fn select_previous(&mut self) {
        if !self.rows.is_empty() {
            self.selected = (self.selected + self.rows.len() - 1) % self.rows.len();
        }
    }
}

/// A key, short enough to sit in a list and long enough to be worth checking.
///
/// Eight base58 characters, as the admin CLI already truncates to. Never the
/// whole of an identity's authority — a person comparing keys should be shown
/// the full one, which is why the header carries it.
pub fn short(key: &PubKey) -> String {
    let full = bs58::encode(key.as_bytes()).into_string();
    full.chars().take(8).collect()
}

pub fn draw(f: &mut Frame, app: &App) {
    let outer = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1),
            Constraint::Min(1),
            Constraint::Length(3),
            Constraint::Length(1),
        ])
        .split(f.area());

    header(f, app, outer[0]);

    let panes = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Length(26), Constraint::Min(20)])
        .split(outer[1]);

    conversations(f, app, panes[0]);
    transcript(f, app, panes[1]);
    input(f, app, outer[2]);
    status(f, app, outer[3]);
}

fn header(f: &mut Frame, app: &App, area: Rect) {
    f.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled(" sqex-chat ", Style::default().add_modifier(Modifier::BOLD)),
            Span::styled(
                format!("· {}", app.me),
                Style::default().fg(Color::DarkGray),
            ),
        ])),
        area,
    );
}

fn conversations(f: &mut Frame, app: &App, area: Rect) {
    let items: Vec<ListItem> = app
        .rows
        .iter()
        .enumerate()
        .map(|(i, r)| {
            let selected = i == app.selected;
            let mut spans = vec![Span::styled(
                format!("{:<16}", truncate(&r.label, 16)),
                if selected {
                    Style::default().add_modifier(Modifier::REVERSED)
                } else {
                    Style::default()
                },
            )];
            if r.unread > 0 {
                spans.push(Span::styled(
                    format!(" {}", r.unread),
                    Style::default().fg(Color::Yellow),
                ));
            }
            if r.waiting {
                // Not an error: they are a member, they have simply never run
                // a client, so there is nowhere to send a key yet.
                spans.push(Span::styled(" ·", Style::default().fg(Color::DarkGray)));
            }
            ListItem::new(Line::from(spans))
        })
        .collect();

    let list = if items.is_empty() {
        List::new(vec![ListItem::new(Line::from(Span::styled(
            "no contacts yet — press ^N",
            Style::default().fg(Color::DarkGray),
        )))])
    } else {
        List::new(items)
    };
    f.render_widget(
        list.block(Block::default().borders(Borders::RIGHT).title("people")),
        area,
    );
}

fn transcript(f: &mut Frame, app: &App, area: Rect) {
    let mut lines: Vec<Line> = Vec::new();
    if app.trouble.gap {
        lines.push(Line::from(Span::styled(
            "─── older messages are past the retention window and cannot be recovered ───",
            Style::default().fg(Color::DarkGray),
        )));
    }
    for s in &app.said {
        let who = Style::default().fg(if s.mine { Color::Green } else { Color::Cyan });
        let mut spans = vec![
            Span::styled(clock(s.at), Style::default().fg(Color::DarkGray)),
            Span::styled(format!("{:>12} ", truncate(&s.who, 12)), who),
            Span::raw(s.text.clone()),
        ];
        if s.edited {
            spans.push(Span::styled(
                " (edited)",
                Style::default().fg(Color::DarkGray),
            ));
        }
        lines.push(Line::from(spans));
    }
    if app.said.is_empty() && app.trouble.is_quiet() {
        lines.push(Line::from(Span::styled(
            "nothing here yet",
            Style::default().fg(Color::DarkGray),
        )));
    }
    if app.peer_typing {
        lines.push(Line::from(Span::styled(
            "             typing…",
            Style::default().fg(Color::DarkGray),
        )));
    }
    let height = area.height.saturating_sub(2) as usize;
    let skip = lines.len().saturating_sub(height);
    f.render_widget(
        Paragraph::new(lines.split_off(skip.min(lines.len())))
            .wrap(Wrap { trim: false })
            .block(Block::default().borders(Borders::NONE)),
        area,
    );
}

fn input(f: &mut Frame, app: &App, area: Rect) {
    let (title, content) = match &app.adding {
        Some(buf) => ("their public key (base58), then Enter", buf.as_str()),
        None => ("message", app.input.as_str()),
    };
    f.render_widget(
        Paragraph::new(content)
            .wrap(Wrap { trim: false })
            .block(Block::default().borders(Borders::ALL).title(title)),
        area,
    );
}

fn status(f: &mut Frame, app: &App, area: Rect) {
    let (text, style) = if app.trouble.is_quiet() {
        (
            " ^C quit · Tab next · ^N add someone · Enter send".to_string(),
            Style::default().fg(Color::DarkGray),
        )
    } else {
        (
            format!(" {}", app.trouble.line()),
            Style::default().fg(Color::Yellow),
        )
    };
    f.render_widget(Paragraph::new(text).style(style), area);
}

/// Wall-clock time of day, UTC, from a Unix timestamp.
///
/// No date and no local zone: a transcript that fits in a pane wants the four
/// characters that distinguish two messages, and pulling in a timezone database
/// to render a chat line is not a trade worth making. The full timestamp is on
/// the entry for anybody who needs it.
fn clock(at: u64) -> String {
    let secs_today = at % 86_400;
    format!("{:02}:{:02} ", secs_today / 3600, (secs_today % 3600) / 60)
}

fn truncate(s: &str, n: usize) -> String {
    if s.chars().count() <= n {
        return s.to_string();
    }
    s.chars().take(n.saturating_sub(1)).collect::<String>() + "…"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trouble_leads_with_the_thing_that_explains_an_empty_screen() {
        // A reader who cannot decrypt the epoch is looking at nothing, and the
        // reason must come first — "3 unreadable" does not explain a blank
        // conversation and "no key" does.
        let t = Trouble {
            unreadable: 3,
            no_key: Some(2),
            gap: true,
            message: None,
        };
        let line = t.line();
        assert!(line.starts_with("no key for epoch 2"), "{line}");
        assert!(line.contains("retention window"));
        assert!(line.contains("3 messages could not be opened"));
        assert!(!t.is_quiet());
    }

    #[test]
    fn a_quiet_status_says_nothing() {
        let t = Trouble::default();
        assert!(t.is_quiet());
        assert_eq!(t.line(), "");
    }

    #[test]
    fn one_unreadable_message_is_not_pluralised() {
        let t = Trouble {
            unreadable: 1,
            ..Default::default()
        };
        assert_eq!(t.line(), "1 message could not be opened");
    }

    #[test]
    fn selection_wraps_in_both_directions() {
        let mut app = App {
            rows: (0..3)
                .map(|i| Row {
                    account: PubKey::new([i; 32]),
                    label: format!("p{i}"),
                    unread: 0,
                    waiting: false,
                })
                .collect(),
            ..Default::default()
        };
        app.select_previous();
        assert_eq!(app.selected, 2);
        app.select_next();
        assert_eq!(app.selected, 0);
    }

    #[test]
    fn selection_on_an_empty_list_does_not_panic() {
        let mut app = App::default();
        app.select_next();
        app.select_previous();
        assert!(app.selected_row().is_none());
    }

    #[test]
    fn the_clock_wraps_at_midnight_and_not_before() {
        assert_eq!(clock(0), "00:00 ");
        assert_eq!(clock(60), "00:01 ");
        assert_eq!(clock(23 * 3600 + 59 * 60), "23:59 ");
        // The next second is the next day's midnight, not 24:00.
        assert_eq!(clock(86_400), "00:00 ");
        assert_eq!(clock(86_400 + 3661), "01:01 ");
    }

    #[test]
    fn truncation_keeps_within_the_column() {
        assert_eq!(truncate("short", 12), "short");
        assert_eq!(truncate("a very long display name", 8).chars().count(), 8);
        // Character-wise, not byte-wise: a name is not necessarily ASCII.
        assert_eq!(truncate("ααααααααα", 4).chars().count(), 4);
    }

    use ratatui::Terminal;
    use ratatui::backend::TestBackend;

    fn render(app: &App, w: u16, h: u16) -> String {
        let mut t = Terminal::new(TestBackend::new(w, h)).unwrap();
        t.draw(|f| draw(f, app)).unwrap();
        let buf = t.backend().buffer().clone();
        (0..buf.area.height)
            .map(|y| {
                (0..buf.area.width)
                    .map(|x| buf[(x, y)].symbol().to_string())
                    .collect::<String>()
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    fn sample() -> App {
        App {
            me: "9hSR6S7W".into(),
            rows: vec![Row {
                account: PubKey::new([2; 32]),
                label: "bob".into(),
                unread: 2,
                waiting: false,
            }],
            selected: 0,
            said: vec![
                Said {
                    who: "bob".into(),
                    mine: false,
                    text: "are you there?".into(),
                    at: 3661,
                    edited: false,
                },
                Said {
                    who: "you".into(),
                    mine: true,
                    text: "i am".into(),
                    at: 3700,
                    edited: true,
                },
            ],
            ..Default::default()
        }
    }

    #[test]
    fn a_conversation_renders() {
        let out = render(&sample(), 80, 20);
        assert!(out.contains("sqex-chat"), "{out}");
        assert!(out.contains("bob"));
        assert!(out.contains("are you there?"));
        assert!(out.contains("01:01"), "the clock is missing:\n{out}");
        assert!(out.contains("(edited)"));
        // A quiet status shows the keys, not a warning.
        assert!(out.contains("^C quit"));
        assert!(out.contains("^N add"));
    }

    #[test]
    fn trouble_reaches_the_screen_rather_than_an_empty_conversation() {
        // The failure this guards is a person staring at a blank pane with no
        // idea anything is wrong.
        let mut app = sample();
        app.said.clear();
        app.trouble.no_key = Some(3);
        let out = render(&app, 100, 20);
        assert!(out.contains("no key for epoch 3"), "{out}");
        assert!(!out.contains("nothing here yet"), "it claimed the room was empty");
    }

    #[test]
    fn a_retention_gap_is_marked_in_the_transcript() {
        let mut app = sample();
        app.trouble.gap = true;
        let out = render(&app, 100, 20);
        assert!(out.contains("older messages"), "{out}");
    }

    #[test]
    fn an_empty_client_says_what_to_do_next() {
        let out = render(&App::default(), 60, 12);
        assert!(out.contains("no contacts yet"), "{out}");
    }

    #[test]
    fn a_cramped_terminal_does_not_panic() {
        // Layout constraints that overflow are a panic, not a wrapped line, and
        // a terminal is resizable by somebody who is not thinking about us.
        for (w, h) in [(20u16, 6u16), (10, 4), (200, 60), (26, 5)] {
            render(&sample(), w, h);
        }
    }

    #[test]
    fn a_long_transcript_shows_the_end_of_it() {
        let mut app = sample();
        app.said = (0..200)
            .map(|i| Said {
                who: "bob".into(),
                mine: false,
                text: format!("message {i}"),
                at: 0,
                edited: false,
            })
            .collect();
        let out = render(&app, 80, 20);
        assert!(out.contains("message 199"), "the newest message scrolled off");
        assert!(!out.contains("message 0 "), "it showed the oldest instead");
    }
}
