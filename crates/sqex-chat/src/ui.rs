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
    pub channel: [u8; 32],
    pub label: String,
    /// A group rather than a direct message. Marked, because "who am I talking
    /// to" and "who can read this" are the same question in one and not in the
    /// other.
    pub group: bool,
    /// Anybody may join and read this one. Marked differently from a private
    /// group because the difference is the whole of what matters about it.
    pub public: bool,
    pub unread: usize,
    /// They have never run a client, so nothing can be sealed to them yet.
    pub waiting: bool,
}

/// One line of conversation, already resolved to what the reader should see.
#[derive(Default)]
pub struct Said {
    /// The display name its author published, if any. **Never shown without
    /// `key`** — see [`author`].
    pub who: String,
    /// The author's key, short. Always present, always drawn.
    pub key: String,
    pub mine: bool,
    pub text: String,
    /// The entry's sequence number, which is how `/save` names a message.
    pub seq: u64,
    /// Whether this line carries a file. The sequence number is shown only for
    /// these: it is what `/save` needs, and putting it on every line would be
    /// a column of noise for the ones nobody can act on.
    pub has_file: bool,
    pub at: u64,
    pub edited: bool,
    /// Deleted by its sender or an admin. Shown as a tombstone rather than
    /// dropped: SIP-16 keeps the entry precisely so a reader can see that
    /// something was removed, instead of finding a conversation that silently
    /// does not follow.
    pub redacted: bool,
    /// The message this one answers, and a stub of what it said. Carried
    /// because a reply shown without its target is a non-sequitur, and the
    /// fold has always kept `Part::Reply` while this struct had nowhere to put
    /// it.
    pub reply_to: Option<(u64, String)>,
    /// Emoji, how many reacted with it, and whether we are one of them. The
    /// timeline has counted these since it was written and nothing has ever
    /// drawn them, so somebody could react to your message and you would never
    /// know.
    pub reactions: Vec<(String, usize, bool)>,
    /// Identities named in the message, as keys. SIP-19 puts no display name
    /// in a mention on purpose — a name inside a message is one the sender
    /// controls, rendered where a reader looks for identity.
    pub mentions: Vec<String>,
}

/// What the status line has to say, in the order it says it.
#[derive(Default)]
pub struct Trouble {
    /// Entries held and not openable **yet** — under the epoch in force, so a
    /// key could still arrive.
    pub unreadable: usize,
    /// Entries under a superseded epoch we never held a key for. Gone, and
    /// nothing that happens later brings them back.
    pub lost: usize,
    /// The current epoch, when we hold no key for it.
    pub no_key: Option<u32>,
    /// History older than the retention window, gone for good.
    pub gap: bool,
    /// This conversation's sequence space restarted — it was destroyed and
    /// recreated under the same identifier — so what came before it was
    /// dropped. Worth saying once: the reader had messages here and now does
    /// not, and nothing else would explain where they went.
    pub restarted: bool,
    /// Anything else — a refusal, a dropped connection.
    pub message: Option<String>,
}

impl Trouble {
    /// Whether there is nothing to act on.
    ///
    /// `lost` is deliberately not counted: it is history that is gone, said
    /// once in the transcript where the messages would have been, and not a
    /// fault for somebody to chase every session.
    pub fn is_quiet(&self) -> bool {
        self.unreadable == 0
            && self.no_key.is_none()
            && !self.gap
            && !self.restarted
            && self.message.is_none()
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
        if self.restarted {
            parts.push(
                "this conversation was restarted — everything before it is gone".to_string(),
            );
        }
        if self.unreadable > 0 {
            parts.push(format!(
                "{} message{} cannot be opened yet",
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

/// One row of a directory search.
pub struct Found {
    pub channel: [u8; 32],
    pub name: String,
    pub topic: String,
    pub members: u16,
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
    /// The last directory search, if one is showing. Numbered, because joining
    /// by index beats pasting sixty-four hex characters.
    pub found: Vec<Found>,
    /// How many matched in total, which may exceed what one reply carries.
    pub found_total: u32,
    /// The message under the cursor, as an index into `said`.
    ///
    /// Reacting, replying, editing and deleting all act on *a message*, and
    /// there was no way to say which: every key went into the input line.
    /// Naming one by sequence number works for a script and not for a person.
    pub picked: Option<usize>,
    /// The reaction picker is open over the picked message.
    pub reacting: bool,
    /// A reply the next send will carry, and a stub of what it answers.
    pub replying: Option<(u64, String)>,
    /// The message the input line is rewriting, if it is rewriting one.
    pub editing: Option<u64>,
    /// What the selected channel is for. Folded from a sealed entry since the
    /// timeline was written and never drawn, so a topic could be set and no
    /// client would show it.
    pub topic: String,
    /// The selected channel has a picture. Said rather than drawn: a terminal
    /// cannot show one, and a coloured-block approximation is not the picture.
    pub has_avatar: bool,
    pub should_quit: bool,
}

/// The reactions offered by the picker.
///
/// A short list on purpose: a terminal has no emoji search, and a long one
/// would be a scrolling grid nobody wants. Any emoji can still be sent by a
/// client that offers more — the wire carries the string, not an index into
/// this.
pub const REACTIONS: &[&str] = &["👍", "🎉", "❤️", "😂", "🤔", "👀"];

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

/// How wide the author column is. A name and a key both have to fit, because
/// [`author`] will not drop the key to make room.
const AUTHOR: usize = 22;

/// The author of a line: a name **and** a key, or a key alone.
///
/// SIP-21, on display names: "A client MUST show the key alongside the name
/// wherever the distinction could matter … and MUST NOT let a name be the only
/// thing a person sees at those moments. This is the one requirement in this
/// SIP that is load-bearing."
///
/// A name is a claim its subject makes. Two accounts may publish the same one,
/// or names differing by a homoglyph, a combining mark or a bidirectional
/// override, and the key is the only thing that tells them apart. So when the
/// column is too narrow for both, it is the **name** that is cut — never the
/// key, which is what makes this function the whole of the rule.
///
/// `mine` is the exception, and a narrow one: our own messages are the one
/// place impersonation is not a question a reader has.
pub fn author(name: &str, key: &str, mine: bool) -> String {
    if mine {
        return "you".to_string();
    }
    if name.is_empty() {
        return key.to_string();
    }
    // The key, the brackets and a space: what the name may have is whatever is
    // left, and never less than nothing.
    let room = AUTHOR.saturating_sub(key.chars().count() + 3);
    if room < 2 {
        return key.to_string();
    }
    format!("{} ({key})", truncate(name, room))
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
    let mut spans = vec![
        Span::styled(" sqex-chat ", Style::default().add_modifier(Modifier::BOLD)),
        Span::styled(
            format!("· {}", app.me),
            Style::default().fg(Color::DarkGray),
        ),
    ];
    if !app.topic.is_empty() {
        spans.push(Span::styled(
            format!(" · {}", truncate(&app.topic, 60)),
            Style::default().fg(Color::Cyan),
        ));
    }
    if app.has_avatar {
        spans.push(Span::styled(
            " · /avatar save <path>",
            Style::default().fg(Color::DarkGray),
        ));
    }
    f.render_widget(Paragraph::new(Line::from(spans)), area);
}

fn conversations(f: &mut Frame, app: &App, area: Rect) {
    let items: Vec<ListItem> = app
        .rows
        .iter()
        .enumerate()
        .map(|(i, r)| {
            let selected = i == app.selected;
            let base = if selected {
                Style::default().add_modifier(Modifier::REVERSED)
            } else {
                Style::default()
            };
            let mut spans = vec![
                // Yellow for public: anybody may join and read it, and that is
                // the one thing about a row worth seeing before you type.
                Span::styled(
                    if r.group { "#" } else { " " }.to_string(),
                    if r.public {
                        base.fg(Color::Yellow)
                    } else {
                        base
                    },
                ),
                Span::styled(format!("{:<15}", truncate(&r.label, 15)), base),
            ];
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
    if !app.found.is_empty() {
        directory(f, app, area);
        return;
    }
    let mut lines: Vec<Line> = Vec::new();
    if app.trouble.lost > 0 {
        // In the transcript, above the messages that did survive, because that
        // is where the missing ones would have been. A status line would say
        // it every session as though something were still going wrong.
        lines.push(Line::from(Span::styled(
            format!(
                "─── {} earlier message{} {} lost with this client's keys ───",
                app.trouble.lost,
                if app.trouble.lost == 1 { "" } else { "s" },
                if app.trouble.lost == 1 { "was" } else { "were" }
            ),
            Style::default().fg(Color::DarkGray),
        )));
    }
    if app.trouble.gap {
        lines.push(Line::from(Span::styled(
            "─── older messages are past the retention window and cannot be recovered ───",
            Style::default().fg(Color::DarkGray),
        )));
    }
    for (i, s) in app.said.iter().enumerate() {
        let picked = app.picked == Some(i);
        let who = Style::default().fg(if s.mine { Color::Green } else { Color::Cyan });

        // What is being answered goes above the answer, indented under the
        // author column. A reply rendered without it reads as a non-sequitur,
        // and the reader has no way to find the target by hand.
        if let Some((seq, stub)) = &s.reply_to {
            lines.push(Line::from(vec![
                Span::raw(" ".repeat(clock(s.at).chars().count() + AUTHOR + 1)),
                Span::styled(
                    format!("↳ {seq}: {}", truncate(stub, 48)),
                    Style::default().fg(Color::DarkGray),
                ),
            ]));
        }

        let body = if s.redacted {
            Span::styled(
                "message deleted",
                Style::default()
                    .fg(Color::DarkGray)
                    .add_modifier(Modifier::ITALIC),
            )
        } else {
            Span::raw(s.text.clone())
        };
        let mut spans = vec![
            // The cursor is a character in the gutter rather than a reversed
            // line: the transcript already uses colour to say who spoke, and
            // inverting it would take that away exactly where it is needed.
            Span::styled(
                if picked { "▸" } else { " " },
                Style::default().fg(Color::Yellow),
            ),
            Span::styled(clock(s.at), Style::default().fg(Color::DarkGray)),
            Span::styled(
                format!("{:>AUTHOR$} ", author(&s.who, &s.key, s.mine)),
                who,
            ),
            body,
        ];
        if s.has_file && !s.redacted {
            spans.push(Span::styled(
                format!("  /save {} ", s.seq),
                Style::default().fg(Color::DarkGray),
            ));
        }
        if s.edited && !s.redacted {
            spans.push(Span::styled(
                " (edited)",
                Style::default().fg(Color::DarkGray),
            ));
        }
        // Mentions as keys, never as names. SIP-19 leaves the display name out
        // of a mention deliberately, and putting one in here from a profile
        // would be showing the reader a name the *sender* chose at the moment
        // they are working out who is being talked about.
        for m in &s.mentions {
            spans.push(Span::styled(
                format!(" @{m}"),
                Style::default().fg(Color::Magenta),
            ));
        }
        lines.push(Line::from(spans));

        if !s.reactions.is_empty() && !s.redacted {
            let mut row = vec![Span::raw(
                " ".repeat(clock(s.at).chars().count() + AUTHOR + 2),
            )];
            for (emoji, count, mine) in &s.reactions {
                row.push(Span::styled(
                    format!("{emoji} {count}  "),
                    if *mine {
                        Style::default().fg(Color::Yellow)
                    } else {
                        Style::default().fg(Color::DarkGray)
                    },
                ));
            }
            lines.push(Line::from(row));
        }

        if picked && app.reacting {
            let mut row = vec![Span::raw(" ".repeat(clock(s.at).chars().count() + AUTHOR + 2))];
            for (n, emoji) in REACTIONS.iter().enumerate() {
                row.push(Span::styled(
                    format!("{}:{emoji}  ", n + 1),
                    Style::default().fg(Color::Yellow),
                ));
            }
            row.push(Span::styled(
                "Esc",
                Style::default().fg(Color::DarkGray),
            ));
            lines.push(Line::from(row));
        }
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

/// The directory, numbered so `/join <n>` can act on it.
fn directory(f: &mut Frame, app: &App, area: Rect) {
    let mut lines = vec![Line::from(Span::styled(
        format!(
            "{} public channel{} — /join <n> to enter, Esc to go back",
            app.found_total,
            if app.found_total == 1 { "" } else { "s" }
        ),
        Style::default().fg(Color::DarkGray),
    ))];
    for (i, c) in app.found.iter().enumerate() {
        let mut spans = vec![
            Span::styled(format!("{:>3}. ", i + 1), Style::default().fg(Color::DarkGray)),
            Span::styled(format!("#{}", c.name), Style::default().fg(Color::Yellow)),
            Span::styled(
                format!("  {} member{}", c.members, if c.members == 1 { "" } else { "s" }),
                Style::default().fg(Color::DarkGray),
            ),
        ];
        if !c.topic.is_empty() {
            spans.push(Span::styled(
                format!("  {}", truncate(&c.topic, 40)),
                Style::default().fg(Color::DarkGray),
            ));
        }
        lines.push(Line::from(spans));
    }
    f.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }), area);
}

fn input(f: &mut Frame, app: &App, area: Rect) {
    // The title says what Enter will do. Sending a reply, rewriting an old
    // message and posting a new one all look identical from the input line
    // otherwise, and only one of them is undoable.
    let editing;
    let replying;
    let (title, content) = match (&app.adding, app.editing, &app.replying) {
        (Some(buf), _, _) => ("their public key (base58), then Enter", buf.as_str()),
        (None, Some(seq), _) => {
            editing = format!("rewriting message {seq} — Esc to leave it alone");
            (editing.as_str(), app.input.as_str())
        }
        (None, None, Some((seq, stub))) => {
            replying = format!("replying to {seq}: {} — Esc to stop", truncate(stub, 40));
            (replying.as_str(), app.input.as_str())
        }
        (None, None, None) => ("message", app.input.as_str()),
    };
    f.render_widget(
        Paragraph::new(content)
            .wrap(Wrap { trim: false })
            .block(Block::default().borders(Borders::ALL).title(title)),
        area,
    );
}

/// The keys and commands, as many as the terminal is wide enough to hold.
///
/// A fixed string was fine while there were three groups of them and stopped
/// being fine as they were added: at 80 columns the end of the line was simply
/// cut off, so the commands that fell off were undiscoverable and nothing said
/// so. Ordered by how often each is wanted, and a group is either shown whole
/// or not at all — half of "/file /save" helps nobody.
fn keys_line(width: usize) -> String {
    const GROUPS: &[&str] = &[
        "^C quit",
        "Tab",
        "Esc pick",
        "^N add",
        "/file /save /redact",
        "/public /find /join",
        "/new /invite /kick",
        "/name /topic /avatar",
        "/profile /block /blocked",
        "/retain /close /read",
    ];
    let mut out = String::new();
    for g in GROUPS {
        let sep = if out.is_empty() { " " } else { " · " };
        if out.chars().count() + sep.len() + g.chars().count() > width {
            break;
        }
        out += sep;
        out += g;
    }
    out
}

fn status(f: &mut Frame, app: &App, area: Rect) {
    let (text, style) = if app.picked.is_some() {
        // The mode's own keys, and only them. A person who has just entered a
        // mode by pressing Esc needs to be told what it does, and the general
        // command list is the wrong answer to that question.
        let mine = app
            .picked
            .and_then(|i| app.said.get(i))
            .is_some_and(|s| s.mine);
        (
            format!(
                " ↑↓ move · a react · r reply{} · d delete · Esc back",
                if mine { " · e rewrite" } else { "" }
            ),
            Style::default().fg(Color::Yellow),
        )
    } else if app.trouble.is_quiet() {
        (
            keys_line(area.width as usize),
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
            lost: 0,
            no_key: Some(2),
            gap: true,
            restarted: false,
            message: None,
        };
        let line = t.line();
        assert!(line.starts_with("no key for epoch 2"), "{line}");
        assert!(line.contains("retention window"));
        assert!(line.contains("3 messages cannot be opened yet"));
        assert!(!t.is_quiet());

        // A restarted sequence space is not quiet either: the reader had
        // messages here a moment ago and now does not, and nothing else on
        // screen would account for it (SIP-16).
        let t = Trouble {
            restarted: true,
            ..Default::default()
        };
        assert!(!t.is_quiet());
        assert!(t.line().contains("restarted"), "{}", t.line());
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
        assert_eq!(t.line(), "1 message cannot be opened yet");
    }

    #[test]
    fn selection_wraps_in_both_directions() {
        let mut app = App {
            rows: (0..3)
                .map(|i| Row {
                    channel: [i; 32],
                    label: format!("p{i}"),
                    group: false,
                    public: false,
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
                channel: [2; 32],
                label: "bob".into(),
                group: false,
                public: false,
                unread: 2,
                waiting: false,
            }],
            selected: 0,
            said: vec![
                Said {
                    who: "bob".into(),
                    mine: false,
                    text: "are you there?".into(),
                    seq: 3,
                    has_file: false,
                    at: 3661,
                    edited: false,
                    redacted: false,
                    ..Default::default()
                },
                Said {
                    who: "you".into(),
                    mine: true,
                    text: "i am".into(),
                    seq: 4,
                    has_file: false,
                    at: 3700,
                    edited: true,
                    redacted: false,
                    ..Default::default()
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
        assert!(out.contains("/file"));
        assert!(out.contains("/find"));
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
    fn a_line_with_a_file_shows_how_to_save_it() {
        let mut app = sample();
        app.said[0].text = "[notes.md, 4 KiB]".into();
        app.said[0].has_file = true;
        let out = render(&app, 100, 20);
        assert!(out.contains("[notes.md, 4 KiB]"), "{out}");
        assert!(out.contains("/save 3"), "the message number is not shown:\n{out}");
        // And not on the line that has no file to save.
        assert!(!out.contains("/save 4"));
    }

    #[test]
    fn lost_history_is_stated_once_in_the_transcript_not_in_the_status() {
        // It is permanent, so a status line repeating it every session is how
        // a status line stops being read.
        let mut app = sample();
        app.trouble.lost = 17;
        let out = render(&app, 100, 20);
        assert!(out.contains("17 earlier messages were lost"), "{out}");
        assert!(
            out.contains("^C quit"),
            "the status line should be free for things to act on"
        );
        assert!(app.trouble.is_quiet(), "lost history is not a fault to chase");
    }

    #[test]
    fn something_to_wait_for_reads_differently_from_something_gone() {
        let t = Trouble {
            unreadable: 2,
            ..Default::default()
        };
        assert_eq!(t.line(), "2 messages cannot be opened yet");
        assert!(!t.is_quiet());
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
    fn the_key_line_is_cut_between_groups_and_never_inside_one() {
        // A narrow terminal loses the least-wanted commands, not the tail of a
        // word: "/file /sa" is worse than not mentioning /file at all.
        for width in 1..140usize {
            let line = keys_line(width);
            assert!(
                line.chars().count() <= width,
                "the key line overflowed {width} columns: {line:?}"
            );
            for group in line.trim().split(" · ").filter(|g| !g.is_empty()) {
                assert!(
                    [
                        "^C quit",
                        "Tab",
                        "^N add",
                        "Esc pick",
                        "/file /save /redact",
                        "/public /find /join",
                        "/new /invite /kick",
                        "/name /topic /avatar",
                        "/profile /block /blocked",
                        "/retain /close /read",
                    ]
                    .contains(&group),
                    "a group was cut in half at width {width}: {group:?}"
                );
            }
        }
        // And a wide terminal gets all of them.
        assert!(keys_line(200).contains("/retain /close /read"));
    }

    #[test]
    fn a_cramped_terminal_does_not_panic() {
        // Layout constraints that overflow are a panic, not a wrapped line, and
        // a terminal is resizable by somebody who is not thinking about us.
        for (w, h) in [(20u16, 6u16), (10, 4), (200, 60), (26, 5)] {
            render(&sample(), w, h);
        }
    }

    /// SIP-16 keeps a redacted entry precisely so a reader can see that
    /// something was removed rather than find a conversation that silently does
    /// not follow. Dropping the line instead is what made /redact look like it
    /// deleted messages without trace.
    #[test]
    fn a_redacted_message_is_shown_as_a_tombstone() {
        let mut app = sample();
        app.said = vec![Said {
            who: "bob".into(),
            mine: false,
            text: "the original words".into(),
            seq: 9,
            has_file: true,
            at: 0,
            edited: true,
            redacted: true,
            ..Default::default()
        }];
        let out = render(&app, 80, 20);

        assert!(out.contains("message deleted"), "no tombstone drawn:\n{out}");
        assert!(
            !out.contains("the original words"),
            "the redacted text was rendered anyway:\n{out}"
        );
        // A tombstone has nothing to save and was not edited into existence.
        // The footer always names /save, so the check is for the per-message
        // form, which carries the sequence number.
        assert!(
            !out.contains("/save 9"),
            "a tombstone offered a file:\n{out}"
        );
        assert!(
            !out.contains("(edited)"),
            "a tombstone claimed to have been edited:\n{out}"
        );
        // And it is still somebody's line, at a time, or the gap says nothing.
        assert!(out.contains("bob"), "the tombstone lost its author:\n{out}");
    }

    /// The fold has counted reactions since it was written and nothing drew
    /// them, so somebody could react to your message and you would never know.
    #[test]
    fn reactions_are_drawn_under_the_message_they_belong_to() {
        let mut app = sample();
        app.said = vec![
            Said {
                who: "bob".into(),
                text: "we ship on friday".into(),
                seq: 3,
                at: 3661,
                reactions: vec![("👍".into(), 2, true), ("🎉".into(), 1, false)],
                ..Default::default()
            },
            Said {
                who: "you".into(),
                mine: true,
                text: "agreed".into(),
                seq: 4,
                at: 3700,
                ..Default::default()
            },
        ];
        let out = render(&app, 80, 20);
        let lines: Vec<&str> = out.lines().collect();
        let at = lines
            .iter()
            .position(|l| l.contains("we ship on friday"))
            .expect("the message is not on screen");
        let row = lines[at + 1];
        assert!(row.contains("👍"), "no reaction row under the message:\n{out}");
        assert!(row.contains('2'), "the count is missing:\n{out}");
        assert!(row.contains("🎉"), "only one of the two was drawn:\n{out}");
        // And under *that* message, not the next one.
        assert!(
            !lines[at + 1].contains("agreed"),
            "the reaction row landed on the wrong message:\n{out}"
        );
    }

    /// A reply with no sign of what it answers reads as a non-sequitur, and
    /// there is no way to find the target by hand.
    #[test]
    fn a_reply_shows_what_it_answers() {
        let mut app = sample();
        app.said = vec![Said {
            who: "you".into(),
            mine: true,
            text: "friday".into(),
            seq: 8,
            at: 3700,
            reply_to: Some((3, "thursday or friday?".into())),
            ..Default::default()
        }];
        let out = render(&app, 80, 20);
        assert!(out.contains("thursday or friday?"), "{out}");
        assert!(out.contains("friday"), "{out}");
    }

    /// A target we no longer hold still shows the marker. "Answering something
    /// we cannot see" is the truth; dropping it would hide that a reply is a
    /// reply at all.
    #[test]
    fn a_reply_to_something_we_do_not_hold_still_says_it_is_one() {
        let mut app = sample();
        app.said = vec![Said {
            who: "bob".into(),
            text: "yes".into(),
            seq: 8,
            at: 3700,
            reply_to: Some((3, "(not held)".into())),
            ..Default::default()
        }];
        let out = render(&app, 80, 20);
        assert!(out.contains("↳ 3"), "the reply marker was dropped:\n{out}");
    }

    #[test]
    fn the_picked_message_is_visibly_picked_and_the_keys_change() {
        let mut app = sample();
        app.picked = Some(1);
        let out = render(&app, 80, 20);
        assert!(out.contains('▸'), "nothing marks the picked message:\n{out}");
        // The mode's own keys replace the command list: somebody who just
        // pressed Esc needs to be told what the mode does.
        assert!(out.contains("a react"), "{out}");
        assert!(out.contains("Esc back"), "{out}");
        // The second message is ours, so rewriting is offered.
        assert!(out.contains("e rewrite"), "{out}");

        // The first is not, and it is not offered — a reader would ignore the
        // edit, so offering it would be a promise the protocol breaks.
        app.picked = Some(0);
        let out = render(&app, 80, 20);
        assert!(!out.contains("e rewrite"), "offered to rewrite bob's message:\n{out}");
    }

    #[test]
    fn the_reaction_picker_offers_numbered_choices() {
        let mut app = sample();
        app.picked = Some(0);
        app.reacting = true;
        let out = render(&app, 80, 20);
        assert!(out.contains("1:"), "the picker is not numbered:\n{out}");
        assert!(out.contains(REACTIONS[0]), "{out}");
    }

    /// SIP-19 leaves the display name out of a mention deliberately, so what
    /// is rendered is the key.
    #[test]
    fn a_mention_is_shown_as_a_key() {
        let mut app = sample();
        app.said = vec![Said {
            who: "bob".into(),
            text: "ask them".into(),
            seq: 3,
            at: 3661,
            mentions: vec!["ZfS2aD5B".into()],
            ..Default::default()
        }];
        let out = render(&app, 80, 20);
        assert!(out.contains("@ZfS2aD5B"), "the mention was dropped:\n{out}");
    }

    #[test]
    fn a_picked_tombstone_offers_nothing_to_do_to_it() {
        let mut app = sample();
        app.said = vec![Said {
            who: "bob".into(),
            text: String::new(),
            seq: 3,
            at: 3661,
            redacted: true,
            reactions: vec![("👍".into(), 1, false)],
            ..Default::default()
        }];
        app.picked = Some(0);
        let out = render(&app, 80, 20);
        // Reactions to a message that no longer exists are not shown against
        // the gap: the tombstone is a record that something was removed, and
        // decorating it re-creates a little of what was deleted.
        assert!(
            !out.contains("👍"),
            "a deleted message kept its reactions:\n{out}"
        );
    }

    /// The topic has been folded from a sealed entry since the timeline was
    /// written and never drawn, so it could be set and no client would show it.
    #[test]
    fn the_topic_is_on_screen_and_an_avatar_says_how_to_look_at_it() {
        let mut app = sample();
        app.topic = "what we ship in October".into();
        let out = render(&app, 100, 20);
        assert!(out.contains("what we ship in October"), "{out}");
        // Nothing claims a picture until there is one.
        assert!(!out.contains("/avatar save"), "{out}");

        app.has_avatar = true;
        let out = render(&app, 100, 20);
        assert!(
            out.contains("/avatar save"),
            "a picture was set and nothing said how to see it:\n{out}"
        );
    }

    /// SIP-21's one load-bearing requirement: "A client MUST show the key
    /// alongside the name wherever the distinction could matter … and MUST NOT
    /// let a name be the only thing a person sees at those moments."
    ///
    /// A name is a claim its subject makes, and two accounts may publish the
    /// same one. If this ever passes with the key absent, the client has become
    /// a thing that can be impersonated by typing.
    #[test]
    fn a_display_name_never_appears_without_its_key() {
        assert_eq!(author("", "9hMLdY3V", false), "9hMLdY3V");
        let line = author("Alice", "9hMLdY3V", false);
        assert!(line.contains("Alice"), "{line}");
        assert!(line.contains("9hMLdY3V"), "{line}");

        // Two accounts, the same claimed name. Only the key separates them, so
        // only the key can be the thing that is always there.
        let one = author("Alice", "9hMLdY3V", false);
        let two = author("Alice", "E4LUkjrZ", false);
        assert_ne!(one, two, "two accounts named Alice rendered identically");

        // A name that will not fit is cut. The key is not.
        let long = author(&"n".repeat(200), "9hMLdY3V", false);
        assert!(
            long.contains("9hMLdY3V"),
            "a long name pushed the key off the line: {long}"
        );
        assert!(long.chars().count() <= AUTHOR, "{long}");

        // Including one made of characters that are wide, combining, or
        // right-to-left — the exact material an impersonation is built from.
        for name in ["🏳️‍🌈🏳️‍🌈🏳️‍🌈🏳️‍🌈🏳️‍🌈", "e\u{301}\u{301}\u{301}\u{301}", "\u{202e}ecilA"] {
            let line = author(name, "9hMLdY3V", false);
            assert!(
                line.contains("9hMLdY3V"),
                "the key was lost rendering {name:?}: {line}"
            );
        }

        // Our own messages are the one place impersonation is not a question a
        // reader has.
        assert_eq!(author("Alice", "9hMLdY3V", true), "you");
    }

    #[test]
    fn the_transcript_shows_a_name_with_the_key_it_belongs_to() {
        let mut app = sample();
        app.said = vec![Said {
            who: "Alice".into(),
            key: "9hMLdY3V".into(),
            text: "hello".into(),
            seq: 3,
            at: 3661,
            ..Default::default()
        }];
        let out = render(&app, 100, 20);
        assert!(out.contains("Alice"), "{out}");
        assert!(
            out.contains("9hMLdY3V"),
            "a name reached the screen with no key beside it:\n{out}"
        );
    }

    #[test]
    fn a_long_transcript_shows_the_end_of_it() {
        let mut app = sample();
        app.said = (0..200)
            .map(|i| Said {
                who: "bob".into(),
                mine: false,
                text: format!("message {i}"),
                seq: i,
                has_file: false,
                at: 0,
                edited: false,
                redacted: false,
                ..Default::default()
            })
            .collect();
        let out = render(&app, 80, 20);
        assert!(out.contains("message 199"), "the newest message scrolled off");
        assert!(!out.contains("message 0 "), "it showed the oldest instead");
    }
}
