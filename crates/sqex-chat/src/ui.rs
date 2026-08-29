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
use ratatui::layout::{Alignment, Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, List, ListItem, Paragraph, Wrap};
use sqnr_core::PubKey;
use unicode_width::UnicodeWidthStr;

/// One row in the conversation list.
pub struct Row {
    pub channel: [u8; 32],
    /// What to call this conversation: a person's display name or the local
    /// label for a direct message, the channel's own name for a group. Empty
    /// when a direct message's peer has published no name and we chose none.
    pub label: String,
    /// The peer's key, short, for a direct message. `None` for a group, whose
    /// name belongs to the channel and not to a person.
    ///
    /// Present so the list can obey SIP-21 the same way the transcript does:
    /// choosing which conversation to type into is exactly a moment where
    /// mistaking one person for another matters.
    pub key: Option<String>,
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
    /// The last thing said here, and when — the line that makes a list of
    /// conversations answer "what is going on" rather than only "what exists".
    pub preview: String,
    pub at: u64,
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
    /// How far this message of ours has got, if we can tell. `None` on
    /// somebody else's — a receipt is about what happened to what you sent.
    pub receipt: Option<Receipt>,
    /// Deleted by its sender or an admin. Shown as a tombstone rather than
    /// dropped: SIP-16 keeps the entry precisely so a reader can see that
    /// something was removed, instead of finding a conversation that silently
    /// does not follow.
    pub redacted: bool,
    /// What this one answers: who wrote it, and a stub of what they said.
    ///
    /// The author matters more than the number. "↳ 57: llll" names a sequence
    /// nobody has memorised; "↳ Alice (6xhq7AJ4): llll" says who is being
    /// answered, and carries the key with the name like everywhere else.
    pub reply_to: Option<(String, String)>,
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

/// How far a message of ours has travelled.
///
/// Deliberately never claims more than the exchange can show. An account that
/// has opted out of receipts reports having read nothing, and is
/// indistinguishable from one that has read nothing — that is what opting out
/// is for. So `Read` means *everybody* here is known to have read it, and a
/// message that stays at `Delivered` may well have been read by somebody who
/// declined to say. Under-claiming is the only safe direction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Receipt {
    /// The exchange took it. Nobody has fetched it yet.
    Sent,
    /// Everybody here has it.
    Delivered,
    /// Everybody here has read it.
    Read,
}

/// One message a search turned up.
pub struct Hit {
    pub seq: u64,
    /// Composed the same way the transcript composes an author, so a result
    /// carries the key beside the name like everywhere else (SIP-21).
    pub who: String,
    pub at: u64,
    pub text: String,
    /// Where the query matched, so it can be picked out of the line.
    pub at_byte: usize,
    pub len: usize,
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
    /// Which conversation is open, **by channel** rather than by position.
    ///
    /// The list is ordered by what happened last, so it reorders under the
    /// cursor whenever a message arrives anywhere. An index would then point
    /// at a different conversation than the one being read — and would move
    /// somebody mid-sentence into a channel they had not chosen.
    pub selected: Option<[u8; 32]>,
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
    /// The command list is on screen, over the transcript.
    pub helping: bool,
    /// What a search turned up, and what was searched for. A view over the
    /// transcript, like the directory and the command list.
    pub hits: Vec<Hit>,
    pub query: String,
    pub searching: bool,
    /// The first message not read when this conversation was opened, if there
    /// was one. A line goes above it.
    pub divider: Option<u64>,
    /// Now, so a day separator can leave the year off the current one and put
    /// it on older history, where a bare date is a trap.
    pub now: u64,
    pub should_quit: bool,
}

/// The reactions offered by the picker.
///
/// A short list on purpose: a terminal has no emoji search, and a long one
/// would be a scrolling grid nobody wants. Any emoji can still be sent by a
/// client that offers more — the wire carries the string, not an index into
/// this.
pub const REACTIONS: &[&str] = &["👍", "🎉", "🧡", "😂", "🤔", "👀"];

impl App {
    pub fn selected_row(&self) -> Option<&Row> {
        self.rows.iter().find(|r| Some(r.channel) == self.selected)
    }

    /// Where the cursor is now, or the top of the list if what it named has
    /// gone — left, closed, or never there.
    pub fn selected_at(&self) -> Option<usize> {
        if self.rows.is_empty() {
            return None;
        }
        Some(
            self.rows
                .iter()
                .position(|r| Some(r.channel) == self.selected)
                .unwrap_or(0),
        )
    }

    pub fn select_next(&mut self) {
        self.select_by(1);
    }

    pub fn select_previous(&mut self) {
        self.select_by(-1);
    }

    fn select_by(&mut self, step: isize) {
        let Some(at) = self.selected_at() else { return };
        let n = self.rows.len();
        let next = (at as isize + step).rem_euclid(n as isize) as usize;
        self.selected = Some(self.rows[next].channel);
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

/// A small block of colour derived from an account key.
///
/// Derived, not uploaded. SIP-21 is explicit that an avatar is a claim like a
/// display name — two accounts may publish the same picture, and one of them
/// may have taken it from the other — so a picture is exactly the wrong thing
/// to identify somebody by. A pattern computed from the key differs whenever
/// the key does, cannot be chosen, and so reinforces the key-beside-name rule
/// instead of competing with it.
///
/// Two cells wide and one tall, each cell carrying two pixels: `▀` painted
/// with a foreground for the top half and a background for the bottom. That is
/// four pixels of a symmetric pattern, which is not a portrait and is not
/// meant to be — it is a colour somebody learns to recognise in a list.
pub fn identicon(key: &str) -> Vec<Span<'static>> {
    let h = fnv(key.as_bytes());
    // Two hues a third of the wheel apart, so the halves stay distinguishable
    // whatever the key, and mid-lightness so both work on dark and light.
    let a = hue((h & 0xFF) as u8);
    let b = hue(((h >> 8) & 0xFF) as u8 / 3 * 2);
    // Four bits choose which of the four pixels take the second colour. The
    // pattern is mirrored across the vertical axis, which is what makes these
    // read as a shape rather than as noise.
    let bits = ((h >> 16) & 0b11) as u8;
    let pick = |on: bool| if on { b } else { a };
    vec![
        Span::styled(
            "▀",
            Style::default()
                .fg(pick(bits & 0b01 != 0))
                .bg(pick(bits & 0b10 != 0)),
        ),
        Span::styled(
            "▀",
            Style::default()
                .fg(pick(bits & 0b10 != 0))
                .bg(pick(bits & 0b01 != 0)),
        ),
    ]
}

/// How wide an identicon is on screen, so callers can leave room for it.
pub const ICON: usize = 2;

/// FNV-1a. Not a security choice — nothing here is secret, and the key it is
/// derived from is public — only a cheap way to spread keys across colours.
fn fnv(bytes: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in bytes {
        h ^= *b as u64;
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    h
}

/// A byte to a colour, going round the wheel at a fixed saturation so no key
/// lands on something unreadably dark or washed out.
fn hue(byte: u8) -> Color {
    let sector = byte as u32 * 6 / 256;
    let within = (byte as u32 * 6 % 256) * 255 / 256;
    let (lo, hi) = (70u8, 220u8);
    let up = (lo as u32 + within * (hi - lo) as u32 / 255) as u8;
    let down = (hi as u32 - within * (hi - lo) as u32 / 255) as u8;
    match sector {
        0 => Color::Rgb(hi, up, lo),
        1 => Color::Rgb(down, hi, lo),
        2 => Color::Rgb(lo, hi, up),
        3 => Color::Rgb(lo, down, hi),
        4 => Color::Rgb(up, lo, hi),
        _ => Color::Rgb(hi, lo, down),
    }
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
    // A contact nobody has named is labelled with its own short key, and
    // pairing that with itself renders "E4LUkjrZ (E4LUkjrZ)". A name that *is*
    // the key is not a name. Handled here rather than at each call site,
    // because it is a property of the pairing.
    if name.is_empty() || name == key {
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
        // Wide enough for an identicon, a name and the key beside it.
        .constraints([Constraint::Length(30), Constraint::Min(20)])
        .split(outer[1]);

    conversations(f, app, panes[0]);
    transcript(f, app, panes[1]);
    input(f, app, outer[2]);
    status(f, app, outer[3]);
}

fn header(f: &mut Frame, app: &App, area: Rect) {
    let dim = Style::default().fg(Color::DarkGray);
    let mut spans = Vec::new();
    if !app.topic.is_empty() {
        spans.push(Span::styled(
            truncate(&app.topic, 60),
            Style::default().fg(Color::Cyan),
        ));
        spans.push(Span::styled(" · ", dim));
    }
    if app.has_avatar {
        spans.push(Span::styled("/avatar save <path> · ", dim));
    }
    spans.push(Span::styled(app.me.clone(), dim));
    // The name of the thing goes in the corner, where a title bar puts it and
    // where the eye is not looking for anything else — with the version, so
    // that "which one am I running" never needs asking. It has been the first
    // question of half the problems today.
    spans.push(Span::styled(
        " sqex-chat ",
        Style::default().add_modifier(Modifier::BOLD),
    ));
    spans.push(Span::styled(
        format!("{} ", env!("CARGO_PKG_VERSION")),
        dim,
    ));
    f.render_widget(
        Paragraph::new(Line::from(spans).alignment(Alignment::Right)),
        area,
    );
}

/// What a row is called: a name and a key, or whichever of the two there is.
///
/// The key is not dropped to make room for the name, for the reason SIP-21
/// gives — two accounts may publish the same name — and picking the wrong
/// conversation to type into is precisely the harm that rule is about.
fn row_label(r: &Row, width: usize) -> String {
    match &r.key {
        Some(key) => author(&r.label, key, false),
        // A group's name is the channel's, not a person's. There is no key it
        // could be confused with.
        None => truncate(&r.label, width),
    }
}

fn conversations(f: &mut Frame, app: &App, area: Rect) {
    // The marker, the identicon, the border, and room for an unread count.
    let w = (area.width as usize)
        .saturating_sub(7 + ICON)
        .clamp(8, AUTHOR);
    let items: Vec<ListItem> = app
        .rows
        .iter()
        .map(|r| {
            let selected = Some(r.channel) == app.selected;
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
            ];
            // A direct message is a person, and gets their identicon. A
            // channel is not, so it gets the space instead — inventing a face
            // for a room would say something untrue about what it is.
            match &r.key {
                Some(key) => spans.extend(identicon(key)),
                None => spans.push(Span::styled(" ".repeat(ICON), base)),
            }
            spans.push(Span::styled(" ", base));
            spans.push(Span::styled(format!("{:<w$}", row_label(r, w), w = w), base));
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
            // A second line, the way every chat client does it: when, and the
            // beginning of what was said. Without it the list says only which
            // conversations exist.
            let mut under = Vec::new();
            if r.at > 0 {
                under.push(Span::styled(
                    format!("   {}", clock(r.at)),
                    if selected { base } else { base.fg(Color::DarkGray) },
                ));
            }
            if !r.preview.is_empty() {
                let room = (area.width as usize).saturating_sub(11);
                under.push(Span::styled(
                    truncate(&r.preview, room),
                    if selected { base } else { base.fg(Color::DarkGray) },
                ));
            }
            ListItem::new(vec![Line::from(spans), Line::from(under)])
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
        list.block(Block::default().borders(Borders::RIGHT)),
        area,
    );
}

/// Break `text` into lines no wider than `width` columns.
///
/// Done here rather than by `Paragraph`'s own wrapping because ratatui cannot
/// align individual lines inside a wrapped paragraph, and the whole point of
/// this layout is that your messages sit on one side and everybody else's on
/// the other. Measured with `UnicodeWidthStr`, the crate ratatui lays out
/// with, so a line that fits here fits on screen.
fn wrap_to(text: &str, width: usize) -> Vec<String> {
    if width == 0 {
        return vec![text.to_string()];
    }
    let mut out: Vec<String> = Vec::new();
    for para in text.split('\n') {
        let mut line = String::new();
        for word in para.split_inclusive(' ') {
            let w = UnicodeWidthStr::width(word.trim_end());
            if !line.is_empty() && UnicodeWidthStr::width(line.as_str()) + w > width {
                out.push(line.trim_end().to_string());
                line = String::new();
            }
            // A single word longer than the bubble is cut rather than allowed
            // to run off: a URL should not push the whole conversation wide.
            if w > width {
                let mut chunk = String::new();
                for ch in word.chars() {
                    if UnicodeWidthStr::width(chunk.as_str()) + 1 > width {
                        out.push(std::mem::take(&mut chunk));
                    }
                    chunk.push(ch);
                }
                line = chunk;
                continue;
            }
            line.push_str(word);
        }
        out.push(line.trim_end().to_string());
    }
    out
}

/// One message, laid out as a run of lines on its own side of the pane.
fn bubble(app: &App, s: &Said, picked: bool, head: bool, width: usize) -> Vec<Line<'static>> {
    let mut out = Vec::new();
    let mine = s.mine;
    let align = if mine { Alignment::Right } else { Alignment::Left };
    let dim = Style::default().fg(Color::DarkGray);

    // Who spoke, once for a run rather than against every line — but always
    // within a few lines of what they said, because the key is what tells two
    // people with the same display name apart (SIP-21).
    if head && !mine {
        let mut spans = identicon(&s.key);
        spans.push(Span::raw(" "));
        spans.push(Span::styled(
            author(&s.who, &s.key, false),
            Style::default().fg(Color::Cyan),
        ));
        out.push(Line::from(spans).alignment(align));
    }

    // What is being answered, as the first line *of* the bubble rather than a
    // dim line floating above it. A quotation that is not visibly attached to
    // the message quoting it is just another message.
    //
    // A target we no longer hold has neither an author nor any words, so it
    // says that once rather than pairing an empty name with an empty
    // quotation.
    let quoted = s.reply_to.as_ref().map(|(who, stub)| {
        if stub.is_empty() {
            format!("↳ {who}")
        } else {
            format!("↳ {who}: {stub}")
        }
    });

    let body = if s.redacted {
        vec!["message deleted".to_string()]
    } else {
        wrap_to(&s.text, width)
    };
    // A bubble sets both halves of its own colour rather than only one. Taking
    // the terminal's background and painting text on it would read fine on a
    // dark theme and be unreadable on a light one, and the client has no way
    // to ask which it is in.
    let style = if s.redacted {
        // A deleted message is not given a bubble: a gap should look like a
        // gap and not like something somebody said.
        dim.add_modifier(Modifier::ITALIC)
    } else if mine {
        Style::default().fg(Color::Indexed(255)).bg(Color::Indexed(24))
    } else {
        Style::default().fg(Color::Indexed(253)).bg(Color::Indexed(238))
    };
    let inside = if s.redacted {
        dim.add_modifier(Modifier::ITALIC)
    } else {
        style.fg(Color::Indexed(250))
    };
    let last = body.len().saturating_sub(1);

    // What trails the message shares its last line, and the whole block is
    // padded to one width so the colour forms a rectangle rather than a ragged
    // edge.
    let mut tail = String::new();
    if s.has_file && !s.redacted {
        tail += &format!("  /save {}", s.seq);
    }
    if s.edited && !s.redacted {
        tail += "  (edited)";
    }
    for m in &s.mentions {
        tail += &format!("  @{m}");
    }
    tail += &format!("  {}", clock(s.at).trim_end());
    if let Some(r) = s.receipt {
        tail += match r {
            Receipt::Sent => " ·",
            Receipt::Delivered => " ✓",
            Receipt::Read => " ✓✓",
        };
    }
    let content = body
        .iter()
        .enumerate()
        .map(|(n, l)| {
            UnicodeWidthStr::width(l.as_str())
                + if n == last { UnicodeWidthStr::width(tail.as_str()) } else { 0 }
        })
        .max()
        .unwrap_or(0);

    // The message decides how wide the bubble is; the quotation fits inside
    // it. Sizing the bubble to the quotation instead made a one-line answer as
    // wide as the paragraph it was answering.
    let quoted = quoted.map(|q| truncate(&q, content));

    // The quotation, a shade off the bubble it belongs to and padded to the
    // same width, so the whole thing is one block.
    if let Some(q) = &quoted {
        let tint = if s.redacted {
            dim.add_modifier(Modifier::ITALIC)
        } else if mine {
            Style::default().fg(Color::Indexed(253)).bg(Color::Indexed(25))
        } else {
            Style::default().fg(Color::Indexed(253)).bg(Color::Indexed(240))
        };
        let mut spans = Vec::new();
        if !mine {
            spans.push(Span::raw(" ".repeat(GUTTER)));
        }
        spans.push(Span::styled(format!(" {q}"), tint));
        spans.push(Span::styled(
            " ".repeat(content.saturating_sub(UnicodeWidthStr::width(q.as_str())) + 1),
            tint,
        ));
        if mine {
            spans.push(Span::raw(" ".repeat(GUTTER)));
        }
        out.push(Line::from(spans).alignment(align));
    }
    for (n, line) in body.iter().enumerate() {
        let mut spans = Vec::new();
        // The cursor sits on the leading edge, which is a different edge for
        // each side. Marking only the first line keeps a long message from
        // looking like several picked ones.
        if !mine {
            spans.push(Span::styled(
                if picked && n == 0 { "▸" } else { " " },
                Style::default().fg(Color::Yellow),
            ));
        }
        let used = UnicodeWidthStr::width(line.as_str())
            + if n == last { UnicodeWidthStr::width(tail.as_str()) } else { 0 };
        spans.push(Span::styled(format!(" {line}"), style));
        // The padding goes *before* what trails the message, so the time ends
        // at the bubble's right edge rather than trailing off wherever the
        // words happened to stop. On a message of several lines that is the
        // difference between a corner and a ragged middle.
        //
        // A deleted message needs no special case: it is always one line, so
        // `content` and `used` are equal and this is the single space of inset
        // that keeps its words in line with everybody else's.
        spans.push(Span::styled(
            " ".repeat(content.saturating_sub(used)),
            style,
        ));
        // The time and the markers ride on the last line rather than taking
        // one of their own: a line per message halves how much of a
        // conversation fits on screen, for information most people read only
        // when they want it.
        if n == last {
            spans.push(Span::styled(tail.clone(), inside));
        }
        spans.push(Span::styled(" ", style));
        if mine {
            spans.push(Span::styled(
                if picked && n == 0 { "◂" } else { " " },
                Style::default().fg(Color::Yellow),
            ));
        }
        out.push(Line::from(spans).alignment(align));
    }


    if !s.reactions.is_empty() && !s.redacted {
        // A reaction is up to 32 bytes chosen by whoever sent it, and a
        // message can carry a distinct one per emoji per account — so both
        // the width of a chip and the number of them are somebody else's
        // decision. Fit what fits and count the rest.
        // Their own colour, set on both halves like a bubble, so the chips
        // read as attached to the message on any terminal background rather
        // than as loose text under it.
        let chip_style = Style::default().fg(Color::Indexed(252)).bg(Color::Indexed(237));
        let ours = Style::default().fg(Color::Indexed(221)).bg(Color::Indexed(237));

        let mut row: Vec<Span> = Vec::new();
        let mut used = 0;
        let mut shown = 0;
        for (emoji, count, is_mine) in &s.reactions {
            let chip = format!(" {} {count} ", plain_emoji(emoji));
            let w = UnicodeWidthStr::width(chip.as_str());
            if used + w > width {
                break;
            }
            used += w;
            shown += 1;
            row.push(Span::styled(chip, if *is_mine { ours } else { chip_style }));
        }
        // Said, not dropped: a count that quietly omitted some would be
        // telling the reader a number that is not the number.
        if shown < s.reactions.len() {
            let more = format!(" +{} ", s.reactions.len() - shown);
            used += UnicodeWidthStr::width(more.as_str());
            row.push(Span::styled(more, chip_style));
        }

        // Under the bubble's *right* corner, whichever side the bubble is on.
        // Taking the message's alignment put an incoming message's reactions
        // against the far edge of the pane, yards from the thing they were
        // reacting to.
        if mine {
            // The same gutter, on the other side: our own bubble leaves a
            // column past its edge for the cursor, so the chips need one too
            // or they hang a column further out than the bubble.
            row.push(Span::raw(" ".repeat(GUTTER)));
            out.push(Line::from(row).alignment(Alignment::Right));
        } else {
            // The bubble is one column in from the edge on this side: an
            // incoming message carries a gutter for the pick cursor. Line up
            // with the bubble, not with the pane.
            let pad = (content + 2 + GUTTER).saturating_sub(used);
            let mut padded = vec![Span::raw(" ".repeat(pad))];
            padded.extend(row);
            out.push(Line::from(padded).alignment(Alignment::Left));
        }
    }
    // The reaction picker, open over the message the cursor is on. Dropped in
    // an earlier draft of this layout, which is exactly the kind of thing a
    // rewrite loses quietly.
    if picked && app.reacting {
        let mut row: Vec<Span> = Vec::new();
        for (n, emoji) in REACTIONS.iter().enumerate() {
            row.push(Span::styled(
                format!("{}:{emoji}  ", n + 1),
                Style::default().fg(Color::Yellow),
            ));
        }
        row.push(Span::styled("Esc", dim));
        out.push(Line::from(row).alignment(align));
    }
    out
}

/// Whether `b` starts a new run: a different author, or long enough after the
/// one before that the reader has lost the thread of who is speaking.
fn starts_run(a: Option<&Said>, b: &Said) -> bool {
    match a {
        None => true,
        Some(a) => a.mine != b.mine || a.who != b.who || a.key != b.key
            || b.at.saturating_sub(a.at) > RUN_GAP,
    }
}

/// How long a silence has to be before the next message is a new run.
const RUN_GAP: u64 = 5 * 60;

fn transcript(f: &mut Frame, app: &App, area: Rect) {
    if app.helping {
        help(f, area);
        return;
    }
    if app.searching {
        results(f, app, area);
        return;
    }
    if !app.found.is_empty() {
        directory(f, app, area);
        return;
    }
    let inner = (area.width as usize).saturating_sub(2);
    // Wide enough to read, narrow enough that the two sides are visibly two
    // sides. A bubble filling the pane would make alignment meaningless.
    let width = (inner * 3 / 5).clamp(16, inner.max(16));

    let mut lines: Vec<Line> = Vec::new();
    let dim = Style::default().fg(Color::DarkGray);
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
            dim,
        )));
    }
    if app.trouble.gap {
        lines.push(Line::from(Span::styled(
            "─── older messages are past the retention window and cannot be recovered ───",
            dim,
        )));
    }

    let mut day: Option<String> = None;
    for (i, s) in app.said.iter().enumerate() {
        // A conversation that runs over days showed 17:50 then 06:10 with
        // nothing to say a night had passed.
        let this_day = day_of(s.at);
        if this_day.is_some() && this_day != day {
            lines.push(
                Line::from(Span::styled(
                    format!("─── {} ───", day_label(s.at, app.now)),
                    dim,
                ))
                .alignment(Alignment::Center),
            );
            day = this_day;
        }
        // Where you had got to when you opened this. Above the first message
        // you had not seen, and it stays there while you read past it.
        if app.divider == Some(s.seq) {
            let n = app.said.len() - i;
            lines.push(
                Line::from(Span::styled(
                    format!("─── {n} unread ───"),
                    Style::default().fg(Color::Yellow),
                ))
                .alignment(Alignment::Center),
            );
        } else if starts_run(i.checked_sub(1).and_then(|p| app.said.get(p)), s) && i > 0 {
            lines.push(Line::from(""));
        }
        let head = starts_run(i.checked_sub(1).and_then(|p| app.said.get(p)), s);
        lines.extend(bubble(app, s, app.picked == Some(i), head, width));
    }

    if app.said.is_empty() && app.trouble.is_quiet() {
        lines.push(Line::from(Span::styled("nothing here yet", dim)));
    }
    if app.peer_typing {
        lines.push(Line::from(Span::styled("typing…", dim)));
    }

    let height = area.height.saturating_sub(2) as usize;
    let skip = lines.len().saturating_sub(height);
    // A short conversation sits at the bottom, against the input box, rather
    // than floating at the top of an empty pane — where the next message would
    // appear a long way from where somebody is typing.
    for _ in lines.len()..height {
        lines.insert(0, Line::from(""));
    }
    f.render_widget(
        // No `Wrap`: the text is already wrapped above, and a wrapped
        // paragraph ignores per-line alignment.
        Paragraph::new(lines.split_off(skip.min(lines.len())))
            .block(Block::default().borders(Borders::NONE)),
        area,
    );
}

/// What a search found, newest first.
fn results(f: &mut Frame, app: &App, area: Rect) {
    let dim = Style::default().fg(Color::DarkGray);
    let mut lines = vec![
        Line::from(vec![
            Span::styled(
                format!(
                    "{} message{} matching ",
                    app.hits.len(),
                    if app.hits.len() == 1 { "" } else { "s" }
                ),
                dim,
            ),
            Span::styled(
                format!("{:?}", app.query),
                Style::default().fg(Color::Yellow),
            ),
            Span::styled("  ·  Esc to go back", dim),
        ]),
        Line::from(""),
    ];
    if app.hits.is_empty() {
        // Said plainly, and said where the results would have been. Searching
        // here only ever reaches what this client has kept: history from
        // before it joined, or from before a key it never received, is not
        // absent from the conversation — only from us.
        lines.push(Line::from(Span::styled(
            "nothing here matches. This searches what this client holds, which              is not necessarily everything that was said.",
            dim,
        )));
    }
    for h in &app.hits {
        let before = &h.text[..h.at_byte];
        let hit = &h.text[h.at_byte..h.at_byte + h.len];
        let after = &h.text[h.at_byte + h.len..];
        lines.push(Line::from(vec![
            // The number, because it is what /save and /redact take and a
            // result you cannot act on is only half an answer.
            Span::styled(format!("{:>4} ", h.seq), dim),
            Span::styled(clock(h.at), dim),
            Span::styled(format!("{:>AUTHOR$} ", truncate(&h.who, AUTHOR)), Style::default().fg(Color::Cyan)),
            Span::raw(before.to_string()),
            Span::styled(
                hit.to_string(),
                Style::default().fg(Color::Indexed(232)).bg(Color::Yellow),
            ),
            Span::raw(after.to_string()),
        ]));
    }
    f.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }), area);
}

/// An emoji without its presentation selector.
///
/// U+FE0F asks for the colourful form of a character that also has a text
/// form. `unicode-width` calls the sequence two columns wide and ratatui lays
/// it out as two, but a good many terminals paint it in one — and the cell
/// ratatui reserved for the second half is left with no background, so a
/// coloured chip comes out with a hole punched through it. ❤️ is the one that
/// does this in practice; every other emoji in the picker is a single code
/// point in the emoji block, where nobody disagrees.
///
/// Dropping the selector gives up the colourful glyph for a monochrome one and
/// gets an emoji whose width everything agrees on. In a layout made of columns
/// that is the better trade.
fn plain_emoji(s: &str) -> String {
    s.chars().filter(|c| *c != '\u{fe0f}' && *c != '\u{fe0e}').collect()
}

/// The column an incoming message leaves for the pick cursor, before its
/// bubble starts. Anything meant to line up with that bubble has to allow for
/// it — the reaction row did not, and sat a column short of the corner.
const GUTTER: usize = 1;

/// How wide the command column is. Every command has to fit inside it with
/// room to spare, or it runs into what it means — which is a thing a test can
/// check only if the commands are data rather than a wall of `push`.
pub const COMMAND: usize = 28;

/// The command list, by section.
pub const HELP: &[(&str, &[(&str, &str)])] = &[
    ("messages", &[
        ("/file <path>", "send a file"),
        ("/save <n> <path>", "keep one somebody sent"),
        ("/forward <n> <m>", "send a file on to conversation m, without re-uploading"),
        ("/redact <n>", "delete a message you posted, and the file it carried"),
    ]),
    ("conversations", &[
        ("/new <name>", "a private group"),
        ("/public <name>", "a channel anybody may find and join"),
        ("/find [query]  /join <n>", "search the directory, and enter one"),
        ("/invite <key>  /kick <key>", "add somebody; remove them and rotate the key"),
        ("/op <key>  /deop <key>", "grant or withdraw admin here"),
        ("/leave  /close", "leave it; or end it for everyone, permanently"),
    ]),
    ("this channel", &[
        ("/name  /topic  /avatar", "what it is called, what it is for, its picture"),
        ("/retain <secs> [max]", "how long it keeps what is said"),
        ("/who  /read", "who is here; how far each of them has read"),
        ("/rotate", "mint a new key for everyone currently here"),
    ]),
    ("finding things", &[
        ("/search <text>", "find it in this conversation"),
    ]),
    ("you", &[
        ("/profile [name | title]", "what you publish about yourself; `off` clears it"),
        ("/block  /unblock  /blocked", "who may reach you"),
    ]),
];

/// Everything the client can do, over the transcript.
///
/// A view rather than a line, because the status line is one row and there are
/// forty of these. It was the only list there was, and at eighty columns the
/// end of it was simply cut off — so the commands that fell off were
/// undiscoverable and nothing said so.
fn help(f: &mut Frame, area: Rect) {
    let dim = Style::default().fg(Color::DarkGray);
    let key = Style::default().fg(Color::Yellow);
    let head = Style::default().fg(Color::Cyan);
    let mut lines = vec![
        Line::from(Span::styled("keys", head)),
        Line::from(vec![
            Span::styled("  Tab ↑↓ ", key),
            Span::styled("move between conversations    ", dim),
            Span::styled("^N ", key),
            Span::styled("add somebody    ", dim),
            Span::styled("^C ", key),
            Span::styled("quit", dim),
        ]),
        Line::from(vec![
            Span::styled("  Esc    ", key),
            Span::styled("pick a message, and then:  ", dim),
            Span::styled("↑↓ ", key),
            Span::styled("move  ", dim),
            Span::styled("a ", key),
            Span::styled("react  ", dim),
            Span::styled("r ", key),
            Span::styled("reply  ", dim),
            Span::styled("e ", key),
            Span::styled("rewrite  ", dim),
            Span::styled("d ", key),
            Span::styled("delete", dim),
        ]),
        Line::from(""),
    ];
    for (title, rows) in HELP {
        lines.push(Line::from(Span::styled((*title).to_string(), head)));
        for (cmd, what) in *rows {
            lines.push(Line::from(vec![
                Span::styled(format!("  {cmd:<COMMAND$}"), key),
                Span::styled((*what).to_string(), dim),
            ]));
        }
        lines.push(Line::from(""));
    }
    lines.push(Line::from(Span::styled("  Esc to go back", dim)));
    f.render_widget(Paragraph::new(lines), area);
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
        // Nothing to say about an empty composer: "message" is the same kind
        // of label as the "people" that used to head the list, naming a thing
        // that is already obvious from looking at it.
        (None, None, None) => ("", app.input.as_str()),
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
    // Short, and it stays short. This used to be the only command list there
    // was, and it grew until the end of it was cut off at eighty columns —
    // which left the commands that fell off undiscoverable, with nothing to
    // say they existed. `/help` carries the list now, and this only has to
    // point at it.
    const GROUPS: &[&str] = &["^C quit", "Tab", "Esc pick", "^N add", "/help"];
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
/// The local time of day, as the person reading it keeps time.
///
/// This was `at % 86_400`, which is UTC and is the correct time in exactly one
/// timezone. Everywhere else the client was quietly showing the wrong hour —
/// here, an hour behind, all day, in every screen anybody looked at.
fn clock(at: u64) -> String {
    match local(at) {
        Some(z) => clock_of(&z),
        // A clock that cannot be worked out is left blank rather than guessed
        // at: a plausible wrong time is worse than none.
        None => "      ".to_string(),
    }
}

/// The formatting alone, given a moment already placed in a zone.
///
/// Separate so it can be tested without asking where this machine is: a test
/// that asserts "01:01" passes in one timezone and fails in the rest.
fn clock_of(z: &jiff::Zoned) -> String {
    format!("{} ", z.strftime("%H:%M"))
}

/// The day a moment falls on, for deciding where a separator goes.
///
/// Compared rather than displayed, so the format only has to be unambiguous.
fn day_of(at: u64) -> Option<String> {
    Some(local(at)?.strftime("%Y-%m-%d").to_string())
}

/// How a day separator reads: "Friday, 28 August", and the year when it is not
/// the current one — a bare date is a trap on old history.
fn day_label(at: u64, now: u64) -> String {
    match (local(at), local(now)) {
        (Some(z), n) => day_label_of(&z, n.map(|n| n.year())),
        _ => String::new(),
    }
}

fn day_label_of(z: &jiff::Zoned, this_year: Option<i16>) -> String {
    if this_year == Some(z.year()) {
        z.strftime("%A, %-d %B").to_string()
    } else {
        z.strftime("%A, %-d %B %Y").to_string()
    }
}

fn local(at: u64) -> Option<jiff::Zoned> {
    let secs = i64::try_from(at).ok()?;
    Some(
        jiff::Timestamp::from_second(secs)
            .ok()?
            .to_zoned(jiff::tz::TimeZone::system()),
    )
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
                    key: None,
                    group: false,
                    public: false,
                    unread: 0,
                    preview: String::new(),
                    at: 0,
                    waiting: false,
                })
                .collect(),
            ..Default::default()
        };
        // Starts at the top, wraps to the bottom and back.
        app.selected = Some([0; 32]);
        app.select_previous();
        assert_eq!(app.selected, Some([2; 32]));
        app.select_next();
        assert_eq!(app.selected, Some([0; 32]));
    }

    #[test]
    fn selection_on_an_empty_list_does_not_panic() {
        let mut app = App::default();
        app.select_next();
        app.select_previous();
        assert!(app.selected_row().is_none());
    }

    /// Fixed offsets, so this says the same thing on every machine. Asserting
    /// a wall clock against the system zone passes where it was written and
    /// fails everywhere else.
    fn at(secs: i64, offset_hours: i8) -> jiff::Zoned {
        jiff::Timestamp::from_second(secs)
            .unwrap()
            .to_zoned(jiff::tz::TimeZone::fixed(jiff::tz::offset(offset_hours)))
    }

    #[test]
    fn the_clock_wraps_at_midnight_and_not_before() {
        assert_eq!(clock_of(&at(0, 0)), "00:00 ");
        assert_eq!(clock_of(&at(60, 0)), "00:01 ");
        assert_eq!(clock_of(&at(23 * 3600 + 59 * 60, 0)), "23:59 ");
        // The next second is the next day's midnight, not 24:00.
        assert_eq!(clock_of(&at(86_400, 0)), "00:00 ");
        assert_eq!(clock_of(&at(86_400 + 3661, 0)), "01:01 ");
    }

    /// The bug this replaced: the clock was `at % 86_400`, which is UTC, and
    /// so was the right time in exactly one zone and an hour or more out in
    /// most of the others.
    #[test]
    fn the_clock_is_local_and_not_utc() {
        let noon_utc = 12 * 3600;
        assert_eq!(clock_of(&at(noon_utc, 0)), "12:00 ");
        assert_eq!(clock_of(&at(noon_utc, 1)), "13:00 ");
        assert_eq!(clock_of(&at(noon_utc, -5)), "07:00 ");
        // And the offset can carry a moment into the day before or after.
        assert_eq!(clock_of(&at(30 * 60, -1)), "23:30 ");
    }

    #[test]
    fn a_day_separator_says_which_day_and_only_says_the_year_when_it_differs() {
        let d = at(1_787_961_600, 0); // 2026-08-29
        assert_eq!(day_label_of(&d, Some(2026)), "Saturday, 29 August");
        assert_eq!(day_label_of(&d, Some(2027)), "Saturday, 29 August 2026");
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
                key: Some("8qbHbw2B".into()),
                group: false,
                public: false,
                unread: 2,
                preview: String::new(),
                at: 0,
                waiting: false,
            }],
            selected: Some([2; 32]),
            said: vec![
                Said {
                    who: "bob".into(),
                    key: "8qbHbw2B".into(),
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
                    key: "9hSR6S7W".into(),
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
        assert!(
            out.contains(clock(3661).trim()),
            "the clock is missing:\n{out}"
        );
        assert!(out.contains("(edited)"));
        // A quiet status shows the keys, not a warning.
        assert!(out.contains("^C quit"));
        assert!(out.contains("^N add"));
        assert!(out.contains("/help"));
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
                    ["^C quit", "Tab", "Esc pick", "^N add", "/help"].contains(&group),
                    "a group was cut in half at width {width}: {group:?}"
                );
            }
        }
        // And a wide terminal gets all of them.
        // And it fits at eighty columns whole, which the command list it
        // replaced had stopped doing.
        assert_eq!(keys_line(200), keys_line(80));
        assert!(keys_line(80).contains("/help"));
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
            // Long enough to leave the quotation room. A one-word answer is
            // its own case, below.
            text: "friday works for me, let us do that".into(),
            seq: 8,
            at: 3700,
            reply_to: Some(("Alice (E4LUkjrZ)".into(), "thursday or friday?".into())),
            ..Default::default()
        }];
        let out = render(&app, 80, 20);
        // The beginning of what is being answered — the quotation is cut to
        // the bubble rather than stretching it.
        assert!(out.contains("thursd"), "{out}");
        // Who is being answered, not which number: a sequence nobody has
        // memorised is not information.
        assert!(out.contains("Alice"), "the reply did not name its author:\n{out}");
        assert!(
            out.contains("E4LUkjrZ"),
            "the reply named somebody with no key beside it:\n{out}"
        );
    }

    /// A target we no longer hold still shows the marker. "Answering something
    /// we cannot see" is the truth; dropping it would hide that a reply is a
    /// reply at all.
    #[test]
    fn a_reply_to_something_we_do_not_hold_still_says_it_is_one() {
        let mut app = sample();
        app.said = vec![Said {
            who: "bob".into(),
            key: "8qbHbw2B".into(),
            text: "yes, that is the one I meant".into(),
            seq: 8,
            at: 3700,
            reply_to: Some(("a message we no longer hold".into(), String::new())),
            ..Default::default()
        }];
        let out = render(&app, 80, 20);
        assert!(out.contains("↳"), "the reply marker was dropped:\n{out}");
        assert!(out.contains("no longer"), "{out}");
    }

    #[test]
    fn the_picked_message_is_visibly_picked_and_the_keys_change() {
        let mut app = sample();
        // The second message is ours, and sits on the right — so its cursor is
        // on the right edge too, pointing in at it.
        app.picked = Some(1);
        let out = render(&app, 80, 20);
        assert!(out.contains('◂'), "nothing marks the picked message:\n{out}");
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
        // Bob's is on the left, so its cursor is on the left edge.
        assert!(out.contains('▸'), "nothing marks an incoming picked message:\n{out}");
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

    /// Choosing which conversation to type into is exactly a moment where
    /// mistaking one person for another matters, so SIP-21's rule applies to
    /// the list as much as to the transcript. The name shipped in the
    /// transcript only, and the list went on showing a bare key.
    #[test]
    fn the_conversation_list_shows_a_name_with_its_key() {
        let mut app = sample();
        app.rows = vec![
            Row {
                channel: [1; 32],
                label: "Alice Byrne".into(),
                key: Some("E4LUkjrZ".into()),
                group: false,
                public: false,
                unread: 0,
                preview: String::new(),
                at: 0,
                waiting: false,
            },
            Row {
                channel: [2; 32],
                label: "shipping".into(),
                key: None,
                group: true,
                public: false,
                unread: 0,
                preview: String::new(),
                at: 0,
                waiting: false,
            },
        ];
        let out = render(&app, 100, 20);
        assert!(out.contains("Alice Byrne"), "the list dropped the name:\n{out}");
        assert!(
            out.contains("E4LUkjrZ"),
            "the list showed a name with no key beside it:\n{out}"
        );
        // A group's name belongs to the channel, not to a person, so there is
        // no key it could be confused with and none is invented.
        assert!(out.contains("shipping"), "{out}");
    }

    #[test]
    fn a_conversation_with_nobody_named_shows_the_key_once() {
        let mut app = sample();
        app.rows = vec![Row {
            channel: [1; 32],
            // What an unnamed contact is labelled with: its own short key.
            label: "E4LUkjrZ".into(),
            key: Some("E4LUkjrZ".into()),
            group: false,
            public: false,
            unread: 0,
            preview: String::new(),
            at: 0,
            waiting: false,
        }];
        let out = render(&app, 100, 20);
        assert!(
            !out.contains("E4LUkjrZ (E4LUkjrZ)"),
            "the key was rendered twice:\n{out}"
        );
        assert!(out.contains("E4LUkjrZ"), "{out}");
    }

    /// A narrow sidebar loses the name, never the key.
    #[test]
    fn a_narrow_list_keeps_the_key() {
        let r = Row {
            channel: [1; 32],
            label: "Alexandra Bartholomew".into(),
            key: Some("E4LUkjrZ".into()),
            group: false,
            public: false,
            unread: 0,
            preview: String::new(),
            at: 0,
            waiting: false,
        };
        for width in 8..=AUTHOR {
            let line = row_label(&r, width);
            assert!(
                line.contains("E4LUkjrZ"),
                "a long name pushed the key out at width {width}: {line}"
            );
        }
    }

    /// A reaction is up to 32 bytes chosen by another client, and a message
    /// can carry one per emoji per account — so how wide the row gets is
    /// somebody else's decision unless this bounds it.
    #[test]
    fn a_reaction_row_cannot_be_pushed_off_the_screen() {
        let mut app = sample();
        app.said = vec![Said {
            who: "bob".into(),
            key: "8qbHbw2B".into(),
            text: "x".into(),
            seq: 1,
            at: 0,
            reactions: (0..40)
                .map(|i| (format!("{}\u{fe0f}", char::from(b'a' + i as u8 % 26)), 1, false))
                .collect(),
            ..Default::default()
        }];
        let out = render(&app, 80, 12);
        for l in out.lines() {
            assert!(
                UnicodeWidthStr::width(l) <= 80,
                "a line ran past the screen ({} cols): {l:?}",
                UnicodeWidthStr::width(l)
            );
        }
        // And the ones that did not fit are counted rather than dropped in
        // silence.
        assert!(out.contains('+'), "the hidden reactions were not counted:\n{out}");
    }

    /// The ordinary case still draws every reaction, with no "+n".
    #[test]
    fn a_few_reactions_all_fit() {
        let mut app = sample();
        app.said = vec![Said {
            who: "bob".into(),
            key: "8qbHbw2B".into(),
            text: "x".into(),
            seq: 1,
            at: 0,
            reactions: vec![
                ("👍".into(), 2, true),
                ("🎉".into(), 1, false),
                ("👀".into(), 3, false),
            ],
            ..Default::default()
        }];
        let out = render(&app, 100, 12);
        for e in ["👍", "🎉", "👀"] {
            assert!(out.contains(e), "{e} was dropped:\n{out}");
        }
        assert!(!out.contains('+'), "a full row claimed to be truncated:\n{out}");
    }

    /// Read cell by cell, because that is what the terminal is handed. A
    /// homemade emulator counting characters made a correct layout look broken
    /// twice; `TestBackend` settles it.
    fn columns(app: &App, w: u16, h: u16) -> Vec<(usize, usize)> {
        let mut t = Terminal::new(TestBackend::new(w, h)).unwrap();
        t.draw(|f| draw(f, app)).unwrap();
        let buf = t.backend().buffer().clone();
        // For each row of the transcript pane, the first and last column
        // holding anything.
        let mut out = Vec::new();
        // Only the transcript's own rows. The layout puts a header above it
        // and an input box and status line below, and the box's border spans
        // the whole width — which is not the transcript overflowing.
        for y in 1..buf.area.height.saturating_sub(4) {
            let cells: Vec<String> = (31..buf.area.width)
                .map(|x| buf[(x, y)].symbol().to_string())
                .collect();
            let first = cells.iter().position(|c| c.trim() != "");
            let last = cells.iter().rposition(|c| c.trim() != "");
            if let (Some(a), Some(b)) = (first, last) {
                out.push((a, b));
            }
        }
        out
    }

    fn said(who: &str, key: &str, mine: bool, text: &str, at: u64) -> Said {
        Said {
            who: who.into(),
            key: key.into(),
            mine,
            text: text.into(),
            at,
            ..Default::default()
        }
    }

    /// The whole point of the layout: mine on one side, everyone else's on the
    /// other, so you can tell at a glance who is speaking without reading.
    #[test]
    fn my_messages_sit_on_the_right_and_everyone_elses_on_the_left() {
        let mut app = sample();
        app.said = vec![
            said("bob", "8qbHbw2B", false, "short", 3661),
            said("you", "9hSR6S7W", true, "also short", 3661),
        ];
        let cols = columns(&app, 100, 20);
        let pane = 100 - 31;
        let incoming = cols.iter().find(|(a, _)| *a <= 2).expect("nothing on the left");
        let outgoing = cols
            .iter()
            .find(|(_, b)| *b >= pane - 3)
            .expect("nothing reaches the right");
        assert!(
            incoming.0 < outgoing.0,
            "the two sides are not on different sides: {cols:?}"
        );
    }

    /// A long message wraps inside its bubble rather than across the pane, and
    /// nothing runs past the edge.
    #[test]
    fn a_long_message_wraps_inside_its_bubble() {
        let mut app = sample();
        let long = "the quick brown fox jumps over the lazy dog and keeps going \
                    well past the width of any sensible bubble in this pane";
        app.said = vec![said("bob", "8qbHbw2B", false, long, 3661)];
        let out = render(&app, 100, 24);
        for l in out.lines() {
            assert!(
                UnicodeWidthStr::width(l) <= 100,
                "a line ran past the screen: {l:?}"
            );
        }
        let cols = columns(&app, 100, 24);
        let pane = 100 - 31;
        // Wrapped to a bubble, not to the pane: nothing reaches the far edge.
        assert!(
            cols.iter().all(|(_, b)| *b < pane - 4),
            "the text used the whole pane instead of a bubble: {cols:?}"
        );
    }

    /// A word with no spaces in it — a URL — is cut rather than allowed to
    /// push the conversation wide.
    #[test]
    fn one_enormous_word_is_cut_rather_than_overflowing() {
        let mut app = sample();
        app.said = vec![said("bob", "8qbHbw2B", false, &"x".repeat(400), 3661)];
        let out = render(&app, 80, 24);
        for l in out.lines() {
            assert!(UnicodeWidthStr::width(l) <= 80, "overflowed: {l:?}");
        }
    }

    /// One header per run, and it carries the key — SIP-21 applies however the
    /// messages are arranged.
    #[test]
    fn a_run_is_headed_once_and_the_header_carries_the_key() {
        let mut app = sample();
        app.said = vec![
            said("bob", "8qbHbw2B", false, "one", 3661),
            said("bob", "8qbHbw2B", false, "two", 3671),
            said("bob", "8qbHbw2B", false, "three", 3681),
        ];
        let out = render(&app, 100, 24);
        assert_eq!(
            out.matches("8qbHbw2B").count(),
            2,
            "expected one header in the transcript and one row in the list:\n{out}"
        );

        // A long enough silence starts a new run, because by then the reader
        // has lost the thread of who is speaking.
        app.said[2].at = 3681 + RUN_GAP + 1;
        let out = render(&app, 100, 24);
        assert_eq!(out.matches("8qbHbw2B").count(), 3, "{out}");
    }

    #[test]
    fn a_day_separator_appears_between_days_and_not_within_one() {
        let mut app = sample();
        app.now = 200_000;
        app.said = vec![
            said("bob", "8qbHbw2B", false, "before midnight", 3661),
            said("bob", "8qbHbw2B", false, "after midnight", 3661 + 86_400),
        ];
        let out = render(&app, 100, 24);
        assert_eq!(
            out.lines().filter(|l| l.contains("─── ")).count(),
            2,
            "expected a separator above each day:\n{out}"
        );

        app.said[1].at = 3661 + 60;
        let out = render(&app, 100, 24);
        assert_eq!(
            out.lines().filter(|l| l.contains("─── ")).count(),
            1,
            "a separator appeared inside one day:\n{out}"
        );
    }

    #[test]
    fn an_identicon_is_stable_for_a_key_and_differs_between_keys() {
        let a = identicon("8qbHbw2B");
        assert_eq!(a.len(), ICON);
        let styles = |v: &[Span]| v.iter().map(|s| (s.style.fg, s.style.bg)).collect::<Vec<_>>();
        assert_eq!(styles(&a), styles(&identicon("8qbHbw2B")), "not stable");
        assert_ne!(
            styles(&a),
            styles(&identicon("9hSR6S7W")),
            "two keys drew the same face"
        );
        // Derived from the key, so a key that differs in one character does
        // not draw the same thing.
        assert_ne!(styles(&identicon("aaaaaaaa")), styles(&identicon("aaaaaaab")));
    }

    /// A conversation sits against the composer, not at the top of an empty
    /// pane — the next message should appear near where somebody is typing.
    #[test]
    fn a_short_conversation_sits_at_the_bottom() {
        let mut app = sample();
        app.said = vec![said("bob", "8qbHbw2B", false, "hello", 3661)];
        let out = render(&app, 100, 24);
        let rows: Vec<&str> = out.lines().collect();
        let at = rows
            .iter()
            .position(|l| l.contains("hello"))
            .expect("the message is not on screen");
        // Below the middle of the transcript, which runs from row 1 to row 19.
        assert!(at > 10, "the conversation floated at the top:\n{out}");
    }

    /// Everything that trails a message shares its last line. A line each for
    /// the time would halve how much of a conversation fits on screen.
    #[test]
    fn the_time_and_markers_ride_on_the_message() {
        let mut app = sample();
        let mut s = said("bob", "8qbHbw2B", false, "here it is", 3661);
        s.has_file = true;
        s.edited = true;
        s.seq = 12;
        app.said = vec![s];
        let out = render(&app, 100, 24);
        let line = out
            .lines()
            .find(|l| l.contains("here it is"))
            .expect("the message is not on screen");
        assert!(line.contains("/save 12"), "the file hint left the line: {line:?}");
        assert!(line.contains("(edited)"), "the edit mark left the line: {line:?}");
        assert!(
            line.contains(clock(3661).trim()),
            "the time left the line: {line:?}"
        );
        // And it all still fits.
        for l in out.lines() {
            assert!(UnicodeWidthStr::width(l) <= 100, "overflowed: {l:?}");
        }
    }

    /// A bubble is a rectangle, so every line of a message carries the same
    /// background — a ragged edge would look like damage rather than a shape.
    #[test]
    fn a_bubble_is_a_rectangle() {
        let mut app = sample();
        app.said = vec![said(
            "bob",
            "8qbHbw2B",
            false,
            "one two three four five six seven eight nine ten eleven twelve",
            3661,
        )];
        let mut t = Terminal::new(TestBackend::new(100, 24)).unwrap();
        t.draw(|f| draw(f, &app)).unwrap();
        let buf = t.backend().buffer().clone();

        // Every row holding part of the message has the same run of coloured
        // cells, and they all start in the same column.
        let mut widths = Vec::new();
        for y in 0..buf.area.height {
            let painted: Vec<u16> = (31..buf.area.width)
                .filter(|x| buf[(*x, y)].style().bg == Some(Color::Indexed(238)))
                .collect();
            if !painted.is_empty() {
                widths.push((painted[0], painted.len()));
            }
        }
        assert!(widths.len() >= 2, "the message did not wrap: {widths:?}");
        assert!(
            widths.iter().all(|(x, _)| *x == widths[0].0),
            "the bubble has a ragged left edge: {widths:?}"
        );
        assert!(
            widths.iter().all(|(_, n)| *n == widths[0].1),
            "the bubble has a ragged right edge: {widths:?}"
        );
    }

    /// A bubble sets both halves of its own colour. Painting text on whatever
    /// the terminal's background happens to be reads on a dark theme and is
    /// unreadable on a light one, and the client cannot ask which it is in.
    #[test]
    fn a_bubble_sets_its_foreground_as_well_as_its_background() {
        let mut app = sample();
        app.said = vec![said("bob", "8qbHbw2B", false, "hello", 3661)];
        let mut t = Terminal::new(TestBackend::new(100, 24)).unwrap();
        t.draw(|f| draw(f, &app)).unwrap();
        let buf = t.backend().buffer().clone();
        let painted = (0..buf.area.height)
            .flat_map(|y| (31..buf.area.width).map(move |x| (x, y)))
            .find(|(x, y)| buf[(*x, *y)].symbol() == "h")
            .expect("the message is not on screen");
        let cell = &buf[painted];
        assert!(cell.style().bg.is_some(), "no bubble behind the text");
        assert!(cell.style().fg.is_some(), "the text took the terminal's colour");
    }

    /// A deleted message is not given a bubble: a gap should look like a gap,
    /// not like something somebody said.
    #[test]
    fn a_tombstone_is_not_dressed_as_a_message() {
        let mut app = sample();
        let mut s = said("bob", "8qbHbw2B", false, "", 3661);
        s.redacted = true;
        app.said = vec![s];
        let mut t = Terminal::new(TestBackend::new(100, 24)).unwrap();
        t.draw(|f| draw(f, &app)).unwrap();
        let buf = t.backend().buffer().clone();
        let painted = (0..buf.area.height)
            .flat_map(|y| (31..buf.area.width).map(move |x| (x, y)))
            .any(|(x, y)| buf[(x, y)].style().bg == Some(Color::Indexed(238)));
        assert!(!painted, "a deleted message was drawn as a bubble");
    }

    /// The list says what is going on, not only what exists.
    #[test]
    fn the_conversation_list_previews_the_last_thing_said() {
        let mut app = sample();
        app.rows[0].preview = "see you at six".into();
        app.rows[0].at = 3661;
        let out = render(&app, 100, 24);
        assert!(out.contains("see you at six"), "no preview in the list:\n{out}");
        assert!(
            out.contains(clock(3661).trim()),
            "no time against the preview:\n{out}"
        );
    }

    /// A receipt says what became of something *you* sent, so it goes on your
    /// messages and nobody else's.
    #[test]
    fn a_receipt_is_shown_on_our_own_messages_only() {
        let mut app = sample();
        let mut mine = said("you", "9hSR6S7W", true, "sent this", 3661);
        mine.receipt = Some(Receipt::Read);
        app.said = vec![said("bob", "8qbHbw2B", false, "theirs", 3661), mine];
        let out = render(&app, 100, 24);
        let theirs = out.lines().find(|l| l.contains("theirs")).unwrap();
        let ours = out.lines().find(|l| l.contains("sent this")).unwrap();
        assert!(ours.contains("✓✓"), "no receipt on our message: {ours:?}");
        assert!(
            !theirs.contains('✓'),
            "a receipt was put on somebody else's message: {theirs:?}"
        );
    }

    #[test]
    fn the_three_stages_read_differently() {
        let mut app = sample();
        let mark = |r| {
            let mut s = said("you", "9hSR6S7W", true, "hello", 3661);
            s.receipt = Some(r);
            s
        };
        let line = |app: &App| {
            render(app, 100, 24)
                .lines()
                .find(|l| l.contains("hello"))
                .unwrap()
                .to_string()
        };
        app.said = vec![mark(Receipt::Sent)];
        let sent = line(&app);
        app.said = vec![mark(Receipt::Delivered)];
        let delivered = line(&app);
        app.said = vec![mark(Receipt::Read)];
        let read = line(&app);
        assert_ne!(sent, delivered);
        assert_ne!(delivered, read);
        assert!(delivered.contains('✓'));
        assert!(read.contains("✓✓"));
    }

    /// Where you had got to when you opened the conversation. The count is
    /// the point — "3 unread" tells you how far to scroll back.
    #[test]
    fn an_unread_divider_marks_where_you_left_off() {
        let mut app = sample();
        app.said = (1..=5)
            .map(|n| {
                let mut s = said("bob", "8qbHbw2B", false, &format!("message {n}"), 3661);
                s.seq = n;
                s
            })
            .collect();
        app.divider = Some(3);
        let out = render(&app, 100, 30);
        let rows: Vec<&str> = out.lines().collect();
        let line = rows
            .iter()
            .position(|l| l.contains("unread"))
            .expect("no divider drawn");
        let third = rows.iter().position(|l| l.contains("message 3")).unwrap();
        let second = rows.iter().position(|l| l.contains("message 2")).unwrap();
        assert!(second < line && line < third, "the divider is in the wrong place:\n{out}");
        // Three messages sit below it.
        assert!(rows[line].contains("3 unread"), "{}", rows[line]);
    }

    #[test]
    fn nothing_unread_draws_no_divider() {
        let mut app = sample();
        app.divider = None;
        let out = render(&app, 100, 24);
        assert!(!out.contains("unread"), "a divider appeared with nothing new:\n{out}");
    }

    /// The status line stopped being the command list, so the list has to be
    /// somewhere. It goes over the transcript, like the directory does.
    #[test]
    fn help_lists_the_commands_and_the_keys() {
        let mut app = sample();
        app.helping = true;
        let out = render(&app, 110, 40);
        // A sample from each section, and the keys that are not commands at
        // all — which were the least discoverable thing in the client.
        for want in [
            "Esc", "react", "rewrite", "/file", "/forward", "/op", "/close", "/retain",
            "/profile", "/blocked", "/who", "/read",
        ] {
            assert!(out.contains(want), "{want} is not in the help:\n{out}");
        }
        // And it is a view over the transcript, not a line under it.
        assert!(!out.contains("are you there?"), "the transcript showed through");
    }

    #[test]
    fn help_fits_a_small_terminal_without_losing_its_head() {
        let mut app = sample();
        app.helping = true;
        // The top is what matters: the keys, which nothing else documents.
        let out = render(&app, 80, 24);
        assert!(out.contains("keys"), "the help lost its top:\n{out}");
        // Checked against the table rather than against the rendering. The
        // rendered version of this test looked for the first double space and
        // found one *inside* a command like "/invite <key>  /kick <key>" — so
        // it passed on exactly the line that was broken.
        for (_, rows) in HELP {
            for (cmd, _) in *rows {
                assert!(
                    UnicodeWidthStr::width(*cmd) + 2 <= COMMAND,
                    "{cmd:?} fills the column and runs into what it means"
                );
            }
        }
        for l in out.lines() {
            assert!(UnicodeWidthStr::width(l) <= 80, "help overflowed: {l:?}");
        }
    }

    fn hit(who: &str, text: &str, needle: &str, at: u64) -> Hit {
        let at_byte = text.to_lowercase().find(&needle.to_lowercase()).unwrap();
        Hit {
            seq: 1,
            who: who.into(),
            at,
            text: text.into(),
            at_byte,
            len: needle.len(),
        }
    }

    #[test]
    fn a_search_shows_what_matched_and_who_said_it() {
        let mut app = sample();
        app.searching = true;
        app.query = "friday".into();
        app.hits = vec![hit("Alice (E4LUkjrZ)", "we ship on friday", "friday", 3661)];
        let out = render(&app, 110, 24);
        assert!(out.contains("we ship on friday"), "{out}");
        // The author, with the key beside the name like everywhere else.
        assert!(out.contains("Alice"), "{out}");
        assert!(out.contains("E4LUkjrZ"), "the result dropped the key:\n{out}");
        assert!(out.contains("1 message matching"), "{out}");
        // The sequence number, which is what /save and /redact take.
        assert!(out.contains("  1 "), "no number to act on:\n{out}");
        // A view over the transcript, not a line under it.
        assert!(!out.contains("are you there?"), "the transcript showed through");
    }

    /// Nothing found says so where the results would have been, and says what
    /// was searched: this reaches what the client holds, which is not
    /// necessarily everything that was said in the channel.
    #[test]
    fn an_empty_search_says_what_it_looked_through() {
        let mut app = sample();
        app.searching = true;
        app.query = "banana".into();
        app.hits = vec![];
        let out = render(&app, 110, 24);
        assert!(out.contains("0 messages matching"), "{out}");
        assert!(out.contains("banana"), "{out}");
        assert!(
            out.contains("not necessarily everything"),
            "an empty result implied the words were never said:\n{out}"
        );
    }

    /// The matching part is picked out, or a result in a long message is a
    /// paragraph to re-read rather than an answer.
    #[test]
    fn the_match_itself_is_marked() {
        let mut app = sample();
        app.searching = true;
        app.query = "friday".into();
        app.hits = vec![hit("bob (8qbHbw2B)", "we ship on friday, not thursday", "friday", 3661)];
        let mut t = Terminal::new(TestBackend::new(110, 24)).unwrap();
        t.draw(|f| draw(f, &app)).unwrap();
        let buf = t.backend().buffer().clone();
        let marked: String = (0..buf.area.height)
            .flat_map(|y| (0..buf.area.width).map(move |x| (x, y)))
            .filter(|(x, y)| buf[(*x, *y)].style().bg == Some(Color::Yellow))
            .map(|(x, y)| buf[(x, y)].symbol().to_string())
            .collect();
        assert_eq!(marked, "friday", "the match was not picked out: {marked:?}");
    }

    /// Reactions hang under the bubble's right corner on both sides. Taking
    /// the message's own alignment put an incoming message's reactions against
    /// the far edge of the pane, yards from the thing they reacted to.
    #[test]
    fn reactions_hang_under_the_right_corner_of_their_bubble() {
        let edges = |mine: bool| {
            let mut app = sample();
            let mut s = said("bob", "8qbHbw2B", mine, "a short message", 3661);
            s.reactions = vec![("👍".into(), 2, false)];
            app.said = vec![s];
            let mut t = Terminal::new(TestBackend::new(110, 24)).unwrap();
            t.draw(|f| draw(f, &app)).unwrap();
            let buf = t.backend().buffer().clone();
            // The bubble's right edge, and the reaction chips' right edge.
            let right_of = |bg: Color| {
                (0..buf.area.height)
                    .flat_map(|y| (31..buf.area.width).map(move |x| (x, y)))
                    .filter(|(x, y)| buf[(*x, *y)].style().bg == Some(bg))
                    .map(|(x, _)| x)
                    .max()
            };
            (
                right_of(if mine { Color::Indexed(24) } else { Color::Indexed(238) }),
                right_of(Color::Indexed(237)),
            )
        };

        for mine in [false, true] {
            let (bubble, chips) = edges(mine);
            let bubble = bubble.expect("no bubble drawn");
            let chips = chips.expect("no reaction chips drawn");
            assert_eq!(
                bubble, chips,
                "reactions did not line up with the bubble's right edge (mine = {mine})"
            );
        }
    }

    /// The chips set both halves of their colour, like a bubble, so they read
    /// as attached to the message rather than as loose text under it.
    #[test]
    fn reaction_chips_carry_their_own_colour() {
        let mut app = sample();
        let mut s = said("bob", "8qbHbw2B", false, "hello", 3661);
        s.reactions = vec![("👍".into(), 1, true)];
        app.said = vec![s];
        let mut t = Terminal::new(TestBackend::new(110, 24)).unwrap();
        t.draw(|f| draw(f, &app)).unwrap();
        let buf = t.backend().buffer().clone();
        let chip = (0..buf.area.height)
            .flat_map(|y| (31..buf.area.width).map(move |x| (x, y)))
            .find(|(x, y)| buf[(*x, *y)].symbol() == "👍")
            .expect("no reaction drawn");
        assert_eq!(buf[chip].style().bg, Some(Color::Indexed(237)));
        assert!(buf[chip].style().fg.is_some(), "the chip took the terminal's colour");
    }

    /// Every emoji the picker offers is one whose width nothing argues about.
    /// A presentation selector makes unicode-width say two and many terminals
    /// paint one, and the cell ratatui reserved for the second half keeps no
    /// background — so a coloured chip comes out with a hole in it.
    #[test]
    fn the_picker_offers_no_emoji_of_disputed_width() {
        for e in REACTIONS {
            assert_eq!(
                e.chars().count(),
                1,
                "{e:?} is a sequence, not a single code point"
            );
            assert_eq!(UnicodeWidthStr::width(*e), 2, "{e:?} is not two columns");
        }
    }

    #[test]
    fn a_reaction_that_arrives_with_a_selector_is_drawn_without_one() {
        let mut app = sample();
        let mut s = said("bob", "8qbHbw2B", false, "hi", 3661);
        // What an older client, or another client, may send.
        s.reactions = vec![("\u{2764}\u{fe0f}".into(), 1, false)];
        app.said = vec![s];
        let mut t = Terminal::new(TestBackend::new(110, 24)).unwrap();
        t.draw(|f| draw(f, &app)).unwrap();
        let buf = t.backend().buffer().clone();
        // No cell inside the chip run is left without a background.
        let run: Vec<(u16, u16)> = (0..buf.area.height)
            .flat_map(|y| (0..buf.area.width).map(move |x| (x, y)))
            .filter(|(x, y)| buf[(*x, *y)].style().bg == Some(Color::Indexed(237)))
            .collect();
        assert!(!run.is_empty(), "no chip drawn");
        let y = run[0].1;
        let (lo, hi) = (run[0].0, run[run.len() - 1].0);
        for x in lo..=hi {
            assert_eq!(
                buf[(x, y)].style().bg,
                Some(Color::Indexed(237)),
                "a hole at x={x}: {:?}",
                buf[(x, y)].symbol()
            );
        }
    }

    /// The quotation is part of the bubble, not a dim line above it, and the
    /// bubble is as wide as the wider of the two — a long quotation used to
    /// stick out past the message quoting it.
    #[test]
    fn a_reply_quotes_inside_the_bubble() {
        let mut app = sample();
        let mut s = said("bob", "8qbHbw2B", false, "yes", 3661);
        s.reply_to = Some((
            "Alice (E4LUkjrZ)".into(),
            "a much longer question than the answer".into(),
        ));
        app.said = vec![s];
        let mut t = Terminal::new(TestBackend::new(110, 24)).unwrap();
        t.draw(|f| draw(f, &app)).unwrap();
        let buf = t.backend().buffer().clone();
        let right_of = |bg: Color| {
            (0..buf.area.height)
                .flat_map(|y| (31..buf.area.width).map(move |x| (x, y)))
                .filter(|(x, y)| buf[(*x, *y)].style().bg == Some(bg))
                .map(|(x, _)| x)
                .max()
        };
        let quote = right_of(Color::Indexed(240)).expect("the quotation has no tint");
        let body = right_of(Color::Indexed(238)).expect("no bubble");
        assert_eq!(quote, body, "the quotation and the message are different widths");
    }

    /// A deleted message gets no bubble, and so no padding shaped like one:
    /// invisible spaces make a line longer than it looks.
    #[test]
    fn a_tombstone_carries_no_invisible_padding() {
        // The observable is alignment: padding in the shape of a bubble it
        // does not have would push a deleted message of ours in from the right
        // edge, out of line with everything else we said.
        let right_edge = |redacted: bool| {
            let mut app = sample();
            let mut s = said("you", "9hSR6S7W", true, "message deleted", 3661);
            s.redacted = redacted;
            app.said = vec![s];
            let out = render(&app, 110, 24);
            out.lines()
                .find(|l| l.contains("message deleted"))
                .map(|l| l.trim_end().chars().count())
                .expect("not on screen")
        };
        assert_eq!(
            right_edge(true),
            right_edge(false),
            "a deleted message did not line up with the others"
        );
    }

    /// Whatever trails a message — the time, and the tick on your own — sits
    /// against the bubble's right edge, however long the last line is. It used
    /// to stop wherever the words did, which on a message of several lines is
    /// a ragged middle rather than a corner.
    ///
    /// Measured in columns. Indexing the rendered string instead would be
    /// wrong wherever a wide character sits earlier in the row, because such a
    /// character is one symbol and two columns.
    #[test]
    fn what_trails_a_message_is_flush_with_the_bubbles_edge() {
        for mine in [false, true] {
            let mut app = sample();
            // Long enough to wrap, so the last line is much shorter than the
            // bubble is wide — where the old layout left the time in mid-air.
            let mut s = said(
                "bob",
                "8qbHbw2B",
                mine,
                "one two three four five six seven eight nine ten eleven twelve thirteen ok",
                3661,
            );
            if mine {
                s.receipt = Some(Receipt::Read);
            }
            app.said = vec![s];
            let mut t = Terminal::new(TestBackend::new(110, 24)).unwrap();
            t.draw(|f| draw(f, &app)).unwrap();
            let buf = t.backend().buffer().clone();
            let bg = if mine { Color::Indexed(24) } else { Color::Indexed(238) };

            // The last row of the bubble is the one carrying the trailer.
            let y = (0..buf.area.height)
                .rfind(|y| (0..buf.area.width).any(|x| buf[(x, *y)].style().bg == Some(bg)))
                .expect("no bubble drawn");
            let painted: Vec<u16> = (0..buf.area.width)
                .filter(|x| buf[(*x, y)].style().bg == Some(bg))
                .collect();
            let edge = *painted.last().unwrap();
            let last_ink = painted
                .iter()
                .copied()
                .rfind(|x| buf[(*x, y)].symbol().trim() != "")
                .expect("nothing written in the bubble");

            // One space of inset, and no more: the trailer is against the edge.
            assert_eq!(
                last_ink + 1,
                edge,
                "what trails the message is not against the bubble's edge \
                 (mine = {mine}): {:?}",
                (0..buf.area.width)
                    .map(|x| buf[(x, y)].symbol().to_string())
                    .collect::<String>()
            );
            if mine {
                // And the tick is the last thing on it.
                assert_eq!(buf[(last_ink, y)].symbol(), "✓");
            }
        }
    }

    /// The message decides how wide the bubble is and the quotation fits
    /// inside it. Sizing the bubble to the quotation instead made a one-line
    /// answer as wide as the paragraph it was answering.
    #[test]
    fn a_quotation_never_widens_the_bubble() {
        let mut short = said("bob", "8qbHbw2B", false, "yes, that is right", 3661);
        short.reply_to = Some((
            "Alice (E4LUkjrZ)".into(),
            "a question very much longer than the answer it gets, going on and on".into(),
        ));
        let mut plain = said("bob", "8qbHbw2B", false, "yes, that is right", 3661);
        plain.reply_to = None;

        let width_of = |s: Said| {
            let mut app2 = sample();
            app2.said = vec![s];
            let mut t = Terminal::new(TestBackend::new(110, 24)).unwrap();
            t.draw(|f| draw(f, &app2)).unwrap();
            let buf = t.backend().buffer().clone();
            (0..buf.area.height)
                .flat_map(|y| (31..buf.area.width).map(move |x| (x, y)))
                .filter(|(x, y)| buf[(*x, *y)].style().bg == Some(Color::Indexed(238)))
                .map(|(x, _)| x)
                .max()
                .expect("no bubble")
        };
        assert_eq!(
            width_of(short),
            width_of(plain),
            "the quotation stretched the bubble"
        );
    }

    /// The cost of that rule, written down: an answer of one word leaves the
    /// quotation almost no room, and it comes out as little more than a mark
    /// saying a reply is a reply.
    #[test]
    fn a_very_short_answer_leaves_little_of_the_quotation() {
        let mut app = sample();
        let mut s = said("bob", "8qbHbw2B", false, "ok", 3661);
        s.reply_to = Some(("Alice (E4LUkjrZ)".into(), "shall we ship on friday?".into()));
        app.said = vec![s];
        let out = render(&app, 110, 24);
        let line = out.lines().find(|l| l.contains("↳")).expect("no quotation");
        assert!(
            line.contains('…'),
            "expected the quotation to be cut: {line:?}"
        );
        // Not enough room for the question, which is the trade this makes.
        assert!(!line.contains("friday"), "{line:?}");
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
