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
use ratatui::layout::{Alignment, Constraint, Direction, Layout, Position, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, List, ListItem, Paragraph, Wrap};
use sqex_chat::client::Link;
use sqnr_core::PubKey;
use unicode_width::UnicodeWidthStr;

/// Every colour the client draws with, in one place.
///
/// Truecolour rather than the 256-colour indices this used to hold. The
/// identicons have always been `Rgb`, so nothing new is being assumed about
/// the terminal — and an index is a number whose meaning depends on the
/// terminal's own palette, which is how the outgoing bubble came to be a
/// muddy `Indexed(24)`: a dark, desaturated teal that reads as sludge next to
/// the blue it was meant to be.
///
/// Named by rôle rather than by hue, so a test can say *which* thing it is
/// checking the colour of, and so changing one is one edit.
pub mod palette {
    use ratatui::style::Color;

    /// Our own bubble. Signal's blue, near enough: saturated and light enough
    /// that near-white text sits on it cleanly.
    pub const SENT_BG: Color = Color::Rgb(0x3A, 0x6A, 0xD6);
    pub const SENT_FG: Color = Color::Rgb(0xF7, 0xF9, 0xFC);
    /// A step *darker* than the bubble, and darker for the sake of the text
    /// on it. Lighter reads better as an inset — which is what it was — but
    /// white on this blue only reaches 4.7:1 to begin with, so anything
    /// lighter than the bubble takes light text worse than the bubble does,
    /// and the quotation was sitting at 3.5:1. Down here it is 7.2:1, and
    /// still a clear step away from the bubble at 1.5:1.
    pub const SENT_QUOTE_BG: Color = Color::Rgb(0x2A, 0x4F, 0xA8);
    /// The time, the ticks and the markers, on blue. Dimmer than the words
    /// and still legible, which one grey for both sides could not manage.
    pub const SENT_TRAILER: Color = Color::Rgb(0xDC, 0xE6, 0xFA);

    /// Everybody else's.
    pub const RECV_BG: Color = Color::Rgb(0x30, 0x34, 0x3C);
    pub const RECV_FG: Color = Color::Rgb(0xE4, 0xE7, 0xED);
    /// The received quotation goes the other way, and the asymmetry is the
    /// point: a dark grey has room above it, and going darker instead would
    /// leave only 1.2:1 between the quotation and the bubble it sits in.
    /// Both sides read as a band inside the bubble; only the direction they
    /// take to get there differs, because only one of them is constrained.
    pub const RECV_QUOTE_BG: Color = Color::Rgb(0x44, 0x4A, 0x54);
    pub const RECV_TRAILER: Color = Color::Rgb(0x9A, 0xA0, 0xAA);

    /// Reaction chips, and the brighter foreground for one we are part of.
    pub const CHIP_BG: Color = Color::Rgb(0x3E, 0x43, 0x4C);
    pub const CHIP_FG: Color = Color::Rgb(0xC8, 0xCD, 0xD6);
    pub const CHIP_MINE: Color = Color::Rgb(0x7A, 0xA2, 0xF7);

    /// Names, headings, and anything else that identifies somebody.
    pub const ACCENT: Color = Color::Rgb(0x7A, 0xA2, 0xF7);
    /// Something to look at: unread counts, the pick cursor, a public channel,
    /// a refusal.
    pub const ATTENTION: Color = Color::Rgb(0xE9, 0xB5, 0x5A);
    /// Ink for text laid *on* `ATTENTION`, which is far too light to take the
    /// terminal's own foreground.
    pub const INK: Color = Color::Rgb(0x14, 0x16, 0x1A);
    /// Present but not being read: hints, timestamps, the keys line.
    pub const MUTED: Color = Color::Rgb(0x78, 0x7E, 0x8A);

    /// The connection light. Green talking, amber reconnecting, red down for
    /// long enough that it should not be counted on.
    pub const LIVE: Color = Color::Rgb(0x5E, 0xC2, 0x7A);
    pub const TRYING: Color = Color::Rgb(0xE9, 0xB5, 0x5A);
    pub const GONE: Color = Color::Rgb(0xE2, 0x69, 0x62);
}

/// One row in the conversation list.
pub struct Row {
    pub channel: [u8; 32],
    /// What to call this conversation: a person's display name or the local
    /// label for a direct message, the channel's own name for a group. Empty
    /// when a direct message's peer has published no name and we chose none.
    pub label: String,
    /// The peer's key **in full**, for a direct message. `None` for a group,
    /// whose name belongs to the channel and not to a person.
    ///
    /// In full because it is what hover, click and `/who` hand over, and a
    /// truncated key is not one. What is *drawn* is [`short_key`] of it, and
    /// only when the peer has no name.
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
    /// The author's key, in full. Always present; drawn only as far as
    /// [`author`] shows it, which since the SIP-21 deviation is not at all
    /// when they have a name.
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
    /// Entries a device signed at a chain position it had already used
    /// (SIP-31). The sequence numbers, because a count says misconduct
    /// happened and a reader wants to know *where*.
    ///
    /// This is the one verdict in SIP-31 that is evidence rather than
    /// housekeeping — it cannot occur without a device signing twice or
    /// somebody replaying — and the SIP requires a client to surface it. A
    /// gap, by contrast, is ordinary and lives in `gap` above.
    pub forked: Vec<u64>,
    /// Entries whose signature verifies and whose signing device nobody could
    /// bind to the account the entry names (SIP-32). The first step proves a
    /// key signed and says nothing about whose it is, so the attribution is
    /// withheld rather than assumed.
    pub unattributed: usize,
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
            && self.forked.is_empty()
            && self.unattributed == 0
            && self.message.is_none()
    }

    /// The status line, worst first.
    ///
    /// Worst first because the line is short and the reader gets whichever
    /// fits: "you have no key" explains an empty conversation and "3 unreadable"
    /// does not.
    pub fn line(&self) -> String {
        let mut parts = Vec::new();
        if !self.forked.is_empty() {
            parts.push(format!(
                "signed twice at one chain position: message{} {} \u{2014} this cannot happen \
                 without a device signing twice or somebody replaying",
                if self.forked.len() == 1 { "" } else { "s" },
                self.forked
                    .iter()
                    .map(|s| s.to_string())
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
        }
        if self.unattributed > 0 {
            parts.push(format!(
                "{} message{} signed by a key nobody can bind to the name on {}",
                self.unattributed,
                if self.unattributed == 1 { "" } else { "s" },
                if self.unattributed == 1 { "it" } else { "them" }
            ));
        }
        if let Some(epoch) = self.no_key {
            parts.push(format!(
                "no key for epoch {epoch} — nobody has sent you one, so this cannot be read"
            ));
        }
        if self.gap {
            parts.push("older messages have passed the retention window and are gone".to_string());
        }
        if self.restarted {
            parts
                .push("this conversation was restarted — everything before it is gone".to_string());
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
    /// SIP-31: the incarnation to sign a join against. Carried from the
    /// directory because `Info` — the other place it appears — needs the
    /// membership a join is trying to acquire.
    pub instance: [u8; 32],
    pub name: String,
    pub topic: String,
    pub members: u16,
}

/// Everything on screen.
#[derive(Default)]
pub struct App {
    pub me: String,
    /// The display name this account has published, if it has published one.
    ///
    /// Shown in the header in place of the key, the same way `author` shows a
    /// name in place of one everywhere else — an account that has published
    /// none falls back to a stub of the key, because a header naming nobody is
    /// worse than one naming them roughly.
    pub name: String,
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
    /// Whether the client has taken the mouse from the terminal.
    ///
    /// False until asked for, which is why `Default` is right here: capture
    /// stops the terminal's own text selection, and that is not a trade to
    /// make on somebody's behalf. Not drawn — kept here because `/mouse`
    /// toggles it and something has to remember which way it went.
    pub mouse: bool,
    /// How much a page of scrolling moves, set from the last frame's pane.
    /// One line short of a screenful either way, so a page keeps a line of
    /// what was already read and the reader can join the two up.
    pub page: usize,
    /// How far back through the conversation the reader has scrolled, in
    /// lines. Nought is the bottom, which is where a conversation opens and
    /// where it stays while somebody is reading the newest of it.
    pub scroll: usize,
    /// A message to bring back to the bottom of the pane on the next frame,
    /// set when the window is resized.
    ///
    /// `scroll` counts **lines**, and every line is a function of the width:
    /// narrow the window and each message wraps into more of them, so the same
    /// offset lands somewhere else entirely. Anchoring to a message is what
    /// makes a resize keep the reader where they were rather than throwing
    /// them into a different part of the conversation.
    pub anchor: Option<usize>,
    /// Set when the pick has just moved, so the next frame brings it into
    /// view.
    ///
    /// A flag rather than "always keep the pick visible", because the two are
    /// different: somebody who scrolls with `^U` while a message is picked is
    /// asking to look elsewhere, and snapping back to the pick would be the
    /// client arguing with them. This only fires on the keystroke that moved
    /// the pick, which is the moment the view is meant to follow.
    ///
    /// Cleared by the loop once the frame that honoured it has drawn.
    pub follow_pick: bool,
    /// The bottom-most message actually on screen, as an index into `said`.
    ///
    /// `None` when the pane holds no message at all. Taken from the frame that
    /// drew, like `page` and `scrollable`: a second copy of the layout could
    /// disagree with the first, and this decides where the picker lands.
    ///
    /// At the bottom of a conversation this *is* the newest message, so it
    /// changes nothing there — it only matters once somebody has paged back.
    pub last_visible: Option<usize>,
    /// Whether the conversation is taller than the pane, so there is anything
    /// to scroll back to.
    ///
    /// The footer says how to page only while this is true. A hint for
    /// something that would do nothing is noise, and the moment a
    /// conversation first outgrows its pane is exactly the moment somebody
    /// wants to know the keys — which is why this is worth a field rather
    /// than a permanent entry in the line.
    pub scrollable: bool,
    /// The message the pointer is over, as an index into `said`.
    ///
    /// Detail on demand, and only detail: nothing a reader *needs* may live
    /// here. A key shown on hover is a key most people never see, which is
    /// the opposite of what SIP-21 asks for — a timestamp is the right sort
    /// of thing, because the short one is already on the message and this is
    /// only the rest of it.
    pub hovered: Option<usize>,
    /// The first message not read when this conversation was opened, if there
    /// was one. A line goes above it.
    pub divider: Option<u64>,
    /// Now, so a day separator can leave the year off the current one and put
    /// it on older history, where a bare date is a trap.
    pub now: u64,
    /// Whether the exchange is reachable. The one thing on screen that is
    /// about the client rather than about anything anybody said.
    pub link: Link,
    /// How many people are in the conversation on screen. Nought until the
    /// exchange has been asked, and the header says nothing rather than
    /// claiming an empty room.
    pub members: usize,
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
    identicon_of(key.as_bytes())
}

/// The same, from whatever identifies the thing.
///
/// A channel has an identifier as good as a key has, and no reason to go
/// without a mark of its own — see [`identicon`].
pub fn identicon_of(id: &[u8]) -> Vec<Span<'static>> {
    let h = fnv(id);
    // Two hues, drawn independently and then pushed apart if they landed too
    // close together.
    //
    // Independently, because deriving the second from the first makes the
    // whole pair a function of one byte — two accounts whose first hue is
    // near each other then get near-identical marks, which is the thing these
    // exist to prevent. Pushed apart, because the comment here has always
    // claimed the halves stay distinguishable and the expression never did it.
    let first = (h & 0xFF) as u8;
    let mut second = ((h >> 8) & 0xFF) as u8;
    // Distance round the wheel, which is a circle: 250 and 5 are ten apart.
    let apart = |x: u8, y: u8| x.wrapping_sub(y).min(y.wrapping_sub(x));
    if apart(first, second) < 60 {
        second = second.wrapping_add(85);
    }
    let a = hue(first);
    let b = hue(second);

    // One of four patterns, every one of which uses **both** colours in both
    // cells: two banded, two chequered.
    //
    // The old version took two bits and let them choose each pixel freely,
    // which meant `00` painted every pixel the first colour and `11` every
    // pixel the second. Forty-seven per cent of keys came out as a flat block
    // with no pattern in it and only one of its two hues — half the
    // information the mark claims to carry, gone, and two accounts a shade
    // apart indistinguishable. It was reported, reasonably, as the identicons
    // having stopped working.
    let bits = ((h >> 16) & 0b11) as u8;
    let (top, bottom) = if bits & 0b01 == 0 { (a, b) } else { (b, a) };
    let cell = |fg: Color, bg: Color| Span::styled("▀", Style::default().fg(fg).bg(bg));
    if bits & 0b10 == 0 {
        // Banded: the same both sides, so it reads as one mark.
        vec![cell(top, bottom), cell(top, bottom)]
    } else {
        // Chequered: the halves swap across the middle.
        vec![cell(top, bottom), cell(bottom, top)]
    }
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

/// How much of a key stands in for it when there is no name.
///
/// Eight base58 characters, as the admin CLI truncates to. Never enough to
/// identify anybody by — see [`author`] for where the whole of it lives.
pub fn short_key(key: &str) -> String {
    key.chars().take(8).collect()
}

/// The author of a line: their name, or a stub of their key if they have none.
///
/// **This departs from SIP-21, deliberately and on the record.** That SIP says
/// a client MUST show the key alongside the name wherever the distinction
/// could matter, and MUST NOT let a name be the only thing a person sees at
/// those moments — "the one requirement in this SIP that is load-bearing".
/// This client now shows the name alone.
///
/// The reason the rule exists does not go away by being deviated from: a name
/// is a claim its subject makes, two accounts may publish the same one, and
/// names differing by a homoglyph, a combining mark or a bidirectional
/// override are indistinguishable on screen. The key is still the only thing
/// that tells them apart. So it is not removed, only moved, and three routes
/// to it are kept — two of which need no mouse, because mouse capture is off
/// until asked for:
///
/// - **hover** a message and the status line gives the whole key;
/// - **click** one and it goes to the clipboard;
/// - **pick** one with Esc and the status line gives the whole key, and `c`
///   copies it. `/who` lists every member's key in full.
///
/// What that trades is the reader who never does any of those things and is
/// therefore never told. That is the risk SIP-21 names, and it is being taken
/// knowingly rather than overlooked.
///
/// `mine` is our own messages, where impersonation is not a question a reader
/// has.
pub fn author(name: &str, key: &str, mine: bool) -> String {
    if mine {
        return "you".to_string();
    }
    // A contact nobody has named goes by a stub of its key. A name that *is*
    // the key is not a name — that is what an unnamed contact's label holds.
    if name.is_empty() || name == key || name == short_key(key) {
        return short_key(key);
    }
    truncate(name, AUTHOR)
}

/// What the last frame drew, for the caller that has to act on it.
///
/// Returned by [`draw`] rather than recomputed, because a second copy of the
/// layout is a second copy that can drift from the first — and a pointer that
/// reports the message above the one under it is worse than no pointer.
#[derive(Default)]
pub struct Drawn {
    /// The transcript's pane. A pointer anywhere else is over nothing.
    pub pane: Rect,
    /// Indexed by absolute screen row: which message is on it.
    pub rows: Vec<Option<usize>>,
    /// How far back the transcript actually went, after clamping. The caller
    /// keeps a wish; this is what came of it, and storing it back is what
    /// stops a held key winding the number up for ever against a short
    /// conversation.
    pub scroll: usize,
    /// Lines in the whole conversation, and how many of them fit. The
    /// difference in `total` between two frames is how much arrived — which is
    /// what a reader looking at history has to be moved by in order to stay
    /// still.
    pub total: usize,
    pub room: usize,
}

impl Drawn {
    pub fn at(&self, column: u16, row: u16) -> Option<usize> {
        if !self.pane.contains(Position { x: column, y: row }) {
            return None;
        }
        *self.rows.get(row as usize)?
    }
}

pub fn draw(f: &mut Frame, app: &App) -> Drawn {
    let outer = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            // Two rows: the header, and a blank one under it. A title bar
            // hard against the panes reads as another row of the panes.
            Constraint::Length(2),
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
    let hover = transcript(f, app, panes[1], f.area().height);
    input(f, app, outer[2]);
    status(f, app, outer[3]);
    hover
}

/// How much of this account's key the header carries.
///
/// Six characters, which is what was asked for and is enough to recognise
/// yourself by. It is **not** enough to identify anybody by, which is why
/// `/whoami` exists: this used to be the one place the whole key appeared, and
/// `short`'s own note says a person comparing keys should be shown all of it.
const KEY_HEAD: usize = 6;

/// This account, this program, and whether either can reach anything.
///
/// Nothing about the conversation: that has a header of its own on its own
/// pane, which is where somebody looks for it.
fn header(f: &mut Frame, app: &App, area: Rect) {
    let dim = Style::default().fg(palette::MUTED);
    // A colour is not a word. Green, amber and red say *that* something has
    // changed and never what, and a reader who has not learnt this particular
    // client's three colours is being asked to guess — including at the one
    // moment the answer matters, which is when it has just gone amber.
    //
    // So all three say which. Leaving green silent made the good state the
    // only one you had to know the code for.
    let (colour, word) = match app.link {
        Link::Up => (palette::LIVE, "connected"),
        Link::Retrying => (palette::TRYING, "reconnecting…"),
        Link::Gone => (palette::GONE, "offline"),
    };
    // Who this is: the published name, or a stub of the key when there is
    // none. The same rule as `author`, and for the same reason — a name is
    // what a person knows themselves by, and `/whoami` is where the whole key
    // lives.
    let me = if app.name.is_empty() {
        app.me.chars().take(KEY_HEAD).collect::<String>()
    } else {
        truncate(&app.name, AUTHOR)
    };
    let mut left = vec![
        Span::styled(" ●", Style::default().fg(colour)),
        Span::styled(format!(" {me}"), dim),
        Span::styled(format!("  {word}"), Style::default().fg(colour)),
    ];
    // The name of the thing goes in the corner, where a title bar puts it and
    // where the eye is not looking for anything else — with the version, so
    // that "which one am I running" never needs asking. It has been the first
    // question of half the problems today.
    let right = format!(" sqex-chat {} ", env!("CARGO_PKG_VERSION"));
    let used: usize = left.iter().map(|s| s.content.width()).sum();
    let pad = (area.width as usize).saturating_sub(used + right.width());
    left.push(Span::raw(" ".repeat(pad)));
    left.push(Span::styled(
        " sqex-chat ",
        Style::default().add_modifier(Modifier::BOLD),
    ));
    left.push(Span::styled(format!("{} ", env!("CARGO_PKG_VERSION")), dim));
    f.render_widget(Paragraph::new(Line::from(left)), area);
}

/// How many rows the conversation's own header takes: who, what, and a rule.
const HEAD: u16 = 3;

/// The conversation, headed on its own pane.
///
/// Where a chat client puts it, and where the topic belongs: it used to be
/// squeezed into the window's top strip at a constant sixty columns, next to
/// this account's key, which is a different subject entirely.
fn conversation_head(f: &mut Frame, app: &App, area: Rect) {
    let dim = Style::default().fg(palette::MUTED);
    let width = area.width as usize;
    let Some(row) = app.selected_row() else {
        return;
    };

    let mut top = vec![Span::raw(" ")];
    match &row.key {
        Some(key) => top.extend(identicon(key)),
        None => top.extend(identicon_of(&row.channel)),
    }
    top.push(Span::raw("  "));
    // A direct message names a person, so it carries their key beside their
    // name — this is exactly a place where mistaking one person for another
    // matters, and SIP-21 does not care that the pane is new.
    let name = match &row.key {
        Some(key) => author(&row.label, key, false),
        None => row.label.clone(),
    };
    top.push(Span::styled(
        name,
        Style::default().add_modifier(Modifier::BOLD),
    ));
    // Hard right: how many people can read this, or the one fact that stops a
    // conversation working before it has started.
    let corner = if row.waiting {
        "not started their client yet".to_string()
    } else if row.group && app.members > 0 {
        format!(
            "{} {}",
            app.members,
            if app.members == 1 { "person" } else { "people" }
        )
    } else {
        String::new()
    };
    let used: usize = top.iter().map(|s| s.content.width()).sum();
    top.push(Span::raw(
        " ".repeat(width.saturating_sub(used + corner.width() + 1)),
    ));
    top.push(Span::styled(
        corner,
        if row.waiting {
            Style::default().fg(palette::ATTENTION)
        } else {
            dim
        },
    ));

    let mut under = Vec::new();
    let mut said = String::new();
    if row.public {
        // The single most consequential thing about a room, so it is said
        // before whatever the room is for.
        said += "public";
    }
    if !app.topic.is_empty() {
        if !said.is_empty() {
            said += " · ";
        }
        said += &app.topic;
    }
    let hint = if app.has_avatar {
        "/avatar save <path>"
    } else {
        ""
    };
    let room = width.saturating_sub(hint.width() + 6);
    under.push(Span::styled(format!("     {}", truncate(&said, room)), dim));
    if !hint.is_empty() {
        let used: usize = under.iter().map(|s| s.content.width()).sum();
        under.push(Span::raw(
            " ".repeat(width.saturating_sub(used + hint.width() + 1)),
        ));
        under.push(Span::styled(hint, dim));
    }

    f.render_widget(
        Paragraph::new(vec![
            Line::from(top),
            Line::from(under),
            // A rule, so the transcript has a top edge to sit under rather
            // than beginning wherever the header happened to stop.
            Line::from(Span::styled("─".repeat(width), dim)),
        ]),
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
            let mut spans: Vec<Span<'static>> = vec![
                // Yellow for public: anybody may join and read it, and that is
                // the one thing about a row worth seeing before you type.
                Span::styled(
                    if r.group { "#" } else { " " }.to_string(),
                    if r.public {
                        base.fg(palette::ATTENTION)
                    } else {
                        base
                    },
                ),
            ];
            // A direct message is marked by its peer's key, a channel by its
            // own identifier. This used to leave a channel blank, on the
            // grounds that inventing a face for a room says something untrue
            // about it — but the objection was to the *face*, and this is not
            // one. It is a colour derived from an identifier, and a channel
            // has an identifier exactly as a person has a key.
            match &r.key {
                Some(key) => spans.extend(identicon(key)),
                None => spans.extend(identicon_of(&r.channel)),
            }
            spans.push(Span::styled(" ", base));
            spans.push(Span::styled(
                format!("{:<w$}", row_label(r, w), w = w),
                base,
            ));
            // `base`, not a bare style. The selected row is drawn reversed,
            // and a span that sets only a foreground keeps the terminal's own
            // background — so the count and the marker came out as holes
            // punched through the highlight.
            if r.unread > 0 {
                spans.push(Span::styled(
                    format!(" {}", r.unread),
                    base.fg(palette::ATTENTION),
                ));
            }
            if r.waiting {
                // Not an error: they are a member, they have simply never run
                // a client, so there is nowhere to send a key yet.
                spans.push(Span::styled(" ·", base.fg(palette::MUTED)));
            }
            // A second line, the way every chat client does it: when, and the
            // beginning of what was said. Without it the list says only which
            // conversations exist.
            let mut under = Vec::new();
            if r.at > 0 {
                under.push(Span::styled(
                    format!("   {}", clock(r.at)),
                    if selected {
                        base
                    } else {
                        base.fg(palette::MUTED)
                    },
                ));
            }
            if !r.preview.is_empty() {
                let room = (area.width as usize).saturating_sub(11);
                under.push(Span::styled(
                    truncate(&r.preview, room),
                    if selected {
                        base
                    } else {
                        base.fg(palette::MUTED)
                    },
                ));
            }
            // Both lines run to the pane's edge, so a selected row is a bar
            // rather than a highlight that stops wherever the words did.
            let inner = area.width.saturating_sub(1) as usize;
            let fill = |line: &mut Vec<Span<'static>>| {
                let used: usize = line.iter().map(|s| s.content.width()).sum();
                line.push(Span::styled(" ".repeat(inner.saturating_sub(used)), base));
            };
            fill(&mut spans);
            fill(&mut under);
            ListItem::new(vec![
                Line::from(spans),
                Line::from(under),
                // A row of air between conversations. Two lines each with
                // nothing between them read as one block of text; the eye has
                // to count to work out where one conversation ends.
                Line::from(""),
            ])
        })
        .collect();

    let list = if items.is_empty() {
        List::new(vec![ListItem::new(Line::from(Span::styled(
            "no contacts yet — press ^N",
            Style::default().fg(palette::MUTED),
        )))])
    } else {
        List::new(items)
    };
    f.render_widget(list.block(Block::default().borders(Borders::RIGHT)), area);
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
    let align = if mine {
        Alignment::Right
    } else {
        Alignment::Left
    };
    let dim = Style::default().fg(palette::MUTED);

    // Who spoke, once for a run rather than against every line — but always
    // within a few lines of what they said, because the key is what tells two
    // people with the same display name apart (SIP-21).
    if head && !mine {
        let mut spans = identicon(&s.key);
        spans.push(Span::raw(" "));
        spans.push(Span::styled(
            author(&s.who, &s.key, false),
            Style::default().fg(palette::ACCENT),
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
        Style::default().fg(palette::SENT_FG).bg(palette::SENT_BG)
    } else {
        Style::default().fg(palette::RECV_FG).bg(palette::RECV_BG)
    };
    let inside = if s.redacted {
        dim.add_modifier(Modifier::ITALIC)
    } else if mine {
        style.fg(palette::SENT_TRAILER)
    } else {
        style.fg(palette::RECV_TRAILER)
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
    let mut content = body
        .iter()
        .enumerate()
        .map(|(n, l)| {
            UnicodeWidthStr::width(l.as_str())
                + if n == last {
                    UnicodeWidthStr::width(tail.as_str())
                } else {
                    0
                }
        })
        .max()
        .unwrap_or(0);

    // The message decides how wide the bubble is; the quotation fits inside
    // it. Sizing the bubble to the quotation instead made a one-line answer as
    // wide as the paragraph it was answering.
    //
    // With a floor under it, because the other extreme is no better: "ok" left
    // the quotation four columns and it came out `↳ Alice (E…`, which names
    // nobody. The floor is bounded by the pane, so a narrow terminal is never
    // overrun, and by the quotation itself, so a short quote cannot widen a
    // short answer — it only ever buys back room there is something to put in.
    if let Some(q) = &quoted {
        content = content.max(
            QUOTE_FLOOR
                .min(width)
                .min(UnicodeWidthStr::width(q.as_str())),
        );
    }
    let quoted = quoted.map(|q| truncate(&q, content));

    // The quotation, a shade off the bubble it belongs to and padded to the
    // same width, so the whole thing is one block.
    if let Some(q) = &quoted {
        let tint = if s.redacted {
            dim.add_modifier(Modifier::ITALIC)
        } else if mine {
            Style::default()
                .fg(palette::SENT_FG)
                .bg(palette::SENT_QUOTE_BG)
        } else {
            Style::default()
                .fg(palette::RECV_FG)
                .bg(palette::RECV_QUOTE_BG)
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
                Style::default().fg(palette::ATTENTION),
            ));
        }
        let used = UnicodeWidthStr::width(line.as_str())
            + if n == last {
                UnicodeWidthStr::width(tail.as_str())
            } else {
                0
            };
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
                Style::default().fg(palette::ATTENTION),
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
        let chip_style = Style::default().fg(palette::CHIP_FG).bg(palette::CHIP_BG);
        let ours = Style::default().fg(palette::CHIP_MINE).bg(palette::CHIP_BG);

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
                Style::default().fg(palette::ATTENTION),
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
        Some(a) => {
            a.mine != b.mine
                || a.who != b.who
                || a.key != b.key
                || b.at.saturating_sub(a.at) > RUN_GAP
        }
    }
}

/// How long a silence has to be before the next message is a new run.
const RUN_GAP: u64 = 5 * 60;

/// The narrowest a bubble may be **when it carries a quotation**.
///
/// The bubble is otherwise sized by its own words, which is right: an answer
/// should not inherit the width of the paragraph it answers. But a one-word
/// answer then left the quotation four columns, and `↳ Alice (E…` identifies
/// nobody — worse than the sequence number it replaced, which at least named a
/// message. Thirty columns is about what "a name, its key, and the first words
/// of what they said" needs.
///
/// Bounded twice at the point of use: never past the pane, and never past the
/// quotation's own width, so a short quote cannot force a wide bubble.
const QUOTE_FLOOR: usize = 30;

fn transcript(f: &mut Frame, app: &App, area: Rect, height: u16) -> Drawn {
    // The views that are not the conversation have nothing to hover: no rows
    // of theirs belong to a message.
    if app.helping {
        help(f, area);
        return Drawn::default();
    }
    if app.searching {
        results(f, app, area);
        return Drawn::default();
    }
    if !app.found.is_empty() {
        directory(f, app, area);
        return Drawn::default();
    }
    // The header belongs to the conversation, so the views that are not the
    // conversation — the command list, a search, the directory — take the
    // whole pane and are handled above.
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(HEAD), Constraint::Min(0)])
        .split(area);
    conversation_head(f, app, rows[0]);
    let area = rows[1];
    let inner = (area.width as usize).saturating_sub(2);
    // Wide enough to read, narrow enough that the two sides are visibly two
    // sides. A bubble filling the pane would make alignment meaningless.
    let width = (inner * 3 / 5).clamp(16, inner.max(16));

    let mut lines: Vec<Line> = Vec::new();
    // Which message each line belongs to, built in step with the lines
    // themselves. Anything that is not a message — a separator, a blank, the
    // note about lost history — owns nothing, and hovering it says nothing.
    let mut owners: Vec<Option<usize>> = Vec::new();
    let dim = Style::default().fg(palette::MUTED);
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
        owners.push(None);
    }
    if app.trouble.gap {
        lines.push(Line::from(Span::styled(
            "─── older messages are past the retention window and cannot be recovered ───",
            dim,
        )));
        owners.push(None);
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
            owners.push(None);
            day = this_day;
        }
        // Where you had got to when you opened this. Above the first message
        // you had not seen, and it stays there while you read past it.
        if app.divider == Some(s.seq) {
            let n = app.said.len() - i;
            lines.push(
                Line::from(Span::styled(
                    format!("─── {n} unread ───"),
                    Style::default().fg(palette::ATTENTION),
                ))
                .alignment(Alignment::Center),
            );
            owners.push(None);
        } else if starts_run(i.checked_sub(1).and_then(|p| app.said.get(p)), s) && i > 0 {
            lines.push(Line::from(""));
            owners.push(None);
        }
        let head = starts_run(i.checked_sub(1).and_then(|p| app.said.get(p)), s);
        let block = bubble(app, s, app.picked == Some(i), head, width);
        // The whole bubble belongs to its message — the run header and the
        // reactions included. Anywhere on it is a place somebody will point.
        owners.extend(std::iter::repeat_n(Some(i), block.len()));
        lines.extend(block);
    }

    if app.said.is_empty() && app.trouble.is_quiet() {
        lines.push(Line::from(Span::styled("nothing here yet", dim)));
        owners.push(None);
    }
    if app.peer_typing {
        lines.push(Line::from(Span::styled("typing…", dim)));
        owners.push(None);
    }

    let total = lines.len();
    // A scrolled transcript gives up its last row to say so. Without that,
    // reading history while messages arrive is silent: they land below the
    // bottom of the view and nothing on screen says anything came.
    let scrolled = app.scroll > 0 && total > area.height.saturating_sub(2) as usize;
    let pane = if scrolled {
        Rect {
            height: area.height.saturating_sub(1),
            ..area
        }
    } else {
        area
    };
    let room = pane.height.saturating_sub(2) as usize;
    // How far back it is possible to go, and how far back we actually went.
    // The caller's number is a wish: it may be left over from a longer
    // conversation, or from before the window was resized.
    let furthest = total.saturating_sub(room);
    // Following the pick. `owners` says which lines belong to the picked
    // message, so the smallest move that puts the whole of it on screen is
    // arithmetic rather than guesswork.
    //
    // Nudged only as far as it has to go — a pick moving off the top scrolls
    // by the lines that message occupies, not by a page — so walking up
    // through a conversation reads as walking rather than jumping.
    // An anchored message goes back to the bottom of the pane, which is where
    // it was when the window changed size. Taken before the pick, because a
    // resize moves the reader's whole view and a pick is one message in it.
    let anchored = app
        .anchor
        .and_then(|i| owners.iter().rposition(|o| *o == Some(i)))
        .map(|last| {
            let shown = pane.height as usize;
            furthest.saturating_sub((last + 1).saturating_sub(shown))
        });
    let wish = match app
        .follow_pick
        .then_some(app.picked)
        .flatten()
        .and_then(|i| {
            let first = owners.iter().position(|o| *o == Some(i))?;
            let last = owners.iter().rposition(|o| *o == Some(i))?;
            Some((first, last))
        }) {
        Some((first, last)) => {
            let here = app.scroll.min(furthest);
            let top = furthest - here;
            if first < top {
                // Above the pane: bring its first line to the top.
                furthest.saturating_sub(first)
            } else if last >= top + room {
                // Below it: bring its last line to the bottom.
                furthest.saturating_sub((last + 1).saturating_sub(room))
            } else {
                app.scroll
            }
        }
        None => app.scroll,
    };
    // A followed pick wins over an anchor. Both fire on a resize when a
    // message is picked, and they want different things: the anchor holds the
    // bottom of the pane, the follow keeps the pick in view. Narrowing makes
    // every message above the anchor taller, so holding the bottom is what
    // pushes the pick off the top — the very fault the follow exists to stop.
    let scroll = if app.follow_pick {
        wish.min(furthest)
    } else {
        anchored.unwrap_or(wish).min(furthest)
    };
    let skip = furthest - scroll;
    // A short conversation sits at the bottom, against the input box, rather
    // than floating at the top of an empty pane — where the next message would
    // appear a long way from where somebody is typing.
    for _ in lines.len()..room {
        lines.insert(0, Line::from(""));
        owners.insert(0, None);
    }
    let shown = lines.split_off(skip.min(lines.len()));
    // The same cut, on the same vector, so a row and its owner cannot come
    // apart. Doing this arithmetic twice is how they would.
    let owners = owners.split_off(skip.min(owners.len()));
    f.render_widget(
        // No `Wrap`: the text is already wrapped above, and a wrapped
        // paragraph ignores per-line alignment.
        Paragraph::new(shown).block(Block::default().borders(Borders::NONE)),
        pane,
    );
    if scrolled {
        f.render_widget(
            Paragraph::new(
                Line::from(Span::styled(
                    format!("─── {scroll} more below · ^D or PgDn, End for the newest ───"),
                    Style::default().fg(palette::ATTENTION),
                ))
                .alignment(Alignment::Center),
            ),
            Rect {
                y: area.y + area.height - 1,
                height: 1,
                ..area
            },
        );
    }

    // Clipped to the pane, not merely to the screen. `owners` runs to the end
    // of the conversation, so writing all of it recorded messages on rows the
    // transcript does not occupy — down in the composer — and anything reading
    // the last entry got a message below the fold. That is what `last_visible`
    // reads to decide where `Esc` starts, and what an anchor reads to put a
    // message back at the bottom.
    let mut rows = vec![None; height as usize];
    for (n, owner) in owners.into_iter().take(pane.height as usize).enumerate() {
        let y = pane.y as usize + n;
        if y < rows.len() {
            rows[y] = owner;
        }
    }
    Drawn {
        pane,
        rows,
        scroll,
        total,
        room,
    }
}

/// What a search found, newest first.
fn results(f: &mut Frame, app: &App, area: Rect) {
    let dim = Style::default().fg(palette::MUTED);
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
                Style::default().fg(palette::ATTENTION),
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
            "nothing here matches. This searches what this client holds, which is \
             not necessarily everything that was said.",
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
            Span::styled(
                format!("{:>AUTHOR$} ", truncate(&h.who, AUTHOR)),
                Style::default().fg(palette::ACCENT),
            ),
            Span::raw(before.to_string()),
            Span::styled(
                hit.to_string(),
                Style::default().fg(palette::INK).bg(palette::ATTENTION),
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
    s.chars()
        .filter(|c| *c != '\u{fe0f}' && *c != '\u{fe0e}')
        .collect()
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
    (
        "messages",
        &[
            ("/file <path>", "send a file"),
            ("/save <n> <path>", "keep one somebody sent"),
            (
                "/forward <n> <m>",
                "send a file on to conversation m, without re-uploading",
            ),
            (
                "/redact <n>",
                "delete a message you posted, and the file it carried",
            ),
        ],
    ),
    (
        "conversations",
        &[
            ("/new <name>", "a private group"),
            ("/public <name>", "a channel anybody may find and join"),
            (
                "/find [query]  /join <n>",
                "search the directory, and enter one",
            ),
            (
                "/invite <key>  /kick <key>",
                "add somebody; remove them and rotate the key",
            ),
            ("/op <key>  /deop <key>", "grant or withdraw admin here"),
            (
                "/leave  /close",
                "leave it; or end it for everyone, permanently",
            ),
        ],
    ),
    (
        "this channel",
        &[
            (
                "/name  /topic  /avatar",
                "what it is called, what it is for, its picture",
            ),
            ("/retain <secs> [max]", "how long it keeps what is said"),
            (
                "/who  /read",
                "who is here and their keys in full; how far each has read",
            ),
            ("/rotate", "mint a new key for everyone currently here"),
        ],
    ),
    (
        "finding things",
        &[("/search <text>", "find it in this conversation")],
    ),
    (
        "you",
        &[
            (
                "/profile [name | title]",
                "what you publish about yourself; `off` clears it",
            ),
            ("/block  /unblock  /blocked", "who may reach you"),
            (
                "/whoami",
                "your key in full — the header carries only the first six",
            ),
            (
                "/mouse [on|off]",
                "scroll with the wheel, and hover a message for its full time; off by default, because it stops the terminal's own text selection",
            ),
            (
                "/reconnect",
                "try the exchange again now, rather than waiting out the backoff",
            ),
        ],
    ),
];

/// Everything the client can do, over the transcript.
///
/// A view rather than a line, because the status line is one row and there are
/// forty of these. It was the only list there was, and at eighty columns the
/// end of it was simply cut off — so the commands that fell off were
/// undiscoverable and nothing said so.
fn help(f: &mut Frame, area: Rect) {
    let dim = Style::default().fg(palette::MUTED);
    let key = Style::default().fg(palette::ATTENTION);
    let head = Style::default().fg(palette::ACCENT);
    let mut lines = vec![
        Line::from(Span::styled("keys", head)),
        Line::from(vec![
            Span::styled("  Tab ", key),
            Span::styled("move between conversations    ", dim),
            Span::styled("↑↓ ", key),
            Span::styled("scan this one    ", dim),
            Span::styled("Esc ", key),
            Span::styled("back out    ", dim),
            Span::styled("^N ", key),
            Span::styled("add somebody    ", dim),
            Span::styled("^C ", key),
            Span::styled("quit", dim),
        ]),
        Line::from(vec![
            Span::styled("  ^U ^D  ", key),
            Span::styled("a screen back or forward    ", dim),
            Span::styled("Home End ", key),
            Span::styled("the oldest, the newest    ", dim),
            Span::styled("/mouse ", key),
            Span::styled("the wheel", dim),
        ]),
        Line::from(vec![
            Span::styled("  ↑↓     ", key),
            Span::styled("pick a message, and then:  ", dim),
            Span::styled("a ", key),
            Span::styled("react  ", dim),
            Span::styled("r ", key),
            Span::styled("reply  ", dim),
            Span::styled("e ", key),
            Span::styled("rewrite  ", dim),
            Span::styled("m ", key),
            Span::styled("message them  ", dim),
            Span::styled("c ", key),
            Span::styled("copy their key  ", dim),
            Span::styled("d ", key),
            Span::styled("delete", dim),
        ]),
        Line::from(""),
        Line::from(vec![
            Span::styled("  a key", head),
            Span::styled(
                "  a name is a claim anybody can make, and two accounts may publish the \
                 same one. The key is",
                dim,
            ),
        ]),
        Line::from(Span::styled(
            "         what tells them apart: pick a message for it, hover or click one, \
             or /who for everybody's.",
            dim,
        )),
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
        Style::default().fg(palette::MUTED),
    ))];
    for (i, c) in app.found.iter().enumerate() {
        let mut spans = vec![
            Span::styled(
                format!("{:>3}. ", i + 1),
                Style::default().fg(palette::MUTED),
            ),
            Span::styled(
                format!("#{}", c.name),
                Style::default().fg(palette::ATTENTION),
            ),
            Span::styled(
                format!(
                    "  {} member{}",
                    c.members,
                    if c.members == 1 { "" } else { "s" }
                ),
                Style::default().fg(palette::MUTED),
            ),
        ];
        if !c.topic.is_empty() {
            spans.push(Span::styled(
                format!("  {}", truncate(&c.topic, 40)),
                Style::default().fg(palette::MUTED),
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
fn keys_line(width: usize, scrollable: bool) -> String {
    // Short, and it stays short. This used to be the only command list there
    // was, and it grew until the end of it was cut off at eighty columns —
    // which left the commands that fell off undiscoverable, with nothing to
    // say they existed. `/help` carries the list now, and this only has to
    // point at it.
    const GROUPS: &[&str] = &["^C quit", "Tab", "↑↓ pick", "^N add", "/help"];
    // First, and only while it applies. A reader who has just watched a
    // message leave the top of the pane is looking for this and nothing else;
    // the rest of the line is what they already know. It is prepended as an
    // ordinary group rather than written straight into `out`, so the width
    // rule below governs it too — the first version bypassed that and
    // overflowed a one-column terminal.
    let groups: Vec<&str> = if scrollable {
        std::iter::once("^U/^D page")
            .chain(GROUPS.iter().copied())
            .collect()
    } else {
        GROUPS.to_vec()
    };
    let mut out = String::new();
    for g in &groups {
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
    // Anything the client has to say outranks every hint, including the
    // mode's own. `c` in pick mode copies a key and the answer — whether it
    // reached a clipboard at all — arrives this way; behind the hints it was
    // invisible, so a copy that silently failed looked exactly like one that
    // worked, and the difference is only discovered at the paste.
    let (text, style) = if !app.trouble.is_quiet() {
        (
            format!(" {}", app.trouble.line()),
            Style::default().fg(palette::ATTENTION),
        )
    } else if let Some(picked) = app.picked.and_then(|i| app.said.get(i)) {
        // The picked message's author, in full, and then the mode's own keys.
        //
        // The key leads for the same reason it does on hover: it is what the
        // name stopped saying, and picking a message is the keyboard's way of
        // asking about one. Somebody who never touches a mouse reaches it
        // here, which is what makes the deviation in `author` survivable.
        let hints = if picked.mine {
            " · a react · r reply · e rewrite · d delete · Esc"
        } else {
            " · a react · r reply · m message · c copy key · d delete · Esc"
        };
        let key = if picked.mine {
            String::new()
        } else {
            format!(" {}", picked.key)
        };
        (
            format!("{key}{hints}"),
            Style::default().fg(palette::ATTENTION),
        )
    } else if let Some(s) = app.hovered.and_then(|i| app.said.get(i)) {
        // In the status line rather than floating by the pointer. A tooltip
        // over a transcript covers the message it is describing, and this line
        // is already where the client puts a detail somebody asked for. It
        // gives way to trouble, which is not a detail.
        //
        // The key leads. It is the thing the name no longer says, and if the
        // line is cut by a narrow terminal it is the half that has to survive.
        (
            format!(" {} · {}", s.key, stamp(s.at)),
            Style::default().fg(palette::MUTED),
        )
    } else {
        (
            keys_line(area.width as usize, app.scrollable),
            Style::default().fg(palette::MUTED),
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

/// The whole of a moment, for when the four characters on the message are not
/// enough — which day, which year, and the seconds.
///
/// The short clock stays on the message. This is the rest of it, and it is the
/// right sort of thing to put behind a pointer: nobody has to find it to read
/// the conversation.
fn stamp(at: u64) -> String {
    match local(at) {
        Some(z) => stamp_of(&z),
        None => String::new(),
    }
}

fn stamp_of(z: &jiff::Zoned) -> String {
    z.strftime("%A, %-d %B %Y at %H:%M:%S %Z").to_string()
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
            forked: Vec::new(),
            unattributed: 0,
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

    /// Keys the length of real ones.
    ///
    /// The short fixtures elsewhere are fine where a key is only something to
    /// print, and no use at all where the question is whether the *whole* key
    /// survived: eight characters look identical before and after a truncation
    /// that would lose thirty-six.
    const ALICE: &str = "9hMLdY3VpKcR2wNtSbXgFzUqE7vJmA4dHyL8nCxTZk6Q";
    const CAROL: &str = "E4LUkjrZ7mWvTpN3sQhBxYdGcF9aKzUt2LnRe5JqXM8V";

    /// `render`, keeping what the frame reported about itself.
    fn drawn(app: &App, w: u16, h: u16) -> Drawn {
        let mut t = Terminal::new(TestBackend::new(w, h)).unwrap();
        let mut out = Drawn::default();
        t.draw(|f| out = draw(f, app)).unwrap();
        out
    }

    fn render(app: &App, w: u16, h: u16) -> String {
        let mut t = Terminal::new(TestBackend::new(w, h)).unwrap();
        t.draw(|f| {
            draw(f, app);
        })
        .unwrap();
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
        assert!(
            !out.contains("nothing here yet"),
            "it claimed the room was empty"
        );
    }

    #[test]
    fn a_line_with_a_file_shows_how_to_save_it() {
        let mut app = sample();
        app.said[0].text = "[notes.md, 4 KiB]".into();
        app.said[0].has_file = true;
        let out = render(&app, 100, 20);
        assert!(out.contains("[notes.md, 4 KiB]"), "{out}");
        assert!(
            out.contains("/save 3"),
            "the message number is not shown:\n{out}"
        );
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
        assert!(
            app.trouble.is_quiet(),
            "lost history is not a fault to chase"
        );
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

    /// SIP-31 requires a client to surface a fork: it is the one verdict there
    /// that is evidence rather than housekeeping.
    ///
    /// It was being classified and thrown away. `Timeline::broken()` had no
    /// caller anywhere in the workspace, so a conversation carrying a fork
    /// looked exactly like a quiet one, and the reader was told nothing.
    #[test]
    fn a_fork_is_not_a_quiet_conversation() {
        assert!(
            Trouble::default().is_quiet(),
            "an empty Trouble must be quiet, or this test proves nothing"
        );

        let t = Trouble {
            forked: vec![41, 42],
            ..Default::default()
        };
        assert!(!t.is_quiet(), "a fork is something to act on");
        let line = t.line();
        assert!(line.contains("41") && line.contains("42"), "{line}");
        assert!(
            line.contains("signed twice"),
            "the line must say what happened: {line}"
        );
    }

    /// The other half, and the reason the two are separate fields: SIP-31 says
    /// a gap is ordinary and MUST NOT be presented as misconduct.
    #[test]
    fn a_gap_does_not_read_as_misconduct() {
        let t = Trouble {
            gap: true,
            ..Default::default()
        };
        let line = t.line();
        assert!(
            !line.contains("signed twice"),
            "pruning is not somebody signing twice: {line}"
        );
        assert!(line.contains("retention"), "{line}");
    }

    /// An entry whose signature verifies and whose device nobody can bind to
    /// the account it names is reported, not quietly accepted (SIP-32).
    #[test]
    fn an_unattributable_signature_is_reported() {
        let t = Trouble {
            unattributed: 1,
            ..Default::default()
        };
        assert!(!t.is_quiet());
        assert!(t.line().contains("nobody can bind"), "{}", t.line());
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
        for scrollable in [false, true] {
            for width in 1..140usize {
                let line = keys_line(width, scrollable);
                assert!(
                    line.chars().count() <= width,
                    "the key line overflowed {width} columns: {line:?}"
                );
                for group in line.trim().split(" · ").filter(|g| !g.is_empty()) {
                    assert!(
                        ["^U/^D page", "^C quit", "Tab", "↑↓ pick", "^N add", "/help"]
                            .contains(&group),
                        "a group was cut in half at width {width}: {group:?}"
                    );
                }
            }
        }
        // And a wide terminal gets all of them.
        // And it fits at eighty columns whole, which the command list it
        // replaced had stopped doing.
        assert_eq!(keys_line(200, false), keys_line(80, false));
        assert!(keys_line(80, false).contains("/help"));
    }

    /// The footer says how to page **only** once there is something above the
    /// pane to page back to.
    ///
    /// This is the whole of the fix: the feature existed, worked, and was
    /// invisible — the line named four other things and never this one, so a
    /// reader watching a message leave the top of the screen had nothing to
    /// go on. A hint shown always would be noise on every short conversation;
    /// shown here it arrives at the moment somebody wants it.
    #[test]
    fn the_key_line_offers_paging_once_there_is_something_to_page_to() {
        let quiet = keys_line(120, false);
        assert!(
            !quiet.contains("^U"),
            "a conversation that fits its pane must not advertise scrolling: {quiet:?}"
        );

        let scrolled = keys_line(120, true);
        assert!(scrolled.contains("^U/^D page"), "{scrolled:?}");
        // Ahead of everything but quitting: it is what the reader is looking
        // for, and the line is cut from the right when it does not fit.
        assert!(
            scrolled.find("^U/^D").unwrap() < scrolled.find("Tab").unwrap(),
            "the paging hint must come before the rest: {scrolled:?}"
        );
        // And it must not push the rest off a narrow screen entirely.
        assert!(
            keys_line(80, true).contains("/help"),
            "{}",
            keys_line(80, true)
        );
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

        assert!(
            out.contains("message deleted"),
            "no tombstone drawn:\n{out}"
        );
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
        assert!(
            row.contains("👍"),
            "no reaction row under the message:\n{out}"
        );
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
        assert!(
            out.contains("Alice"),
            "the reply did not name its author:\n{out}"
        );
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
        assert!(
            out.contains('◂'),
            "nothing marks the picked message:\n{out}"
        );
        // The mode's own keys replace the command list: somebody who just
        // pressed Esc needs to be told what the mode does.
        assert!(out.contains("a react"), "{out}");
        assert!(out.contains("Esc"), "{out}");
        // The second message is ours, so rewriting is offered.
        assert!(out.contains("e rewrite"), "{out}");

        // The first is not, and it is not offered — a reader would ignore the
        // edit, so offering it would be a promise the protocol breaks.
        app.picked = Some(0);
        let out = render(&app, 80, 20);
        assert!(
            !out.contains("e rewrite"),
            "offered to rewrite bob's message:\n{out}"
        );
        // Bob's is on the left, so its cursor is on the left edge.
        assert!(
            out.contains('▸'),
            "nothing marks an incoming picked message:\n{out}"
        );
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
    fn a_display_name_stands_alone_and_a_nameless_one_shows_a_stub() {
        // The deviation from SIP-21, stated as a test so it cannot happen by
        // accident: a name that is published is the whole of what is drawn.
        assert_eq!(author("Alice", "9hMLdY3V", false), "Alice");

        // Somebody who has published no name goes by a stub of their key,
        // because a row with nothing in it names nobody at all.
        assert_eq!(author("", "9hMLdY3V", false), "9hMLdY3V");
        assert_eq!(author("", ALICE, false), short_key(ALICE));
        // And a label that is only the key repeated is not a name.
        assert_eq!(author(&short_key(ALICE), ALICE, false), short_key(ALICE));

        // A name too long for the column is cut, as any name always was.
        let long = author(&"n".repeat(200), "9hMLdY3V", false);
        assert!(long.chars().count() <= AUTHOR, "{long}");

        // Our own messages are the one place impersonation is not a question a
        // reader has.
        assert_eq!(author("Alice", "9hMLdY3V", true), "you");
    }

    /// What the deviation costs, written down where it will be read.
    ///
    /// Two accounts publishing one name are now indistinguishable on the line
    /// itself — that is the risk SIP-21 names, taken knowingly. What must not
    /// happen is the key becoming unreachable, so every route to it is held
    /// here: the message carries it whole, hovering says it, picking says it,
    /// and neither of the last two needs a mouse for the keyboard one.
    #[test]
    fn two_accounts_with_one_name_are_told_apart_by_something() {
        assert_eq!(author("Alice", ALICE, false), author("Alice", CAROL, false));

        let mut app = sample();
        app.said = vec![
            said("Alice", ALICE, false, "it is me", 3661),
            said("Alice", CAROL, false, "no, me", 3700),
        ];
        // Hovering one and then the other says two different things, and each
        // says the whole key rather than a stub of it.
        for (i, key) in [(0, ALICE), (1, CAROL)] {
            app.hovered = Some(i);
            let out = render(&app, 130, 24);
            assert!(
                out.contains(key),
                "hovering did not give the whole key:\n{out}"
            );
        }
        app.hovered = None;
        // And picking, which is the same answer without a mouse.
        for (i, key) in [(0, ALICE), (1, CAROL)] {
            app.picked = Some(i);
            let out = render(&app, 130, 24);
            assert!(
                out.contains(key),
                "picking did not give the whole key:\n{out}"
            );
            assert!(out.contains("c copy key"), "no way to take it:\n{out}");
        }
    }

    /// Picking somebody else's message offers `m`, and picking your own does
    /// not.
    ///
    /// There is no direct message with yourself — a DM's identifier derives
    /// from two accounts (SIP-16), and both would be you — so offering the key
    /// there would be advertising a refusal.
    #[test]
    fn picking_offers_a_way_to_message_the_author_but_not_yourself() {
        let mut app = sample();
        app.said = vec![
            said("Alice", ALICE, false, "it is me", 3661),
            said("me", CAROL, true, "and this is mine", 3700),
        ];

        app.picked = Some(0);
        let theirs = render(&app, 130, 24);
        assert!(
            theirs.contains("m message"),
            "no way to reach them:\n{theirs}"
        );

        app.picked = Some(1);
        let mine = render(&app, 130, 24);
        assert!(
            !mine.contains("m message"),
            "offered a direct message with yourself:\n{mine}"
        );
    }

    /// The frame reports the bottom-most message on screen, and once somebody
    /// has paged back that is **not** the newest one.
    ///
    /// This is what decides where `Esc` lands. Picking the newest after a page
    /// back would throw the view forward to a message deliberately scrolled
    /// away from, losing the reader's place in the same keystroke.
    #[test]
    fn the_frame_reports_the_last_message_on_screen_not_the_newest() {
        let mut app = sample();
        app.said = (0..60)
            .map(|n| {
                said(
                    "Alice",
                    ALICE,
                    false,
                    &format!("message {n}"),
                    3600 + n as u64,
                )
            })
            .collect();
        let newest = app.said.len() - 1;

        // At the bottom, the last on screen is the newest — so this changes
        // nothing for somebody who has not scrolled.
        app.scroll = 0;
        let bottom = drawn(&app, 130, 24);
        assert_eq!(
            bottom.rows.iter().rev().flatten().next().copied(),
            Some(newest),
            "at the bottom the last visible message must be the newest"
        );

        // Paged back, it must not be.
        app.scroll = 20;
        let up = drawn(&app, 130, 24);
        let last = up.rows.iter().rev().flatten().next().copied();
        assert!(last.is_some(), "a scrolled pane still shows messages");
        assert!(
            last != Some(newest),
            "after paging back the newest message is still reported as on screen: {last:?}"
        );
    }

    /// Walking the pick upwards takes the view with it.
    ///
    /// Without this the picker climbs off the top of the pane and keeps going
    /// — the selection is somewhere in the conversation, invisible, and every
    /// key that acts on it is aimed at a message nobody can see.
    #[test]
    fn the_view_follows_the_pick_off_the_top_of_the_pane() {
        let mut app = sample();
        app.said = (0..60)
            .map(|n| {
                said(
                    "Alice",
                    ALICE,
                    false,
                    &format!("message {n}"),
                    3600 + n as u64,
                )
            })
            .collect();

        // Start where Esc would put it: the newest, at the bottom.
        app.picked = Some(app.said.len() - 1);
        app.scroll = 0;
        let at_bottom = drawn(&app, 130, 24);
        assert_eq!(at_bottom.scroll, 0, "the newest message needs no scrolling");

        // Now walk the pick well above the pane without asking to follow: the
        // view stays put, which is the behaviour being fixed.
        app.picked = Some(5);
        let ignored = drawn(&app, 130, 24);
        assert_eq!(
            ignored.scroll, 0,
            "without the request the view must not move on its own"
        );
        assert!(
            !ignored.rows.iter().flatten().any(|o| *o == 5),
            "message 5 should be off screen here"
        );

        // Ask, and it comes into view.
        app.follow_pick = true;
        let followed = drawn(&app, 130, 24);
        assert!(
            followed.scroll > 0,
            "following the pick must scroll back: {}",
            followed.scroll
        );
        assert!(
            followed.rows.iter().flatten().any(|o| *o == 5),
            "the picked message must be on screen after following"
        );
    }

    /// An anchored message comes back to the bottom of the pane, whatever the
    /// width.
    ///
    /// This is what a resize needs: `scroll` counts lines, every line is a
    /// function of the width, so the same offset lands somewhere else once the
    /// window changes shape. Anchoring to a message is the only thing that
    /// survives the rewrap.
    #[test]
    fn an_anchored_message_returns_to_the_bottom_at_any_width() {
        let mut app = sample();
        app.said = (0..60)
            .map(|n| {
                said(
                    "Alice",
                    ALICE,
                    false,
                    &format!("message {n} with enough words in it to wrap when narrow"),
                    3600 + n as u64,
                )
            })
            .collect();

        for width in [130u16, 90, 70] {
            app.anchor = Some(30);
            let d = drawn(&app, width, 24);
            let last = d.rows.iter().rev().flatten().next().copied();
            assert_eq!(
                last,
                Some(30),
                "at {width} columns the anchored message did not land at the bottom"
            );
        }
    }

    /// A picked message must still be on screen after the window narrows.
    ///
    /// The anchor holds the *bottom* of the pane, and narrowing makes every
    /// message above it taller — so a pick that was near the top gets pushed
    /// off it, and the keys that act on a pick are aimed at something nobody
    /// can see. Exactly the fault the pick's follow exists to prevent, arriving
    /// by a different route.
    #[test]
    fn a_picked_message_is_still_on_screen_after_a_resize() {
        let mut app = sample();
        app.said = (0..60)
            .map(|n| {
                said(
                    "Alice",
                    ALICE,
                    false,
                    &format!("message {n} with enough words in it to wrap when the pane narrows"),
                    3600 + n as u64,
                )
            })
            .collect();

        // Wide: anchor the bottom of the pane, and pick something near its top.
        app.anchor = Some(40);
        let wide = drawn(&app, 130, 24);
        let top = wide.rows.iter().flatten().next().copied().unwrap();
        app.picked = Some(top);
        assert!(
            wide.rows.iter().flatten().any(|o| *o == top),
            "the pick starts on screen"
        );

        // Narrow, exactly as `Event::Resize` does it: anchor the bottom, and
        // ask to follow the pick because there is one.
        app.anchor = Some(40);
        app.follow_pick = true;
        let narrow = drawn(&app, 80, 24);
        assert!(
            narrow.rows.iter().flatten().any(|o| *o == top),
            "the picked message ({top}) fell off the pane when the window narrowed"
        );
    }

    #[test]
    fn the_transcript_names_who_spoke() {
        let mut app = sample();
        app.said = vec![Said {
            who: "Alice".into(),
            key: ALICE.into(),
            text: "hello".into(),
            seq: 3,
            at: 3661,
            ..Default::default()
        }];
        let out = render(&app, 100, 20);
        assert!(out.contains("Alice"), "{out}");
        // And nothing else: a forty-four character key across every run header
        // is what this change was about.
        assert!(!out.contains(ALICE), "the key is back on the line:\n{out}");
    }

    /// Choosing which conversation to type into is exactly a moment where
    /// mistaking one person for another matters, so SIP-21's rule applies to
    /// the list as much as to the transcript. The name shipped in the
    /// transcript only, and the list went on showing a bare key.
    #[test]
    fn the_conversation_list_names_each_conversation() {
        let mut app = sample();
        app.rows = vec![
            Row {
                channel: [1; 32],
                label: "Alice Byrne".into(),
                key: Some(CAROL.into()),
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
        assert!(
            out.contains("Alice Byrne"),
            "the list dropped the name:\n{out}"
        );
        // The key is not on the row. It is a Tab and an Esc away, and on the
        // conversation once one is open — see the SIP-21 note on `author`.
        assert!(
            !out.contains(CAROL),
            "the list is carrying a whole key across the pane:\n{out}"
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
    fn a_narrow_list_cuts_the_name_and_never_half_a_key() {
        let r = Row {
            channel: [1; 32],
            label: "Alexandra Bartholomew".into(),
            key: Some(CAROL.into()),
            group: false,
            public: false,
            unread: 0,
            preview: String::new(),
            at: 0,
            waiting: false,
        };
        for width in 8..=AUTHOR {
            let line = row_label(&r, width);
            assert!(line.chars().count() <= AUTHOR, "{line}");
            // A name, cut. Never a fragment of the key, which would look like
            // a key and identify nobody — the row shows the name or, for
            // somebody unnamed, a stub that is deliberately eight characters.
            assert!(
                line.starts_with("Alexandra") || line == short_key(CAROL),
                "at width {width} the row reads {line:?}"
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
                .map(|i| {
                    (
                        format!("{}\u{fe0f}", char::from(b'a' + i as u8 % 26)),
                        1,
                        false,
                    )
                })
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
        assert!(
            out.contains('+'),
            "the hidden reactions were not counted:\n{out}"
        );
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
        assert!(
            !out.contains('+'),
            "a full row claimed to be truncated:\n{out}"
        );
    }

    /// Read cell by cell, because that is what the terminal is handed. A
    /// homemade emulator counting characters made a correct layout look broken
    /// twice; `TestBackend` settles it.
    fn columns(app: &App, w: u16, h: u16) -> Vec<(usize, usize)> {
        let mut t = Terminal::new(TestBackend::new(w, h)).unwrap();
        t.draw(|f| {
            draw(f, app);
        })
        .unwrap();
        let buf = t.backend().buffer().clone();
        // For each row of the transcript pane, the first and last column
        // holding anything.
        let mut out = Vec::new();
        // Only the rows the *messages* are on. Above them sit the window
        // header, a blank row and the conversation's own header — whose rule
        // spans the pane on purpose — and below them the input box, whose
        // border does too. Neither is the transcript overflowing.
        for y in (2 + HEAD)..buf.area.height.saturating_sub(4) {
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

    /// The message rows of the transcript, and nothing else.
    ///
    /// Read from the buffer a cell at a time rather than sliced out of
    /// `render`'s string: a wide glyph is one cell whose neighbour is empty,
    /// so counting characters and counting columns are different things. That
    /// difference has produced two wrong bug reports here already.
    fn transcript_text(app: &App, w: u16, h: u16) -> String {
        let mut t = Terminal::new(TestBackend::new(w, h)).unwrap();
        t.draw(|f| {
            draw(f, app);
        })
        .unwrap();
        let buf = t.backend().buffer().clone();
        ((2 + HEAD)..buf.area.height.saturating_sub(4))
            .map(|y| {
                (31..buf.area.width)
                    .map(|x| buf[(x, y)].symbol().to_string())
                    .collect::<String>()
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// A row of cells, as symbols, so a width can be counted in columns.
    fn row_at(app: &App, w: u16, h: u16, y: u16) -> String {
        let mut t = Terminal::new(TestBackend::new(w, h)).unwrap();
        t.draw(|f| {
            draw(f, app);
        })
        .unwrap();
        let buf = t.backend().buffer().clone();
        (0..buf.area.width)
            .map(|x| buf[(x, y)].symbol().to_string())
            .collect()
    }

    /// The colour of the first `●` on screen.
    fn light(app: &App) -> Option<Color> {
        let mut t = Terminal::new(TestBackend::new(100, 24)).unwrap();
        t.draw(|f| {
            draw(f, app);
        })
        .unwrap();
        let buf = t.backend().buffer().clone();
        (0..buf.area.width)
            .find(|x| buf[(*x, 0)].symbol() == "●")
            .and_then(|x| buf[(x, 0)].style().fg)
    }

    #[test]
    fn the_header_leads_with_the_light_and_who_you_are() {
        let mut app = sample();
        app.me = "9hSR6S7WabcdefGHIJK".into();

        // With a name published, that is who you are — the same rule the rest
        // of the client follows since names stopped carrying their keys.
        app.name = "Alice".into();
        let top = row_at(&app, 100, 24, 0);
        assert!(top.starts_with(" ● Alice"), "{top:?}");
        assert!(
            !top.contains("9hSR6S"),
            "the key is still there too: {top:?}"
        );

        // With none, a stub of the key: a header naming nobody is worse than
        // one naming them roughly.
        app.name.clear();
        let top = row_at(&app, 100, 24, 0);
        assert!(top.starts_with(" ● 9hSR6S"), "{top:?}");
        // Six characters and no more. The rest of the key is what `/whoami`
        // is for — it is not a thing to compare against at a glance, and
        // sixty-four characters across the top said nothing to anybody.
        assert!(!top.contains("9hSR6S7"), "the key was not cut: {top:?}");
    }

    /// Green talking, amber reconnecting, red down for long enough to matter.
    #[test]
    fn the_light_says_which_of_the_three() {
        let mut app = sample();
        app.link = Link::Up;
        assert_eq!(light(&app), Some(palette::LIVE));
        app.link = Link::Retrying;
        assert_eq!(light(&app), Some(palette::TRYING));
        app.link = Link::Gone;
        assert_eq!(light(&app), Some(palette::GONE));
    }

    /// A colour says that something changed, never what. Every state says
    /// which in words, including the good one — leaving that silent made it
    /// the only state you had to know the colour code for.
    #[test]
    fn every_state_of_the_link_says_which_it_is() {
        let mut app = sample();
        for (link, word, other) in [
            (Link::Up, "connected", ["reconnecting", "offline"]),
            (Link::Retrying, "reconnecting", ["connected", "offline"]),
            (Link::Gone, "offline", ["connected", "reconnecting"]),
        ] {
            app.link = link;
            let top = row_at(&app, 100, 24, 0);
            assert!(
                top.contains(word),
                "{link:?} does not say {word:?}: {top:?}"
            );
            for wrong in other {
                assert!(
                    !top.contains(wrong),
                    "{link:?} also says {wrong:?}: {top:?}"
                );
            }
        }
    }

    #[test]
    fn the_program_and_its_version_end_at_the_right_edge() {
        let app = sample();
        for w in [80u16, 100, 200] {
            let top = row_at(&app, w, 24, 0);
            assert!(
                top.trim_end().ends_with(env!("CARGO_PKG_VERSION")),
                "the version is not against the right edge at {w}: {top:?}"
            );
            assert!(top.contains("sqex-chat"), "{top:?}");
        }
    }

    /// The margin that was asked for. A title bar hard against the panes reads
    /// as another row of the panes.
    #[test]
    fn a_blank_row_separates_the_header_from_the_panes() {
        let app = sample();
        assert_eq!(row_at(&app, 100, 24, 1).trim(), "");
    }

    /// SIP-21, in a place that did not exist before: choosing what to type
    /// into is exactly a moment where mistaking one person for another
    /// matters, and this header is what somebody checks.
    #[test]
    fn the_conversation_is_headed_on_its_own_pane() {
        let app = sample();
        let head = row_at(&app, 100, 24, 2);
        assert!(
            head.contains("bob"),
            "the header does not name it: {head:?}"
        );
    }

    #[test]
    fn the_pane_header_is_three_rows_over_a_rule() {
        let app = sample();
        for w in [40u16, 100, 200] {
            let rule = row_at(&app, w, 24, 1 + HEAD);
            let pane: String = rule.chars().skip(31).collect();
            assert!(
                !pane.is_empty() && pane.chars().all(|c| c == '─'),
                "no rule under the header at {w}: {rule:?}"
            );
            // And the rule is the pane's, not the window's: the conversation
            // list keeps its own border.
            assert!(
                !rule.starts_with('─'),
                "the rule ran across the list: {rule:?}"
            );
        }
    }

    #[test]
    fn a_long_topic_is_cut_to_the_pane_and_not_to_a_constant() {
        let mut app = sample();
        app.topic = "a topic considerably longer than any terminal anybody would \
                     sensibly use, going on and on well past sixty columns"
            .into();
        for w in [60u16, 80, 100] {
            let out = render(&app, w, 24);
            for l in out.lines() {
                assert!(
                    UnicodeWidthStr::width(l) <= w as usize,
                    "the topic ran past a {w}-column screen: {l:?}"
                );
            }
        }
    }

    /// A count of nought is not a fact about a room, it is not having asked
    /// yet. Saying "0 people" would be inventing one.
    #[test]
    fn the_member_count_waits_until_it_is_known() {
        let mut app = sample();
        app.rows[0].key = None;
        app.rows[0].group = true;
        app.rows[0].label = "general".into();
        assert!(!row_at(&app, 100, 24, 2).contains("people"));
        app.members = 4;
        assert!(row_at(&app, 100, 24, 2).contains("4 people"));
        app.members = 1;
        assert!(row_at(&app, 100, 24, 2).contains("1 person"));
    }

    /// An identicon is two cells of `▀`: the foreground is the top half of
    /// each cell and the background the bottom. If a cell's foreground and
    /// background are the same colour there is no pattern in it at all — it is
    /// a solid block — and if *both* cells are solid and the same, the whole
    /// mark is one flat colour carrying half the information it claims to.
    ///
    /// Written after the marks were reported as having "stopped working".
    #[test]
    fn no_key_renders_as_a_flat_blob() {
        let mut flat = Vec::new();
        for n in 0..400u32 {
            // Keys the shape of real ones, since the length feeds the hash.
            let key = format!("{n:0>44}");
            let spans = identicon(&key);
            let colours: Vec<_> = spans
                .iter()
                .flat_map(|s| [s.style.fg.unwrap(), s.style.bg.unwrap()])
                .collect();
            if colours.iter().all(|c| *c == colours[0]) {
                flat.push(key);
            }
        }
        assert!(
            flat.is_empty(),
            "{} of 400 keys have no pattern at all, e.g. {:?}",
            flat.len(),
            &flat[..flat.len().min(3)]
        );
    }

    /// The two halves have to be different colours, or the mark is a blob
    /// whatever the pattern says. The doc comment claimed a third of the wheel
    /// between them; the expression did not do it.
    #[test]
    fn the_two_halves_of_a_mark_are_visibly_different() {
        for n in 0..400u32 {
            let key = format!("{n:0>44}");
            let spans = identicon(&key);
            let seen: std::collections::HashSet<_> = spans
                .iter()
                .flat_map(|s| [s.style.fg.unwrap(), s.style.bg.unwrap()])
                .collect();
            assert_eq!(seen.len(), 2, "{key} uses {} colours, not two", seen.len());
        }
    }

    /// The point of the mark is that two of them differ. Half the keys used to
    /// come out as a flat block, which collapsed the space they are drawn
    /// from; deriving the second hue from the first collapsed it again a
    /// different way.
    #[test]
    fn two_keys_seldom_look_alike() {
        let mark = |key: &str| {
            identicon(key)
                .iter()
                .map(|s| (s.style.fg.unwrap(), s.style.bg.unwrap()))
                .collect::<Vec<_>>()
        };
        let marks: Vec<_> = (0..400u32).map(|n| mark(&format!("{n:0>44}"))).collect();
        let distinct: std::collections::HashSet<_> = marks.iter().collect();
        assert!(
            distinct.len() > 380,
            "only {} of 400 marks are distinct",
            distinct.len()
        );
    }

    /// A channel has an identifier as good as a key, and no reason to go
    /// without a mark of its own.
    #[test]
    fn a_group_is_marked_by_its_channel_and_not_left_blank() {
        let one = identicon_of(&[7u8; 32]);
        let same = identicon_of(&[7u8; 32]);
        let other = identicon_of(&[8u8; 32]);
        let colours = |v: &Vec<Span<'static>>| {
            v.iter()
                .map(|s| (s.style.fg, s.style.bg))
                .collect::<Vec<_>>()
        };
        assert_eq!(colours(&one), colours(&same));
        assert_ne!(colours(&one), colours(&other));

        let mut app = sample();
        app.rows[0].key = None;
        app.rows[0].group = true;
        assert!(
            row_at(&app, 100, 24, 2).contains('▀'),
            "a group has no mark of its own"
        );
    }

    /// The palette is a matter of taste and a test cannot judge taste. What it
    /// can hold is the floor: text has to be legible on the thing it is drawn
    /// on, and every one of these pairs is a decision somebody will change.
    #[test]
    fn every_pairing_is_legible() {
        fn luminance(c: Color) -> f64 {
            let Color::Rgb(r, g, b) = c else {
                panic!("not truecolour: {c:?}")
            };
            let f = |v: u8| {
                let v = f64::from(v) / 255.0;
                if v <= 0.03928 {
                    v / 12.92
                } else {
                    ((v + 0.055) / 1.055).powf(2.4)
                }
            };
            0.2126 * f(r) + 0.7152 * f(g) + 0.0722 * f(b)
        }
        let contrast = |a: Color, b: Color| {
            let (x, y) = (luminance(a), luminance(b));
            (x.max(y) + 0.05) / (x.min(y) + 0.05)
        };
        // What somebody is actually reading.
        for (name, fg, bg) in [
            ("sent", palette::SENT_FG, palette::SENT_BG),
            ("sent quote", palette::SENT_FG, palette::SENT_QUOTE_BG),
            ("received", palette::RECV_FG, palette::RECV_BG),
            ("received quote", palette::RECV_FG, palette::RECV_QUOTE_BG),
            ("chip", palette::CHIP_FG, palette::CHIP_BG),
            ("a search hit", palette::INK, palette::ATTENTION),
        ] {
            let got = contrast(fg, bg);
            assert!(got >= 4.5, "{name} is at {got:.1}:1, which is not readable");
        }
        // And what rides alongside it, deliberately quieter: the time, the
        // ticks, a reaction we are part of.
        //
        // A lower bar, and it has to be. White on this blue is 4.7:1, so
        // *nothing* dimmer than the body text can reach 4.5 on it — that is a
        // fact about the colour rather than about the choice of grey, and the
        // honest thing is to hold secondary text to the floor it belongs to
        // rather than to raise it until it stops being secondary.
        for (name, fg, bg) in [
            ("sent trailer", palette::SENT_TRAILER, palette::SENT_BG),
            ("received trailer", palette::RECV_TRAILER, palette::RECV_BG),
            ("chip of ours", palette::CHIP_MINE, palette::CHIP_BG),
        ] {
            let got = contrast(fg, bg);
            assert!(got >= 3.0, "{name} is at {got:.1}:1, which is not readable");
        }
        // And the two sides have to be told apart at a glance, which is the
        // whole of why they are coloured at all.
        assert!(
            contrast(palette::SENT_BG, palette::RECV_BG) >= 1.5,
            "the two sides are nearly the same colour"
        );
        // A quotation has to stay visibly a band inside its bubble. Raising
        // its text contrast by moving it towards the bubble's own colour
        // would be trading one unreadable thing for another.
        for (name, quote, bubble) in [
            ("sent", palette::SENT_QUOTE_BG, palette::SENT_BG),
            ("received", palette::RECV_QUOTE_BG, palette::RECV_BG),
        ] {
            let got = contrast(quote, bubble);
            assert!(
                got >= 1.2,
                "the {name} quotation is at {got:.2}:1 against its bubble — it has \
                 stopped being a quotation and become part of the message"
            );
        }
    }

    /// The screen, and the map from its rows back to the messages on them.
    fn drawn_at(app: &App, w: u16, h: u16) -> (Vec<String>, Drawn) {
        let mut t = Terminal::new(TestBackend::new(w, h)).unwrap();
        let mut hover = Drawn::default();
        t.draw(|f| hover = draw(f, app)).unwrap();
        let buf = t.backend().buffer().clone();
        let rows = (0..buf.area.height)
            .map(|y| {
                (0..buf.area.width)
                    .map(|x| buf[(x, y)].symbol().to_string())
                    .collect::<String>()
            })
            .collect();
        (rows, hover)
    }

    /// The first row **of the transcript** holding `text`.
    ///
    /// From the pane down, not from the top of the screen: the conversation's
    /// header names the same person the run header does, and a search over the
    /// whole screen finds that one — which belongs to no message, and made
    /// this look like a bug in the map.
    fn row_of(rows: &[String], hover: &Drawn, text: &str) -> u16 {
        rows.iter()
            .enumerate()
            .skip(hover.pane.y as usize)
            .find(|(_, r)| r.contains(text))
            .unwrap_or_else(|| panic!("{text:?} is not in the transcript"))
            .0 as u16
    }

    /// The selected row is drawn reversed, and a span that sets only a
    /// foreground keeps the terminal's own background — so the unread count
    /// and the waiting marker came out as holes punched through the
    /// highlight, and the highlight itself stopped wherever the words did.
    #[test]
    fn a_selected_row_is_a_solid_bar_across_the_list() {
        let mut app = sample();
        app.rows[0].unread = 3;
        app.rows[0].waiting = true;
        let mut t = Terminal::new(TestBackend::new(100, 24)).unwrap();
        t.draw(|f| {
            draw(f, &app);
        })
        .unwrap();
        let buf = t.backend().buffer().clone();

        // The row the cursor is on: every cell up to the list's border has to
        // be part of the same bar.
        // Asserted on the *reversal*, which is what selection is drawn with.
        // Not on whether a cell has a background: the widget leaves one on
        // very nearly every cell, so that question is answered yes almost
        // wherever it is asked and a test built on it cannot fail.
        //
        // Columns 3 onwards: 0 is the public marker, 1 and 2 are the
        // identicon — which has colours of its own and must keep them — and
        // 29 is the list's border.
        let y = 2;
        let reversed = |x: u16| {
            buf[(x, y)]
                .style()
                .add_modifier
                .contains(Modifier::REVERSED)
        };
        assert!(reversed(4), "the row is not highlighted at all");
        let holes: Vec<u16> = (3..29).filter(|x| !reversed(*x)).collect();
        assert!(
            holes.is_empty(),
            "the highlight has holes in it at columns {holes:?}"
        );
    }

    /// Two lines each, with nothing between them, read as one block of text:
    /// the eye has to count to find where a conversation ends.
    #[test]
    fn conversations_are_separated_by_a_blank_line() {
        let mut app = sample();
        // Both rows need a second line with something on it, or the blank one
        // this is looking for is just an empty preview and the test cannot
        // tell the margin from its absence.
        app.rows[0].at = 3661;
        app.rows[0].preview = "see you then".into();
        app.rows.push(Row {
            channel: [9; 32],
            label: "carol".into(),
            key: Some(CAROL.into()),
            group: false,
            public: false,
            unread: 0,
            preview: "hello".into(),
            at: 3661,
            waiting: false,
        });
        let rows: Vec<String> = render(&app, 100, 24)
            .lines()
            .map(|l| l.chars().take(29).collect::<String>())
            .collect();
        let first = rows.iter().position(|r| r.contains("bob")).unwrap();
        let second = rows.iter().position(|r| r.contains("carol")).unwrap();
        assert!(
            rows[second - 1].trim().is_empty(),
            "no air between the conversations: {:?}",
            &rows[first..=second]
        );
    }

    /// A long conversation used to show only its tail, and there was no way
    /// back: not the wheel, not a key, nothing.
    #[test]
    fn scrolling_back_reaches_what_the_tail_hid() {
        let mut app = sample();
        app.said = (0..60)
            .map(|n| {
                said(
                    "bob",
                    "8qbHbw2B",
                    false,
                    &format!("message number {n}"),
                    3661,
                )
            })
            .collect();
        let bottom = render(&app, 100, 24);
        assert!(bottom.contains("message number 59"), "{bottom}");
        assert!(
            !bottom.contains("message number 0 "),
            "nothing was hidden to find"
        );

        // Far enough back to reach the first of them.
        app.scroll = 500;
        let top = render(&app, 100, 24);
        assert!(
            top.contains("message number 0 "),
            "scrolling did not reach the oldest:\n{top}"
        );
        assert!(!top.contains("message number 59"), "it did not move at all");
    }

    /// A wish, not an instruction: it may be left from a longer conversation
    /// or a taller window, and a held key would otherwise wind it up for ever.
    #[test]
    fn scrolling_stops_at_the_oldest_line() {
        let mut app = sample();
        app.said = (0..60)
            .map(|n| {
                said(
                    "bob",
                    "8qbHbw2B",
                    false,
                    &format!("message number {n}"),
                    3661,
                )
            })
            .collect();
        let mut t = Terminal::new(TestBackend::new(100, 24)).unwrap();

        app.scroll = usize::MAX;
        let mut drawn = Drawn::default();
        t.draw(|f| drawn = draw(f, &app)).unwrap();
        let far = drawn.scroll;
        assert!(far > 0 && far < 500, "clamped to {far}");

        // Asking for more does not go further, and the screen does not change.
        app.scroll = far;
        let a = render(&app, 100, 24);
        app.scroll = far + 50;
        assert_eq!(a, render(&app, 100, 24), "it moved past the oldest line");
    }

    /// Reading history while messages arrive has to say they arrived: they
    /// land below the bottom of the view, where nothing shows them.
    #[test]
    fn a_scrolled_transcript_says_there_is_more_below() {
        let mut app = sample();
        app.said = (0..60)
            .map(|n| {
                said(
                    "bob",
                    "8qbHbw2B",
                    false,
                    &format!("message number {n}"),
                    3661,
                )
            })
            .collect();
        assert!(
            !render(&app, 100, 24).contains("more below"),
            "at the bottom"
        );
        app.scroll = 20;
        let out = render(&app, 100, 24);
        assert!(
            out.contains("more below"),
            "no mark of being scrolled:\n{out}"
        );
        assert!(
            out.contains("End"),
            "and nothing says how to get back:\n{out}"
        );
    }

    /// The map from rows to messages has to move with the view, or hovering
    /// scrolled-back history names whatever happens to be at that row now.
    #[test]
    fn the_map_follows_the_scroll() {
        let mut app = sample();
        app.said = (0..60)
            .map(|n| {
                said(
                    "bob",
                    "8qbHbw2B",
                    false,
                    &format!("message number {n}"),
                    3661,
                )
            })
            .collect();
        app.scroll = 20;
        let (rows, drawn) = drawn_at(&app, 100, 24);
        // Whatever is on screen at this depth — asked of the screen rather
        // than worked out here, since how many lines a message takes is the
        // layout's business and not this test's.
        let mut checked = 0;
        for (y, row) in rows.iter().enumerate() {
            // The pane only: a row is the whole screen, and the conversation
            // list down the left has words of its own.
            let pane: String = row.chars().skip(drawn.pane.x as usize).collect();
            let Some(rest) = pane.trim().strip_prefix("message number ") else {
                continue;
            };
            let n: usize = rest.split_whitespace().next().unwrap().parse().unwrap();
            assert_eq!(
                drawn.at(drawn.pane.x + 1, y as u16),
                Some(n),
                "row {y} shows message {n} and the map says otherwise"
            );
            checked += 1;
        }
        assert!(
            checked > 3,
            "only {checked} messages were on screen to check"
        );
    }

    /// The map has to come from the frame that drew it. A second copy of the
    /// layout can disagree with the first, and a pointer that names the
    /// message above the one under it is worse than no pointer.
    #[test]
    fn the_row_a_message_is_drawn_on_names_that_message() {
        let app = sample();
        let (rows, hover) = drawn_at(&app, 100, 24);
        let x = hover.pane.x + 1;
        for (want, text) in [(0usize, "are you there?"), (1, "i am")] {
            let y = row_of(&rows, &hover, text);
            assert_eq!(
                hover.at(x, y),
                Some(want),
                "the row holding {text:?} points at the wrong message"
            );
        }
    }

    /// The run header and the reactions are part of the message, because that
    /// is what somebody is pointing at when they point at them.
    #[test]
    fn the_whole_bubble_belongs_to_its_message() {
        let mut app = sample();
        app.said[0].reactions = vec![("🧡".into(), 1, false)];
        let (rows, hover) = drawn_at(&app, 100, 24);
        let x = hover.pane.x + 1;
        for text in ["bob", "are you there?", "🧡"] {
            let y = row_of(&rows, &hover, text);
            assert_eq!(
                hover.at(x, y),
                Some(0),
                "{text:?} is not part of its message"
            );
        }
    }

    /// A short conversation is padded from the top and a long one is cut from
    /// it, and the map has to survive both. This is the case that would drift:
    /// the rows are moved by one arithmetic and the owners by another, and
    /// nothing on screen would show that they had come apart.
    #[test]
    fn the_map_survives_a_transcript_that_has_scrolled() {
        let mut app = sample();
        app.said = (0..40)
            .map(|n| {
                said(
                    "bob",
                    "8qbHbw2B",
                    n % 2 == 0,
                    &format!("message number {n}"),
                    3661 + n as u64 * RUN_GAP * 2,
                )
            })
            .collect();
        let (rows, hover) = drawn_at(&app, 100, 24);
        let x = hover.pane.x + 1;
        // The newest is on screen; the oldest has scrolled off.
        let y = row_of(&rows, &hover, "message number 39");
        assert_eq!(
            hover.at(x, y),
            Some(39),
            "the newest message is misattributed"
        );
        assert!(
            !rows.iter().any(|r| r.contains("message number 0 ")),
            "nothing scrolled, so this proves nothing"
        );
    }

    /// Everything that is not a message is nothing to point at, and a
    /// separator that claimed to be a message would put a time on the wrong
    /// thing entirely.
    #[test]
    fn what_is_not_a_message_belongs_to_nobody() {
        let mut app = sample();
        app.said[1].at = app.said[0].at + 60 * 60 * 30;
        let (rows, hover) = drawn_at(&app, 100, 24);
        let x = hover.pane.x + 1;
        let y = row_of(&rows, &hover, "───");
        assert_eq!(
            hover.at(x, y),
            None,
            "a day separator claimed to be a message"
        );

        // And outside the pane: the conversation list, and the input box.
        let anywhere = row_of(&rows, &hover, "i am");
        assert_eq!(
            hover.at(0, anywhere),
            None,
            "the list is not the transcript"
        );
        assert_eq!(hover.at(x, 23), None, "the input box is not the transcript");
    }

    /// The four characters on the message are the time; this is the rest of
    /// it. Behind a pointer because nobody has to find it to read.
    #[test]
    fn hovering_says_the_whole_moment() {
        let mut app = sample();
        app.hovered = Some(0);
        let out = render(&app, 100, 24);
        let want = stamp(app.said[0].at);
        assert!(!want.is_empty());
        assert!(
            out.contains(&want),
            "the full time is not on screen:\n{out}"
        );
        // And it stands down for the keys line when nothing is under it.
        app.hovered = None;
        assert!(!render(&app, 100, 24).contains(&want));
    }

    /// A copy either reached a clipboard or did not, and that answer has to
    /// get past the mode's own hints — it is only otherwise discovered at the
    /// paste, when the key is no longer on screen to try again.
    #[test]
    fn what_the_client_has_to_say_outranks_every_hint() {
        let mut app = sample();
        app.picked = Some(0);
        assert!(
            render(&app, 110, 24).contains("a react"),
            "no hints when quiet"
        );

        app.trouble.message = Some("could not reach the clipboard. their key: abc".into());
        let out = render(&app, 110, 24);
        assert!(out.contains("could not reach the clipboard"), "{out}");
    }

    /// Trouble is not a detail somebody asked for, and it wins.
    #[test]
    fn a_fault_outranks_the_pointer() {
        let mut app = sample();
        app.hovered = Some(0);
        app.trouble.no_key = Some(7);
        let out = render(&app, 100, 24);
        assert!(out.contains("no key for epoch 7"), "{out}");
        assert!(!out.contains(&stamp(app.said[0].at)), "{out}");
    }

    #[test]
    fn the_whole_moment_says_the_day_the_year_and_the_seconds() {
        // A fixed offset, so this reads the same wherever it is run.
        let said = stamp_of(&at(3661, 1));
        assert_eq!(said, "Thursday, 1 January 1970 at 02:01:01 +01");
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
        let incoming = cols
            .iter()
            .find(|(a, _)| *a <= 2)
            .expect("nothing on the left");
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
    fn a_run_is_headed_once_and_the_header_names_who_spoke() {
        let mut app = sample();
        app.said = vec![
            said("bob", "8qbHbw2B", false, "one", 3661),
            said("bob", "8qbHbw2B", false, "two", 3671),
            said("bob", "8qbHbw2B", false, "three", 3681),
        ];
        let out = transcript_text(&app, 100, 24);
        assert_eq!(
            out.matches("bob").count(),
            1,
            "expected exactly one run header:\n{out}"
        );

        // A long enough silence starts a new run, because by then the reader
        // has lost the thread of who is speaking.
        app.said[2].at = 3681 + RUN_GAP + 1;
        let out = transcript_text(&app, 100, 24);
        assert_eq!(out.matches("bob").count(), 2, "{out}");
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
        let styles = |v: &[Span]| {
            v.iter()
                .map(|s| (s.style.fg, s.style.bg))
                .collect::<Vec<_>>()
        };
        assert_eq!(styles(&a), styles(&identicon("8qbHbw2B")), "not stable");
        assert_ne!(
            styles(&a),
            styles(&identicon("9hSR6S7W")),
            "two keys drew the same face"
        );
        // Derived from the key, so a key that differs in one character does
        // not draw the same thing.
        assert_ne!(
            styles(&identicon("aaaaaaaa")),
            styles(&identicon("aaaaaaab"))
        );
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
        assert!(
            line.contains("/save 12"),
            "the file hint left the line: {line:?}"
        );
        assert!(
            line.contains("(edited)"),
            "the edit mark left the line: {line:?}"
        );
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
        t.draw(|f| {
            draw(f, &app);
        })
        .unwrap();
        let buf = t.backend().buffer().clone();

        // Every row holding part of the message has the same run of coloured
        // cells, and they all start in the same column.
        let mut widths = Vec::new();
        for y in 0..buf.area.height {
            let painted: Vec<u16> = (31..buf.area.width)
                .filter(|x| buf[(*x, y)].style().bg == Some(palette::RECV_BG))
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
        t.draw(|f| {
            draw(f, &app);
        })
        .unwrap();
        let buf = t.backend().buffer().clone();
        let painted = (0..buf.area.height)
            .flat_map(|y| (31..buf.area.width).map(move |x| (x, y)))
            .find(|(x, y)| buf[(*x, *y)].symbol() == "h")
            .expect("the message is not on screen");
        let cell = &buf[painted];
        assert!(cell.style().bg.is_some(), "no bubble behind the text");
        assert!(
            cell.style().fg.is_some(),
            "the text took the terminal's colour"
        );
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
        t.draw(|f| {
            draw(f, &app);
        })
        .unwrap();
        let buf = t.backend().buffer().clone();
        let painted = (0..buf.area.height)
            .flat_map(|y| (31..buf.area.width).map(move |x| (x, y)))
            .any(|(x, y)| buf[(x, y)].style().bg == Some(palette::RECV_BG));
        assert!(!painted, "a deleted message was drawn as a bubble");
    }

    /// The list says what is going on, not only what exists.
    #[test]
    fn the_conversation_list_previews_the_last_thing_said() {
        let mut app = sample();
        app.rows[0].preview = "see you at six".into();
        app.rows[0].at = 3661;
        let out = render(&app, 100, 24);
        assert!(
            out.contains("see you at six"),
            "no preview in the list:\n{out}"
        );
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
        assert!(
            second < line && line < third,
            "the divider is in the wrong place:\n{out}"
        );
        // Three messages sit below it.
        assert!(rows[line].contains("3 unread"), "{}", rows[line]);
    }

    #[test]
    fn nothing_unread_draws_no_divider() {
        let mut app = sample();
        app.divider = None;
        let out = render(&app, 100, 24);
        assert!(
            !out.contains("unread"),
            "a divider appeared with nothing new:\n{out}"
        );
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
            "Esc", "react", "rewrite", "/file", "/forward", "/op", "/close", "/retain", "/profile",
            "/blocked", "/who", "/read",
        ] {
            assert!(out.contains(want), "{want} is not in the help:\n{out}");
        }
        // And it is a view over the transcript, not a line under it.
        assert!(
            !out.contains("are you there?"),
            "the transcript showed through"
        );
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
        assert!(
            out.contains("E4LUkjrZ"),
            "the result dropped the key:\n{out}"
        );
        assert!(out.contains("1 message matching"), "{out}");
        // The sequence number, which is what /save and /redact take.
        assert!(out.contains("  1 "), "no number to act on:\n{out}");
        // A view over the transcript, not a line under it.
        assert!(
            !out.contains("are you there?"),
            "the transcript showed through"
        );
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
        // Read as the sentence it is, across however many rows it took.
        //
        // Asserted whole rather than on a phrase, because the whole is what
        // was wrong with it: the literal carried fourteen spaces in the middle
        // of "which is", and they were on screen. A phrase either side of the
        // gap would have passed happily.
        // At several widths, and wide ones especially. The literal used to
        // carry fourteen spaces in the middle of "which is", and at 110
        // columns the wrap happened to break inside the run and swallow it —
        // so the one width this was first tested at was the one width that
        // hid the defect. At 120 and above they sat in the middle of the
        // sentence, on screen, for anybody with a wide terminal.
        for w in [110u16, 120, 160] {
            let flow = flowed(&app, w, 24);
            assert!(
                flow.contains(
                    "This searches what this client holds, which is not necessarily \
                     everything that was said."
                ),
                "the sentence does not read as one at {w} columns:\n{flow}"
            );
        }
    }

    /// The transcript pane as prose: each row trimmed, and the rows joined
    /// with one space. Wrapping is invisible to it, and a gap inside a line is
    /// not.
    ///
    /// The pane only. The conversation list has a border down its right edge,
    /// and joining whole rows threaded a `│` through the middle of every
    /// sentence that wrapped.
    fn flowed(app: &App, w: u16, h: u16) -> String {
        let mut t = Terminal::new(TestBackend::new(w, h)).unwrap();
        t.draw(|f| {
            draw(f, app);
        })
        .unwrap();
        let buf = t.backend().buffer().clone();
        (0..buf.area.height)
            .map(|y| {
                (30..buf.area.width)
                    .map(|x| buf[(x, y)].symbol().to_string())
                    .collect::<String>()
                    .trim()
                    .to_string()
            })
            .filter(|l| !l.is_empty())
            .collect::<Vec<_>>()
            .join(" ")
    }

    /// The matching part is picked out, or a result in a long message is a
    /// paragraph to re-read rather than an answer.
    #[test]
    fn the_match_itself_is_marked() {
        let mut app = sample();
        app.searching = true;
        app.query = "friday".into();
        app.hits = vec![hit(
            "bob (8qbHbw2B)",
            "we ship on friday, not thursday",
            "friday",
            3661,
        )];
        let mut t = Terminal::new(TestBackend::new(110, 24)).unwrap();
        t.draw(|f| {
            draw(f, &app);
        })
        .unwrap();
        let buf = t.backend().buffer().clone();
        let marked: String = (0..buf.area.height)
            .flat_map(|y| (0..buf.area.width).map(move |x| (x, y)))
            .filter(|(x, y)| buf[(*x, *y)].style().bg == Some(palette::ATTENTION))
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
            t.draw(|f| {
                draw(f, &app);
            })
            .unwrap();
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
                right_of(if mine {
                    palette::SENT_BG
                } else {
                    palette::RECV_BG
                }),
                right_of(palette::CHIP_BG),
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
        t.draw(|f| {
            draw(f, &app);
        })
        .unwrap();
        let buf = t.backend().buffer().clone();
        let chip = (0..buf.area.height)
            .flat_map(|y| (31..buf.area.width).map(move |x| (x, y)))
            .find(|(x, y)| buf[(*x, *y)].symbol() == "👍")
            .expect("no reaction drawn");
        assert_eq!(buf[chip].style().bg, Some(palette::CHIP_BG));
        assert!(
            buf[chip].style().fg.is_some(),
            "the chip took the terminal's colour"
        );
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
        t.draw(|f| {
            draw(f, &app);
        })
        .unwrap();
        let buf = t.backend().buffer().clone();
        // No cell inside the chip run is left without a background.
        let run: Vec<(u16, u16)> = (0..buf.area.height)
            .flat_map(|y| (0..buf.area.width).map(move |x| (x, y)))
            .filter(|(x, y)| buf[(*x, *y)].style().bg == Some(palette::CHIP_BG))
            .collect();
        assert!(!run.is_empty(), "no chip drawn");
        let y = run[0].1;
        let (lo, hi) = (run[0].0, run[run.len() - 1].0);
        for x in lo..=hi {
            assert_eq!(
                buf[(x, y)].style().bg,
                Some(palette::CHIP_BG),
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
        t.draw(|f| {
            draw(f, &app);
        })
        .unwrap();
        let buf = t.backend().buffer().clone();
        let right_of = |bg: Color| {
            (0..buf.area.height)
                .flat_map(|y| (31..buf.area.width).map(move |x| (x, y)))
                .filter(|(x, y)| buf[(*x, *y)].style().bg == Some(bg))
                .map(|(x, _)| x)
                .max()
        };
        let quote = right_of(palette::RECV_QUOTE_BG).expect("the quotation has no tint");
        let body = right_of(palette::RECV_BG).expect("no bubble");
        assert_eq!(
            quote, body,
            "the quotation and the message are different widths"
        );
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
            t.draw(|f| {
                draw(f, &app);
            })
            .unwrap();
            let buf = t.backend().buffer().clone();
            let bg = if mine {
                palette::SENT_BG
            } else {
                palette::RECV_BG
            };

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
    fn a_quotation_never_widens_the_bubble_past_the_floor() {
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
            t.draw(|f| {
                draw(f, &app2);
            })
            .unwrap();
            let buf = t.backend().buffer().clone();
            (0..buf.area.height)
                .flat_map(|y| (31..buf.area.width).map(move |x| (x, y)))
                .filter(|(x, y)| buf[(*x, *y)].style().bg == Some(palette::RECV_BG))
                .map(|(x, _)| x)
                .max()
                .expect("no bubble")
        };
        // The floor may widen a narrow bubble up to `QUOTE_FLOOR`. What it
        // must never do is size the bubble to the *quotation*, which is what
        // made a one-line answer as wide as the paragraph it answered.
        let plain = width_of(plain);
        let short = width_of(short);
        assert!(
            short <= plain.max(plain_start() + QUOTE_FLOOR as u16),
            "the quotation stretched the bubble: {short} > {plain}"
        );
        assert!(short >= plain, "the floor should never narrow a bubble");
    }

    /// Where an incoming bubble begins: the pane's left edge plus its gutter.
    /// The widths above are absolute columns, so the floor has to be measured
    /// from the same origin.
    fn plain_start() -> u16 {
        31 + GUTTER as u16
    }

    /// The whole point of the floor. Without it a one-word answer cut the
    /// quotation to `↳ Alice (E…`, which names nobody — the sequence number it
    /// replaced at least identified a message.
    #[test]
    fn a_short_answer_still_names_who_it_answers() {
        let mut app = sample();
        let mut s = said("bob", "8qbHbw2B", false, "ok", 3661);
        s.reply_to = Some(("Alice (E4LUkjrZ)".into(), "shall we ship on friday?".into()));
        app.said = vec![s];
        let out = render(&app, 110, 24);
        let line = out.lines().find(|l| l.contains("↳")).expect("no quotation");
        assert!(
            line.contains("Alice (E4LUkjrZ)"),
            "the quotation does not say who is being answered: {line:?}"
        );
    }

    /// The floor is bounded by the pane as well as by the quotation. A narrow
    /// terminal has no thirty columns to give.
    ///
    /// Asserted on the **clock**, not on where the colour stops. ratatui clips
    /// a paragraph at its pane, so a bubble wider than the pane paints no
    /// further right than one that fits — "did it run off the edge" is a
    /// question the buffer cannot answer. What overflow actually costs is the
    /// end of the line, and the end of the line is the time.
    #[test]
    fn the_floor_never_pushes_the_clock_off_a_narrow_pane() {
        let mut app = sample();
        let mut s = said("bob", "8qbHbw2B", false, "ok", 3661);
        s.reply_to = Some((
            "Alice (E4LUkjrZ)".into(),
            "a question much longer than the pane is wide".into(),
        ));
        app.said = vec![s];
        let time = clock(3661).trim_end().to_string();
        for w in [60u16, 70, 80] {
            let out = render(&app, w, 24);
            assert!(
                out.contains(&time),
                "the floor pushed the time off a {w}-column terminal:\n{out}"
            );
        }
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
        assert!(
            out.contains("message 199"),
            "the newest message scrolled off"
        );
        assert!(!out.contains("message 0 "), "it showed the oldest instead");
    }
}
