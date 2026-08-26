//! Folding a channel's log into what a person sees.
//!
//! SIP-19 places authority over edits and redactions with the **receiver**, and
//! the reason is worth restating because it looks like an oversight: the
//! exchange can only check them in a public channel, where it can read the
//! body. A rule that holds where it is least needed is worse than no rule,
//! because it invites the assumption that it holds everywhere. So every client
//! enforces, and this is where that enforcement lives.
//!
//! # What is checked here
//!
//! - An edit is ignored unless it comes from the **account** that posted its
//!   target. Not the device: a person may edit from a different client than
//!   they posted from, and requiring the same one would break that for no gain.
//! - An edit older than [`EDIT_WINDOW`] past its target is ignored.
//! - A redaction is honoured only from that account or a channel admin.
//! - A reference to an entry we do not hold is ignored, because the check above
//!   cannot be performed without it.
//!
//! These comparisons are between public identities, not secrets, so constant
//! time is **not** required — noted because SIP-13 requires it for room proofs
//! and a reader moving between the two should know the difference is deliberate.
//!
//! # What is not promised
//!
//! Redaction removes the entry at the exchange and asks every client to forget.
//! This one does. A client that already displayed the message can keep it, and
//! one written to be dishonest certainly will.

use std::collections::BTreeMap;

use sqnr_core::PubKey;

use crate::channel::KIND_SYSTEM;
use crate::message::{Body, EDIT_WINDOW, Post};

/// One entry as it reached us, with its body already opened if we could.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Received {
    pub seq: u64,
    pub account: PubKey,
    pub posted: u64,
    /// SIP-16 entry kind: `0x00` written by the exchange, `0x01` by a member.
    pub kind: u8,
    /// `None` when the body was of a type we do not know, or could not be
    /// opened. Either way it is carried rather than dropped, so a client can
    /// say something was there.
    pub body: Option<Body>,
}

/// A message as it should be shown.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {
    pub seq: u64,
    pub account: PubKey,
    pub posted: u64,
    pub post: Post,
    /// When the edit that won was posted. A client SHOULD show this: presenting
    /// an edit as though it were the original hides that the text changed after
    /// it was read.
    pub edited: Option<u64>,
    /// The sequence number of the edit currently winning, so a later one with a
    /// higher number can replace it.
    edit_seq: Option<u64>,
    pub redacted: bool,
    /// Emoji to the accounts that reacted with it, each at most once.
    pub reactions: BTreeMap<String, Vec<PubKey>>,
}

impl Message {
    /// Whether anything survives to show. A redacted message is still shown, as
    /// a gap — the tombstone is the record.
    pub fn is_visible(&self) -> bool {
        !self.redacted
    }
}

/// The conversation, folded.
#[derive(Debug, Clone, Default)]
pub struct Timeline {
    messages: BTreeMap<u64, Message>,
    /// Bodies we could not read at all, by sequence number.
    unreadable: Vec<u64>,
    pub name: String,
    pub topic: String,
    /// Which entry set the metadata currently held, so a later one wins.
    metadata_seq: u64,
}

impl Timeline {
    pub fn new() -> Timeline {
        Timeline::default()
    }

    /// Messages in the order the exchange assigned, which is the order
    /// everybody sees.
    pub fn messages(&self) -> impl Iterator<Item = &Message> {
        self.messages.values()
    }

    pub fn get(&self, seq: u64) -> Option<&Message> {
        self.messages.get(&seq)
    }

    /// Sequence numbers whose body we could not read — a later version of the
    /// format, or a key we do not hold. A client should say something was
    /// there rather than showing a gap it cannot explain.
    pub fn unreadable(&self) -> &[u64] {
        &self.unreadable
    }

    /// Fold a run of entries. `admins` is the channel's admin list from SIP-16
    /// `Info`, which is the only place authority is a fact.
    pub fn fold(entries: &[Received], admins: &[PubKey]) -> Timeline {
        let mut t = Timeline::new();
        for e in entries {
            t.apply(e, admins);
        }
        t
    }

    pub fn apply(&mut self, e: &Received, admins: &[PubKey]) {
        // An entry the exchange wrote is not a message and never carried a
        // SIP-19 body. It is a membership or rotation event, rendered from
        // SIP-16's own `System` layout, and counting it as something we failed
        // to read would tell a client a gap exists where none does.
        if e.kind == KIND_SYSTEM {
            return;
        }
        let Some(body) = &e.body else {
            // Well formed and not understood, or sealed under a key we lack.
            // Either way it happened, and the reader is told.
            self.unreadable.push(e.seq);
            return;
        };
        match body {
            Body::Post(post) => {
                self.messages.insert(
                    e.seq,
                    Message {
                        seq: e.seq,
                        account: e.account,
                        posted: e.posted,
                        post: post.clone(),
                        edited: None,
                        edit_seq: None,
                        redacted: false,
                        reactions: BTreeMap::new(),
                    },
                );
            }
            Body::Edit { target, post } => {
                let Some(m) = self.messages.get_mut(target) else {
                    // A target we do not hold — pruned, or from before we
                    // joined. The authority check cannot be made, so nothing is.
                    return;
                };
                if m.account != e.account {
                    return;
                }
                if e.posted.saturating_sub(m.posted) > EDIT_WINDOW {
                    return;
                }
                // Where two edits target one entry, the higher sequence wins.
                if m.edit_seq.is_some_and(|prev| prev > e.seq) {
                    return;
                }
                m.post = post.clone();
                m.edited = Some(e.posted);
                m.edit_seq = Some(e.seq);
            }
            Body::Redact { target } => {
                let Some(m) = self.messages.get_mut(target) else {
                    return;
                };
                if m.account != e.account && !admins.contains(&e.account) {
                    return;
                }
                m.redacted = true;
                m.post = Post::default();
            }
            Body::Reaction { target, add, emoji } => {
                let Some(m) = self.messages.get_mut(target) else {
                    return;
                };
                let who = m.reactions.entry(emoji.clone()).or_default();
                match add {
                    // Keyed on (account, target, emoji): adding one that exists
                    // changes nothing, and removing one that does not is
                    // ordinary rather than an error.
                    true => {
                        if !who.contains(&e.account) {
                            who.push(e.account);
                        }
                    }
                    false => who.retain(|a| a != &e.account),
                }
                if who.is_empty() {
                    m.reactions.remove(emoji);
                }
            }
            Body::Metadata { name, topic, .. } => {
                // Only an admin names a channel, and the highest sequence
                // number is current.
                if !admins.contains(&e.account) || e.seq < self.metadata_seq {
                    return;
                }
                self.name = name.clone();
                self.topic = topic.clone();
                self.metadata_seq = e.seq;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::message::Post;

    fn key(b: u8) -> PubKey {
        PubKey::new([b; 32])
    }

    fn post(seq: u64, who: u8, posted: u64, text: &str) -> Received {
        Received {
            seq,
            account: key(who),
            posted,
            kind: 0x01,
            body: Some(Body::Post(Post::text(text))),
        }
    }

    fn body(seq: u64, who: u8, posted: u64, b: Body) -> Received {
        Received {
            seq,
            account: key(who),
            posted,
            kind: 0x01,
            body: Some(b),
        }
    }

    #[test]
    fn a_conversation_folds_in_the_order_the_exchange_assigned() {
        let t = Timeline::fold(
            &[
                post(1, 1, 100, "one"),
                post(2, 2, 101, "two"),
                post(3, 1, 102, "three"),
            ],
            &[],
        );
        let texts: Vec<&str> = t.messages().filter_map(|m| m.post.body_text()).collect();
        assert_eq!(texts, vec!["one", "two", "three"]);
    }

    #[test]
    fn an_author_may_edit_their_own_message() {
        let t = Timeline::fold(
            &[
                post(1, 1, 100, "teh typo"),
                body(
                    2,
                    1,
                    110,
                    Body::Edit {
                        target: 1,
                        post: Post::text("the typo"),
                    },
                ),
            ],
            &[],
        );
        let m = t.get(1).unwrap();
        assert_eq!(m.post.body_text(), Some("the typo"));
        assert_eq!(m.edited, Some(110));
    }

    #[test]
    fn nobody_else_may_edit_it() {
        // The forgery this check exists for. The exchange cannot make it in a
        // private channel, so every reader does.
        let t = Timeline::fold(
            &[
                post(1, 1, 100, "what I said"),
                body(
                    2,
                    2,
                    101,
                    Body::Edit {
                        target: 1,
                        post: Post::text("what they claim I said"),
                    },
                ),
            ],
            &[],
        );
        let m = t.get(1).unwrap();
        assert_eq!(m.post.body_text(), Some("what I said"));
        assert_eq!(m.edited, None);
    }

    #[test]
    fn an_edit_arriving_too_late_is_ignored() {
        let t = Timeline::fold(
            &[
                post(1, 1, 100, "as written"),
                body(
                    2,
                    1,
                    100 + EDIT_WINDOW + 1,
                    Body::Edit {
                        target: 1,
                        post: Post::text("rewritten a year later"),
                    },
                ),
            ],
            &[],
        );
        assert_eq!(t.get(1).unwrap().post.body_text(), Some("as written"));
    }

    #[test]
    fn the_later_of_two_edits_wins_whatever_order_they_arrive_in() {
        let first = body(
            2,
            1,
            101,
            Body::Edit {
                target: 1,
                post: Post::text("second thoughts"),
            },
        );
        let second = body(
            3,
            1,
            102,
            Body::Edit {
                target: 1,
                post: Post::text("third thoughts"),
            },
        );
        let t = Timeline::fold(&[post(1, 1, 100, "first"), first.clone(), second.clone()], &[]);
        assert_eq!(t.get(1).unwrap().post.body_text(), Some("third thoughts"));

        // And folding them the other way round reaches the same state, which
        // is what makes the log replayable.
        let t = Timeline::fold(&[post(1, 1, 100, "first"), second, first], &[]);
        assert_eq!(t.get(1).unwrap().post.body_text(), Some("third thoughts"));
    }

    #[test]
    fn an_author_or_an_admin_may_redact_and_a_stranger_may_not() {
        let entries = |who: u8| {
            vec![
                post(1, 1, 100, "regrettable"),
                body(2, who, 101, Body::Redact { target: 1 }),
            ]
        };
        assert!(Timeline::fold(&entries(1), &[]).get(1).unwrap().redacted);
        // An admin, which is the moderation path.
        assert!(Timeline::fold(&entries(9), &[key(9)]).get(1).unwrap().redacted);
        // Anybody else.
        assert!(!Timeline::fold(&entries(2), &[key(9)]).get(1).unwrap().redacted);
    }

    #[test]
    fn a_redacted_message_leaves_a_gap_rather_than_vanishing() {
        // The tombstone is the record: a reader should see that something was
        // deleted rather than find a conversation that silently does not
        // follow.
        let t = Timeline::fold(
            &[
                post(1, 1, 100, "gone"),
                body(2, 1, 101, Body::Redact { target: 1 }),
            ],
            &[],
        );
        let m = t.get(1).unwrap();
        assert!(!m.is_visible());
        assert_eq!(m.post.body_text(), None);
        assert_eq!(t.messages().count(), 1);
    }

    #[test]
    fn reactions_are_keyed_on_who_what_and_which_emoji() {
        let react = |seq, who, add, emoji: &str| {
            body(
                seq,
                who,
                100,
                Body::Reaction {
                    target: 1,
                    add,
                    emoji: emoji.into(),
                },
            )
        };
        let t = Timeline::fold(
            &[
                post(1, 1, 100, "a thing"),
                react(2, 1, true, "👍"),
                react(3, 2, true, "👍"),
                // Adding one that exists changes nothing.
                react(4, 2, true, "👍"),
                react(5, 2, true, "🎉"),
            ],
            &[],
        );
        let m = t.get(1).unwrap();
        assert_eq!(m.reactions["👍"].len(), 2);
        assert_eq!(m.reactions["🎉"].len(), 1);

        // Removing is ordinary, and the last one out takes the emoji with it.
        let t = Timeline::fold(
            &[
                post(1, 1, 100, "a thing"),
                react(2, 1, true, "👍"),
                react(3, 1, false, "👍"),
                // Removing one that does not exist is not an error either.
                react(4, 2, false, "🎉"),
            ],
            &[],
        );
        assert!(t.get(1).unwrap().reactions.is_empty());
    }

    #[test]
    fn a_reference_to_an_entry_we_do_not_hold_is_ignored() {
        // Pruned, or from before we joined. The authority check cannot be made
        // without the target, so nothing is done.
        let t = Timeline::fold(
            &[
                body(
                    5,
                    2,
                    100,
                    Body::Edit {
                        target: 1,
                        post: Post::text("about a message we never saw"),
                    },
                ),
                body(6, 2, 100, Body::Redact { target: 1 }),
                body(
                    7,
                    2,
                    100,
                    Body::Reaction {
                        target: 1,
                        add: true,
                        emoji: "👍".into(),
                    },
                ),
            ],
            &[key(2)],
        );
        assert_eq!(t.messages().count(), 0);
    }

    #[test]
    fn only_an_admin_names_a_channel_and_the_latest_wins() {
        let meta = |seq, who, name: &str| {
            body(
                seq,
                who,
                100,
                Body::Metadata {
                    name: name.into(),
                    topic: String::new(),
                    avatar: None,
                },
            )
        };
        let t = Timeline::fold(&[meta(1, 9, "planning"), meta(2, 2, "hijacked")], &[key(9)]);
        assert_eq!(t.name, "planning");

        let t = Timeline::fold(&[meta(1, 9, "planning"), meta(2, 9, "renamed")], &[key(9)]);
        assert_eq!(t.name, "renamed");
    }

    #[test]
    fn an_exchange_written_entry_is_not_a_message_and_not_a_gap() {
        // It never carried a SIP-19 body, so reporting it as unreadable would
        // tell a client something is missing when nothing is.
        let t = Timeline::fold(
            &[
                post(1, 1, 100, "a message"),
                Received {
                    seq: 2,
                    account: PubKey::new([0; 32]),
                    posted: 101,
                    kind: KIND_SYSTEM,
                    body: None,
                },
            ],
            &[],
        );
        assert_eq!(t.messages().count(), 1);
        assert!(t.unreadable().is_empty());
    }

    #[test]
    fn a_body_we_could_not_read_is_carried_rather_than_dropped() {
        // A later version of the format, or a key we do not hold. Either way
        // it happened, and a client should say so rather than show a gap it
        // cannot explain.
        let t = Timeline::fold(
            &[
                post(1, 1, 100, "readable"),
                Received {
                    seq: 2,
                    account: key(1),
                    posted: 101,
                    kind: 0x01,
                    body: None,
                },
            ],
            &[],
        );
        assert_eq!(t.messages().count(), 1);
        assert_eq!(t.unreadable(), &[2]);
    }
}
