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

use crate::blob::Attachment;
use crate::channel::KIND_SYSTEM;
use crate::message::{Body, EDIT_WINDOW, Post};

/// What SIP-31 verification concluded about an entry.
///
/// Three states, not two. Collapsing `Broken` into `Valid` hides the omission
/// the chain exists to make visible; collapsing it into `Forged` accuses an
/// origin of rewriting when it may only have pruned.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Verdict {
    /// Signed by the device the entry names, and following that device's chain.
    #[default]
    Valid,
    /// The signature is absent, or does not verify under the entry's device.
    /// Not a message: a reader MUST NOT show it as one.
    Forged,
    /// A gap in a device's chain. Ordinary — pruning, retention, and joining a
    /// channel without its history all produce one — so it is reported and the
    /// message is still shown.
    Gap,
    /// Two entries by one device at one chain position. This cannot happen
    /// without that device signing twice or somebody replaying, and it is the
    /// only one of these that is evidence.
    Fork,
    /// The signature verifies and **nobody can say whose key it is** (SIP-32).
    ///
    /// SIP-31's second step binds the signing device to the account the entry
    /// names, through a SIP-20 credential. Where no credential can be obtained
    /// the first step still proves a key signed, and proves nothing about who.
    /// Reported rather than quietly accepted, because a mapping somebody
    /// asserts and evidence somebody can check are different things and this is
    /// the only place a reader would find out which they hold.
    Unattributed,
}

/// What SIP-34 verification concluded about the exchange's claim on an entry.
///
/// **Deliberately separate from [`Verdict`], and both must be checked.** They
/// answer different questions — who wrote this, and where the exchange says it
/// put it. SIP-34 warns that a verifier which checks a receipt and skips
/// SIP-31's steps has confirmed that an exchange carried something and learned
/// nothing about who wrote it, and that the reverse omission is the more likely
/// one.
///
/// The distinction that carries the most weight is between the first two.
/// *Unclaimed* is an exchange that said nothing; *repudiated* is one that said
/// something untrue. An implementation that collapses them — a single nullable
/// field whose `None` means both — has built a mechanism the exchange can
/// switch off by corrupting its own signatures.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Standing {
    /// No receipt. The exchange was not asked, or does not implement SIP-34.
    /// It makes no claim, and this says nothing about the entry.
    #[default]
    Unclaimed,
    /// A receipt that verifies under the key this client pinned, over a head
    /// that follows the one held for the entry before it.
    Vouched,
    /// A receipt that verifies, with no predecessor held to link it to.
    ///
    /// Ordinary: pruning, retention, `expires_after` and joining a channel with
    /// history all produce one. A reader SHOULD show that continuity across the
    /// gap is unverified and MUST NOT present it as misconduct.
    Unlinked,
    /// A receipt that verifies and whose head does **not** follow the one held
    /// for the entry before it.
    ///
    /// This cannot happen without the exchange having advanced its head over an
    /// entry this reader was not shown. It is evidence, and unlike a gap it is
    /// surfaced.
    Diverged,
    /// A receipt that is present and does not verify under the pinned key.
    ///
    /// Not absence. The exchange signed something it cannot stand behind, and a
    /// client surfaces it exactly as it surfaces a forged entry.
    Repudiated,
}

/// What a reader can say about a tombstone (SIP-32).
///
/// SIP-16's redaction removes the bytes and keeps the entry, and the removal is
/// the exchange's own act — it is the only party that can take them. So the
/// question a reader can actually answer is not *was this deleted* but *did
/// anybody authorised ask for it*, which the paired SIP-19 `Redact` body
/// answers, in the log, signed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Deletion {
    /// Not a tombstone.
    #[default]
    No,
    /// A tombstone with a signed `Redact` from its author or an admin behind
    /// it. Somebody asked, and was entitled to.
    Asked,
    /// A tombstone with nothing corroborating it. The exchange did this on its
    /// own authority — which it can, and which a reader should be able to see
    /// rather than have it pass as an ordinary deletion.
    Unasked,
}

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
    /// The entry arrived carrying no body at all.
    ///
    /// SIP-16 redaction removes the body and keeps the entry with `len` 0 as a
    /// tombstone, so this is a message that was deleted — not one this client
    /// failed to open. Telling a reader their key is missing when somebody
    /// simply deleted a message sends them looking for a fault that is not
    /// there.
    ///
    /// The distinction is safe to make on length: a sealed body always carries
    /// its tag, so nothing openable is ever zero bytes.
    pub tombstone: bool,
    /// What SIP-31 verification concluded. `Valid` for an entry the exchange
    /// wrote itself, which carries an actor's signature inside its body rather
    /// than one of its own.
    pub verdict: Verdict,
    /// What SIP-34 verification concluded, which is a different question — see
    /// [`Standing`].
    pub standing: Standing,
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
    /// SIP-32: whether anybody authorised asked for this removal, or the
    /// exchange simply made it. `No` unless `redacted`.
    pub deletion: Deletion,
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
    forged: Vec<u64>,
    broken: Vec<(u64, Verdict)>,
    pub name: String,
    pub topic: String,
    /// The channel's picture, as an attachment reference. Kept rather than
    /// discarded: a client that drops it cannot show one, and cannot carry it
    /// over when it changes the name — which turns any rename into a deletion
    /// of the avatar.
    pub avatar: Option<Attachment>,
    /// Which entry set the metadata currently held, so a later one wins.
    metadata_seq: u64,
    /// SIP-36 calls, by the `seq` of the invitation.
    calls: BTreeMap<u64, CallRecord>,
}

/// A SIP-36 call, folded from the log.
///
/// Built only from entries — never from a `CallState` signal, which SIP-36
/// forbids deriving anything durable from. A signal drives a ringing screen and
/// nothing else; this is what happened.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallRecord {
    /// The `seq` of the invitation.
    pub seq: u64,
    /// Who called.
    pub account: PubKey,
    pub posted: u64,
    pub media: u8,
    pub ring_secs: u16,
    /// A SIP-13 room secret. Held because joining needs it, and because a
    /// reader that discarded it could not rejoin a call still in progress.
    pub secret: [u8; 32],
    /// The first `CallEnd` by sequence number, where one arrived: its outcome
    /// and duration, and who posted it.
    pub ended: Option<(u8, u32, PubKey)>,
}

impl CallRecord {
    /// What to show for this call, given the time now.
    ///
    /// **A call with no `CallEnd` whose ring window has passed is missed, and a
    /// reader derives that rather than waiting for an entry.** The party that
    /// would have posted one is the party whose client crashed, lost its
    /// connection or was closed — the common case, and it needs no protocol. A
    /// client that waited would show a call ringing forever.
    ///
    /// `None` means still ringing: no end, and the window has not passed.
    pub fn outcome(&self, now: u64) -> Option<u8> {
        match self.ended {
            Some((outcome, _, _)) => Some(outcome),
            None if now > self.posted.saturating_add(u64::from(self.ring_secs)) => {
                Some(crate::message::CALL_MISSED)
            }
            None => None,
        }
    }
}

impl Timeline {
    pub fn new() -> Timeline {
        Timeline::default()
    }

    /// Calls in the order the exchange assigned.
    pub fn calls(&self) -> impl Iterator<Item = &CallRecord> {
        self.calls.values()
    }

    /// One call by the `seq` of its invitation.
    pub fn call(&self, seq: u64) -> Option<&CallRecord> {
        self.calls.get(&seq)
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

    /// Entries whose signature did not verify. Never folded into the messages,
    /// because the whole point is that nobody vouched for them.
    pub fn forged(&self) -> &[u64] {
        &self.forged
    }

    /// Entries where a device's chain did not follow. Shown, and marked: a gap
    /// is ordinary and only a fork is evidence, so a client that presented
    /// either as tampering would cry wolf on every channel with a retention
    /// window.
    pub fn broken(&self) -> &[(u64, Verdict)] {
        &self.broken
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
        // Nobody vouched for this, so it is not a message and must not be shown
        // as one. Recorded rather than dropped: a reader should be told that
        // something arrived claiming to be from somebody and was not.
        if e.verdict == Verdict::Forged {
            self.forged.push(e.seq);
            return;
        }
        if e.verdict != Verdict::Valid {
            self.broken.push((e.seq, e.verdict));
        }
        // An entry the exchange wrote is not a message and never carried a
        // SIP-19 body. It is a membership or rotation event, rendered from
        // SIP-16's own `System` layout, and counting it as something we failed
        // to read would tell a client a gap exists where none does.
        if e.kind == KIND_SYSTEM {
            return;
        }
        let Some(body) = &e.body else {
            if e.tombstone {
                // Deleted, and the entry kept so the gap is visible. A reader
                // arriving after the redaction never held the words and never
                // will, but should still see that something was here.
                self.messages.insert(
                    e.seq,
                    Message {
                        seq: e.seq,
                        account: e.account,
                        posted: e.posted,
                        post: Post::default(),
                        edited: None,
                        edit_seq: None,
                        redacted: true,
                        // A tombstone arriving with nothing to explain it. If a
                        // signed `Redact` follows in this run it is upgraded
                        // below; if none ever does, the exchange did this.
                        deletion: Deletion::Unasked,
                        reactions: BTreeMap::new(),
                    },
                );
                return;
            }
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
                        deletion: Deletion::No,
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
                // Somebody entitled to asked, and said so in a signed entry.
                // That is the strongest thing a reader can establish about a
                // removal the exchange performed.
                m.deletion = Deletion::Asked;
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
            Body::Metadata {
                name,
                topic,
                avatar,
            } => {
                // Only an admin names a channel, and the highest sequence
                // number is current.
                if !admins.contains(&e.account) || e.seq < self.metadata_seq {
                    return;
                }
                self.name = name.clone();
                self.topic = topic.clone();
                self.avatar = avatar.clone();
                self.metadata_seq = e.seq;
            }
            Body::Call {
                media,
                ring_secs,
                secret,
            } => {
                self.calls.insert(
                    e.seq,
                    CallRecord {
                        seq: e.seq,
                        account: e.account,
                        posted: e.posted,
                        media: *media,
                        ring_secs: *ring_secs,
                        secret: *secret,
                        ended: None,
                    },
                );
            }
            Body::CallEnd {
                target,
                outcome,
                duration,
            } => {
                let Some(call) = self.calls.get_mut(target) else {
                    // A call we do not hold — pruned, or from before we joined.
                    return;
                };
                // Two `CallEnd`s targeting one call are ordinary: two parties
                // observed the same call ending. The first by sequence number
                // is shown, and the rest are kept out rather than overwriting
                // it, so a late one cannot rewrite an answered call as missed.
                if call.ended.is_none() {
                    call.ended = Some((*outcome, *duration, e.account));
                }
            }
        }
    }
}

#[cfg(test)]
mod call_tests {
    use super::*;
    use crate::channel::KIND_MEMBER;
    use crate::message::{CALL_ANSWERED, CALL_DECLINED, CALL_MISSED, MEDIA_AUDIO};

    fn key(b: u8) -> PubKey {
        PubKey::new([b; 32])
    }

    fn entry(seq: u64, who: u8, posted: u64, body: Body) -> Received {
        Received {
            seq,
            account: key(who),
            posted,
            kind: KIND_MEMBER,
            body: Some(body),
            tombstone: false,
            verdict: Verdict::Valid,
            standing: Standing::Unclaimed,
        }
    }

    fn invitation(seq: u64, who: u8, posted: u64, ring_secs: u16) -> Received {
        entry(
            seq,
            who,
            posted,
            Body::Call {
                media: MEDIA_AUDIO,
                ring_secs,
                secret: [9; 32],
            },
        )
    }

    /// **A call with no ending and a ring window in the past is missed, and a
    /// reader derives it.** The party that would have posted a `CallEnd` is the
    /// party whose client crashed, lost its connection or was closed — the
    /// common case, needing no protocol. Waiting for an entry shows a call
    /// ringing forever.
    #[test]
    fn an_unanswered_call_becomes_missed_without_anybody_saying_so() {
        let mut t = Timeline::new();
        t.apply(&invitation(1, 1, 1_000, 30), &[]);
        let call = t.call(1).unwrap();

        // Inside the window it is still ringing, and saying anything else would
        // be wrong in the other direction.
        assert_eq!(call.outcome(1_000), None);
        assert_eq!(call.outcome(1_030), None);
        // Past it, missed — with no second entry involved.
        assert_eq!(call.outcome(1_031), Some(CALL_MISSED));
    }

    #[test]
    fn an_answered_call_keeps_its_outcome_however_long_ago_it_was() {
        let mut t = Timeline::new();
        t.apply(&invitation(1, 1, 1_000, 30), &[]);
        t.apply(
            &entry(
                2,
                1,
                1_005,
                Body::CallEnd {
                    target: 1,
                    outcome: CALL_ANSWERED,
                    duration: 42,
                },
            ),
            &[],
        );
        let call = t.call(1).unwrap();
        assert_eq!(call.outcome(9_999_999), Some(CALL_ANSWERED));
        assert_eq!(call.ended.unwrap().1, 42);
    }

    /// Two `CallEnd`s targeting one call are ordinary — two parties observed
    /// the same call ending — and the first by sequence number is shown.
    ///
    /// The rule matters in one direction in particular: a late `declined` must
    /// not rewrite a call that was answered.
    #[test]
    fn the_first_ending_by_sequence_wins_and_a_later_one_cannot_rewrite_it() {
        let mut t = Timeline::new();
        t.apply(&invitation(1, 1, 1_000, 30), &[]);
        for (seq, outcome) in [(2, CALL_ANSWERED), (3, CALL_DECLINED)] {
            t.apply(
                &entry(
                    seq,
                    2,
                    1_010,
                    Body::CallEnd {
                        target: 1,
                        outcome,
                        duration: 0,
                    },
                ),
                &[],
            );
        }
        assert_eq!(t.call(1).unwrap().outcome(2_000), Some(CALL_ANSWERED));
    }

    /// An ending naming a call this reader does not hold — pruned, or from
    /// before it joined — changes nothing and is not an error.
    #[test]
    fn an_ending_for_a_call_we_never_saw_is_ignored() {
        let mut t = Timeline::new();
        t.apply(
            &entry(
                7,
                1,
                1_000,
                Body::CallEnd {
                    target: 4,
                    outcome: CALL_ANSWERED,
                    duration: 1,
                },
            ),
            &[],
        );
        assert!(t.calls().next().is_none());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::message::Post;

    fn key(b: u8) -> PubKey {
        PubKey::new([b; 32])
    }

    fn tombstone(seq: u64, who: u8, posted: u64) -> Received {
        Received {
            seq,
            account: PubKey::new([who; 32]),
            posted,
            kind: 0x01,
            tombstone: true,
            body: None,
            verdict: Verdict::Valid,
            standing: Standing::Unclaimed,
        }
    }

    fn post(seq: u64, who: u8, posted: u64, text: &str) -> Received {
        Received {
            seq,
            account: key(who),
            posted,
            kind: 0x01,
            tombstone: false,
            body: Some(Body::Post(Post::text(text))),
            verdict: Verdict::Valid,
            standing: Standing::Unclaimed,
        }
    }

    fn body(seq: u64, who: u8, posted: u64, b: Body) -> Received {
        Received {
            seq,
            account: key(who),
            posted,
            kind: 0x01,
            tombstone: false,
            body: Some(b),
            verdict: Verdict::Valid,
            standing: Standing::Unclaimed,
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
        let t = Timeline::fold(
            &[post(1, 1, 100, "first"), first.clone(), second.clone()],
            &[],
        );
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
        assert!(
            Timeline::fold(&entries(9), &[key(9)])
                .get(1)
                .unwrap()
                .redacted
        );
        // Anybody else.
        assert!(
            !Timeline::fold(&entries(2), &[key(9)])
                .get(1)
                .unwrap()
                .redacted
        );
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
                    tombstone: false,
                    body: None,
                    verdict: Verdict::Valid,
                    standing: Standing::Unclaimed,
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
                    tombstone: false,
                    body: None,
                    verdict: Verdict::Valid,
                    standing: Standing::Unclaimed,
                },
            ],
            &[],
        );
        assert_eq!(t.messages().count(), 1);
        assert_eq!(t.unreadable(), &[2]);
    }

    /// A reader arriving after a redaction never held the words and never
    /// will. The entry still reaches them, with no body, and SIP-16 keeps it
    /// so the gap is visible — so it is a deleted message, not one this client
    /// failed to open. Reporting "cannot be opened" sends the reader looking
    /// for a missing key that does not exist.
    #[test]
    fn a_tombstone_reads_as_deleted_and_not_as_unreadable() {
        let mut t = Timeline::new();
        t.apply(&post(1, 1, 10, "still here"), &[]);
        t.apply(&tombstone(2, 1, 20), &[]);

        assert!(
            t.unreadable().is_empty(),
            "a tombstone was reported as unreadable: {:?}",
            t.unreadable()
        );
        let m = t.get(2).expect("the tombstone was dropped entirely");
        assert!(m.redacted, "the tombstone was not marked redacted");
        assert!(!m.is_visible());
        assert_eq!(m.account, PubKey::new([1; 32]), "it lost its author");
        assert_eq!(m.posted, 20, "it lost its time");

        // And it does not disturb what is around it.
        assert_eq!(t.get(1).map(|m| m.redacted), Some(false));
    }

    /// An entry with a body this client cannot read is a different thing, and
    /// must keep saying so — a key may still arrive for it.
    #[test]
    fn an_unopenable_body_is_still_unreadable() {
        let mut t = Timeline::new();
        let mut e = tombstone(3, 1, 30);
        e.tombstone = false; // body absent because we could not open it
        t.apply(&e, &[]);

        assert_eq!(t.unreadable(), &[3]);
        assert!(t.get(3).is_none(), "an unopenable entry became a message");
    }
}

#[cfg(test)]
mod deletion_tests {
    use super::*;
    use crate::channel::KIND_MEMBER;
    use crate::message::Post as SipPost;

    fn key(b: u8) -> PubKey {
        PubKey::new([b; 32])
    }

    fn said(seq: u64, who: u8, text: &str) -> Received {
        Received {
            seq,
            account: key(who),
            posted: 100 + seq,
            kind: KIND_MEMBER,
            body: Some(Body::Post(SipPost::text(text))),
            tombstone: false,
            verdict: Verdict::Valid,
            standing: Standing::Unclaimed,
        }
    }

    fn tombstone(seq: u64, who: u8) -> Received {
        Received {
            seq,
            account: key(who),
            posted: 100 + seq,
            kind: KIND_MEMBER,
            body: None,
            tombstone: true,
            verdict: Verdict::Valid,
            standing: Standing::Unclaimed,
        }
    }

    fn asked(seq: u64, who: u8, target: u64) -> Received {
        Received {
            seq,
            account: key(who),
            posted: 100 + seq,
            kind: KIND_MEMBER,
            body: Some(Body::Redact { target }),
            tombstone: false,
            verdict: Verdict::Valid,
            standing: Standing::Unclaimed,
        }
    }

    /// A removal the author asked for, in a signed entry the reader holds.
    #[test]
    fn a_removal_somebody_asked_for_is_told_apart_from_one_nobody_did() {
        let t = Timeline::fold(&[said(1, 1, "regret"), asked(2, 1, 1)], &[]);
        let m = t.get(1).unwrap();
        assert!(m.redacted);
        assert_eq!(m.deletion, Deletion::Asked);

        // The same tombstone with nothing behind it. The exchange can do this,
        // and a reader should be able to see that it did rather than have it
        // pass as an ordinary deletion.
        let t = Timeline::fold(&[tombstone(1, 1)], &[]);
        let m = t.get(1).unwrap();
        assert!(m.redacted);
        assert_eq!(m.deletion, Deletion::Unasked);
    }

    /// An admin may ask; a stranger may not, and their asking changes nothing.
    #[test]
    fn only_an_authorised_request_corroborates_a_removal() {
        let entries = [said(1, 1, "regret"), asked(2, 9, 1)];
        let t = Timeline::fold(&entries, &[]);
        let m = t.get(1).unwrap();
        assert!(!m.redacted, "a stranger's redaction was honoured");
        assert_eq!(m.deletion, Deletion::No);

        // The same run, with that account an admin.
        let t = Timeline::fold(&entries, &[key(9)]);
        let m = t.get(1).unwrap();
        assert!(m.redacted);
        assert_eq!(m.deletion, Deletion::Asked);
    }

    /// A message nobody deleted says so.
    #[test]
    fn an_ordinary_message_reports_no_deletion() {
        let t = Timeline::fold(&[said(1, 1, "still here")], &[]);
        assert_eq!(t.get(1).unwrap().deletion, Deletion::No);
    }
}
