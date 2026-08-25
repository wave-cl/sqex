//! What the exchange deliberately does not do.
//!
//! SIP-12 says it plainly: the exchange forwards packets and does not manage a
//! call, so a jitter buffer, loss concealment and rate control are the
//! application's problem. This module is the jitter buffer and the loss
//! concealment decision — the smallest thing that turns an unreliable,
//! unordered stream of datagrams back into twenty milliseconds of audio every
//! twenty milliseconds.
//!
//! Concealment itself belongs to Opus: a decode with no packet produces a
//! plausible continuation of what came before. All this module decides is
//! *when* to ask for one, which is the part the codec cannot know.

use std::collections::BTreeMap;
use std::time::{Duration, Instant};

use crate::media::classify;

/// One arrived frame: the packet that carried it, and what it holds.
struct Media {
    /// SIP-12 packet sequence — counts packets, so a hole here is loss.
    seq: u64,
    packet: Vec<u8>,
}

/// Opus is happiest at 48 kHz and the transport does not care, so there is no
/// reason to run anything else.
pub const SAMPLE_RATE: u32 = 48_000;
/// One frame of audio, in milliseconds.
pub const FRAME_MS: u64 = 20;
/// Samples in one mono frame: 48 kHz for 20 ms.
pub const FRAME_SAMPLES: usize = (SAMPLE_RATE as usize * FRAME_MS as usize) / 1000;

/// What the playout tick should do with this slot.
#[derive(Debug, PartialEq, Eq)]
pub enum Playout {
    /// Decode this packet.
    Frame(Vec<u8>),
    /// The packet for this slot is not coming. Ask Opus to invent one.
    Conceal,
    /// The sender deliberately said nothing here (SIP-14). **Never conceal
    /// this** — concealment extrapolates from what was last heard, so it would
    /// invent speech out of a silence nobody spoke.
    Silence,
    /// Nothing is in flight, or the buffer is still filling. Play silence and
    /// do not advance — an idle line is not a lost packet.
    Idle,
}

#[derive(Debug, Default, Clone)]
pub struct Stats {
    pub sent: u64,
    pub received: u64,
    /// Arrived after its slot had already been played.
    pub late: u64,
    /// Arrived twice.
    pub duplicate: u64,
    /// Slots played from Opus's imagination rather than from a packet.
    pub concealed: u64,
    /// Slots the sender chose not to fill (SIP-14 discontinuous transmission).
    pub silent: u64,
    /// Times the buffer emptied and had to refill.
    pub underruns: u64,
    /// Frames thrown away to shed accumulated delay.
    pub trimmed: u64,
}

impl Stats {
    /// Fraction of the packets the sender must have sent that never arrived,
    /// judged from the sequence numbers rather than from a report the peer
    /// would have to send us.
    pub fn loss_pct(&self, span: u64) -> f64 {
        if span == 0 {
            return 0.0;
        }
        let missing = span.saturating_sub(self.received);
        (missing as f64 / span as f64) * 100.0
    }
}

/// Holds arriving packets briefly so that reordering and variable delay come
/// out the far side as an even cadence.
pub struct Jitter {
    /// Keyed by media timestamp — *where audio belongs in time* — not by
    /// packet sequence. With SIP-14 the two differ: a sender that stops talking
    /// stops sending, so the timestamp runs on while the sequence does not.
    frames: BTreeMap<u64, Media>,
    /// The media timestamp the next tick will play.
    cursor: u64,
    /// Lowest and highest *sequence* numbers seen, for the loss estimate.
    lowest: Option<u64>,
    highest: u64,
    /// Sequence and timestamp of the last frame handed to playout, so a gap can
    /// be split into loss and silence.
    last_played: Option<(u64, u32)>,
    /// Slots in the gap we are crossing that were lost, and slots that were
    /// somebody not talking. Computed once on entering the gap.
    conceal_run: u64,
    silent_run: u64,
    /// How many frames to hold before starting to play.
    depth: u64,
    playing: bool,
    pub stats: Stats,
}

impl Jitter {
    pub fn new(depth: u64) -> Jitter {
        Jitter {
            frames: BTreeMap::new(),
            cursor: 0,
            lowest: None,
            highest: 0,
            last_played: None,
            conceal_run: 0,
            silent_run: 0,
            depth,
            playing: false,
            stats: Stats::default(),
        }
    }

    /// How many frames are waiting to be played.
    pub fn depth_now(&self) -> usize {
        self.frames.len()
    }

    /// The span of sequence numbers seen, which is how many the peer sent.
    pub fn span(&self) -> u64 {
        match self.lowest {
            Some(low) => self.highest - low + 1,
            None => 0,
        }
    }

    /// Take one arrived frame: its packet sequence number, its media timestamp,
    /// and the codec packet.
    pub fn push(&mut self, seq: u64, timestamp: u32, packet: Vec<u8>) {
        self.stats.received += 1;
        self.lowest = Some(self.lowest.map_or(seq, |l| l.min(seq)));
        self.highest = self.highest.max(seq);

        let slot = u64::from(timestamp);
        // Before playing there is no cursor to be behind: the first slot is
        // whatever the buffer's lowest timestamp turns out to be when playout
        // starts, which need not be zero and need not be the first frame the
        // peer produced.
        if self.playing && slot < self.cursor {
            // Its slot has already been played and concealed. Nothing useful
            // left to do with it, and inserting it would play it out of order.
            self.stats.late += 1;
            return;
        }
        if self.frames.insert(slot, Media { seq, packet }).is_some() {
            self.stats.duplicate += 1;
        }
    }

    /// Whether the buffer is carrying delay it has no use for.
    ///
    /// A fixed-depth buffer cannot recover from a backlog on its own. Once
    /// frames arrive at the same rate they are played, whatever piled up at the
    /// start is carried for the rest of the call as pure latency — and a call
    /// that is half a second behind is a call people talk over. In practice a
    /// backlog *does* pile up at the start: the peer may not be listening yet
    /// when the first frames go out, and QUIC will hold the datagrams it
    /// receives until something reads them, so they arrive in a burst.
    ///
    /// Three times the nominal depth leaves room for ordinary jitter without
    /// mistaking it for a backlog.
    pub fn overfull(&self) -> bool {
        self.playing && self.frames.len() as u64 > self.depth * 3
    }

    /// Shed one frame of delay, returning the frame that will not be played.
    ///
    /// The caller should still decode it: Opus carries state from one frame to
    /// the next, and skipping one outright is audible in the frames that
    /// follow. Decoding but not playing costs one 20 ms slot, so the call
    /// catches up at twice real time rather than lurching forward all at once.
    pub fn trim(&mut self) -> Option<Vec<u8>> {
        if !self.overfull() {
            return None;
        }
        let media = self.frames.remove(&self.cursor)?;
        self.last_played = Some((media.seq, self.cursor as u32));
        self.cursor += 1;
        self.conceal_run = 0;
        self.silent_run = 0;
        self.stats.trimmed += 1;
        Some(media.packet)
    }

    /// Decide what the next 20 ms of audio comes from, and advance.
    pub fn pop(&mut self) -> Playout {
        if !self.playing {
            // Fill before starting, so that the first reordering does not
            // immediately underrun.
            if (self.frames.len() as u64) <= self.depth {
                return Playout::Idle;
            }
            self.cursor = *self.frames.keys().next().expect("non-empty");
            self.playing = true;
        }

        if let Some(media) = self.frames.remove(&self.cursor) {
            self.last_played = Some((media.seq, self.cursor as u32));
            self.cursor += 1;
            // The gap, if there was one, is behind us now.
            self.conceal_run = 0;
            self.silent_run = 0;
            return Playout::Frame(media.packet);
        }

        if self.frames.is_empty() {
            // Nothing behind this gap either: the peer has gone quiet, or the
            // path has stalled. Concealing indefinitely would invent speech out
            // of silence, so stop and refill instead.
            self.stats.underruns += 1;
            self.playing = false;
            self.conceal_run = 0;
            self.silent_run = 0;
            return Playout::Idle;
        }

        // An empty slot with something waiting further on. Work out *once*, on
        // entering the gap, how much of it was lost and how much was somebody
        // not talking — the answer needs the frame on the far side, which is
        // why it cannot be decided when the gap is left behind.
        if self.conceal_run == 0 && self.silent_run == 0 {
            if let (Some(prev), Some((&ts, next))) = (self.last_played, self.frames.iter().next()) {
                let gap = classify(prev, (next.seq, ts as u32));
                self.conceal_run = gap.lost;
                self.silent_run = gap.silent;
            } else {
                // Nothing has been played yet, so there is no gap to measure
                // against — treat the slot as loss, as before.
                self.conceal_run = 1;
            }
        }

        self.cursor += 1;
        // Conceal first, then fall silent. Loss adjacent to real audio is where
        // the codec's extrapolation is worth anything; deep inside a pause it
        // would be inventing from nothing.
        if self.conceal_run > 0 {
            self.conceal_run -= 1;
            self.stats.concealed += 1;
            return Playout::Conceal;
        }
        self.silent_run -= 1;
        self.stats.silent += 1;
        Playout::Silence
    }
}

/// Round-trip timing, for running `call` against a peer in `echo` mode.
///
/// There is no clock shared with the peer and no attempt to establish one, so
/// one-way delay is not measurable. Round trip is, and it is the honest number:
/// it counts both relay hops in each direction.
#[derive(Default)]
pub struct Rtt {
    outstanding: BTreeMap<u64, Instant>,
    samples: Vec<Duration>,
}

impl Rtt {
    pub fn sent(&mut self, seq: u64) {
        self.outstanding.insert(seq, Instant::now());
        // A frame that never comes back is not a measurement; it is loss, and
        // it is counted elsewhere. Keep the map from growing without bound.
        while self.outstanding.len() > 256 {
            let first = *self.outstanding.keys().next().expect("non-empty");
            self.outstanding.remove(&first);
        }
    }

    pub fn returned(&mut self, seq: u64) {
        if let Some(at) = self.outstanding.remove(&seq) {
            self.samples.push(at.elapsed());
        }
    }

    pub fn is_empty(&self) -> bool {
        self.samples.is_empty()
    }

    /// p50 and p95 of everything measured so far.
    pub fn percentiles(&self) -> (Duration, Duration) {
        let mut s = self.samples.clone();
        s.sort();
        let at = |p: f64| s[(((s.len() - 1) as f64) * p).round() as usize];
        (at(0.50), at(0.95))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn packet(n: u8) -> Vec<u8> {
        vec![n; 4]
    }

    /// Feed enough to start playing, from sequence number `from`.
    fn primed(depth: u64, from: u64) -> Jitter {
        let mut j = Jitter::new(depth);
        for i in 0..=depth {
            j.push(from + i, (from + i) as u32, packet(i as u8));
        }
        j
    }

    #[test]
    fn holds_until_the_buffer_has_filled() {
        let mut j = Jitter::new(3);
        for i in 0..3 {
            j.push(i, (i) as u32, packet(i as u8));
            assert_eq!(j.pop(), Playout::Idle, "should still be filling at {i}");
        }
        j.push(3, 3, packet(3));
        assert_eq!(j.pop(), Playout::Frame(packet(0)));
    }

    #[test]
    fn plays_in_order_despite_arriving_out_of_it() {
        let mut j = Jitter::new(1);
        j.push(1, 1, packet(1));
        j.push(0, 0, packet(0));
        j.push(2, 2, packet(2));
        assert_eq!(j.pop(), Playout::Frame(packet(0)));
        assert_eq!(j.pop(), Playout::Frame(packet(1)));
        assert_eq!(j.pop(), Playout::Frame(packet(2)));
        assert_eq!(j.stats.late, 0, "reordering inside the buffer is not late");
    }

    #[test]
    fn conceals_a_gap_that_later_frames_have_overtaken() {
        let mut j = primed(2, 0);
        j.push(4, 4, packet(4)); // 3 is missing
        assert_eq!(j.pop(), Playout::Frame(packet(0)));
        assert_eq!(j.pop(), Playout::Frame(packet(1)));
        assert_eq!(j.pop(), Playout::Frame(packet(2)));
        assert_eq!(j.pop(), Playout::Conceal);
        assert_eq!(j.pop(), Playout::Frame(packet(4)));
        assert_eq!(j.stats.concealed, 1);
    }

    #[test]
    fn silence_rather_than_endless_invention_when_the_peer_stops() {
        let mut j = primed(1, 0);
        assert_eq!(j.pop(), Playout::Frame(packet(0)));
        assert_eq!(j.pop(), Playout::Frame(packet(1)));
        assert_eq!(j.pop(), Playout::Idle);
        assert_eq!(j.pop(), Playout::Idle);
        assert_eq!(j.stats.concealed, 0, "an idle line is not a lost packet");
        assert_eq!(j.stats.underruns, 1);
    }

    #[test]
    fn a_frame_whose_slot_has_passed_is_late_not_replayed() {
        let mut j = primed(1, 0);
        assert_eq!(j.pop(), Playout::Frame(packet(0)));
        assert_eq!(j.pop(), Playout::Frame(packet(1)));
        j.push(0, 0, packet(0));
        assert_eq!(j.stats.late, 1);
        assert_eq!(j.depth_now(), 0, "it should not be queued for replay");
    }

    #[test]
    fn sequence_numbers_need_not_start_at_zero() {
        let mut j = primed(1, 5_000);
        assert_eq!(j.pop(), Playout::Frame(packet(0)));
        assert_eq!(j.pop(), Playout::Frame(packet(1)));
    }

    #[test]
    fn a_repeat_is_counted_and_not_played_twice() {
        let mut j = Jitter::new(1);
        j.push(0, 0, packet(0));
        j.push(0, 0, packet(0));
        j.push(1, 1, packet(1));
        assert_eq!(j.stats.duplicate, 1);
        assert_eq!(j.pop(), Playout::Frame(packet(0)));
        assert_eq!(j.pop(), Playout::Frame(packet(1)));
        assert_eq!(j.pop(), Playout::Idle);
    }

    #[test]
    fn a_backlog_is_shed_rather_than_carried_for_the_rest_of_the_call() {
        let mut j = Jitter::new(3);
        // A burst: the peer was not listening, then read everything at once.
        for i in 0..40 {
            j.push(i, (i) as u32, packet(i as u8));
        }
        assert!(matches!(j.pop(), Playout::Frame(_)), "starts playing");
        assert!(j.overfull(), "36 frames is not a jitter buffer, it is a delay");

        // Each tick sheds one frame and plays one, so the excess drains at
        // twice real time instead of never.
        let mut ticks = 0;
        while j.overfull() {
            assert!(j.trim().is_some());
            assert!(matches!(j.pop(), Playout::Frame(_)));
            ticks += 1;
            assert!(ticks < 40, "trimming should converge");
        }
        assert!(j.depth_now() as u64 <= j.depth * 3);
        assert_eq!(j.stats.trimmed, ticks);
    }

    #[test]
    fn a_healthy_buffer_is_never_trimmed() {
        let mut j = primed(3, 0);
        for i in 4..40 {
            j.push(i, (i) as u32, packet(i as u8));
            assert!(j.trim().is_none(), "steady state should not shed frames");
            assert!(matches!(j.pop(), Playout::Frame(_)));
        }
        assert_eq!(j.stats.trimmed, 0);
    }

    /// The whole point of SIP-14. A speaker who stops talking stops sending,
    /// so the timestamp runs on while the sequence does not — and those slots
    /// must be played as silence, never concealed. Concealment extrapolates
    /// from what was last heard, so concealing here would put words in a
    /// silent person's mouth.
    #[test]
    fn a_pause_in_speech_is_silence_and_is_never_concealed() {
        let mut j = Jitter::new(1);
        // Two frames of speech, then the speaker stops for a second: fifty
        // slots pass and not one packet is lost.
        j.push(0, 0, packet(0));
        j.push(1, 1, packet(1));
        j.push(2, 51, packet(2));

        assert_eq!(j.pop(), Playout::Frame(packet(0)));
        assert_eq!(j.pop(), Playout::Frame(packet(1)));
        for slot in 2..51 {
            assert_eq!(j.pop(), Playout::Silence, "slot {slot} was a pause");
        }
        assert_eq!(j.pop(), Playout::Frame(packet(2)), "and then they spoke");
        assert_eq!(j.stats.concealed, 0, "nothing was invented");
        assert_eq!(j.stats.silent, 49);
    }

    /// And the converse: a hole in the *sequence* is real loss, even though the
    /// timestamps say the same thing they would for a pause.
    #[test]
    fn a_hole_in_the_sequence_is_still_concealed() {
        let mut j = Jitter::new(1);
        j.push(0, 0, packet(0));
        j.push(1, 1, packet(1));
        // Three slots on, and three packets never arrived.
        j.push(5, 5, packet(5));

        assert_eq!(j.pop(), Playout::Frame(packet(0)));
        assert_eq!(j.pop(), Playout::Frame(packet(1)));
        for _ in 0..3 {
            assert_eq!(j.pop(), Playout::Conceal);
        }
        assert_eq!(j.pop(), Playout::Frame(packet(5)));
        assert_eq!(j.stats.concealed, 3);
        assert_eq!(j.stats.silent, 0);
    }

    /// A pause that also loses a packet: only as many slots as there were
    /// missing packets may be concealed, and the rest is the pause.
    #[test]
    fn a_pause_with_loss_in_it_splits_the_difference() {
        let mut j = Jitter::new(1);
        j.push(0, 0, packet(0));
        j.push(1, 1, packet(1));
        // Twenty slots on, but two packets are missing from the sequence.
        j.push(4, 21, packet(4));

        assert_eq!(j.pop(), Playout::Frame(packet(0)));
        assert_eq!(j.pop(), Playout::Frame(packet(1)));
        let mut concealed = 0;
        let mut silent = 0;
        for _ in 2..21 {
            match j.pop() {
                Playout::Conceal => concealed += 1,
                Playout::Silence => silent += 1,
                other => panic!("unexpected {other:?}"),
            }
        }
        assert_eq!(concealed, 2, "bounded by the packets that went missing");
        assert_eq!(silent, 17);
        assert_eq!(j.pop(), Playout::Frame(packet(4)));
    }

    #[test]
    fn loss_is_judged_from_the_span_of_sequence_numbers() {
        let mut j = Jitter::new(1);
        for i in [0u64, 1, 2, 3, 5, 6, 7, 8, 9] {
            j.push(i, (i) as u32, packet(i as u8));
        }
        assert_eq!(j.span(), 10);
        assert_eq!(j.stats.received, 9);
        assert!((j.stats.loss_pct(j.span()) - 10.0).abs() < f64::EPSILON);
    }
}
