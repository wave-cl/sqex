//! SIP-14: telling silence apart from loss.
//!
//! Opus knows when nobody is talking, and says so by emitting a one-byte packet
//! instead of sixty-five. Acting on that — not sending — is where the bandwidth
//! actually is, because a one-byte payload still costs a hundred bytes once the
//! datagram header, the AEAD tag, QUIC and UDP/IP are counted.
//!
//! But a sender that simply stops leaves the receiver looking at missing
//! sequence numbers, which is exactly what loss looks like. A jitter buffer that
//! guesses wrong asks the codec to conceal, and concealment extrapolates from
//! what was last heard — so it invents speech out of a silence nobody spoke.
//!
//! The fix is two counters instead of one, which is the answer RTP reached for
//! the same reason. SIP-12's sequence number counts **packets** and stays the
//! AEAD nonce and the loss signal. A four-byte **timestamp**, carried in front
//! of the codec packet inside SIP-12's opaque payload, counts **time** and
//! advances even across frames that were never sent. Then:
//!
//! ```text
//! missing slots = ts_n - ts_p - 1     media frames that did not arrive
//! lost packets  = seq_n - seq_p - 1   packets that should have
//! ```
//!
//! and at most `lost packets` of those slots can possibly be loss. The rest is
//! somebody not talking.

use sqnr_core::{Error, Result};

/// Bytes of media header in front of each body: a type byte and a timestamp.
pub const HEADER: usize = 5;

/// This frame carries a codec packet.
pub const TYPE_AUDIO: u8 = 0x01;
/// This frame describes silence instead of transmitting it.
pub const TYPE_COMFORT: u8 = 0x02;

/// Loudest comfort noise a receiver will ever synthesise, in half-decibels
/// below full scale: -30 dBFS.
///
/// `level` is the one number in this stack a peer merely *asserts* — everything
/// else is checkable — and the receiver acts on it by making a sound. Without a
/// clamp, one byte set to zero is a full-scale burst into somebody's headphones.
pub const QUIETEST_LOUD: u8 = 60;

/// A packet this short is the codec saying it has nothing worth sending.
///
/// It is what libopus reports rather than something negotiated, and a packet
/// that short cannot be speech.
pub const DTX_MAX: usize = 2;

/// What a room sounds like when nobody is talking (SIP-15).
///
/// Two bytes, sent about once a second, so the far end can *make* the silence
/// rather than be handed a hole or a guess.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Comfort {
    /// RMS in half-decibels below full scale. 255 is digital silence.
    pub level: u8,
    /// Fraction of energy above 1 kHz, 0..=255. A rumble is low, a hiss high.
    pub tilt: u8,
}

impl Comfort {
    /// Describe a frame of room tone.
    pub fn measure(samples: &[f32]) -> Comfort {
        Comfort::from_parts(rms(samples), tilt(samples))
    }

    /// Describe a room from a level and a tilt measured however the caller
    /// likes — over one frame, or smoothed across a pause.
    pub fn from_parts(rms: f32, tilt: u8) -> Comfort {
        let level = if rms <= 0.0 {
            255
        } else {
            (-2.0 * 20.0 * rms.log10()).round().clamp(0.0, 254.0) as u8
        };
        Comfort { level, tilt }
    }

    /// The amplitude to synthesise at — never louder than [`QUIETEST_LOUD`],
    /// however loud the peer claims its room is.
    pub fn amplitude(&self) -> f32 {
        if self.level == 255 {
            return 0.0;
        }
        10f32.powf(-f32::from(self.level.max(QUIETEST_LOUD)) / 40.0)
    }
}

/// Root mean square, which both ends need and neither should re-derive.
fn rms(samples: &[f32]) -> f32 {
    if samples.is_empty() {
        return 0.0;
    }
    (samples.iter().map(|s| s * s).sum::<f32>() / samples.len() as f32).sqrt()
}

/// Fraction of energy above roughly 1 kHz, as a byte.
///
/// Measured by difference: a one-pole low-pass gives the low part, and what is
/// left over is the high. Crude, and enough to tell a fan from a hiss.
fn tilt(samples: &[f32]) -> u8 {
    // One-pole at ~1 kHz for 48 kHz. Exactness does not matter here; both ends
    // only have to mean roughly the same thing by "bright".
    const A: f32 = 0.12;
    let mut lp = 0.0f32;
    let (mut low, mut high) = (0.0f32, 0.0f32);
    for s in samples {
        lp += A * (s - lp);
        low += lp * lp;
        high += (s - lp) * (s - lp);
    }
    let total = low + high;
    if total <= 0.0 {
        return 0;
    }
    (255.0 * (high / total)).round().clamp(0.0, 255.0) as u8
}

/// What a frame carries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Body {
    /// One codec packet.
    Audio(Vec<u8>),
    /// A description of the silence being skipped.
    Comfort(Comfort),
}

/// One media frame as it travels inside a SIP-12 frame.
///
/// `| type: u8 | timestamp: u32 | body |`
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    /// Which 20 ms slot this belongs in, counted from an arbitrary origin.
    /// Advances for every frame the sender produced, including the ones it
    /// decided not to send.
    pub timestamp: u32,
    pub body: Body,
}

impl Frame {
    pub fn audio(timestamp: u32, packet: Vec<u8>) -> Frame {
        Frame {
            timestamp,
            body: Body::Audio(packet),
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(HEADER + 64);
        match &self.body {
            Body::Audio(packet) => {
                out.push(TYPE_AUDIO);
                out.extend_from_slice(&self.timestamp.to_be_bytes());
                out.extend_from_slice(packet);
            }
            Body::Comfort(c) => {
                out.push(TYPE_COMFORT);
                out.extend_from_slice(&self.timestamp.to_be_bytes());
                out.push(c.level);
                out.push(c.tilt);
            }
        }
        out
    }

    /// `Ok(None)` for a frame of a type we do not know: SIP-15 reserves the
    /// space so one can be added without a flag day, and ignoring it is what
    /// keeps that promise.
    pub fn decode(b: &[u8]) -> Result<Option<Frame>> {
        if b.len() < HEADER {
            return Err(Error::Malformed(format!(
                "media frame is {} bytes, want at least {HEADER}",
                b.len()
            )));
        }
        let timestamp = u32::from_be_bytes(b[1..HEADER].try_into().unwrap());
        match b[0] {
            TYPE_AUDIO => Ok(Some(Frame {
                timestamp,
                body: Body::Audio(b[HEADER..].to_vec()),
            })),
            TYPE_COMFORT => {
                if b.len() != HEADER + 2 {
                    return Err(Error::Malformed(format!(
                        "comfort frame is {} bytes, want {}",
                        b.len(),
                        HEADER + 2
                    )));
                }
                Ok(Some(Frame {
                    timestamp,
                    body: Body::Comfort(Comfort {
                        level: b[HEADER],
                        tilt: b[HEADER + 1],
                    }),
                }))
            }
            _ => Ok(None),
        }
    }
}

/// Decides whether a frame is speech, adapting to the room it is in.
///
/// SIP-14 left this to the codec and SIP-15 takes it back, for a reason worth
/// keeping in view: Opus's detector is deciding whether *encoding* is
/// worthwhile, not whether *transmitting* is, and against a noise floor it keeps
/// deciding yes. Once the far end can synthesise the room, we can afford to be
/// more aggressive than the codec — being wrong now costs a moment of comfort
/// noise instead of a hole.
pub struct Gate {
    /// The quietest frame in the window that just finished. This is the room.
    floor: f32,
    /// The quietest so far in the window still running.
    running_min: f32,
    seen: u32,
    /// Frames still to send after the last one that was speech.
    hangover: u32,
    hangover_frames: u32,
}

impl Gate {
    /// How far above the noise floor a frame must be to *start* counting as
    /// speech. About 10 dB — comfortably above room tone, below a voice.
    const OPEN: f32 = 3.2;
    /// And how far it must fall to stop. Lower than [`Gate::OPEN`] on purpose:
    /// a single threshold makes the gate chatter around it, and chattering is
    /// audible even when the levels match, because a real room and a
    /// synthesised one have different textures. Alternating between them
    /// several times a second is most of what "a little choppy" is.
    const CLOSE: f32 = 1.8;
    /// Absolute floor, so a digitally silent input does not make the gate
    /// infinitely sensitive and open on nothing.
    const FLOOR_MIN: f32 = 0.0005;
    /// Ceiling on the estimate: -30 dBFS, which is a *very* noisy room.
    ///
    /// This is what stops the gate muting a monologue. A minimum over a window
    /// is only the room if the window contains a gap, and a sustained vowel, a
    /// hum or music need not contain one — then the "quietest frame" is speech,
    /// the threshold goes above it, and the speaker is cut off. Capping the
    /// floor bounds that: the gate can be too permissive in a loud room, which
    /// costs bandwidth, and can never be so aggressive that it removes a voice.
    const FLOOR_MAX: f32 = 0.03;
    /// Frames over which the quietest is taken to be the room. Two seconds:
    /// long enough that speech contains a gap, short enough to follow a room
    /// that changes.
    const WINDOW: u32 = 100;

    /// `hangover_frames` keeps the gate open after speech stops. Without it,
    /// the gaps between words become gaps in the transmission and word tails
    /// get clipped; 15 frames is 300 ms, about the length of a breath.
    pub fn new(hangover_frames: u32) -> Gate {
        Gate {
            floor: Self::FLOOR_MIN,
            running_min: f32::MAX,
            seen: 0,
            hangover: 0,
            hangover_frames,
        }
    }

    /// Is this frame speech? Updates the noise-floor estimate either way.
    ///
    /// The floor is the **quietest frame of the last window**, which is the one
    /// estimator that does not depend on the decision it feeds. Tracking it by
    /// following the level instead means choosing between two failures, and I
    /// wrote both: rise while the gate is open and a long monologue drags the
    /// floor up until the speaker is muted; rise only while it is shut and a
    /// call that opens mid-sentence never shuts, because the floor starts below
    /// the room and nothing can lift it.
    ///
    /// Speech usually contains gaps, so a two-second minimum finds the room even
    /// while somebody is talking — and where it does not, [`Gate::FLOOR_MAX`]
    /// catches it. Until the first window closes the floor sits at its minimum,
    /// which means the gate is **open**: at worst the first two seconds are
    /// transmitted in full, which is the right way to be wrong.
    pub fn is_speech(&mut self, samples: &[f32]) -> bool {
        let level = rms(samples);
        self.running_min = self.running_min.min(level);
        self.seen += 1;
        if self.seen >= Self::WINDOW {
            self.floor = self.running_min.clamp(Self::FLOOR_MIN, Self::FLOOR_MAX);
            self.running_min = f32::MAX;
            self.seen = 0;
        }

        let threshold = if self.hangover > 0 {
            Self::CLOSE
        } else {
            Self::OPEN
        };
        if level > self.floor * threshold {
            self.hangover = self.hangover_frames;
            return true;
        }
        if self.hangover > 0 {
            self.hangover -= 1;
            return true;
        }
        false
    }

    /// The room as currently estimated, for tests and diagnostics.
    pub fn floor(&self) -> f32 {
        self.floor
    }
}

/// Makes the noise a [`Comfort`] describes.
///
/// White noise at the right level still sounds nothing like a room, so the
/// generator keeps a one-pole low-passed copy and mixes the two by `tilt`: all
/// low is a rumble, all high is a hiss, and most rooms want mostly the former.
pub struct Noise {
    seed: u64,
    lp: f32,
    /// What is actually being played, which chases what was last described.
    /// A descriptor arriving once a second is a step in level unless something
    /// smooths it, and a step in a noise floor is exactly the click that makes
    /// a pause sound broken.
    at: Option<(f32, f32)>,
}

impl Default for Noise {
    fn default() -> Noise {
        Noise::new()
    }
}

impl Noise {
    pub fn new() -> Noise {
        Noise {
            seed: 0x2545_F491_4F6C_DD1D,
            lp: 0.0,
            at: None,
        }
    }

    /// Fill `out` with one frame of the described room, gliding toward a new
    /// description rather than stepping to it.
    pub fn fill(&mut self, comfort: Comfort, out: &mut [f32]) {
        let target = (comfort.amplitude(), f32::from(comfort.tilt) / 255.0);
        // A tenth of the way per frame: about 200 ms to settle, which is quick
        // enough to follow a room and slow enough to be inaudible.
        let (amplitude, bright) = match self.at {
            Some((a, b)) => (a + 0.1 * (target.0 - a), b + 0.1 * (target.1 - b)),
            None => target,
        };
        self.at = Some((amplitude, bright));
        if amplitude <= 0.0 {
            out.fill(0.0);
            return;
        }
        // The same one-pole as the tilt measurement, so both ends mean roughly
        // the same thing by "above 1 kHz".
        const A: f32 = 0.12;
        for s in out.iter_mut() {
            self.seed = self.seed.wrapping_mul(6364136223846793005).wrapping_add(1);
            let white = (self.seed >> 33) as f32 / (1u64 << 30) as f32 - 1.0;
            self.lp += A * (white - self.lp);
            *s = (1.0 - bright) * self.lp + bright * (white - self.lp);
        }
        // Filtering changes the level by an amount that depends on the tilt, so
        // measure what came out and scale it, rather than carrying a fudge
        // factor that is only right for one setting.
        let made = rms(out);
        if made > 0.0 {
            let gain = amplitude / made;
            for s in out.iter_mut() {
                *s *= gain;
            }
        }
    }
}

/// Decides what to send, and keeps the timestamp advancing while it says no.
pub struct Sender {
    timestamp: u32,
    /// Was the last frame speech?
    was_speaking: bool,
    /// Frames since we last put anything on the wire.
    since_sent: u32,
    /// Frames between comfort descriptors while silent.
    keepalive: u32,
    gate: Gate,
    /// Smoothed level and tilt of the quiet frames seen lately.
    ///
    /// A single frame's RMS wanders by a surprising amount, so describing the
    /// room from whichever frame the keepalive lands on makes the far end step
    /// to a slightly different level once a second. Averaging over the pause
    /// describes the room rather than a moment of it.
    room: Option<(f32, f32)>,
    enabled: bool,
}

impl Sender {
    /// `keepalive_frames` is how long a silent sender may stay off the wire.
    /// Something must go out periodically or the peer cannot tell silence from
    /// a dead session — and with SIP-15 that something also refreshes the
    /// description of the room.
    pub fn new(keepalive_frames: u32, enabled: bool) -> Sender {
        Sender {
            timestamp: 0,
            was_speaking: true,
            since_sent: 0,
            keepalive: keepalive_frames,
            gate: Gate::new(15),
            room: None,
            enabled,
        }
    }

    /// Offer this slot's audio. Returns the frame to send, or `None` to stay
    /// quiet; `encode` is called only when there is something worth encoding.
    ///
    /// Either way the timestamp advances: that is what lets the far end know
    /// how much time passed while nothing arrived.
    pub fn offer(
        &mut self,
        samples: &[f32],
        encode: impl FnOnce(&[f32]) -> Result<Vec<u8>>,
    ) -> Result<Option<Frame>> {
        let timestamp = self.timestamp;
        self.timestamp = self.timestamp.wrapping_add(1);
        self.since_sent += 1;

        let speaking = !self.enabled || self.gate.is_speech(samples);
        if !speaking {
            // Track the room while it is quiet, which is the only time we can
            // actually see it.
            let (level, tilt) = (rms(samples), f32::from(tilt(samples)));
            self.room = Some(match self.room {
                Some((l, t)) => (l + 0.25 * (level - l), t + 0.25 * (tilt - t)),
                None => (level, tilt),
            });
        }
        // The first silent frame after speech opens the run and describes it,
        // so the far end can start making the right noise immediately rather
        // than a second later.
        let opens_silence = !speaking && self.was_speaking;
        let keepalive_due = self.since_sent >= self.keepalive;
        self.was_speaking = speaking;

        if speaking {
            self.since_sent = 0;
            return Ok(Some(Frame::audio(timestamp, encode(samples)?)));
        }
        if opens_silence || keepalive_due {
            self.since_sent = 0;
            let (level, tilt) = self
                .room
                .unwrap_or((rms(samples), f32::from(tilt(samples))));
            return Ok(Some(Frame {
                timestamp,
                body: Body::Comfort(Comfort::from_parts(level, tilt as u8)),
            }));
        }
        Ok(None)
    }

    /// How many media slots have been produced, sent or not.
    pub fn produced(&self) -> u32 {
        self.timestamp
    }

    pub fn gate(&self) -> &Gate {
        &self.gate
    }
}

/// How a receiver should fill the slots between two frames that did arrive.
#[derive(Debug, PartialEq, Eq)]
pub struct Gap {
    /// Slots to conceal: packets that should have come and did not.
    pub lost: u64,
    /// Slots the sender deliberately skipped. Never conceal these.
    pub silent: u64,
}

/// Split the slots between two received frames into loss and silence.
///
/// `prev` and `next` are `(sequence, timestamp)` of two frames that arrived in
/// that order. Sequence counts packets, so a hole in it is loss; timestamp
/// counts time, so a hole in it is either loss or somebody not talking. At most
/// as many slots as there were missing packets can be loss.
pub fn classify(prev: (u64, u32), next: (u64, u32)) -> Gap {
    let (seq_p, ts_p) = prev;
    let (seq_n, ts_n) = next;
    // Wrapping, because the timestamp is a u32 that runs for years and then
    // does not.
    let slots = u64::from(ts_n.wrapping_sub(ts_p).saturating_sub(1));
    let missing_packets = seq_n.saturating_sub(seq_p).saturating_sub(1);
    let lost = missing_packets.min(slots);
    Gap {
        lost,
        silent: slots - lost,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::jitter::FRAME_SAMPLES;

    fn opus_packet() -> Vec<u8> {
        vec![7u8; 65]
    }

    /// A frame of room tone at roughly the level a quiet room sits at.
    fn room(seed: &mut u64, amplitude: f32) -> Vec<f32> {
        (0..FRAME_SAMPLES)
            .map(|_| {
                *seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
                ((*seed >> 33) as f32 / (1u64 << 30) as f32 - 1.0) * amplitude
            })
            .collect()
    }

    fn talking() -> Vec<f32> {
        let mut phase = 0.0f32;
        (0..FRAME_SAMPLES)
            .map(|_| {
                phase = (phase + 0.05) % std::f32::consts::TAU;
                phase.sin() * 0.4
            })
            .collect()
    }

    fn send(s: &mut Sender, samples: &[f32]) -> Option<Frame> {
        s.offer(samples, |_| Ok(opus_packet())).unwrap()
    }

    #[test]
    fn both_frame_types_round_trip() {
        let audio = Frame::audio(70_000, opus_packet());
        assert_eq!(Frame::decode(&audio.encode()).unwrap(), Some(audio));

        let comfort = Frame {
            timestamp: 9,
            body: Body::Comfort(Comfort {
                level: 120,
                tilt: 40,
            }),
        };
        assert_eq!(Frame::decode(&comfort.encode()).unwrap(), Some(comfort));
    }

    /// SIP-15 reserves the type space so a frame can be added later without a
    /// flag day. Keeping that promise means ignoring what we do not know.
    #[test]
    fn an_unknown_frame_type_is_ignored_not_an_error() {
        let mut bytes = Frame::audio(1, opus_packet()).encode();
        bytes[0] = 0x7f;
        assert_eq!(Frame::decode(&bytes).unwrap(), None);
    }

    #[test]
    fn a_frame_of_the_wrong_shape_is_refused() {
        assert!(Frame::decode(&[]).is_err());
        assert!(
            Frame::decode(&[TYPE_AUDIO, 0, 0, 1]).is_err(),
            "short header"
        );
        // A comfort frame is exactly two bytes of body, no more and no less.
        assert!(Frame::decode(&[TYPE_COMFORT, 0, 0, 0, 1, 60]).is_err());
        assert!(Frame::decode(&[TYPE_COMFORT, 0, 0, 0, 1, 60, 40, 0]).is_err());
        assert!(Frame::decode(&[TYPE_COMFORT, 0, 0, 0, 1, 60, 40]).is_ok());
    }

    #[test]
    fn a_level_round_trips_through_its_encoding() {
        let mut seed = 1u64;
        for amplitude in [0.5f32, 0.05, 0.006, 0.0005] {
            let samples = room(&mut seed, amplitude);
            let measured = Comfort::measure(&samples);
            let want = rms(&samples);
            // Below the clamp the amplitude is deliberately not what was
            // measured; above it, it should be close.
            if measured.level > QUIETEST_LOUD {
                let got = measured.amplitude();
                assert!(
                    (got / want).log2().abs() < 0.2,
                    "level {} decoded to {got} from {want}",
                    measured.level
                );
            }
        }
    }

    /// The one field a peer asserts rather than demonstrates, so the clamp is
    /// normative: a byte set to zero must not be a full-scale burst.
    #[test]
    fn comfort_noise_is_never_loud_however_loud_the_peer_claims() {
        for level in [0u8, 1, 30, 59] {
            let c = Comfort { level, tilt: 128 };
            assert!(
                c.amplitude() <= 10f32.powf(-30.0 / 20.0) + 1e-6,
                "level {level} escaped the clamp at {}",
                c.amplitude()
            );
        }
        assert_eq!(
            Comfort {
                level: 255,
                tilt: 0
            }
            .amplitude(),
            0.0,
            "digital silence"
        );
    }

    #[test]
    fn synthesised_noise_settles_on_the_level_it_was_told() {
        let mut pcm = vec![0f32; FRAME_SAMPLES];
        for level in [70u8, 100, 140] {
            let c = Comfort { level, tilt: 60 };
            let mut n = Noise::new();
            // Give it time to glide; the first frame deliberately does not
            // jump to the target.
            for _ in 0..60 {
                n.fill(c, &mut pcm);
            }
            let (want, got) = (c.amplitude(), rms(&pcm));
            assert!(
                (got / want).log2().abs() < 0.5,
                "asked for {want}, settled at {got} (level {level})"
            );
        }
    }

    /// A descriptor arrives about once a second, and a real room's level is not
    /// identical each time. Stepping straight to a new level is a click in the
    /// noise floor, which is what a listener calls choppy.
    #[test]
    fn a_changed_description_is_glided_to_not_stepped_to() {
        let mut n = Noise::new();
        let mut pcm = vec![0f32; FRAME_SAMPLES];
        let quiet = Comfort {
            level: 120,
            tilt: 60,
        };
        for _ in 0..60 {
            n.fill(quiet, &mut pcm);
        }
        let before = rms(&pcm);

        // Now claim the room is four times louder.
        let louder = Comfort {
            level: 96,
            tilt: 60,
        };
        n.fill(louder, &mut pcm);
        let first_step = rms(&pcm);
        assert!(
            first_step < before * 1.5,
            "one frame should not jump: {before} to {first_step}"
        );
        for _ in 0..60 {
            n.fill(louder, &mut pcm);
        }
        assert!(
            (rms(&pcm) / louder.amplitude()).log2().abs() < 0.5,
            "but it should get there"
        );
    }

    /// The gate must not chatter around a single threshold: alternating a real
    /// room with a synthesised one is audible even when the levels match.
    #[test]
    fn the_gate_does_not_chatter_on_a_level_sitting_at_the_threshold() {
        let mut g = Gate::new(2);
        let mut seed = 21u64;
        for _ in 0..Gate::WINDOW {
            g.is_speech(&room(&mut seed, 0.006));
        }
        // Right at the opening threshold, wobbling either side of it.
        let edge = g.floor() * Gate::OPEN * 1.05;
        let mut flips = 0;
        let mut last = false;
        for i in 0..100 {
            let amplitude = if i % 2 == 0 { edge } else { edge * 0.75 };
            let speech = g.is_speech(&room(&mut seed, amplitude * 3f32.sqrt()));
            if speech != last {
                flips += 1;
            }
            last = speech;
        }
        assert!(flips <= 2, "the gate chattered {flips} times");
    }

    #[test]
    fn tilt_tells_a_rumble_from_a_hiss() {
        let mut seed = 5u64;
        let white = room(&mut seed, 0.05);
        let mut lp = 0.0f32;
        let rumble: Vec<f32> = white
            .iter()
            .map(|s| {
                lp += 0.02 * (s - lp);
                lp * 8.0
            })
            .collect();
        assert!(
            tilt(&rumble) < tilt(&white),
            "a low-passed room should read darker: {} vs {}",
            tilt(&rumble),
            tilt(&white)
        );
    }

    #[test]
    fn the_gate_opens_on_speech_and_closes_on_a_room() {
        let mut g = Gate::new(0);
        let mut seed = 3u64;
        // A window of room tone, so it knows what the room is.
        for _ in 0..Gate::WINDOW {
            g.is_speech(&room(&mut seed, 0.006));
        }
        assert!(
            !g.is_speech(&room(&mut seed, 0.006)),
            "room tone is not speech"
        );
        assert!(g.is_speech(&talking()), "a voice is");
        assert!(g.floor() < 0.02, "the floor should have settled low");
    }

    #[test]
    fn hangover_keeps_the_gate_open_between_words() {
        let mut g = Gate::new(15);
        let mut seed = 3u64;
        for _ in 0..Gate::WINDOW {
            g.is_speech(&room(&mut seed, 0.006));
        }
        g.is_speech(&talking());
        // The gap between two words must not close the gate, or word tails and
        // the start of the next one get clipped.
        for i in 0..15 {
            assert!(
                g.is_speech(&room(&mut seed, 0.006)),
                "closed after {i} frames"
            );
        }
        assert!(!g.is_speech(&room(&mut seed, 0.006)), "and then it closes");
    }

    /// A call that opens mid-sentence must not mute the speaker while it works
    /// out what the room is. Until it knows, it sends everything.
    #[test]
    fn speech_from_the_very_first_frame_is_sent() {
        let mut s = Sender::new(50, true);
        for i in 0..10 {
            let f = send(&mut s, &talking()).expect("speech is always sent");
            assert_eq!(f.timestamp, i);
            assert!(matches!(f.body, Body::Audio(_)), "{:?}", f.body);
        }
    }

    /// And a long monologue must not mute it either — the failure of a floor
    /// that follows the level upward.
    #[test]
    fn a_monologue_does_not_gate_itself_off() {
        let mut s = Sender::new(50, true);
        let mut seed = 11u64;
        for _ in 0..Gate::WINDOW {
            send(&mut s, &room(&mut seed, 0.006));
        }
        for i in 0..500 {
            let f = send(&mut s, &talking()).unwrap_or_else(|| panic!("muted at frame {i}"));
            assert!(matches!(f.body, Body::Audio(_)), "described at frame {i}");
        }
    }

    #[test]
    fn speech_is_always_sent_and_the_encoder_only_runs_for_it() {
        let mut s = Sender::new(50, true);
        let mut ran = 0;
        for i in 0..10 {
            let f = s
                .offer(&talking(), |_| {
                    ran += 1;
                    Ok(opus_packet())
                })
                .unwrap()
                .expect("speech is always sent");
            assert_eq!(f.timestamp, i);
            assert!(matches!(f.body, Body::Audio(_)));
        }
        assert_eq!(
            ran, 10,
            "the encoder ran exactly for the frames that went out"
        );
    }

    #[test]
    fn a_pause_is_described_once_and_then_kept_quiet() {
        let mut s = Sender::new(50, true);
        let mut seed = 9u64;
        // A real call opens with the room, which is how the gate learns it.
        for _ in 0..Gate::WINDOW {
            send(&mut s, &room(&mut seed, 0.006));
        }
        for _ in 0..30 {
            send(&mut s, &talking());
        }

        // The gate holds open for its hangover — that is what stops word tails
        // being clipped — and then the first genuinely silent frame describes
        // the room rather than encoding it.
        let mut opener = None;
        for _ in 0..40 {
            if let Some(f) = send(&mut s, &room(&mut seed, 0.006))
                && matches!(f.body, Body::Comfort(_))
            {
                opener = Some(f);
                break;
            }
        }
        let opener = opener.expect("a run opener within the hangover");
        assert!(matches!(opener.body, Body::Comfort(_)), "{:?}", opener.body);

        // Then nothing at all until the keepalive refreshes the description.
        let mut quiet_frames = 0;
        for _ in 0..49 {
            if send(&mut s, &room(&mut seed, 0.006)).is_none() {
                quiet_frames += 1;
            }
        }
        assert_eq!(quiet_frames, 49, "a settled pause costs nothing at all");
        let refresh = send(&mut s, &room(&mut seed, 0.006)).expect("keepalive");
        assert!(matches!(refresh.body, Body::Comfort(_)));
    }

    #[test]
    fn the_timestamp_advances_across_frames_nobody_sent() {
        let mut s = Sender::new(1000, true);
        let mut seed = 9u64;
        for _ in 0..Gate::WINDOW {
            send(&mut s, &room(&mut seed, 0.006));
        }
        for _ in 0..30 {
            send(&mut s, &talking());
        }
        // Ride out the hangover and the opener, then a long quiet stretch.
        let mut quiet = 0;
        for _ in 0..120 {
            if send(&mut s, &room(&mut seed, 0.006)).is_none() {
                quiet += 1;
            }
        }
        assert!(
            quiet > 90,
            "most of a quiet stretch costs nothing, sent {}",
            120 - quiet
        );
        let before = s.produced();
        let back = send(&mut s, &talking()).expect("speech again");
        assert_eq!(
            back.timestamp, before,
            "time passed though nothing was sent"
        );
        assert_eq!(s.produced(), before + 1);
    }

    #[test]
    fn disabled_sends_everything_as_audio() {
        let mut s = Sender::new(50, false);
        let mut seed = 9u64;
        for i in 0..200 {
            let f = send(&mut s, &room(&mut seed, 0.006)).expect("nothing is suppressed");
            assert_eq!(f.timestamp, i);
            assert!(matches!(f.body, Body::Audio(_)), "and never a descriptor");
        }
    }

    #[test]
    fn a_continuous_stream_has_no_gap_at_all() {
        assert_eq!(classify((5, 100), (6, 101)), Gap { lost: 0, silent: 0 });
    }

    #[test]
    fn packets_missing_from_a_continuous_stream_are_loss() {
        assert_eq!(classify((5, 100), (9, 104)), Gap { lost: 3, silent: 0 });
    }

    #[test]
    fn slots_skipped_with_no_packets_missing_are_silence() {
        assert_eq!(
            classify((5, 100), (6, 200)),
            Gap {
                lost: 0,
                silent: 99
            },
            "this is the case that must never be concealed"
        );
    }

    #[test]
    fn a_gap_can_be_both_and_loss_is_bounded_by_the_packets_missing() {
        assert_eq!(
            classify((5, 100), (8, 150)),
            Gap {
                lost: 2,
                silent: 47
            }
        );
    }

    #[test]
    fn the_timestamp_wrapping_does_not_produce_a_two_year_gap() {
        assert_eq!(
            classify((5, u32::MAX - 1), (6, 1)),
            Gap { lost: 0, silent: 2 }
        );
    }
}

/// Measurements, not assertions.
///
/// These answer questions about how the codec and this framing actually behave
/// that no documentation does. `#[ignore]`d so they never gate CI, and kept so
/// nobody has to re-derive the answers. The measurements that rejected SIP-14's
/// design are recorded in SIP-14 itself, which is Replaced — they are not
/// re-runnable against this code and should not be.
///
/// ```text
/// cargo test -p sqex-voice -- --ignored --nocapture
/// ```
#[cfg(test)]
mod probe {
    use super::*;
    use crate::jitter::{FRAME_SAMPLES, Jitter, Playback, Playout, SAMPLE_RATE};

    /// Where does the residual chop in a pause come from?
    ///
    /// `cargo test -p sqex-voice -- --ignored --nocapture chop`
    #[test]
    #[ignore = "reports numbers; run explicitly"]
    fn chop_envelope() {
        let mut enc =
            opus::Encoder::new(SAMPLE_RATE, opus::Channels::Mono, opus::Application::Voip).unwrap();
        enc.set_bitrate(opus::Bitrate::Bits(24_000)).unwrap();
        enc.set_dtx(false).unwrap();
        let mut sender = Sender::new(50, true);
        let mut seed = 0x2545_F491_4F6C_DD1Du64;
        let mut phase = 0.0f32;
        let step = std::f32::consts::TAU * 440.0 / SAMPLE_RATE as f32;
        let mut buffer = Jitter::new(3);
        let mut seq = 0u64;
        let mut kinds: Vec<char> = Vec::new();

        for i in 0..500 {
            let pcm: Vec<f32> = (0..FRAME_SAMPLES)
                .map(|_| {
                    seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
                    let noise = ((seed >> 33) as f32 / (1u64 << 30) as f32 - 1.0) * 0.006;
                    let s = if (150..250).contains(&i) {
                        phase.sin() * 0.5 + noise
                    } else {
                        noise
                    };
                    phase = (phase + step) % std::f32::consts::TAU;
                    s
                })
                .collect();
            let framed = sender
                .offer(&pcm, |p| {
                    enc.encode_vec_float(p, 1024)
                        .map_err(|e| Error::Malformed(format!("{e}")))
                })
                .unwrap();
            match framed {
                Some(f) => {
                    kinds.push(match &f.body {
                        Body::Audio(_) => 'A',
                        Body::Comfort(c) => {
                            if i > 320 {
                                print!(" [lvl {} tilt {}]", c.level, c.tilt);
                            }
                            'C'
                        }
                    });
                    buffer.push(seq, f.timestamp, f.body);
                    seq += 1;
                }
                None => kinds.push('.'),
            }
        }
        println!();

        let mut playback = Playback::new(SAMPLE_RATE).unwrap();
        let mut pcm = vec![0f32; FRAME_SAMPLES];
        let mut levels = Vec::new();
        loop {
            let slot = buffer.pop();
            if !playback.render(&slot, &mut pcm) {
                break;
            }
            levels.push(rms(&pcm));
        }

        println!("\n  what the sender did, slots 300-420:");
        println!(
            "    {}",
            kinds[300..420.min(kinds.len())].iter().collect::<String>()
        );
        let pause = &levels[330..levels.len().saturating_sub(5)];
        let (lo, hi) = pause
            .iter()
            .fold((f32::MAX, 0.0f32), |(l, h), x| (l.min(*x), h.max(*x)));
        let jump: f32 =
            pause.windows(2).map(|w| (w[1] - w[0]).abs()).sum::<f32>() / (pause.len() - 1) as f32;
        println!(
            "  heard in the pause: mean {:.5} range {lo:.5}-{hi:.5} ({:.1}x), mean step {jump:.5}",
            pause.iter().sum::<f32>() / pause.len() as f32,
            hi / lo
        );
        let show: Vec<String> = pause[..40].iter().map(|x| format!("{x:.4}")).collect();
        println!("    {}\n", show.join(" "));
    }

    /// What SIP-15 costs and what it sounds like, end to end through the real
    /// gate, encoder, buffer and synthesiser.
    ///
    /// `cargo test -p sqex-voice -- --ignored --nocapture sip15`
    #[test]
    #[ignore = "reports numbers; run explicitly"]
    fn sip15_cost_and_envelope() {
        let mut enc =
            opus::Encoder::new(SAMPLE_RATE, opus::Channels::Mono, opus::Application::Voip).unwrap();
        enc.set_bitrate(opus::Bitrate::Bits(24_000)).unwrap();
        enc.set_dtx(false).unwrap();
        let mut sender = Sender::new(50, true);

        // Two seconds of talking, then ten of a quiet room — a real pause has a
        // noise floor, and that is the case every synthetic test gets wrong.
        let mut seed = 0x2545_F491_4F6C_DD1Du64;
        let mut phase = 0.0f32;
        let step = std::f32::consts::TAU * 440.0 / SAMPLE_RATE as f32;
        let mut buffer = Jitter::new(3);
        let mut seq = 0u64;
        let (mut sent, mut described) = (0u32, 0u32);

        for i in 0..600 {
            let pcm: Vec<f32> = (0..FRAME_SAMPLES)
                .map(|_| {
                    seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
                    let noise = ((seed >> 33) as f32 / (1u64 << 30) as f32 - 1.0) * 0.006;
                    let s = if i < 100 {
                        phase.sin() * 0.5 + noise
                    } else {
                        noise
                    };
                    phase = (phase + step) % std::f32::consts::TAU;
                    s
                })
                .collect();
            let framed = sender
                .offer(&pcm, |p| {
                    enc.encode_vec_float(p, 1024)
                        .map_err(|e| Error::Malformed(format!("{e}")))
                })
                .unwrap();
            if let Some(f) = framed {
                sent += 1;
                if matches!(f.body, Body::Comfort(_)) {
                    described += 1;
                }
                buffer.push(seq, f.timestamp, f.body);
                seq += 1;
            }
        }

        let mut playback = Playback::new(SAMPLE_RATE).unwrap();
        let mut pcm = vec![0f32; FRAME_SAMPLES];
        let mut levels = Vec::new();
        loop {
            let slot = buffer.pop();
            if matches!(slot, Playout::Idle) {
                break;
            }
            playback.render(&slot, &mut pcm);
            levels.push(rms(&pcm));
        }

        let pause = &levels[150..];
        let (lo, hi) = pause
            .iter()
            .fold((f32::MAX, 0.0f32), |(l, h), x| (l.min(*x), h.max(*x)));
        println!(
            "\n  SIP-15 over 600 slots (2 s speech, 10 s pause):\n                 sent {sent} packets ({described} of them descriptors); continuous would send 600\n                 pause heard: mean {:.4} range {lo:.4}-{hi:.4} (true floor 0.0035), \
             dead frames {}/{}\n",
            pause.iter().sum::<f32>() / pause.len() as f32,
            pause.iter().filter(|x| **x < 0.0005).count(),
            pause.len()
        );
    }
}
