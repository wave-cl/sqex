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

/// Bytes of media header in front of each codec packet.
pub const HEADER: usize = 4;

/// A packet this short is the codec saying it has nothing worth sending.
///
/// It is what libopus reports rather than something negotiated, and a packet
/// that short cannot be speech.
pub const DTX_MAX: usize = 2;

/// One media frame as it travels inside a SIP-12 frame.
///
/// `| timestamp: u32 | payload |`
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    /// Which 20 ms slot this audio belongs in, counted from an arbitrary
    /// origin. Advances for every frame the sender produced, including the ones
    /// it decided not to send.
    pub timestamp: u32,
    /// One codec packet.
    pub payload: Vec<u8>,
}

impl Frame {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(HEADER + self.payload.len());
        out.extend_from_slice(&self.timestamp.to_be_bytes());
        out.extend_from_slice(&self.payload);
        out
    }

    pub fn decode(b: &[u8]) -> Result<Frame> {
        if b.len() < HEADER {
            return Err(Error::Malformed(format!(
                "media frame is {} bytes, want at least {HEADER}",
                b.len()
            )));
        }
        Ok(Frame {
            timestamp: u32::from_be_bytes(b[..HEADER].try_into().unwrap()),
            payload: b[HEADER..].to_vec(),
        })
    }
}

/// Decides what to send, and keeps the timestamp advancing while it says no.
pub struct Sender {
    timestamp: u32,
    /// Was the last frame we produced one the codec wanted sent?
    was_speaking: bool,
    /// Frames since we last put anything on the wire.
    since_sent: u32,
    /// Frames between forced transmissions while silent.
    keepalive: u32,
    enabled: bool,
}

impl Sender {
    /// `keepalive_frames` is how long a silent sender may stay off the wire.
    /// Something must go out periodically or the peer cannot tell silence from
    /// a dead session.
    pub fn new(keepalive_frames: u32, enabled: bool) -> Sender {
        Sender {
            timestamp: 0,
            was_speaking: true,
            since_sent: 0,
            keepalive: keepalive_frames,
            enabled,
        }
    }

    /// Offer the codec's output for this slot; get back the frame to send, or
    /// `None` to stay quiet.
    ///
    /// Either way the timestamp advances: that is what lets the far end know how
    /// much time passed while nothing arrived.
    pub fn offer(&mut self, packet: Vec<u8>) -> Option<Frame> {
        let timestamp = self.timestamp;
        self.timestamp = self.timestamp.wrapping_add(1);
        self.since_sent += 1;

        let speaking = packet.len() > DTX_MAX;
        // The first short packet after speech opens a silent run, and carries
        // the codec's description of what that silence sounds like. Sending it
        // is what lets the far end play comfort noise instead of a hole.
        let opens_silence = !speaking && self.was_speaking;
        let keepalive_due = self.since_sent >= self.keepalive;
        self.was_speaking = speaking;

        if !self.enabled || speaking || opens_silence || keepalive_due {
            self.since_sent = 0;
            Some(Frame { timestamp, payload: packet })
        } else {
            None
        }
    }

    /// How many media slots have been produced, sent or not.
    pub fn produced(&self) -> u32 {
        self.timestamp
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

    fn speech() -> Vec<u8> {
        vec![7u8; 65]
    }
    fn quiet() -> Vec<u8> {
        vec![0u8; 1]
    }

    #[test]
    fn a_frame_round_trips_and_a_stub_is_refused() {
        let f = Frame { timestamp: 70_000, payload: speech() };
        assert_eq!(Frame::decode(&f.encode()).unwrap(), f);
        // A frame carrying only a header is legal: an empty codec packet.
        assert!(Frame::decode(&[0, 0, 0, 1]).is_ok());
        assert!(Frame::decode(&[0, 0, 1]).is_err());
        assert!(Frame::decode(&[]).is_err());
    }

    #[test]
    fn speech_always_goes_out() {
        let mut s = Sender::new(50, true);
        for i in 0..10 {
            let f = s.offer(speech()).expect("speech is always sent");
            assert_eq!(f.timestamp, i);
        }
    }

    #[test]
    fn silence_goes_quiet_after_one_frame_of_comfort_noise() {
        let mut s = Sender::new(50, true);
        s.offer(speech()).unwrap();

        // The first quiet frame still goes: it opens the run and describes it.
        let opener = s.offer(quiet()).expect("the run opener is sent");
        assert_eq!(opener.timestamp, 1);
        assert_eq!(opener.payload, quiet());

        // And then nothing until the keepalive, which falls on the 50th frame
        // after the last transmission — the opener reset the counter.
        for i in 1..50 {
            assert!(s.offer(quiet()).is_none(), "frame {i} should stay quiet");
        }
        assert!(s.offer(quiet()).is_some(), "the 50th is the keepalive");
    }

    #[test]
    fn the_timestamp_advances_across_frames_nobody_sent() {
        let mut s = Sender::new(1000, true);
        s.offer(speech()).unwrap();
        s.offer(quiet()).unwrap(); // opener
        for _ in 0..100 {
            assert!(s.offer(quiet()).is_none());
        }
        let back = s.offer(speech()).expect("speech again");
        assert_eq!(
            back.timestamp, 102,
            "time passed even though nothing was sent"
        );
        assert_eq!(s.produced(), 103);
    }

    #[test]
    fn a_new_silent_run_opens_again() {
        let mut s = Sender::new(1000, true);
        s.offer(speech()).unwrap();
        assert!(s.offer(quiet()).is_some(), "first run opens");
        assert!(s.offer(quiet()).is_none());
        s.offer(speech()).unwrap();
        assert!(s.offer(quiet()).is_some(), "second run opens too");
    }

    #[test]
    fn disabled_sends_everything() {
        let mut s = Sender::new(50, false);
        s.offer(speech()).unwrap();
        for i in 0..200 {
            let f = s.offer(quiet()).expect("nothing is suppressed");
            assert_eq!(f.timestamp, i + 1);
        }
    }

    /// The bug a live ear caught and the tests did not: rendering a pause as
    /// digital zeros chops the room's noise floor in and out fifty times a
    /// second. A microphone is never digitally silent, so a pause is a low
    /// noise floor — and cutting that to nothing and back is what "choppy"
    /// sounds like.
    ///
    /// Measured against a real encoder and decoder, so it fails if either the
    /// rendering or the codec's behaviour changes.
    #[test]
    fn a_pause_is_rendered_without_cutting_the_noise_floor() {
        use crate::jitter::{FRAME_SAMPLES, SAMPLE_RATE};
        let rms = |s: &[f32]| (s.iter().map(|x| x * x).sum::<f32>() / s.len() as f32).sqrt();

        let mut enc =
            opus::Encoder::new(SAMPLE_RATE, opus::Channels::Mono, opus::Application::Voip).unwrap();
        enc.set_bitrate(opus::Bitrate::Bits(24_000)).unwrap();
        enc.set_dtx(true).unwrap();
        let mut sender = Sender::new(50, true);

        // Speech, then a quiet room — not digital silence, which is the whole
        // point: a real pause has a noise floor.
        let mut seed = 0x2545_F491_4F6C_DD1Du64;
        let mut phase = 0.0f32;
        let step = std::f32::consts::TAU * 440.0 / SAMPLE_RATE as f32;
        let mut slots: Vec<Option<Vec<u8>>> = Vec::new();
        for i in 0..200 {
            let pcm: Vec<f32> = (0..FRAME_SAMPLES)
                .map(|_| {
                    seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
                    let noise = ((seed >> 33) as f32 / (1u64 << 30) as f32 - 1.0) * 0.006;
                    let s = if i < 50 { phase.sin() * 0.5 + noise } else { noise };
                    phase = (phase + step) % std::f32::consts::TAU;
                    s
                })
                .collect();
            let packet = enc.encode_vec_float(&pcm, 1024).unwrap();
            slots.push(sender.offer(packet).map(|f| f.payload));
        }

        // Render the way the call loop does: every slot reaches the decoder.
        let mut dec = opus::Decoder::new(SAMPLE_RATE, opus::Channels::Mono).unwrap();
        let mut pcm = vec![0f32; FRAME_SAMPLES];
        let levels: Vec<f32> = slots
            .iter()
            .map(|slot| {
                dec.decode_float(slot.as_deref().unwrap_or(&[]), &mut pcm, false)
                    .unwrap();
                rms(&pcm)
            })
            .collect();

        let pause = &levels[60..190];
        let dead = pause.iter().filter(|x| **x < 0.0005).count();
        assert_eq!(
            dead, 0,
            "a pause must not contain digitally dead frames; {dead} of {} were silent, \
             which is the chop",
            pause.len()
        );
    }

    #[test]
    fn a_continuous_stream_has_no_gap_at_all() {
        assert_eq!(classify((5, 100), (6, 101)), Gap { lost: 0, silent: 0 });
    }

    #[test]
    fn packets_missing_from_a_continuous_stream_are_loss() {
        // Three slots passed and three packets went missing: all loss.
        assert_eq!(classify((5, 100), (9, 104)), Gap { lost: 3, silent: 0 });
    }

    #[test]
    fn slots_skipped_with_no_packets_missing_are_silence() {
        // A hundred slots passed and not one packet was lost: nobody spoke.
        assert_eq!(
            classify((5, 100), (6, 200)),
            Gap { lost: 0, silent: 99 },
            "this is the case that must never be concealed"
        );
    }

    #[test]
    fn a_gap_can_be_both_and_loss_is_bounded_by_the_packets_missing() {
        // Fifty slots passed; two packets vanished. At most two can be loss.
        assert_eq!(classify((5, 100), (8, 150)), Gap { lost: 2, silent: 47 });
    }

    #[test]
    fn the_timestamp_wrapping_does_not_produce_a_two_year_gap() {
        let g = classify((5, u32::MAX - 1), (6, 1));
        assert_eq!(g, Gap { lost: 0, silent: 2 });
    }
}

#[cfg(test)]
mod probe {
    use crate::jitter::{FRAME_SAMPLES, SAMPLE_RATE};

    /// The real thing: a speech-then-silence stream put through the actual
    /// transmit policy, decoded two ways, so the envelopes can be compared.
    ///
    /// `cargo test -p sqex-voice -- --ignored --nocapture envelope`
    #[test]
    #[ignore = "reports numbers; run explicitly"]
    fn silence_envelope_zeros_versus_decoding() {
        use crate::media::{DTX_MAX, Sender};
        let rms = |s: &[f32]| (s.iter().map(|x| x * x).sum::<f32>() / s.len() as f32).sqrt();

        let mut enc =
            opus::Encoder::new(SAMPLE_RATE, opus::Channels::Mono, opus::Application::Voip).unwrap();
        enc.set_bitrate(opus::Bitrate::Bits(24_000)).unwrap();
        enc.set_dtx(true).unwrap();
        let mut sender = Sender::new(50, true);

        // 1 s of tone, then 3 s of a quiet room.
        const NOISE: f32 = 0.006;
        let mut seed = 0x2545_F491_4F6C_DD1Du64;
        let mut phase = 0.0f32;
        let step = std::f32::consts::TAU * 440.0 / SAMPLE_RATE as f32;
        let mut slots: Vec<Option<Vec<u8>>> = Vec::new();
        let mut sizes: Vec<usize> = Vec::new();
        for i in 0..200 {
            // A real microphone is never digitally silent. "As silent as
            // possible" is a room's noise floor: breathing, a fan, the
            // preamp's own hiss. This is what the encoder actually sees.
            let pcm: Vec<f32> = (0..FRAME_SAMPLES)
                .map(|_| {
                    seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
                    let noise = ((seed >> 33) as f32 / (1u64 << 30) as f32 - 1.0) * NOISE;
                    let s = if i < 50 { phase.sin() * 0.5 + noise } else { noise };
                    phase = (phase + step) % std::f32::consts::TAU;
                    s
                })
                .collect();
            let packet = enc.encode_vec_float(&pcm, 1024).unwrap();
            match sender.offer(packet) {
                Some(f) => {
                    sizes.push(f.payload.len());
                    slots.push(Some(f.payload));
                }
                None => slots.push(None),
            }
        }
        let sent_in_pause = slots[60..].iter().filter(|s| s.is_some()).count();
        let big_in_pause = slots[60..]
            .iter()
            .filter(|s| s.as_ref().is_some_and(|p| p.len() > DTX_MAX))
            .count();
        println!(
            "\n  during the pause: {sent_in_pause} packets sent, of which {big_in_pause} \
             were full-size comfort-noise updates"
        );

        let envelope = |zeros_on_silence: bool| -> Vec<f32> {
            let mut d = opus::Decoder::new(SAMPLE_RATE, opus::Channels::Mono).unwrap();
            let mut pcm = vec![0f32; FRAME_SAMPLES];
            slots
                .iter()
                .map(|slot| match slot {
                    Some(p) => {
                        d.decode_float(p, &mut pcm, false).unwrap();
                        rms(&pcm)
                    }
                    None if zeros_on_silence => 0.0,
                    None => {
                        d.decode_float(&[], &mut pcm, false).unwrap();
                        rms(&pcm)
                    }
                })
                .collect()
        };
        // "Choppy" is exactly frame-to-frame jumps in level, so measure that.
        let report = |label: &str, v: &[f32]| {
            let pause = &v[60..190];
            let mean = pause.iter().sum::<f32>() / pause.len() as f32;
            let jump: f32 = pause.windows(2).map(|w| (w[1] - w[0]).abs()).sum::<f32>()
                / (pause.len() - 1) as f32;
            let silent_frames = pause.iter().filter(|x| **x < 0.0005).count();
            println!(
                "  {label}  mean {mean:.4}  mean frame-to-frame jump {jump:.4}  \
                 dead-silent frames {silent_frames}/{}",
                pause.len()
            );
            let s: Vec<String> = v[60..85].iter().map(|x| format!("{x:.3}")).collect();
            println!("      first 25 of the pause: {}", s.join(" "));
        };
        report("zeros on silence (ships now):", &envelope(true));
        report("decode every slot:          ", &envelope(false));
        println!();
    }

    /// What does a decoder produce for a slot with no packet, and does it
    /// depend on what it last heard?
    ///
    /// This decides how silence should be rendered. Reports rather than
    /// asserts: `cargo test -p sqex-voice -- --ignored --nocapture cng`
    #[test]
    #[ignore = "reports numbers; run explicitly"]
    fn cng_after_speech_versus_after_dtx() {
        let rms = |s: &[f32]| (s.iter().map(|x| x * x).sum::<f32>() / s.len() as f32).sqrt();

        let mut enc =
            opus::Encoder::new(SAMPLE_RATE, opus::Channels::Mono, opus::Application::Voip).unwrap();
        enc.set_bitrate(opus::Bitrate::Bits(24_000)).unwrap();
        enc.set_dtx(true).unwrap();
        let mut phase = 0.0f32;
        let step = std::f32::consts::TAU * 440.0 / SAMPLE_RATE as f32;
        let mut speech = |n: usize| -> Vec<Vec<u8>> {
            (0..n)
                .map(|_| {
                    let pcm: Vec<f32> = (0..FRAME_SAMPLES)
                        .map(|_| {
                            let s = phase.sin() * 0.5;
                            phase = (phase + step) % std::f32::consts::TAU;
                            s
                        })
                        .collect();
                    enc.encode_vec_float(&pcm, 1024).unwrap()
                })
                .collect()
        };
        let talk = speech(30);
        // Now feed it silence until it starts emitting DTX packets.
        let mut cn = Vec::new();
        for _ in 0..40 {
            cn.push(enc.encode_vec_float(&vec![0.0; FRAME_SAMPLES], 1024).unwrap());
        }
        let cn_packet = cn.iter().rev().find(|p| p.len() <= super::DTX_MAX).cloned();
        println!("\n  a DTX packet was produced: {}", cn_packet.is_some());

        let mut pcm = vec![0f32; FRAME_SAMPLES];

        // A: null-decode straight after speech — this is packet loss.
        let mut d = opus::Decoder::new(SAMPLE_RATE, opus::Channels::Mono).unwrap();
        for p in &talk {
            d.decode_float(p, &mut pcm, false).unwrap();
        }
        let mut after_speech = Vec::new();
        for _ in 0..25 {
            d.decode_float(&[], &mut pcm, false).unwrap();
            after_speech.push(rms(&pcm));
        }

        // B: null-decode after a DTX packet — this is a pause.
        let mut d = opus::Decoder::new(SAMPLE_RATE, opus::Channels::Mono).unwrap();
        for p in &talk {
            d.decode_float(p, &mut pcm, false).unwrap();
        }
        if let Some(p) = &cn_packet {
            d.decode_float(p, &mut pcm, false).unwrap();
            println!("  decoding the DTX packet itself gives rms {:.4}", rms(&pcm));
        }
        let mut after_dtx = Vec::new();
        for _ in 0..25 {
            d.decode_float(&[], &mut pcm, false).unwrap();
            after_dtx.push(rms(&pcm));
        }

        let show = |label: &str, v: &[f32]| {
            let head: Vec<String> = v[..8].iter().map(|x| format!("{x:.4}")).collect();
            println!(
                "  {label}: first 8 {:?}  … last {:.4}",
                head,
                v.last().unwrap()
            );
        };
        show("null-decode after SPEECH (loss) ", &after_speech);
        show("null-decode after DTX    (pause)", &after_dtx);
        println!("  digital zeros would be     : 0.0000\n");
    }
}
