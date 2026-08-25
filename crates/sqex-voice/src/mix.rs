//! Summing several people into one pair of ears.
//!
//! In a room each peer arrives as its own stream — its own session key, its own
//! jitter buffer, its own decoder — and something has to add them together
//! before they reach a speaker. That something is here, and it is small: mixing
//! is addition, and the only real decision is what to do about the fact that
//! addition overflows.
//!
//! # Why the gain moves with the number of talkers and not with the peaks
//!
//! Two people at full scale sum to twice full scale. The obvious fix — scale
//! each frame by its own peak — is the wrong one: the gain then changes twenty
//! times a second, and every time someone starts or stops talking the whole
//! room audibly ducks and swells around them. That pumping is more distracting
//! than the clipping it avoids.
//!
//! So the gain follows the number of *active* streams instead, at
//! `1/sqrt(active)`. That is the equal-power rule, and it is right because
//! separate people are not correlated: two independent voices sum in power
//! rather than in amplitude, so dividing by `sqrt(n)` holds the mix at about
//! the level of one of them. It changes only when someone joins or leaves, and
//! it is the same for everyone in the frame, so nobody is ducked to make room
//! for anybody else.
//!
//! The clamp is a real backstop rather than decoration. Two *correlated*
//! signals at full scale — the same tone twice, or one person's audio somehow
//! arriving down two paths — sum in amplitude, and `1.6 / sqrt(2)` is 1.13,
//! which clips. Speech from different people in a room does not do this, but
//! the mixer does not get to assume that.

/// Adds streams together for one 20 ms slot.
///
/// Reused across slots rather than reallocated: this runs fifty times a second
/// for the life of a call.
pub struct Mixer {
    acc: Vec<f32>,
    active: usize,
}

impl Mixer {
    pub fn new(samples: usize) -> Mixer {
        Mixer {
            acc: vec![0.0; samples],
            active: 0,
        }
    }

    /// Begin a slot.
    pub fn start(&mut self) {
        self.acc.fill(0.0);
        self.active = 0;
    }

    /// Add one peer's audio. A stream that is silent still counts as active —
    /// a pause in speech is not an absence, and letting the gain jump every
    /// time somebody draws breath is exactly the pumping this avoids.
    pub fn add(&mut self, samples: &[f32]) {
        for (a, s) in self.acc.iter_mut().zip(samples) {
            *a += s;
        }
        self.active += 1;
    }

    /// How many streams went into this slot.
    pub fn active(&self) -> usize {
        self.active
    }

    /// The finished slot: attenuated for the number of talkers, and clamped.
    pub fn finish(&mut self) -> &[f32] {
        if self.active > 1 {
            let gain = 1.0 / (self.active as f32).sqrt();
            for a in self.acc.iter_mut() {
                *a *= gain;
            }
        }
        for a in self.acc.iter_mut() {
            *a = a.clamp(-1.0, 1.0);
        }
        &self.acc
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audio::rms;

    fn constant(v: f32, n: usize) -> Vec<f32> {
        vec![v; n]
    }

    #[test]
    fn one_talker_comes_through_untouched() {
        let mut m = Mixer::new(4);
        m.start();
        m.add(&constant(0.5, 4));
        assert_eq!(m.finish(), &[0.5, 0.5, 0.5, 0.5]);
    }

    #[test]
    fn nobody_talking_is_silence_not_a_divide_by_zero() {
        let mut m = Mixer::new(4);
        m.start();
        assert_eq!(m.finish(), &[0.0; 4]);
        assert_eq!(m.active(), 0);
    }

    /// The case the gain rule is actually for: separate people, which means
    /// uncorrelated signals.
    #[test]
    fn three_loud_but_unrelated_talkers_do_not_clip() {
        let n = crate::jitter::FRAME_SAMPLES;
        let voices: Vec<Vec<f32>> = [440.0, 660.0, 887.0]
            .iter()
            .map(|hz| crate::audio::tone_at(*hz, 1).remove(0))
            .collect();
        assert!(voices.iter().all(|v| rms(v) > 0.3), "each is loud");

        let mut m = Mixer::new(n);
        m.start();
        for v in &voices {
            m.add(v);
        }
        let out = m.finish();
        let clipped = out.iter().filter(|s| s.abs() >= 0.999).count();
        assert_eq!(clipped, 0, "equal-power gain should have been enough");
        // And the room is about as loud as one person in it, which is the
        // whole point of the rule.
        assert!(
            (rms(out) - rms(&voices[0])).abs() < 0.1,
            "mix {} vs one voice {}",
            rms(out),
            rms(&voices[0])
        );
    }

    /// And the case it is not for, stated so nobody later mistakes the clamp
    /// for dead code.
    #[test]
    fn correlated_signals_at_full_scale_still_reach_the_clamp() {
        let mut m = Mixer::new(4);
        m.start();
        m.add(&constant(0.8, 4));
        m.add(&constant(0.8, 4));
        let out = m.finish();
        // 1.6 summed, 1.13 after equal-power gain, clamped to 1.0. Two
        // independent voices would not have done this; the same one twice does.
        assert!(out.iter().all(|s| (*s - 1.0).abs() < 1e-6), "{out:?}");
    }

    #[test]
    fn everyone_is_attenuated_by_the_same_amount() {
        let mut m = Mixer::new(2);
        m.start();
        m.add(&[0.4, 0.0]);
        m.add(&[0.0, 0.4]);
        m.add(&[0.0, 0.0]);
        let out = m.finish();
        assert!(
            (out[0] - out[1]).abs() < 1e-6,
            "nobody is ducked to make room for anybody else"
        );
    }

    #[test]
    fn the_clamp_is_a_backstop_and_still_holds() {
        let mut m = Mixer::new(2);
        m.start();
        for _ in 0..2 {
            m.add(&[1.0, -1.0]);
        }
        let out = m.finish();
        assert!(out.iter().all(|s| (-1.0..=1.0).contains(s)), "{out:?}");
    }

    #[test]
    fn the_gain_does_not_move_when_a_talker_merely_pauses() {
        let n = 480;
        let mut m = Mixer::new(n);

        m.start();
        m.add(&constant(0.5, n));
        m.add(&constant(0.5, n));
        let both_talking = rms(m.finish());

        // Same two peers; one of them has stopped making noise for a moment.
        // Its stream is still there, so the gain must not change.
        m.start();
        m.add(&constant(0.5, n));
        m.add(&constant(0.0, n));
        let one_quiet = rms(m.finish());

        assert!(
            (one_quiet - both_talking / 2.0).abs() < 1e-5,
            "the remaining talker changed level: {both_talking} then {one_quiet}"
        );
    }
}
