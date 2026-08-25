//! The pieces a relayed voice call needs and SIP-12 deliberately does not
//! provide: a codec, a jitter buffer, loss concealment, and somewhere for the
//! sound to come from and go to.
//!
//! These live in a library rather than in the binary so that an integration
//! test can drive a whole call — tone in, Opus out, through a real `sqexd`,
//! back to audio — without a microphone, a speaker, or a person.
//!
//! For more than two people there is [`room`] (SIP-13), which is a roster and
//! a mesh of ordinary two-party sessions rather than anything new, and [`mix`],
//! which adds the resulting streams back together.
//!
//! See `src/main.rs` for the calls themselves.

pub mod audio;
pub mod jitter;
pub mod media;
pub mod mix;
pub mod room;
