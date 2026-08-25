//! The pieces a relayed voice call needs and SIP-12 deliberately does not
//! provide: a codec, a jitter buffer, loss concealment, and somewhere for the
//! sound to come from and go to.
//!
//! These live in a library rather than in the binary so that an integration
//! test can drive a whole call — tone in, Opus out, through a real `sqexd`,
//! back to audio — without a microphone, a speaker, or a person.
//!
//! See `src/main.rs` for the call itself.

pub mod audio;
pub mod jitter;
