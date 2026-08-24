//! Shared types for sqex: keys, and the signed admin-command protocol.
//!
//! This crate has no networking. It defines what an administrator signs and how
//! the server checks it, so that the daemon and any client (a test signer, the
//! YubiKey desktop app) agree on the bytes.

pub mod error;
pub mod key;
pub mod protocol;

pub use error::{Error, Result};
pub use key::PubKey;
pub use protocol::{Action, Command, Nonce, SIG_CONTEXT, SignedCommand, Signer, SoftwareSigner};

/// Crate version, surfaced in server status.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
