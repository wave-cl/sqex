//! The one error type shared across sqex.

use thiserror::Error;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Error)]
pub enum Error {
    #[error("key: {0}")]
    Key(String),

    #[error("malformed message: {0}")]
    Malformed(String),

    #[error("signature verification failed")]
    BadSignature,

    /// The nonce in a signed command was unknown, already used, or expired.
    #[error("challenge invalid or expired")]
    BadChallenge,

    /// The command was signed for a different server than this one.
    #[error("command was not addressed to this server")]
    WrongServer,

    /// The signer's key is not in the configured admin list.
    #[error("signer is not an authorized administrator")]
    NotAdmin,
}
