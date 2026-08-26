//! A terminal chat client for sqex: end-to-end encrypted direct messages.
//!
//! The exchange sees ordering, membership and retention. It does not see a
//! message, and it cannot: every entry in a direct message is sealed under an
//! epoch key that never leaves the two parties' devices.
//!
//! # The split
//!
//! - [`store`] is the client's memory, and the part with the design in it. An
//!   epoch key arrives sealed against a one-time prekey and opening it spends
//!   that prekey, so the copy written to disk is the only one that will exist
//!   tomorrow.
//! - [`client`] is the protocol: publishing prekeys, distributing epoch keys,
//!   posting and fetching.
//! - `ui` renders, and is deliberately given no I/O of its own.
//!
//! # What this deliberately does not do
//!
//! Direct messages only. A direct message's identifier derives from the two
//! accounts (SIP-16), so starting one needs nothing from the exchange — but
//! there is no route that answers *"which channels am I in"*, so a private
//! group channel cannot be discovered at all and is out of scope here. The
//! consequence for direct messages is narrower but real, and stated where a
//! person will meet it: a message from an account not in the contact list
//! cannot be seen, because nothing tells the client to look for it.

pub mod attach;
pub mod client;
pub mod store;

pub use attach::{Prepared, describe, file_name, kind_of};
pub use client::{Chat, ChatError, Conversation};
pub use store::{Contact, Store, StoreError};
