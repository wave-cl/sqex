//! The sqex server, as a library so tests and supervisors can drive it.

pub mod admission;
pub mod beacon;
pub mod challenge;
pub mod channel;
pub mod config;
pub mod device;
pub mod events;
pub mod mailbox;
pub mod peer_client;
pub mod prekey;
pub mod profile;
pub mod replica;
pub mod resolve;
pub mod room;
pub mod server;
pub mod session;
pub mod state;

pub use config::Config;
pub use server::{Bound, Server, bind, serve};
