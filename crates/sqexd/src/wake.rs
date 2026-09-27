//! SIP-45: wakes for devices that cannot hold a stream.
//!
//! When an event would go to an account, each of its devices with an
//! endpoint and no stream of its own is posted a content-free wake -- one
//! per device per `WAKE_MIN_SECS` while it stays away, a ring excepted.
//! The posting happens on a task of its own: the stream an event is also
//! written to never waits on somebody else's push distributor.

use std::sync::{Arc, Weak};
use std::time::Duration;

use sqex_proto::events::Event;
use sqex_proto::wake::{WAKE_BODY, WAKE_MIN_SECS, WAKE_TIMEOUT_SECS};
use sqnr_core::PubKey;
use tokio::sync::mpsc;

use crate::server::Server;
use crate::state::now_unix;

/// What `tell` hands the waker: who was told, and whether it was a ring.
pub struct Told {
    /// Accounts. Every device of each of them is woken, as SIP-45 has it.
    pub accounts: Vec<PubKey>,
    /// SIP-51: devices, named one by one. An event addressed to a single
    /// device wakes that device; its siblings are not parties to the session
    /// it is about, and a wake they can do nothing with is a wake nobody
    /// asked for.
    pub devices: Vec<PubKey>,
    pub urgent: bool,
}

/// Whether an event is one a device should be woken for at once.
pub fn urgent(event: &Event) -> bool {
    matches!(event, Event::Ringing { .. } | Event::CrossCall { .. })
}

/// Whether an event is one a sleeping device should be woken for at all.
/// A signal or a cursor is momentary -- a phone woken for "somebody is
/// typing" arrives to find nothing -- and a heartbeat or a resync is about
/// the stream itself, which an absent device does not hold. A ring is
/// raised as its own event beside the signal that carried it.
pub fn wakes(event: &Event) -> bool {
    !matches!(
        event,
        Event::Signal { .. }
            | Event::Cursor { .. }
            | Event::Heartbeat
            | Event::Resync
            | Event::Unknown(_)
    )
}

/// The waker's handle: `tell` sends here and forgets.
#[derive(Clone)]
pub struct Waker {
    tx: mpsc::UnboundedSender<Told>,
}

impl Waker {
    pub fn tell(&self, accounts: &[PubKey], event: &Event) {
        if accounts.is_empty() || !wakes(event) {
            return;
        }
        let _ = self.tx.send(Told {
            accounts: accounts.to_vec(),
            devices: Vec::new(),
            urgent: urgent(event),
        });
    }

    /// SIP-51: wake one device, and none of its siblings.
    pub fn tell_device(&self, device: &PubKey, event: &Event) {
        if !wakes(event) {
            return;
        }
        let _ = self.tx.send(Told {
            accounts: Vec::new(),
            devices: vec![*device],
            urgent: urgent(event),
        });
    }
}

/// Start the waker. `allow_loopback_http` is for tests, which stand a
/// listener up on loopback; a deployment posts to `https://` only.
pub fn start(server: Weak<Server>) -> Waker {
    let (tx, mut rx) = mpsc::unbounded_channel::<Told>();
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(WAKE_TIMEOUT_SECS))
        .user_agent("sqexd")
        .build()
        .ok();
    tokio::spawn(async move {
        while let Some(told) = rx.recv().await {
            let Some(client) = &client else { continue };
            let Some(server) = server.upgrade() else {
                break;
            };
            let now = now_unix();
            // Every device of each account told, and then the devices named
            // one by one. Both go through the same coalescing and the same
            // "is it already listening" check -- a device addressed by key is
            // not a special case of a device, only of the addressing.
            let each: Vec<(PubKey, String, u64)> = told
                .accounts
                .iter()
                .flat_map(|a| server.devices.wakeable(a))
                .chain(told.devices.iter().filter_map(|d| {
                    server
                        .devices
                        .wakeable_device(d)
                        .map(|(endpoint, woken)| (*d, endpoint, woken))
                }))
                .collect();
            for (device, endpoint, woken) in each {
                if server.events.listening(&device) {
                    continue;
                }
                if !told.urgent && now.saturating_sub(woken) < WAKE_MIN_SECS {
                    continue;
                }
                server.devices.woke(&device);
                let client = client.clone();
                let server = Arc::clone(&server);
                tokio::spawn(async move {
                    match client.post(&endpoint).body(WAKE_BODY).send().await {
                        Ok(r) if r.status() == 404 || r.status() == 410 => {
                            // The distributor no longer knows it.
                            server.devices.forget_wake(&device);
                        }
                        Ok(_) => {}
                        Err(e) => {
                            tracing::debug!(device = %device, "wake failed: {e}");
                        }
                    }
                });
            }
        }
    });
    Waker { tx }
}
