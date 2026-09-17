//! SIP-52: one round trip for a device that has been away.
//!
//! **Composition, not authority.** Every byte of a channel's answer comes
//! from [`Channels::fetch`] and [`Channels::get_keys`], called exactly as the
//! `/channel/fetch` and `/channel/key/get` routes call them for the same
//! caller; the unnamed list is [`Channels::mine`]; the prekey count is
//! [`Prekeys::count`]. This module decides only the order, the budget, and
//! what to say about a channel it could not or did not read. The test for it
//! is byte equality against those routes.

use sqex_proto::catchup::{
    Catchup, Caught, CaughtUp, MAX_CATCHUP_BYTES, MAX_UNNAMED, STATUS_ABSENT, STATUS_DEFERRED,
    STATUS_OK,
};
use sqex_proto::channel::{Entries, MAX_BATCH};
use sqnr_core::PubKey;

use crate::channel::Channels;
use crate::prekey::Prekeys;

/// Answer a catch-up. Never fails: a channel that cannot be read is answered
/// as absent, and everything else the caller could ask for is answered.
pub fn answer(
    channels: &Channels,
    prekeys: &Prekeys,
    account: &PubKey,
    device: &PubKey,
    req: &Catchup,
    now: u64,
) -> CaughtUp {
    let budget = req.budget.min(MAX_CATCHUP_BYTES) as usize;
    let mut spent = 0usize;
    let mut exhausted = false;
    let mut caught = Vec::with_capacity(req.named.len());

    for named in &req.named {
        if exhausted {
            // Not looked at, and not claimed either way: a status that said
            // "readable" for a channel nobody checked would be a claim, and
            // "absent" would be a lie.
            caught.push(Caught {
                channel: named.channel,
                status: STATUS_DEFERRED,
                more: true,
                fetched: Vec::new(),
                got: Vec::new(),
            });
            continue;
        }
        // Exactly the fetch route's call, with `wait_secs: 0` and no
        // receipts: a woken device collects what landed, and the stream it
        // holds says what is coming.
        let mut entries: Entries =
            match channels.fetch(account, device, &named.channel, named.since, false) {
                Ok(entries) => entries,
                // One answer for "not yours" and "not here" -- the fetch route's
                // own refusal is already that answer; this route says less.
                Err(_) => {
                    caught.push(Caught {
                        channel: named.channel,
                        status: STATUS_ABSENT,
                        more: false,
                        fetched: Vec::new(),
                        got: Vec::new(),
                    });
                    continue;
                }
            };
        // Envelopes, in full: a device with an entry it cannot open has
        // nothing, and there is at most one envelope per epoch per device. A
        // public channel has none and the key route refuses to look; that is
        // an empty answer here, not an absent channel.
        let got = channels
            .get_keys(account, device, &named.channel, named.since_epoch)
            .map(|g| g.encode())
            .unwrap_or_default();
        spent += got.len();
        // The batch itself may have been cut by MAX_BATCH.
        let mut more = entries.entries.len() >= MAX_BATCH;
        // Then entries, oldest first, until the next would not fit. The
        // fixed part of an `Entries` reply is counted with the first entry.
        let mut kept = 0usize;
        let mut bytes = encoded_len(&entries, kept);
        while kept < entries.entries.len() {
            let with_next = encoded_len(&entries, kept + 1);
            if spent + with_next > budget {
                more = true;
                exhausted = true;
                break;
            }
            kept += 1;
            bytes = with_next;
        }
        if kept < entries.entries.len() {
            entries.entries.truncate(kept);
        }
        spent += bytes;
        caught.push(Caught {
            channel: named.channel,
            status: STATUS_OK,
            more,
            fetched: entries.encode(),
            got,
        });
        if spent >= budget {
            exhausted = true;
        }
    }

    let unnamed = channels
        .mine(account, 0)
        .map(|mine| {
            mine.channels
                .into_iter()
                .filter(|m| !req.named.iter().any(|n| n.channel == m.channel))
                .take(MAX_UNNAMED)
                .map(|m| sqex_proto::catchup::Unnamed {
                    channel: m.channel,
                    last: m.last,
                })
                .collect()
        })
        .unwrap_or_default();

    CaughtUp {
        now,
        prekeys: prekeys.count(device).one_time,
        caught,
        unnamed,
    }
}

/// How long an `Entries` reply is with its first `n` entries and everything
/// else as is. Measured by encoding rather than summed by hand, so it cannot
/// drift from the encoder.
fn encoded_len(entries: &Entries, n: usize) -> usize {
    let cut = Entries {
        now: entries.now,
        first: entries.first,
        last: entries.last,
        entries: entries.entries[..n].to_vec(),
        signals: entries.signals.clone(),
        tip: entries.tip,
    };
    cut.encode().len()
}
