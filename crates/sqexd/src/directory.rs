//! SIP-55: the federated directory.
//!
//! An exchange reads each labelled peer's public directory on an interval,
//! as any identified client could, and answers a search with its own
//! directory and everything it holds of its peers' -- each row naming the
//! exchange that orders the channel, and whether a copy is held here.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use sqex_proto::channel::{Found, List, Listing, MAX_DIRECTORY, Public, Row};
use sqex_proto::h3::H3Client;
use sqnr_core::PubKey;

use crate::server::Server;
use crate::state::now_unix;

/// How often each peer's directory is read.
pub const DIRECTORY_SECS: u64 = 60;
/// How long a peer's last directory stands in for one it will not serve.
pub const DIRECTORY_STALE: u64 = 15 * 60;
/// Rows read per peer.
pub const PEER_ROWS: usize = 256;

/// What one peer last served: its rows, its domain, and when.
struct PeerDirectory {
    domain: String,
    rows: Vec<Public>,
    at: u64,
}

/// Every peer's directory as last read.
#[derive(Default)]
pub struct Directories {
    peers: Mutex<HashMap<PubKey, PeerDirectory>>,
}

impl Directories {
    /// Keep what `peer` served.
    pub fn took(&self, peer: PubKey, domain: String, rows: Vec<Public>) {
        self.peers.lock().unwrap().insert(
            peer,
            PeerDirectory {
                domain,
                rows,
                at: now_unix(),
            },
        );
    }

    /// The peers' rows matching `query`, freshest reads only, in peer
    /// order -- less any channel this exchange lists itself.
    fn matching(&self, query: &str, skip: &dyn Fn(&[u8; 32]) -> bool) -> Vec<Row> {
        let now = now_unix();
        let q = query.to_lowercase();
        let peers = self.peers.lock().unwrap();
        let mut keys: Vec<&PubKey> = peers.keys().collect();
        keys.sort_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
        let mut out = Vec::new();
        for key in keys {
            let d = &peers[key];
            if now.saturating_sub(d.at) > DIRECTORY_STALE {
                continue;
            }
            for p in &d.rows {
                if skip(&p.channel) {
                    continue;
                }
                if !q.is_empty()
                    && !p.name.to_lowercase().contains(&q)
                    && !p.topic.to_lowercase().contains(&q)
                {
                    continue;
                }
                out.push(Row {
                    channel: p.channel,
                    instance: p.instance,
                    home: *key,
                    domain: d.domain.clone(),
                    here: false,
                    members: p.members,
                    last: p.last,
                    name: p.name.clone(),
                    topic: p.topic.clone(),
                });
            }
        }
        out
    }
}

/// Answer a search: this exchange's directory, then its peers'.
pub fn search(
    server: &Server,
    query: &str,
    offset: u32,
) -> Result<Found, crate::channel::ChannelError> {
    // Every local match, paged by hand below: the local directory pages
    // itself, and the union has to be paged as one list.
    let mut local: Vec<Row> = Vec::new();
    let mut page = 0u32;
    loop {
        let Listing {
            channels, total, ..
        } = server.channels().list(query, page)?;
        if channels.is_empty() {
            break;
        }
        for p in channels {
            let home = server.channels().origin_of(&p.channel);
            let domain = home
                .and_then(|o| server.forwarder(&o).map(|f| f.domain.clone()))
                .or_else(|| {
                    home.and_then(|_| server.channels().moved_to(&p.channel).map(|(_, d)| d))
                })
                .unwrap_or_default();
            local.push(Row {
                channel: p.channel,
                instance: p.instance,
                home: home.unwrap_or(server.public_key),
                domain,
                here: true,
                members: p.members,
                last: p.last,
                name: p.name,
                topic: p.topic,
            });
        }
        page += MAX_DIRECTORY as u32;
        if page as usize >= total as usize || page > 4096 {
            break;
        }
    }
    let here: std::collections::HashSet<[u8; 32]> = local.iter().map(|r| r.channel).collect();
    let mut rows = local;
    rows.extend(server.directories.matching(query, &|c| here.contains(c)));
    let total = rows.len() as u32;
    let rows: Vec<Row> = rows
        .into_iter()
        .skip(offset as usize)
        .take(MAX_DIRECTORY)
        .collect();
    Ok(Found {
        now: now_unix(),
        total,
        rows,
    })
}

/// Read every labelled peer's directory, every `DIRECTORY_SECS`.
pub async fn run(server: Arc<Server>, seed: [u8; 32]) {
    loop {
        for peer in server.peer_directory().peers {
            if peer.domain.is_empty() {
                continue;
            }
            let Ok((key, addr)) = server.relay_find(&peer.domain).await else {
                continue;
            };
            if key != peer.key {
                tracing::warn!(domain = %peer.domain, expected = %peer.key, found = %key, "a peer's domain names another key");
                continue;
            }
            let Ok(mut client) = H3Client::connect(addr, key.as_bytes(), &seed).await else {
                continue;
            };
            let mut rows = Vec::new();
            let mut offset = 0u32;
            while rows.len() < PEER_ROWS {
                let Ok((200, body)) = client
                    .post(
                        "/channel/list",
                        List {
                            offset,
                            query: String::new(),
                        }
                        .encode(),
                    )
                    .await
                else {
                    break;
                };
                let Ok(listing) = Listing::decode(&body) else {
                    break;
                };
                if listing.channels.is_empty() {
                    break;
                }
                offset += listing.channels.len() as u32;
                rows.extend(listing.channels);
                if offset >= listing.total {
                    break;
                }
            }
            rows.truncate(PEER_ROWS);
            server.directories.took(key, peer.domain.clone(), rows);
        }
        tokio::time::sleep(std::time::Duration::from_secs(server.directory_secs)).await;
    }
}
