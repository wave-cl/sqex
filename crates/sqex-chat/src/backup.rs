//! SIP-48: a sealed backup at the exchange.
//!
//! The store's history goes up as SIP-18 blobs held by the account -- one
//! segment per channel, in the form SIP-42 sends a sibling, so restoring is
//! receiving from a past self -- and a manifest the device signs and seals
//! under the backup key names them. The key is the person's: shown once as
//! words, kept in the store for the next backup, and never sent anywhere.

use std::collections::HashMap;

use sqex_proto::backup::{
    Held, KIND_CONTACTS, KIND_HISTORY, Manifest, Plain, Segment, ask, drop_all, open, words,
};
use sqex_proto::blob::{Attachment, KIND_FILE};
use sqex_proto::channel_key::ChannelKey;
use sqex_proto::device::{Devices, ListDevices};
use sqex_proto::refusal::Code as RefusalCode;
use sqex_proto::timeline::Timeline;
use sqnr_core::PubKey;

use crate::attach::Prepared;
use crate::client::{Chat, ChatError};
use crate::sync::{Message, PAGE};

type Result<T> = std::result::Result<T, ChatError>;

const META_KEY: &str = "backup_key";

/// What a backup did.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct BackedUp {
    pub generation: u64,
    /// Channels whose segment was uploaded this time.
    pub uploaded: usize,
    /// Channels whose segment from last time still covered them.
    pub kept: usize,
    pub contacts: usize,
    pub bytes: u64,
    pub quota: u64,
    pub used: u64,
}

/// What a restore did.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Restored {
    pub generation: u64,
    pub channels: usize,
    pub entries: usize,
    pub keys: usize,
    pub contacts: usize,
    /// Segments this client could not apply: a channel the exchange no
    /// longer serves, a kind it does not know, a blob that would not open.
    pub skipped: Vec<String>,
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn framed(messages: &[Message]) -> Vec<u8> {
    let mut out = Vec::new();
    for m in messages {
        let body = m.encode();
        out.extend_from_slice(&(body.len() as u32).to_be_bytes());
        out.extend_from_slice(&body);
    }
    out
}

fn unframed(bytes: &[u8]) -> Result<Vec<Message>> {
    let mut out = Vec::new();
    let mut at = 0;
    while at + 4 <= bytes.len() {
        let len = u32::from_be_bytes(bytes[at..at + 4].try_into().unwrap()) as usize;
        at += 4;
        if at + len > bytes.len() {
            return Err(ChatError::Protocol("a segment is cut short".into()));
        }
        out.push(
            Message::decode(&bytes[at..at + len])
                .map_err(|e| ChatError::Protocol(e.to_string()))?,
        );
        at += len;
    }
    Ok(out)
}

fn contacts_segment(contacts: &[(PubKey, bool, String)]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + contacts.len() * 40);
    out.extend_from_slice(&(contacts.len() as u32).to_be_bytes());
    for (account, verified, label) in contacts {
        out.extend_from_slice(account.as_bytes());
        out.push(u8::from(*verified));
        let l: Vec<u8> = label.bytes().take(u16::MAX as usize).collect();
        out.extend_from_slice(&(l.len() as u16).to_be_bytes());
        out.extend_from_slice(&l);
    }
    out
}

fn contacts_from(bytes: &[u8]) -> Result<Vec<(PubKey, bool, String)>> {
    if bytes.len() < 4 {
        return Err(ChatError::Protocol(
            "a contacts segment is cut short".into(),
        ));
    }
    let count = u32::from_be_bytes(bytes[..4].try_into().unwrap()) as usize;
    let mut at = 4;
    let mut out = Vec::with_capacity(count);
    for _ in 0..count {
        if at + 35 > bytes.len() {
            return Err(ChatError::Protocol(
                "a contacts segment is cut short".into(),
            ));
        }
        let account = PubKey::new(bytes[at..at + 32].try_into().unwrap());
        let verified = bytes[at + 32] != 0;
        let len = u16::from_be_bytes([bytes[at + 33], bytes[at + 34]]) as usize;
        at += 35;
        if at + len > bytes.len() {
            return Err(ChatError::Protocol(
                "a contacts segment is cut short".into(),
            ));
        }
        let label = String::from_utf8_lossy(&bytes[at..at + len]).into_owned();
        at += len;
        out.push((account, verified, label));
    }
    Ok(out)
}

impl Chat {
    /// The backup key this store holds, if one was made or given.
    pub fn backup_key(&self) -> Result<Option<[u8; 32]>> {
        Ok(self.store().meta(META_KEY)?.and_then(|v| v.try_into().ok()))
    }

    /// Make a backup key and keep it. Shown to the person as words by the
    /// caller; there is no getting it back from the exchange.
    pub fn new_backup_key(&self) -> Result<[u8; 32]> {
        let mut key = [0u8; 32];
        {
            use rand_core::RngCore;
            rand_core::OsRng.fill_bytes(&mut key);
        }
        self.store().set_meta(META_KEY, &key)?;
        Ok(key)
    }

    /// Keep a backup key the person typed back in.
    pub fn set_backup_key(&self, key: &[u8; 32]) -> Result<()> {
        self.store().set_meta(META_KEY, key)?;
        Ok(())
    }

    /// The backup key as SIP-41 words.
    pub fn backup_words(key: &[u8; 32]) -> [&'static str; sqex_proto::backup::WORD_COUNT] {
        words(key)
    }

    /// What the exchange holds for `account` (ours, or one we succeeded).
    pub async fn backup_held(&mut self, account: &PubKey) -> Result<Held> {
        let body = self.post_raw("/backup/read", ask(account)).await?;
        Held::decode(&body).map_err(|e| ChatError::Protocol(e.to_string()))
    }

    /// Write the store to the exchange under `key`: every channel's signed
    /// entries and epoch keys, and the contacts. A channel whose range has
    /// not moved since the last backup keeps its segment; the rest go up
    /// afresh and the old ones are released.
    pub async fn backup(&mut self, key: &[u8; 32]) -> Result<BackedUp> {
        let me = self.me;
        let held = self.backup_held(&me).await?;
        let previous: Vec<Segment> = if held.is_some() {
            match open(key, &me, held.generation, &held.sealed) {
                Ok(p) => p.segments,
                // Another key wrote it: start over rather than build on
                // segments this key cannot describe.
                Err(_) => Vec::new(),
            }
        } else {
            Vec::new()
        };
        let mut report = BackedUp {
            generation: held.generation + 1,
            ..Default::default()
        };
        let limits = self.blob_limits().await?;
        let chunk = limits.chunk as usize;
        let mut segments = Vec::new();

        for (channel, first, last) in self.store().entry_ranges()? {
            if let Some(p) = previous
                .iter()
                .find(|s| s.kind == KIND_HISTORY && s.channel == channel)
                && p.first == first
                && p.last == last
            {
                segments.push(p.clone());
                report.kept += 1;
                continue;
            }
            let keys: Vec<(u32, [u8; 32])> = self
                .store()
                .keys_of(&channel)?
                .into_iter()
                .map(|(e, k)| (e, *k.as_bytes()))
                .collect();
            let instance = self.store().incarnation(&channel)?.unwrap_or([0; 32]);
            let mut messages = Vec::new();
            if !keys.is_empty() {
                messages.push(Message::Keys { channel, keys });
            }
            let mut since = first.saturating_sub(1);
            loop {
                let raw = self.store().entries_after(&channel, since, PAGE)?;
                if raw.is_empty() {
                    break;
                }
                let mut entries = Vec::with_capacity(raw.len());
                for (seq, b) in &raw {
                    let mut at = 0;
                    if let Ok(e) = sqex_proto::channel::Entry::read_receipted(b, &mut at) {
                        // SIP-57: a message with a timer has no business in
                        // a backup, which is opened at a time nobody chose.
                        if e.expires_after == 0 {
                            entries.push(e);
                        }
                    }
                    since = *seq;
                }
                if !entries.is_empty() {
                    messages.push(Message::Entries {
                        channel,
                        instance,
                        entries,
                    });
                }
                if raw.len() < PAGE {
                    break;
                }
            }
            let bytes = framed(&messages);
            let prepared = self.prepare_bytes("history", &bytes, chunk)?;
            let a = self.upload(me.as_bytes(), &prepared).await?;
            report.uploaded += 1;
            report.bytes += a.size;
            segments.push(Segment {
                kind: KIND_HISTORY,
                blob: a.blob,
                key: a.key,
                channel,
                first,
                last,
            });
        }

        // Contacts, every time: small, and the verified flags are the part
        // that cannot be got back any other way.
        let verified: Vec<PubKey> = self
            .store()
            .verified()?
            .into_iter()
            .map(|(k, _)| k)
            .collect();
        let contacts: Vec<(PubKey, bool, String)> = self
            .store()
            .contacts()?
            .into_iter()
            .map(|c| (c.account, verified.contains(&c.account), c.label))
            .collect();
        report.contacts = contacts.len();
        if !contacts.is_empty() {
            let bytes = contacts_segment(&contacts);
            let prepared = self.prepare_bytes("contacts", &bytes, chunk)?;
            let a = self.upload(me.as_bytes(), &prepared).await?;
            report.bytes += a.size;
            segments.push(Segment {
                kind: KIND_CONTACTS,
                blob: a.blob,
                key: a.key,
                channel: [0; 32],
                first: 0,
                last: 0,
            });
        }
        // Held blobs from last time stay held.
        segments.extend(
            previous
                .iter()
                .filter(|s| s.kind == sqex_proto::backup::KIND_HELD)
                .cloned(),
        );

        let plain = Plain {
            written: now(),
            segments,
        };
        // Another device may have written meanwhile: take its generation
        // and go once more. Its segments are released, which is the price
        // of two devices backing up the same history at once.
        let mut generation = report.generation;
        for _ in 0..2 {
            let m = Manifest::make(&self.seed, key, &me, generation, &plain)
                .map_err(|e| ChatError::Protocol(e.to_string()))?;
            match self.post_raw("/backup/write", m.encode()).await {
                Ok(_) => break,
                Err(ChatError::Refused(_, r)) if r.code == RefusalCode::StaleGeneration => {
                    generation = r
                        .detail
                        .as_deref()
                        .and_then(|d| d.parse::<u64>().ok())
                        .unwrap_or(generation)
                        + 1;
                }
                Err(e) => return Err(e),
            }
        }
        report.generation = generation;
        let after = self.backup_held(&me).await?;
        report.quota = after.quota;
        report.used = after.used;
        Ok(report)
    }

    /// Take a backup into this store: ours, or -- as a SIP-44 successor --
    /// the account we succeeded. Entries are verified as a sibling's would
    /// be; keys are taken on the writer's word, which was this account's.
    pub async fn restore(&mut self, key: &[u8; 32], from: Option<PubKey>) -> Result<Restored> {
        let account = from.unwrap_or(self.me);
        let held = self.backup_held(&account).await?;
        if !held.is_some() {
            return Err(ChatError::Protocol(format!(
                "{account} has no backup at this exchange"
            )));
        }
        // Signed by a device of that account -- the account itself, or one
        // on its list, whose credential the exchange kept (SIP-32).
        let manifest = held.manifest();
        let by_account = held.device == account && manifest.verifies(&account, &account);
        if !by_account {
            let body = self
                .post_raw("/device/list", ListDevices { account }.encode())
                .await?;
            let devices = Devices::decode(&body).map_err(|e| ChatError::Protocol(e.to_string()))?;
            let listed = devices.devices.iter().any(|d| d.device == held.device);
            if !listed || !manifest.verifies(&held.device, &account) {
                return Err(ChatError::Protocol(
                    "the backup's manifest was not signed by a device of that account".into(),
                ));
            }
        }
        let plain = open(key, &account, held.generation, &held.sealed)
            .map_err(|e| ChatError::Protocol(e.to_string()))?;
        let mut report = Restored {
            generation: held.generation,
            ..Default::default()
        };
        let mut timelines: HashMap<[u8; 32], Timeline> = HashMap::new();
        for s in &plain.segments {
            if s.kind != KIND_HISTORY && s.kind != KIND_CONTACTS {
                continue;
            }
            let headed = self.head(&s.blob).await?;
            if !headed.found {
                report.skipped.push(format!(
                    "segment {} is no longer held",
                    bs58::encode(s.blob).into_string()
                ));
                continue;
            }
            let a = Attachment {
                kind: KIND_FILE,
                blob: s.blob,
                key: s.key,
                size: headed.size,
                chunks: headed.chunks,
                mime: String::new(),
                meta: Vec::new(),
                preview: Vec::new(),
            };
            let bytes = match self.download(&a).await {
                Ok(b) => b,
                Err(e) => {
                    report.skipped.push(format!(
                        "segment {}: {e}",
                        bs58::encode(s.blob).into_string()
                    ));
                    continue;
                }
            };
            if s.kind == KIND_CONTACTS {
                for (who, verified, label) in contacts_from(&bytes)? {
                    self.store().add_contact(&who, &label, now())?;
                    if verified {
                        self.store().verify(&who, now())?;
                    }
                    report.contacts += 1;
                }
                continue;
            }
            let mut applied = false;
            for m in unframed(&bytes)? {
                match m {
                    Message::Keys { channel, keys } => {
                        for (epoch, k) in keys {
                            self.store().put_key(&channel, epoch, &ChannelKey::new(k))?;
                            report.keys += 1;
                        }
                        applied = true;
                    }
                    Message::Entries {
                        channel,
                        instance,
                        entries,
                    } => {
                        let timeline = timelines.entry(channel).or_default();
                        match self.import(timeline, &channel, instance, &entries).await {
                            Ok(n) => {
                                report.entries += n;
                                applied = true;
                            }
                            Err(e) => {
                                report.skipped.push(format!(
                                    "channel {}: {e}",
                                    bs58::encode(channel).into_string()
                                ));
                                break;
                            }
                        }
                    }
                    _ => {}
                }
            }
            if applied {
                report.channels += 1;
            }
        }
        Ok(report)
    }

    /// Release everything the exchange holds for this account.
    pub async fn drop_backup(&mut self) -> Result<()> {
        self.post_raw("/backup/drop", drop_all()).await?;
        Ok(())
    }

    /// A segment from bytes in hand: sealed like a file, named like one.
    fn prepare_bytes(&self, name: &str, plaintext: &[u8], chunk: usize) -> Result<Prepared> {
        Prepared::from_bytes(name, plaintext, chunk)
    }
}
