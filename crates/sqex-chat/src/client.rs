//! The protocol half: prekeys, epoch keys, posting and fetching.
//!
//! Everything here is done by the client, and that is the point — if the
//! exchange could do any of it, the design would be wrong. It seals, it opens,
//! it verifies prekey signatures itself, and it refuses a replayed counter,
//! because the exchange is either unable or is the party being constrained.

use sqex_proto::channel::{
    Ack, ByChannel, ChannelInfo, Create, Entries, Fetch, Invitee, KIND_MEMBER, Post, Posted, Role,
    TYPE_INFO, Visibility, direct_message_id,
};
use sqex_proto::channel_key::{
    ChannelKey, Get as KeyGet, Got, Put as KeyPut, PutAck, open_envelope, seal_envelope,
};
use sqex_proto::message::{Body, Post as SipPost};
use sqex_proto::prekey::{
    Cleared, Counts, LOW_WATER, POOL, Pool, Prekey, Publish, TYPE_CLEAR, TYPE_COUNT, Take, Taken,
};
use sqex_proto::timeline::{Received, Timeline};
use sqnr::Client;
use sqnr_core::PubKey;

use crate::store::{Store, StoreError};

/// A direct message's retention window, in seconds.
///
/// SIP-16's default is 30 days and this follows it. It is the exchange's
/// promise about when entries are pruned, not a security property — a member
/// who read a message has it.
const RETENTION_SECS: u32 = 30 * 24 * 60 * 60;

/// How long a fetch may park waiting for something to arrive.
///
/// Under SIP-16's `MAX_WAIT` of 25 s, so the exchange never has to clamp it.
pub const WAIT_SECS: u16 = 20;

#[derive(Debug)]
pub enum ChatError {
    Store(StoreError),
    Transport(String),
    /// The exchange refused, with the status and whatever it said.
    Refused(u16, String),
    Protocol(String),
    /// We are a member with no key for the current epoch. SIP-17 asks that this
    /// be said plainly rather than shown as an empty conversation.
    NoKey(u32),
    /// The exchange answered a chat route with the router's own 404. It is
    /// running, and it does not implement chat at all.
    NoChatHere(String),
    /// The other party has published no prekeys, so SIP-23 forbids sealing to
    /// them at all. Not an error in the conversation — the channel exists and
    /// they are in it — but nothing can be said until they start their client.
    NotReady(PubKey),
}

impl std::fmt::Display for ChatError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ChatError::Store(e) => write!(f, "{e}"),
            ChatError::Transport(e) => write!(f, "{e}"),
            ChatError::Refused(code, body) => write!(f, "the exchange refused ({code}): {body}"),
            ChatError::Protocol(e) => write!(f, "{e}"),
            ChatError::NoKey(epoch) => write!(
                f,
                "no key for epoch {epoch} — you were not sent one, so this conversation \
                 cannot be read until somebody sends it"
            ),
            ChatError::NoChatHere(path) => write!(
                f,
                "this exchange has no {path} — it is running, but it is older than the \
                 chat services (SIPs 16-24, sqex 0.9.0). Upgrade it, or point at one \
                 that has them"
            ),
            ChatError::NotReady(who) => write!(
                f,
                "{who} has not started their client yet, so there is nowhere to send a \
                 key — the conversation exists and will work as soon as they do"
            ),
        }
    }
}

impl std::error::Error for ChatError {}

impl From<StoreError> for ChatError {
    fn from(e: StoreError) -> ChatError {
        ChatError::Store(e)
    }
}

type Result<T> = std::result::Result<T, ChatError>;

/// What a fetch turned up, and everything the reader must be told about it.
pub struct Conversation {
    pub timeline: Timeline,
    /// Entries we hold and could not open. Carried rather than dropped, so a
    /// client can say something was there.
    pub unreadable: Vec<u64>,
    /// True when our `since` was below the exchange's oldest retained entry: we
    /// have been away longer than the window and there is history we can never
    /// fill. It must be shown as a gap and not as the whole conversation.
    pub gap: bool,
    /// Somebody is typing (SIP-19's only signal).
    pub typing: bool,
    pub last: u64,
}

pub struct Chat {
    client: Client,
    seed: [u8; 32],
    /// Our own account. With no registered devices an account is its own
    /// device, which is the ordinary single-client case and the one this
    /// client is built for.
    pub me: PubKey,
    store: Store,
}

impl Chat {
    pub fn new(client: Client, seed: [u8; 32], me: PubKey, store: Store) -> Chat {
        Chat {
            client,
            seed,
            me,
            store,
        }
    }

    pub fn store(&self) -> &Store {
        &self.store
    }

    /// One request, with the exchange's refusals turned into something a
    /// person can act on. `pub(crate)` so the blob module shares exactly this
    /// handling rather than growing a second, laxer copy of it.
    pub(crate) async fn post_raw(&mut self, path: &str, body: Vec<u8>) -> Result<Vec<u8>> {
        self.post(path, body).await
    }

    async fn post(&mut self, path: &str, body: Vec<u8>) -> Result<Vec<u8>> {
        let (code, body) = self
            .client
            .post(path, body)
            .await
            .map_err(ChatError::Transport)?;
        if code != 200 {
            let said = String::from_utf8_lossy(&body).into_owned();
            // The router's own 404 for a path it does not have, as against a
            // chat route's 404 for a channel or blob that does not exist —
            // those answer JSON. Told apart here because the two mean entirely
            // different things to whoever is reading the message: one is "your
            // exchange is too old", the other is "that thing is not there".
            if code == 404 && said.trim() == "not found" {
                return Err(ChatError::NoChatHere(path.to_string()));
            }
            return Err(ChatError::Refused(code, said));
        }
        Ok(body)
    }

    // ---- prekeys --------------------------------------------------------

    /// Publish prekeys if the pool is low, and make sure a fallback exists.
    ///
    /// SIP-23 asks a device to keep `POOL` published and top up below
    /// `LOW_WATER`. Called on startup, and again whenever we spend one.
    pub async fn top_up_prekeys(&mut self) -> Result<()> {
        let mut pool = self.store.pool(&self.seed)?;
        if pool.one_time_left() == 0 && pool.fallback_id() == 0 {
            pool = self.restart_pool(pool).await?;
        }
        let mut publish = Vec::new();
        if pool.one_time_left() < LOW_WATER {
            publish.extend(pool.mint_one_time(POOL - pool.one_time_left()));
        }
        // A fallback after every batch, not only the first: its id is the only
        // thing `Count` reports, so it is what a future client with a lost
        // store will have to start above.
        if pool.fallback_id() == 0 || !publish.is_empty() {
            publish.push(pool.mint_fallback());
        }
        if publish.is_empty() {
            return Ok(());
        }
        // Persist before publishing. The other order loses the secret for a
        // prekey the exchange is already handing out, which is an envelope
        // nobody can open.
        self.store.save_pool(&pool)?;
        for batch in publish.chunks(sqex_proto::prekey::MAX_PUBLISH) {
            self.post(
                "/prekey/publish",
                Publish {
                    prekeys: batch.to_vec(),
                }
                .encode(),
            )
            .await?;
        }
        Ok(())
    }

    /// Discard whatever the exchange still holds for us, and resume above it.
    ///
    /// An empty pool is a new client or a client whose store was lost, and the
    /// two are indistinguishable from here — but not from the exchange, which
    /// remembers every id this device published and refuses each one forever,
    /// and which is still serving prekeys whose secrets went with the store.
    /// Both halves of that are SIP-23's `Clear`: it discards the prekeys, so a
    /// peer gets `found: 0` and declines to seal rather than sealing to
    /// something that will never open, and it answers with `next_id`, which is
    /// the only way a client whose own record is gone can publish again.
    ///
    /// A brand-new device clears nothing and gets `next_id` 1, so this is one
    /// request on first run rather than a special case to detect.
    async fn restart_pool(&mut self, pool: Pool) -> Result<Pool> {
        let mut state = pool.save();
        match self.post("/prekey/clear", vec![TYPE_CLEAR]).await {
            Ok(body) => {
                let cleared =
                    Cleared::decode(&body).map_err(|e| ChatError::Protocol(e.to_string()))?;
                state.next_id = state.next_id.max(cleared.next_id);
            }
            // An exchange without `Clear` predates the amendment. Fall back to
            // what `Count` can say — the current fallback's id is a lower bound
            // on what has been used — and to the clock floor beneath it. The
            // stale prekeys stay, so sending may fail until they drain; that is
            // the state this amendment exists to fix and it is not a reason to
            // refuse to start.
            Err(ChatError::Refused(..)) | Err(ChatError::NoChatHere(_)) => {
                let body = self.post("/prekey/count", vec![TYPE_COUNT]).await?;
                let counts =
                    Counts::decode(&body).map_err(|e| ChatError::Protocol(e.to_string()))?;
                state.next_id = state.next_id.max(counts.fallback_id.saturating_add(1));
            }
            Err(e) => return Err(e),
        }
        Ok(Pool::load(&self.seed, state))
    }

    /// Ask for a prekey for `them`, and check it ourselves.
    async fn take_prekey_for(&mut self, them: PubKey) -> Result<Prekey> {
        let body = self.post("/prekey/take", Take { device: them }.encode()).await?;
        let taken = Taken::decode(&body).map_err(|e| ChatError::Protocol(e.to_string()))?;
        if !taken.found {
            // SIP-23 is deliberate about this: there is no static-only path, so
            // refusing to seal is the correct behaviour and it is visible.
            return Err(ChatError::NotReady(them));
        }
        let p = taken
            .prekey
            .ok_or_else(|| ChatError::Protocol("a found prekey with no prekey in it".into()))?;
        // The exchange is the party this signature exists to constrain, so
        // trusting its check would be verifying nothing.
        p.verify(&them)
            .map_err(|e| ChatError::Protocol(format!("prekey for {them} does not verify: {e}")))?;
        Ok(p)
    }

    // ---- opening a conversation -----------------------------------------

    /// The channel two accounts share. Derived, not asked for.
    pub fn dm_with(&self, them: &PubKey) -> [u8; 32] {
        direct_message_id(&self.me, them)
    }

    /// Make sure the direct message with `them` exists and we hold its key.
    ///
    /// Idempotent: `Create` against a channel we are already in answers without
    /// changing anything, so this is also the ordinary way to reopen one.
    pub async fn open_dm(&mut self, them: &PubKey) -> Result<[u8; 32]> {
        let channel = self.dm_with(them);
        self.post(
            "/channel/create",
            Create {
                channel,
                visibility: Visibility::Private,
                retention_secs: RETENTION_SECS,
                max_entries: 0,
                // A private channel's name is carried sealed (SIP-19); at the
                // exchange it must be empty, because a membership graph plus a
                // name says far more than the graph.
                name: String::new(),
                topic: String::new(),
                invites: vec![Invitee {
                    account: *them,
                    role: Role::Admin,
                }],
            }
            .encode(),
        )
        .await?;

        self.collect_keys(&channel).await?;
        Ok(channel)
    }

    /// Make sure the channel has an epoch and that we hold its key.
    ///
    /// Separate from `open_dm`, and it has to be. A direct message can be
    /// opened with somebody who has never run a client: they become a member
    /// immediately, but SIP-23 forbids sealing a key to a device that has
    /// published no prekeys, so there is nothing to mint *to* yet. That is a
    /// conversation waiting to start, not a failure to open one, and the
    /// difference is what a person sees on the screen.
    pub async fn ensure_epoch(&mut self, channel: &[u8; 32], them: &PubKey) -> Result<u32> {
        let info = self.info(channel).await?;
        if info.epoch == 0 {
            self.mint_epoch(channel, them, 1).await?;
            return Ok(self.info(channel).await?.epoch);
        }
        if self.store.key(channel, info.epoch)?.is_none() {
            self.collect_keys(channel).await?;
            if self.store.key(channel, info.epoch)?.is_none() {
                // No key for the epoch in force. Either nobody sealed one to
                // us, or we lost the store that held it — and the envelope
                // will not open again, because the prekey it was sealed
                // against is spent.
                //
                // Both parties to a direct message are admins, so the way out
                // is the one SIP-17 already provides: mint the next epoch and
                // seal it to both. What was said under the old one stays
                // unreadable, which is the forward secrecy working; the
                // conversation continues, which is the point.
                //
                // This is a direct-message move and not a general one. In a
                // group, a member who was simply never given the key would be
                // seizing an epoch they were deliberately left out of.
                self.mint_epoch(channel, them, info.epoch + 1).await?;
                let after = self.info(channel).await?.epoch;
                return self
                    .store
                    .key(channel, after)?
                    .map(|_| after)
                    .ok_or(ChatError::NoKey(after));
            }
        }
        Ok(info.epoch)
    }

    /// Mint an epoch key and seal it to both parties.
    ///
    /// To *both*, including ourselves: our own other devices need it, and the
    /// exchange keeps the envelope for collection rather than for storage.
    async fn mint_epoch(&mut self, channel: &[u8; 32], them: &PubKey, epoch: u32) -> Result<()> {
        let key = ChannelKey::generate();
        let mut envelopes = Vec::new();
        for who in [self.me, *them] {
            let p = self.take_prekey_for(who).await?;
            envelopes.push(
                seal_envelope(&who, p.id, &p.public, epoch, &[key])
                    .map_err(|e| ChatError::Protocol(e.to_string()))?,
            );
        }
        let body = self
            .post(
                "/channel/key/put",
                KeyPut {
                    channel: *channel,
                    epoch,
                    envelopes,
                }
                .encode(),
            )
            .await?;
        let ack = PutAck::decode(&body).map_err(|e| ChatError::Protocol(e.to_string()))?;
        if ack.accepted {
            self.store.put_key(channel, epoch, &key)?;
        } else {
            // The other end minted the same epoch first. One `Put` wins and the
            // loser collects instead — this is the direct-message creation race
            // settling, not an error.
            self.collect_keys(channel).await?;
        }
        // We spent two prekeys of our own getting here.
        self.top_up_prekeys().await?;
        Ok(())
    }

    /// Collect any epoch keys waiting for us and store them.
    ///
    /// The envelope is a one-shot: opening it spends the prekey it was sealed
    /// against, so what is written here is the only copy that will exist
    /// tomorrow.
    pub async fn collect_keys(&mut self, channel: &[u8; 32]) -> Result<usize> {
        let since = self.store.highest_epoch(channel)?;
        let body = self
            .post(
                "/channel/key/get",
                KeyGet {
                    channel: *channel,
                    since_epoch: since,
                }
                .encode(),
            )
            .await?;
        let got = Got::decode(&body).map_err(|e| ChatError::Protocol(e.to_string()))?;
        if got.envelopes.is_empty() {
            return Ok(0);
        }

        let mut pool = self.store.pool(&self.seed)?;
        let mut opened = 0;
        for env in &got.envelopes {
            if self.store.key(channel, env.from_epoch)?.is_some() {
                continue;
            }
            let secret = match pool.take(env.prekey_id) {
                Ok(s) => s,
                // A spent prekey here is the exchange serving one twice, or a
                // replay. Either way it is not openable and not fatal: the
                // other epochs in this batch may still be good.
                Err(_) => continue,
            };
            let keys = match open_envelope(&self.seed, &secret, env) {
                Ok(k) => k,
                Err(_) => continue,
            };
            for (i, k) in keys.into_iter().enumerate() {
                self.store.put_key(channel, env.from_epoch + i as u32, &k)?;
                opened += 1;
            }
        }
        // Deleting is the mechanism, and it only counts once it is durable.
        self.store.save_pool(&pool)?;
        if opened > 0 {
            self.top_up_prekeys().await?;
        }
        Ok(opened)
    }

    /// Rebuild a conversation from what this client kept.
    ///
    /// Needs no network and must not: the entries are still on the exchange but
    /// they will not open a second time, so this store is the only place the
    /// conversation exists. `them` and this account are the two admins of a
    /// direct message, which is what `Timeline` needs to judge a redaction.
    pub fn history(&self, channel: &[u8; 32], them: &PubKey) -> Result<Timeline> {
        let admins = [self.me, *them];
        let mut timeline = Timeline::new();
        for (seq, account, posted, kind, plain) in self.store.messages(channel)? {
            timeline.apply(
                &Received {
                    seq,
                    account,
                    posted,
                    kind,
                    body: plain.and_then(|p| Body::decode(&p).ok().flatten()),
                },
                &admins,
            );
        }
        Ok(timeline)
    }

    // ---- talking --------------------------------------------------------

    pub async fn info(&mut self, channel: &[u8; 32]) -> Result<ChannelInfo> {
        let body = self
            .post(
                "/channel/info",
                ByChannel { channel: *channel }.encode(TYPE_INFO),
            )
            .await?;
        ChannelInfo::decode(&body).map_err(|e| ChatError::Protocol(e.to_string()))
    }

    /// Seal a message and post it.
    ///
    /// `them` is needed because sending into a conversation nobody has minted a
    /// key for yet is how most first messages go, and minting needs to know who
    /// to seal to.
    pub async fn send(&mut self, channel: &[u8; 32], them: &PubKey, text: &str) -> Result<Posted> {
        self.send_post(channel, them, SipPost::text(text)).await
    }

    /// Send a message built by the caller — text, attachments, a reply, or a
    /// combination. `send` is this with one text part.
    pub async fn send_post(
        &mut self,
        channel: &[u8; 32],
        them: &PubKey,
        post: SipPost,
    ) -> Result<Posted> {
        post.validate().map_err(|e| ChatError::Protocol(e.to_string()))?;
        self.send_body(channel, them, Body::Post(post)).await
    }

    async fn send_body(
        &mut self,
        channel: &[u8; 32],
        them: &PubKey,
        body: Body,
    ) -> Result<Posted> {
        let epoch = self.ensure_epoch(channel, them).await?;
        let info = self.info(channel).await?;
        let key = self
            .store
            .key(channel, epoch)?
            .ok_or(ChatError::NoKey(epoch))?;

        // The counter must never repeat under one key. Take the higher of what
        // we remember and what the exchange accepted from us — the exchange
        // keeps it independently of pruning precisely so a client that lost the
        // number can resume without guessing.
        let (_, mine, seen_epoch) = self.store.cursor(channel)?;
        let local = if seen_epoch == epoch { mine } else { 0 };
        let msg_seq = local.max(info.my_msg_seq) + 1;

        let sealed = key
            .seal(channel, epoch, &self.me, msg_seq, &body.encode())
            .map_err(|e| ChatError::Protocol(e.to_string()))?;

        // Recorded before the post, not after. If the answer is lost in flight
        // the entry may still have landed, and burning a counter costs nothing
        // while reusing one costs the confidentiality of two messages.
        self.store.set_msg_seq(channel, epoch, msg_seq)?;

        let out = self
            .post(
                "/channel/post",
                Post {
                    channel: *channel,
                    epoch,
                    msg_seq,
                    expires_after: 0,
                    body: sealed,
                }
                .encode(),
            )
            .await?;
        Posted::decode(&out).map_err(|e| ChatError::Protocol(e.to_string()))
    }

    /// Say we are typing. Best-effort: a signal nobody stores is not worth an
    /// error path.
    pub async fn typing(&mut self, channel: &[u8; 32], on: bool) {
        use sqex_proto::channel::SignalOut;
        use sqex_proto::message::{SIGNAL_TYPING, Signal};
        let body = Signal::Typing(on).encode();
        let _ = self
            .client
            .post(
                "/channel/signal",
                SignalOut {
                    channel: *channel,
                    kind: SIGNAL_TYPING,
                    body,
                }
                .encode(),
            )
            .await;
    }

    /// Fetch what is new, open it, and fold it into a conversation.
    ///
    /// `timeline` carries what we already had, so this is incremental: the
    /// exchange is asked only for entries past our cursor.
    pub async fn poll(
        &mut self,
        channel: &[u8; 32],
        timeline: &mut Timeline,
        wait_secs: u16,
    ) -> Result<Conversation> {
        let (since, _, _) = self.store.cursor(channel)?;
        let body = self
            .post(
                "/channel/fetch",
                Fetch {
                    channel: *channel,
                    since,
                    wait_secs,
                }
                .encode(),
            )
            .await?;
        let entries = Entries::decode(&body).map_err(|e| ChatError::Protocol(e.to_string()))?;

        // Being below the oldest retained entry means we have been away longer
        // than the window. There is history we can never fill, and presenting
        // what remains as the whole conversation would be a lie.
        let gap = since > 0 && entries.first > since;

        // Who may redact and whose metadata counts — Timeline needs this, and
        // it is only in the member list.
        let info = self.info(channel).await?;
        let admins: Vec<PubKey> = info
            .members
            .iter()
            .filter(|m| m.role == Role::Admin)
            .map(|m| m.account)
            .collect();

        let mut replay = self.store.replay_for(channel)?;
        let mut last = since;
        for e in &entries.entries {
            last = last.max(e.seq);
            if e.kind == KIND_MEMBER {
                // SIP-17: a counter we have already seen under this key is
                // either the exchange replaying or somebody else doing it, and
                // it must not be decrypted.
                if !replay.accept(&e.device, e.epoch, e.msg_seq) {
                    continue;
                }
                self.store.record_seen(channel, &e.device, e.epoch, e.msg_seq)?;
            }
            let plain = self
                .store
                .key(channel, e.epoch)
                .ok()
                .flatten()
                .and_then(|k| k.open(channel, e.epoch, &e.device, e.msg_seq, &e.body).ok());
            // Kept, not cached. The counter may not be decrypted twice and the
            // exchange serves an epoch key's envelope once, so a message not
            // written here is one this client can never read again.
            self.store.put_message(
                channel,
                e.seq,
                &e.account,
                e.posted,
                e.kind,
                plain.as_deref(),
            )?;
            let body = plain.and_then(|p| Body::decode(&p).ok().flatten());
            timeline.apply(
                &Received {
                    seq: e.seq,
                    account: e.account,
                    posted: e.posted,
                    kind: e.kind,
                    body,
                },
                &admins,
            );
        }
        if last > since {
            self.store.set_since(channel, last)?;
        }

        let typing = entries.signals.iter().any(|s| {
            use sqex_proto::message::{SIGNAL_TYPING, Signal};
            s.kind == SIGNAL_TYPING
                && matches!(Signal::decode(&s.body), Ok(Some(Signal::Typing(true))))
        });

        Ok(Conversation {
            timeline: timeline.clone(),
            unreadable: timeline.unreadable().to_vec(),
            gap,
            typing,
            last,
        })
    }

    /// Mark everything up to `seq` read, so the other side's client can say so.
    pub async fn mark_read(&mut self, channel: &[u8; 32], seq: u64) -> Result<()> {
        use sqex_proto::channel::Cursor;
        let body = self
            .post(
                "/channel/cursor",
                Cursor {
                    channel: *channel,
                    read: seq,
                    receipts: true,
                }
                .encode(),
            )
            .await?;
        Ack::decode(&body).map_err(|e| ChatError::Protocol(e.to_string()))?;
        Ok(())
    }
}
