//! The protocol half: prekeys, epoch keys, posting and fetching.
//!
//! Everything here is done by the client, and that is the point — if the
//! exchange could do any of it, the design would be wrong. It seals, it opens,
//! it verifies prekey signatures itself, and it refuses a replayed counter,
//! because the exchange is either unable or is the party being constrained.

use sqex_proto::channel::{
    Ack, ByAccount, ByChannel, ChannelInfo, Create, Entries, Fetch, Invite, Invitee, KIND_MEMBER,
    List, Listing, MAX_MINE, MAX_NAME, MAX_TOPIC, Membership, Mine, Mines, Post, Posted, Role,
    TYPE_INFO, TYPE_JOIN, TYPE_LEAVE, TYPE_REMOVE, Visibility, direct_message_id,
};
use sqex_proto::channel_key::{
    Absent, ChannelKey, Get as KeyGet, Got, Put as KeyPut, PutAck, TYPE_MISSING, open_envelope,
    seal_envelope,
};
use sqex_proto::credential::{Credential, SCOPE_CHAT};
use sqex_proto::device::{Device, Devices, ListDevices, Register, Revoke};
use sqex_proto::message::{Body, Post as SipPost};
use sqex_proto::prekey::{
    Cleared, Counts, LOW_WATER, POOL, Pool, Prekey, Publish, TYPE_CLEAR, TYPE_COUNT, Take, Taken,
};
use sqex_proto::timeline::{Received, Timeline};
use sqnr::Client;
use sqnr_core::PubKey;

use crate::store::{Kept, Store, StoreError};

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
    /// An envelope for that recipient and epoch already exists. SIP-17 has the
    /// exchange refuse a second, so re-keying somebody means a new epoch.
    AlreadyKeyed(u32),
    /// The operation is an admin's and this account is not one.
    NotAnAdmin,
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
            ChatError::AlreadyKeyed(epoch) => write!(
                f,
                "they already have an envelope for epoch {epoch} and the exchange will not \
                 replace it — if they cannot open it, rotate to hand out a new key"
            ),
            ChatError::NotAnAdmin => write!(f, "that is an admin's to do, and you are not one"),
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

/// Everybody a channel key must reach.
fn members_of(info: &ChannelInfo) -> Vec<PubKey> {
    info.members.iter().map(|m| m.account).collect()
}

/// Everyone a channel key must actually reach.
///
/// **Devices, not accounts.** SIP-17 derives its per-sender subkey from the
/// device precisely so two clients under one identity do not share one and
/// reuse a nonce — so an envelope has to be openable by the device that will
/// use it, and a device holds its own key, not its account's.
///
/// An account with no registered devices is its own device, which is the
/// ordinary single-client case and why this was invisible for so long.
impl Chat {
    async fn devices_of(&mut self, members: &[PubKey]) -> Result<Vec<PubKey>> {
        let mut out = Vec::new();
        for account in members {
            let body = self
                .post("/device/list", ListDevices { account: *account }.encode())
                .await?;
            let listed =
                Devices::decode(&body).map_err(|e| ChatError::Protocol(e.to_string()))?;
            if listed.devices.is_empty() {
                out.push(*account);
            } else {
                out.extend(listed.devices.iter().map(|d| d.device));
            }
        }
        Ok(out)
    }
}

/// Whether an account may mint an epoch here.
fn is_admin(info: &ChannelInfo, who: &PubKey) -> bool {
    info.members
        .iter()
        .any(|m| m.account == *who && m.role == Role::Admin)
}

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
    /// Entries held under a superseded epoch we have no key for. Gone for
    /// good, as against `unreadable`, which is something to wait for.
    pub lost: usize,
    /// Somebody is typing (SIP-19's only signal).
    pub typing: bool,
    pub last: u64,
    /// Who may redact and rename, as of this fetch. Returned so a caller can
    /// keep its own copy current: the next start may be offline, and folding a
    /// history without it shows a redacted message and an unnamed channel.
    pub admins: Vec<PubKey>,
}

pub struct Chat {
    client: Client,
    seed: [u8; 32],
    /// The account we act for. Membership, roles, direct-message identifiers
    /// and display are all per account.
    pub me: PubKey,
    /// This client's own key. Sealing subkeys, message counters and prekeys are
    /// all per device, which is the distinction SIP-17 and SIP-22 exist to
    /// draw — two clients under one identity must not share a subkey.
    device: PubKey,
    store: Store,
}

impl Chat {
    /// `device` is this client's own key — what it seals under, publishes
    /// prekeys for, and counts messages with. The **account** it acts for is
    /// usually the same key, and is not once the client has been linked to
    /// one, which is what `device claim` records.
    pub fn new(client: Client, seed: [u8; 32], device: PubKey, store: Store) -> Chat {
        let me = store.account().ok().flatten().unwrap_or(device);
        Chat {
            client,
            seed,
            me,
            device,
            store,
        }
    }

    /// This client's own key, as against the account it acts for.
    pub fn device(&self) -> PubKey {
        self.device
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
            // A refusal the caller can act on, rather than a status code it has
            // to parse. This one matters now that the client no longer decides
            // locally whether it may rotate: SIP-17 lets a member rekey after
            // revoking one of its own devices, and only the exchange holds the
            // facts to judge it.
            if code == 403 && said.contains("not_an_admin") {
                return Err(ChatError::NotAnAdmin);
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
        // What the **exchange** holds, not what we remember publishing. They
        // can differ, and the difference is invisible from here: an exchange
        // restored from a backup, or one that lost its pool, leaves a client
        // whose own count looks healthy with nothing published and no reason to
        // notice. The failure that produces is silent and total — every seal to
        // this device is refused, so no channel key reaches it.
        //
        // Our own count still matters and is not redundant: a secret we no
        // longer hold is useless however many the exchange is serving, so the
        // pool is topped up to satisfy whichever of the two is short.
        let served = match self.post("/prekey/count", vec![TYPE_COUNT]).await {
            Ok(body) => Counts::decode(&body)
                .map(|c| c.one_time)
                .unwrap_or(pool.one_time_left()),
            Err(_) => pool.one_time_left(),
        };
        let have = pool.one_time_left().min(served);

        let mut publish = Vec::new();
        if have < LOW_WATER {
            publish.extend(pool.mint_one_time(POOL - have));
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

    /// The channels this account is in, as the exchange sees them.
    ///
    /// The only way to learn about a channel nobody told us about. For direct
    /// messages it is a cross-check rather than a discovery — the identifier
    /// derives from the two accounts — but it is what finds a conversation
    /// somebody started with us while this client had never heard of them.
    pub async fn mine(&mut self) -> Result<Vec<Membership>> {
        let mut all = Vec::new();
        let mut offset = 0u32;
        loop {
            let body = self.post("/channel/mine", Mine { offset }.encode()).await?;
            let page = Mines::decode(&body).map_err(|e| ChatError::Protocol(e.to_string()))?;
            let got = page.channels.len();
            all.extend(page.channels);
            // The total can move under paging as memberships change; stopping
            // on a short page rather than on the count avoids looping forever
            // if it grows while we read.
            if got < MAX_MINE || all.len() as u32 >= page.total {
                break;
            }
            offset += got as u32;
        }
        Ok(all)
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
    pub async fn ensure_epoch(&mut self, channel: &[u8; 32]) -> Result<u32> {
        let info = self.info(channel).await?;
        // A public channel has no epoch and never gains one. Everything in it
        // is stored in the clear, because anybody may join and would therefore
        // hold any key it used — SIP-16 says so plainly, and encrypting anyway
        // would produce something that looks end-to-end and is not.
        if info.visibility == Visibility::Public {
            return Ok(0);
        }
        if info.epoch == 0 {
            let to = self.devices_of(&members_of(&info)).await?;
            self.mint_epoch(channel, 1, &to).await?;
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
                // Minting the next epoch is the way out that SIP-17 already
                // provides, and it is an **admin's** move. In a direct message
                // both parties are admins so it always applies; in a group, a
                // member who was simply never given the key would be seizing an
                // epoch they were deliberately left out of, so a member without
                // the role is told plainly instead.
                if !is_admin(&info, &self.me) {
                    return Err(ChatError::NoKey(info.epoch));
                }
                let to = self.devices_of(&members_of(&info)).await?;
                self.mint_epoch(channel, info.epoch + 1, &to).await?;
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

    /// Mint an epoch key and seal it to every member.
    ///
    /// Including ourselves: our own other devices need it, and the exchange
    /// keeps the envelope for collection rather than for storage.
    ///
    /// A member who has published no prekeys is **skipped rather than fatal**.
    /// SIP-17 says a rotation must not be blocked by one member being
    /// unreachable — a security mechanism able to prevent a revocation is a
    /// poor trade — and SIP-23 says a device that has published nothing cannot
    /// be sealed to at all. They heal it themselves by publishing prekeys and
    /// collecting, which is why `Missing` exists. The one case where being
    /// unreachable *is* fatal is a two-party conversation, where skipping the
    /// other party leaves nobody to talk to.
    async fn mint_epoch(
        &mut self,
        channel: &[u8; 32],
        epoch: u32,
        members: &[PubKey],
    ) -> Result<()> {
        let key = ChannelKey::generate();
        let mut envelopes = Vec::new();
        let mut skipped = Vec::new();
        for who in members {
            match self.take_prekey_for(*who).await {
                Ok(p) => envelopes.push(
                    seal_envelope(who, p.id, &p.public, epoch, &[key])
                        .map_err(|e| ChatError::Protocol(e.to_string()))?,
                ),
                Err(ChatError::NotReady(w)) if members.len() > 2 => skipped.push(w),
                Err(e) => return Err(e),
            }
        }
        if envelopes.is_empty() {
            return Err(ChatError::NotReady(
                skipped.first().copied().unwrap_or(self.me),
            ));
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
            // Somebody else minted the same epoch first. One `Put` wins and the
            // loser collects instead — this is the creation race settling, not
            // an error, and in a direct message it is the ordinary outcome of
            // both ends starting at once.
            self.collect_keys(channel).await?;
        }
        // We spent one prekey per member getting here, our own included.
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
            // Entries under these epochs were held and unreadable; now they are
            // not. Nothing else would ever revisit them.
            self.store.rewind(channel)?;
        }
        if opened > 0 {
            self.top_up_prekeys().await?;
        }
        Ok(opened)
    }

    /// Rebuild a conversation from what this client kept.
    ///
    /// Needs no network and must not: the entries are still on the exchange but
    /// they will not open a second time, so this store is the only place the
    /// conversation exists. `admins` is what `Timeline` needs to judge a
    /// redaction or a metadata change, and it is remembered from the last poll
    /// so that a client starting offline still folds correctly.
    pub fn history(&self, channel: &[u8; 32], admins: &[PubKey]) -> Result<Timeline> {
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
                admins,
            );
        }
        Ok(timeline)
    }

    // ---- devices (SIP-20 and SIP-22) ------------------------------------

    /// The devices this account has registered, and when each expires.
    pub async fn my_devices(&mut self) -> Result<Vec<Device>> {
        let body = self
            .post("/device/list", ListDevices { account: self.me }.encode())
            .await?;
        Ok(Devices::decode(&body)
            .map_err(|e| ChatError::Protocol(e.to_string()))?
            .devices)
    }

    /// Sign a credential naming `device`, so that device may act for us.
    ///
    /// The credential is **portable and self-contained**: anybody holding the
    /// account key can verify it with no record of the grant, which is what
    /// lets a device present it to an exchange that has never heard of it. That
    /// is also why it cannot be withdrawn — revocation is SIP-22's half, and it
    /// lives at the exchange because a signature cannot un-sign itself.
    pub fn issue_credential(&self, device: &PubKey, lifetime: u64) -> Result<Credential> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        Credential::issue(&self.seed, device, SCOPE_CHAT, now, now + lifetime)
            .map_err(|e| ChatError::Protocol(e.to_string()))
    }

    /// Register ourselves as a device of the account that signed `credential`.
    ///
    /// Called by the **new** device, on its own connection: the credential's
    /// delegate must equal the caller's transport identity, so a credential
    /// somebody found is a credential they cannot use.
    pub async fn register_self(&mut self, credential: &Credential) -> Result<()> {
        self.post(
            "/device/register",
            Register {
                credential: credential.clone(),
            }
            .encode(),
        )
        .await?;
        Ok(())
    }

    /// Hand the epoch in force to our own other devices.
    ///
    /// SIP-17 permits this without an admin — a device may seal to devices of
    /// its own account — and it is how a client linked after a conversation
    /// started gets in without anybody rotating. Rotating instead would be the
    /// wrong tool: it would deny the new device everything said before it, and
    /// disturb every other member to do it.
    ///
    /// One envelope per request, because the exchange refuses a whole batch if
    /// any single recipient already holds one for that epoch — and a sibling
    /// that already has its key is the ordinary case, not a failure.
    pub async fn reseal_to_siblings(&mut self, channel: &[u8; 32]) -> Result<usize> {
        let info = self.info(channel).await?;
        if info.epoch == 0 {
            return Ok(0);
        }
        let key = self
            .store
            .key(channel, info.epoch)?
            .ok_or(ChatError::NoKey(info.epoch))?;

        let mut sealed = 0;
        let mut siblings = 0;
        for device in self.my_devices().await? {
            if device.device == self.device {
                continue;
            }
            siblings += 1;
            let p = match self.take_prekey_for(device.device).await {
                Ok(p) => p,
                // Not yet started, so nothing to seal to. It will collect once
                // it has published, and asking again costs one request.
                Err(ChatError::NotReady(_)) => continue,
                Err(e) => return Err(e),
            };
            let envelope = seal_envelope(&device.device, p.id, &p.public, info.epoch, &[key])
                .map_err(|e| ChatError::Protocol(e.to_string()))?;
            let body = self
                .post(
                    "/channel/key/put",
                    KeyPut {
                        channel: *channel,
                        epoch: info.epoch,
                        envelopes: vec![envelope],
                    }
                    .encode(),
                )
                .await?;
            if PutAck::decode(&body)
                .map_err(|e| ChatError::Protocol(e.to_string()))?
                .accepted
            {
                sealed += 1;
            }
        }
        self.top_up_prekeys().await?;
        if siblings > 0 && sealed == 0 {
            // They already hold this epoch, or they have published nothing to
            // seal against. Either is ordinary, and saying nothing at all is
            // how the one operation a linked device depends on fails invisibly.
            // One envelope per recipient per epoch, and the exchange will not
            // replace it — so a sibling that already has one either holds the
            // key or lost the secret that opened it, and from here those look
            // identical. Naming the remedy beats reporting a non-event.
            return Err(ChatError::Protocol(format!(
                "{siblings} other device(s) already hold an envelope for epoch {}; \
                 if one of them still cannot read this, /rotate",
                info.epoch
            )));
        }
        Ok(sealed)
    }

    /// Whether this client still acts for the account it was linked to.
    ///
    /// `None` when it was never linked — an account with no registered devices
    /// is its own device, and there is nothing to check. `Some(false)` means it
    /// has been revoked, which is otherwise learned only by being refused as a
    /// stranger to every conversation it can see.
    pub async fn still_linked(&mut self) -> Result<Option<bool>> {
        if self.me == self.device {
            return Ok(None);
        }
        let devices = self.my_devices().await?;
        Ok(Some(devices.iter().any(|d| d.device == self.device)))
    }

    /// Which devices in this channel hold no key for the epoch in force.
    ///
    /// SIP-17 says to check after inviting somebody and after any device
    /// registers, because those are the two moments that create a member who
    /// can fetch entries and open none of them — a state nothing else reports.
    pub async fn stranded(&mut self, channel: &[u8; 32]) -> Result<Absent> {
        let body = self
            .post(
                "/channel/key/missing",
                ByChannel { channel: *channel }.encode(TYPE_MISSING),
            )
            .await?;
        Absent::decode(&body).map_err(|e| ChatError::Protocol(e.to_string()))
    }

    /// Withdraw a device.
    ///
    /// What a portable credential structurally cannot do. Note what it does
    /// *not* undo: SIP-17 is explicit that a revoked device keeps every key it
    /// was ever given, so this bounds what happens next rather than reaching
    /// back. Rotating is what actually cuts them off from what follows.
    pub async fn revoke_device(&mut self, device: &PubKey) -> Result<()> {
        self.post("/device/revoke", Revoke { device: *device }.encode())
            .await?;
        Ok(())
    }

    // ---- groups ---------------------------------------------------------

    /// Create a private group and invite its first members.
    ///
    /// The identifier is random, not derived: a group has no two accounts to
    /// derive from, which is exactly why it cannot be found without SIP-16's
    /// `Mine` and why that amendment exists. The name is **not** given to the
    /// exchange — a private channel's name is stored empty there, because a
    /// membership graph plus a name says considerably more than the graph — so
    /// it is posted as a sealed metadata entry once the epoch exists.
    pub async fn create_group(&mut self, name: &str, invite: &[PubKey]) -> Result<[u8; 32]> {
        let mut channel = [0u8; 32];
        {
            use rand_core::RngCore;
            rand_core::OsRng.fill_bytes(&mut channel);
        }
        self.post(
            "/channel/create",
            Create {
                channel,
                visibility: Visibility::Private,
                retention_secs: RETENTION_SECS,
                max_entries: 0,
                name: String::new(),
                topic: String::new(),
                invites: invite
                    .iter()
                    .map(|a| Invitee {
                        account: *a,
                        role: Role::Member,
                    })
                    .collect(),
            }
            .encode(),
        )
        .await?;
        self.ensure_epoch(&channel).await?;
        if !name.is_empty() {
            self.set_name(&channel, name).await?;
        }
        Ok(channel)
    }

    /// Make a public channel: anybody may find it and anybody may join.
    ///
    /// Its name and topic go to the exchange **in the clear**, which is the
    /// point — the directory is how somebody finds a room they were never told
    /// about. A private channel's name is sealed precisely because it has a
    /// membership graph beside it; a public one has nothing to protect.
    pub async fn create_public(&mut self, name: &str, topic: &str) -> Result<[u8; 32]> {
        let mut channel = [0u8; 32];
        {
            use rand_core::RngCore;
            rand_core::OsRng.fill_bytes(&mut channel);
        }
        self.post(
            "/channel/create",
            Create {
                channel,
                visibility: Visibility::Public,
                retention_secs: RETENTION_SECS,
                max_entries: 0,
                name: name.chars().take(MAX_NAME).collect(),
                topic: topic.chars().take(MAX_TOPIC).collect(),
                invites: Vec::new(),
            }
            .encode(),
        )
        .await?;
        Ok(channel)
    }

    /// Search the public directory. An empty query returns everything.
    pub async fn find(&mut self, query: &str, offset: u32) -> Result<Listing> {
        let body = self
            .post(
                "/channel/list",
                List {
                    offset,
                    query: query.to_string(),
                }
                .encode(),
            )
            .await?;
        Listing::decode(&body).map_err(|e| ChatError::Protocol(e.to_string()))
    }

    /// Join a public channel. A private one refuses, which is what stops its
    /// identifier being a way in.
    pub async fn join(&mut self, channel: &[u8; 32]) -> Result<()> {
        self.post(
            "/channel/join",
            ByChannel { channel: *channel }.encode(TYPE_JOIN),
        )
        .await?;
        Ok(())
    }

    /// Name a channel, for everyone who can read it.
    ///
    /// A sealed entry rather than a field, so the exchange never learns what a
    /// private channel is called. Only an admin's is honoured by a reader.
    pub async fn set_name(&mut self, channel: &[u8; 32], name: &str) -> Result<Posted> {
        self.send_body(
            channel,
            Body::Metadata {
                name: name.to_string(),
                topic: String::new(),
                avatar: None,
            },
        )
        .await
    }

    /// Add somebody, and give them the key.
    ///
    /// Inviting does **not** rotate: SIP-17 leaves it to the inviter whether a
    /// new member gets the history, and sealing them the current epoch grants
    /// it. Rotating instead would deny it, which is a different decision and
    /// not one to make silently on somebody's behalf.
    pub async fn invite(&mut self, channel: &[u8; 32], who: &PubKey) -> Result<()> {
        self.post(
            "/channel/invite",
            Invite {
                channel: *channel,
                account: *who,
                role: Role::Member,
            }
            .encode(),
        )
        .await?;
        let info = self.info(channel).await?;
        let key = self
            .store
            .key(channel, info.epoch)?
            .ok_or(ChatError::NoKey(info.epoch))?;
        let mut envelopes = Vec::new();
        for device in self.devices_of(&[*who]).await? {
            let p = self.take_prekey_for(device).await?;
            envelopes.push(
                seal_envelope(&device, p.id, &p.public, info.epoch, &[key])
                    .map_err(|e| ChatError::Protocol(e.to_string()))?,
            );
        }
        let body = self
            .post(
                "/channel/key/put",
                KeyPut {
                    channel: *channel,
                    epoch: info.epoch,
                    envelopes,
                }
                .encode(),
            )
            .await?;
        let ack = PutAck::decode(&body).map_err(|e| ChatError::Protocol(e.to_string()))?;
        self.top_up_prekeys().await?;
        if !ack.accepted {
            // An envelope for this recipient at this epoch already exists, and
            // SIP-17 has the exchange refuse a second — that one-per-recipient
            // rule is what settles the creation race. So a re-invite cannot
            // re-key somebody: if they cannot open the envelope that is already
            // there, the only way to hand them a key is a new epoch.
            return Err(ChatError::AlreadyKeyed(info.epoch));
        }
        Ok(())
    }

    /// Mint the next epoch and seal it to everyone currently in the channel.
    ///
    /// The general remedy an admin has. It is what `remove` does implicitly,
    /// and it is the only way to re-key a member whose envelope for the epoch
    /// in force is one they can no longer open — a lost store, most often.
    /// What was said under the old epoch stays readable to whoever already
    /// holds its key and unreadable to whoever does not; this hands out the
    /// next one, not the last.
    pub async fn rotate(&mut self, channel: &[u8; 32]) -> Result<u32> {
        let info = self.info(channel).await?;
        // Not gated on being an admin here. SIP-17 lets a member rekey after
        // revoking one of its own devices, and the exchange is the party that
        // can check it — it holds both the revocation and the moment the epoch
        // was minted. Refusing locally would make that rule unreachable.
        let _ = is_admin(&info, &self.me);
        let to = self.devices_of(&members_of(&info)).await?;
        self.mint_epoch(channel, info.epoch + 1, &to).await?;
        Ok(self.info(channel).await?.epoch)
    }

    /// Add somebody without giving them the key.
    ///
    /// The exchange permits it and SIP-17 describes the result: a member who
    /// can fetch entries and open none of them. Exposed for tests, because the
    /// distinction between history that is gone and a key that has not arrived
    /// is only worth having if both sides of it are checked.
    #[doc(hidden)]
    pub async fn post_invite_without_key(
        &mut self,
        channel: &[u8; 32],
        who: &PubKey,
    ) -> Result<()> {
        self.post(
            "/channel/invite",
            Invite {
                channel: *channel,
                account: *who,
                role: Role::Member,
            }
            .encode(),
        )
        .await?;
        Ok(())
    }

    /// Remove somebody, and rotate so what follows is not theirs.
    ///
    /// The rotation is the point and it is not optional: the exchange refuses
    /// them further entries, but a removed member keeps every key it was ever
    /// given (SIP-17 says so plainly), so without a new epoch they can still
    /// read everything posted after they left from the exchange's own copy —
    /// or from anyone who forwards it.
    pub async fn remove(&mut self, channel: &[u8; 32], who: &PubKey) -> Result<()> {
        self.post(
            "/channel/remove",
            ByAccount {
                channel: *channel,
                account: *who,
            }
            .encode(TYPE_REMOVE),
        )
        .await?;
        let info = self.info(channel).await?;
        let to = self.devices_of(&members_of(&info)).await?;
        self.mint_epoch(channel, info.epoch + 1, &to).await?;
        Ok(())
    }

    /// Leave a channel.
    pub async fn leave(&mut self, channel: &[u8; 32]) -> Result<()> {
        self.post(
            "/channel/leave",
            ByChannel { channel: *channel }.encode(TYPE_LEAVE),
        )
        .await?;
        Ok(())
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
    /// Minting on demand is how most first messages go, so this may distribute
    /// a key before it posts anything.
    pub async fn send(&mut self, channel: &[u8; 32], text: &str) -> Result<Posted> {
        self.send_post(channel, SipPost::text(text)).await
    }

    /// Send a message built by the caller — text, attachments, a reply, or a
    /// combination. `send` is this with one text part.
    pub async fn send_post(&mut self, channel: &[u8; 32], post: SipPost) -> Result<Posted> {
        post.validate().map_err(|e| ChatError::Protocol(e.to_string()))?;
        self.send_body(channel, Body::Post(post)).await
    }

    /// Seal and post any SIP-19 body — a message, an edit, a reaction, or the
    /// channel's own metadata.
    pub async fn send_body(&mut self, channel: &[u8; 32], body: Body) -> Result<Posted> {
        let epoch = self.ensure_epoch(channel).await?;
        let info = self.info(channel).await?;

        // The counter must never repeat under one key. Take the higher of what
        // we remember and what the exchange accepted from us — the exchange
        // keeps it independently of pruning precisely so a client that lost the
        // number can resume without guessing.
        let (_, mine, seen_epoch) = self.store.cursor(channel)?;
        let local = if seen_epoch == epoch { mine } else { 0 };
        let msg_seq = local.max(info.my_msg_seq) + 1;

        let plain = body.encode();
        let sealed = if epoch == 0 {
            // Public: posted as it stands. The counter is still kept, because
            // the exchange orders on it and a reader still sees which device
            // said what — it simply is not a nonce here, since there is no key.
            plain
        } else {
            self.store
                .key(channel, epoch)?
                .ok_or(ChatError::NoKey(epoch))?
                .seal(channel, epoch, &self.device, msg_seq, &plain)
                .map_err(|e| ChatError::Protocol(e.to_string()))?
        };

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
        let mut info = self.info(channel).await?;

        // Somebody may have rotated while this client was running — after a
        // removal, or after revoking a device. Collect once when we hold no key
        // for the epoch in force, or a client would sit showing unreadable
        // entries until it was restarted.
        if info.epoch > 0 && self.store.key(channel, info.epoch)?.is_none() {
            self.collect_keys(channel).await?;
            info = self.info(channel).await?;
        }
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
            }
            let plain = if e.epoch == 0 {
                // Epoch 0 is unsealed by construction: every entry in a public
                // channel, and the exchange's own system entries everywhere.
                Some(e.body.clone())
            } else {
                self.store
                    .key(channel, e.epoch)
                    .ok()
                    .flatten()
                    .and_then(|k| k.open(channel, e.epoch, &e.device, e.msg_seq, &e.body).ok())
            };
            // Kept, not cached. The counter may not be decrypted twice and the
            // exchange serves an epoch key's envelope once, so a message not
            // written here is one this client can never read again.
            // Recorded only once it has actually been opened. SIP-17's rule is
            // that a counter must not be *decrypted* twice; marking one seen on
            // an attempt that failed would refuse the entry for good, which is
            // exactly what happens to a device linked after the fact — it polls
            // before its key arrives, and every message it could not read then
            // stays unreadable forever.
            if plain.is_some() && e.kind == KIND_MEMBER {
                self.store.record_seen(channel, &e.device, e.epoch, e.msg_seq)?;
            }
            self.store.put_message(
                channel,
                Kept {
                    seq: e.seq,
                    account: e.account,
                    posted: e.posted,
                    kind: e.kind,
                    plain: plain.as_deref(),
                },
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

        // Everything the timeline could not open, minus what is gone for good:
        // the two are counted apart because they deserve different words, and
        // reporting a permanent loss every session as though it were a fault
        // is how a status line stops being read.
        // Whether an unopened entry is gone or merely late is one question
        // about the channel, not one per message: if we hold the key for the
        // epoch in force, anything still shut is under an older one, and a
        // rotation hands out the next epoch and never a past one. If we do not
        // hold it, the opposite — an admin can still send it.
        //
        // Derived rather than recorded, deliberately. An earlier version wrote
        // the judgement onto each row as it arrived, which went stale the
        // moment a rotation changed the answer and left rows nothing would
        // ever revisit.
        let have_current = self.store.key(channel, info.epoch)?.is_some();
        let shut: Vec<u64> = timeline.unreadable().to_vec();
        Ok(Conversation {
            lost: if have_current { shut.len() } else { 0 },
            unreadable: if have_current { Vec::new() } else { shut },
            timeline: timeline.clone(),
            gap,
            typing,
            last,
            admins,
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
