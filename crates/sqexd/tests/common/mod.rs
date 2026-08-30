//! SIP-31 signing, for tests that speak the wire directly.
//!
//! An integration test here builds its own `Post`, `Create` and membership
//! requests, and every one of them now carries a signature the exchange checks.
//! Producing one needs three things a test would otherwise not care about: the
//! exchange's own key, the channel's incarnation, and this device's chain
//! position. The first is fixed per server; the other two come from
//! `/channel/info`, which is one extra request and keeps every test honest
//! about resuming the chain rather than guessing at it.

#![allow(dead_code)]

use sqex_proto::channel::{Action, ChannelInfo, Create, Invitee, Post, Role, Visibility};
use sqex_proto::entry_sig::{
    ActionTerms, EntryTerms, GENESIS, Place, link, sign_action, sign_entry,
};
use sqnr::Client;
use sqnr_core::PubKey;

/// Everything needed to sign as one device against one exchange.
#[derive(Clone, Copy)]
pub struct Signer {
    pub seed: [u8; 32],
    pub account: PubKey,
    pub device: PubKey,
    pub exchange: PubKey,
}

impl Signer {
    pub fn new(seed: [u8; 32], key: PubKey, server_pub: [u8; 32]) -> Signer {
        Signer {
            seed,
            account: key,
            device: key,
            exchange: PubKey::new(server_pub),
        }
    }

    /// A linked device: signs as itself, acts for another account.
    pub fn for_account(mut self, account: PubKey) -> Signer {
        self.account = account;
        self
    }

    pub async fn info(&self, client: &mut Client, channel: [u8; 32]) -> ChannelInfo {
        use sqex_proto::channel::{ByChannel, TYPE_INFO};
        let (code, body) = client
            .post("/channel/info", ByChannel { channel }.encode(TYPE_INFO))
            .await
            .unwrap();
        assert_eq!(code, 200, "info refused while signing");
        ChannelInfo::decode(&body).unwrap()
    }

    fn place(&self, instance: [u8; 32], channel: [u8; 32]) -> Place {
        Place {
            exchange: self.exchange,
            instance,
            channel,
        }
    }

    /// A signed post, at the chain position the exchange is expecting.
    pub async fn post(
        &self,
        client: &mut Client,
        channel: [u8; 32],
        epoch: u32,
        msg_seq: u64,
        body: Vec<u8>,
    ) -> Post {
        let info = self.info(client, channel).await;
        self.post_at(&info, channel, epoch, msg_seq, body)
    }

    /// The same, when the caller already has the info in hand.
    pub fn post_at(
        &self,
        info: &ChannelInfo,
        channel: [u8; 32],
        epoch: u32,
        msg_seq: u64,
        body: Vec<u8>,
    ) -> Post {
        let terms = EntryTerms {
            place: self.place(info.instance, channel),
            account: self.account,
            device: self.device,
            epoch,
            msg_seq,
            expires_after: 0,
            chain_seq: info.my_chain_seq,
            prev: info.my_chain_head,
            body: &body,
        };
        Post {
            channel,
            epoch,
            msg_seq,
            expires_after: 0,
            chain_seq: info.my_chain_seq,
            prev: info.my_chain_head,
            sig: sign_entry(&self.seed, &terms),
            body,
        }
    }

    /// An action for a channel this device is not in yet — a join.
    ///
    /// Signed against the incarnation the caller already knows (from the
    /// directory, or because it created the channel), and from this device's
    /// own chain state rather than the exchange's report, which it cannot ask
    /// for without the membership it is trying to acquire.
    #[allow(clippy::too_many_arguments)]
    pub fn action_outside(
        &self,
        channel: [u8; 32],
        instance: [u8; 32],
        event: u8,
        subject: &PubKey,
        arg: &[u8],
        chain_seq: u64,
        prev: [u8; 32],
    ) -> Action {
        let terms = ActionTerms {
            place: self.place(instance, channel),
            actor: self.account,
            actor_device: self.device,
            event,
            subject: *subject,
            arg,
            chain_seq,
            prev,
        };
        Action {
            chain_seq,
            prev,
            sig: sign_action(&self.seed, &terms).unwrap(),
        }
    }

    /// A post for a channel this device is not in — used where the refusal is
    /// the point, and asking `Info` first would be refused instead, which is
    /// the right answer for the wrong reason.
    pub fn post_outside(
        &self,
        channel: [u8; 32],
        instance: [u8; 32],
        epoch: u32,
        msg_seq: u64,
        body: Vec<u8>,
    ) -> Post {
        let info = ChannelInfo {
            instance,
            my_chain_seq: 0,
            my_chain_head: GENESIS,
            ..blank()
        };
        self.post_at(&info, channel, epoch, msg_seq, body)
    }

    pub async fn action(
        &self,
        client: &mut Client,
        channel: [u8; 32],
        event: u8,
        subject: &PubKey,
        arg: &[u8],
    ) -> Action {
        let info = self.info(client, channel).await;
        self.action_at(&info, channel, event, subject, arg)
    }

    pub fn action_at(
        &self,
        info: &ChannelInfo,
        channel: [u8; 32],
        event: u8,
        subject: &PubKey,
        arg: &[u8],
    ) -> Action {
        let terms = ActionTerms {
            place: self.place(info.instance, channel),
            actor: self.account,
            actor_device: self.device,
            event,
            subject: *subject,
            arg,
            chain_seq: info.my_chain_seq,
            prev: info.my_chain_head,
        };
        Action {
            chain_seq: info.my_chain_seq,
            prev: info.my_chain_head,
            sig: sign_action(&self.seed, &terms).unwrap(),
        }
    }

    /// A create with one `added` signed per invitee, against the incarnation it
    /// proposes. The creator chooses the incarnation because SIP-31 binds it
    /// into every signature and there is nothing to ask yet.
    pub fn create(
        &self,
        channel: [u8; 32],
        instance: [u8; 32],
        visibility: Visibility,
        retention_secs: u32,
        name: &str,
        invites: Vec<Invitee>,
    ) -> Create {
        self.create_chained(
            &mut Chain::default(),
            channel,
            instance,
            visibility,
            retention_secs,
            name,
            invites,
        )
    }

    /// The same, advancing a chain the caller keeps.
    ///
    /// A create consumes one chain position per invitee, so a peer that goes on
    /// to rotate or post in the same channel must carry that forward — starting
    /// again from zero is a fork, and the exchange says so.
    #[allow(clippy::too_many_arguments)]
    pub fn create_chained(
        &self,
        chain: &mut Chain,
        channel: [u8; 32],
        instance: [u8; 32],
        visibility: Visibility,
        retention_secs: u32,
        name: &str,
        invites: Vec<Invitee>,
    ) -> Create {
        let mut actions = Vec::with_capacity(invites.len());
        for i in invites.iter() {
            actions.push(self.action_chained(
                chain,
                channel,
                instance,
                sqex_proto::channel::EVENT_ADDED,
                &i.account,
                &[i.role as u8],
            ));
        }
        Create {
            channel,
            instance,
            visibility,
            retention_secs,
            max_entries: 0,
            name: name.into(),
            topic: String::new(),
            invites,
            actions,
        }
    }
}

/// A device's chain in one channel, advanced locally as it signs.
///
/// What a client keeps: the position it will use next and the link to put in
/// it. Tests that post more than once per device need this, because the second
/// post from a fixed starting point is a fork.
pub struct Chain {
    pub seq: u64,
    pub head: [u8; 32],
}

impl Default for Chain {
    fn default() -> Chain {
        Chain { seq: 0, head: GENESIS }
    }
}

impl Signer {
    /// A signed post that advances `chain`.
    pub fn post_chained(
        &self,
        chain: &mut Chain,
        channel: [u8; 32],
        instance: [u8; 32],
        epoch: u32,
        msg_seq: u64,
        body: Vec<u8>,
    ) -> Post {
        let terms = EntryTerms {
            place: Place { exchange: self.exchange, instance, channel },
            account: self.account,
            device: self.device,
            epoch,
            msg_seq,
            expires_after: 0,
            chain_seq: chain.seq,
            prev: chain.head,
            body: &body,
        };
        let sig = sign_entry(&self.seed, &terms);
        let head = link(&terms.input());
        let post = Post {
            channel,
            epoch,
            msg_seq,
            expires_after: 0,
            chain_seq: chain.seq,
            prev: chain.head,
            sig,
            body,
        };
        chain.seq += 1;
        chain.head = head;
        post
    }

    /// A signed post at the chain's **current** position, leaving it there.
    ///
    /// For requests a test expects to be refused. A chain position is spent
    /// when something is in the log at it, so advancing over a refusal would
    /// leave a gap the exchange then reports as a broken chain — which is the
    /// rule working, not the test being awkward.
    pub fn post_probe(
        &self,
        chain: &Chain,
        channel: [u8; 32],
        instance: [u8; 32],
        epoch: u32,
        msg_seq: u64,
        body: Vec<u8>,
    ) -> Post {
        let mut scratch = Chain { seq: chain.seq, head: chain.head };
        self.post_chained(&mut scratch, channel, instance, epoch, msg_seq, body)
    }

    /// A signed action that advances `chain`.
    pub fn action_chained(
        &self,
        chain: &mut Chain,
        channel: [u8; 32],
        instance: [u8; 32],
        event: u8,
        subject: &PubKey,
        arg: &[u8],
    ) -> Action {
        let terms = ActionTerms {
            place: Place { exchange: self.exchange, instance, channel },
            actor: self.account,
            actor_device: self.device,
            event,
            subject: *subject,
            arg,
            chain_seq: chain.seq,
            prev: chain.head,
        };
        let action = Action {
            chain_seq: chain.seq,
            prev: chain.head,
            sig: sign_action(&self.seed, &terms).unwrap(),
        };
        chain.seq += 1;
        chain.head = link(&terms.input().unwrap());
        action
    }
}

/// A `ChannelInfo` with nothing in it but what a caller fills in.
fn blank() -> ChannelInfo {
    ChannelInfo {
        visibility: Visibility::Public,
        epoch: 0,
        instance: GENESIS,
        retention_secs: 0,
        max_entries: 0,
        first: 0,
        last: 0,
        my_msg_seq: 0,
        my_chain_seq: 0,
        my_chain_head: GENESIS,
        now: 0,
        members: Vec::new(),
        name: String::new(),
        topic: String::new(),
    }
}

/// A distinct incarnation per test channel. Any 32 bytes will do as long as one
/// identifier never reuses them; the exchange refuses a repeat.
pub fn instance_for(channel: [u8; 32], n: u8) -> [u8; 32] {
    let mut i = channel;
    i[0] ^= 0x5a;
    i[31] ^= n;
    i
}

/// The role byte, as an action's `arg`.
pub fn role_arg(role: Role) -> [u8; 1] {
    [role as u8]
}
