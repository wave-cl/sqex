//! SIP-17 channel keys: one ciphertext, one key, many readers.
//!
//! A private channel is sealed under a symmetric key every member holds and the
//! exchange does not. The key belongs to an **epoch**; an admin mints a new one
//! to rotate, which is what makes removing a member mean more than "cannot
//! post".
//!
//! # Two things that look alike and are not
//!
//! **Rotation is revocation, not forward secrecy.** It stops a removed member
//! reading what is said *next* and does nothing about what was said before —
//! that member keeps every key it was given.
//!
//! **Forward secrecy is the envelope's**, and it comes from SIP-23: the second
//! Diffie-Hellman term uses a prekey whose secret is destroyed on use, so an
//! attacker who copied envelopes and later obtained an identity key gets
//! nothing from them.
//!
//! # Why the subkey is per device and not per person
//!
//! A shared key with a per-sender counter is a nonce-reuse machine: two senders
//! that both start at zero collide on their first message, and
//! ChaCha20-Poly1305 answers that by leaking the XOR of both plaintexts and
//! losing its authentication entirely. A *person* is the wrong unit of
//! separation, because one person runs several clients. A **device** is the
//! right one, because a device is the thing that holds a counter.

use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use sha2::{Digest, Sha512};
use sqnr_core::{Error, PubKey, Result};

use crate::channel::{ACTION_LEN, Action};

/// Domain separator for a sender's subkey.
pub const KEY_CONTEXT: &[u8] = b"sqex-channel-key-v1";
/// Domain separator for sealing an epoch key to a device.
pub const ENVELOPE_CONTEXT: &[u8] = b"sqex-channel-envelope-v1";
/// Domain separator for a SIP-32 publication signature.
///
/// Distinct from the sealing context above, and doing a different job: that one
/// derives the key an envelope is sealed under, this one attests to who put it
/// there. Before it a member received a channel key and could not tell who had
/// handed it over — SIP-31 named this as its nearest residual gap.
pub const ENVELOPE_PUB_CONTEXT: &[u8] = b"sqex-envelope-v1";

pub const TYPE_PUT: u8 = 0x01;
pub const TYPE_GET: u8 = 0x02;
pub const TYPE_MISSING: u8 = 0x03;

/// Envelopes one `Put` may carry. Set by the 64 KiB request body: one envelope
/// is 76 bytes of header plus 16 + 32 × range, so 256 at the current epoch come
/// to 31 KiB, with margin.
/// Envelopes one `Put` may carry.
///
/// **Halved from 256 by SIP-32**, which added a publisher and a signature to
/// each. SIP-17's arithmetic is 80 bytes of header plus `16 + 32 × range` of
/// ciphertext — 128 bytes at the current epoch, and 256 of those came to 32 KiB
/// inside a 64 KiB request. At 224 bytes, 256 of them would be 56 KiB, which
/// leaves no margin against a body that also carries its own header. A fully
/// populated channel already needed several calls and now needs twice as many,
/// which is what the same-epoch `Put` exists to permit.
pub const MAX_ENVELOPES: usize = 128;
/// Epochs one envelope may grant. A single envelope at this range is 32 KiB,
/// which is where the number comes from rather than any property of epochs.
pub const MAX_RANGE: u32 = 1024;
/// Epochs one channel may reach.
pub const MAX_EPOCH: u32 = 65_536;

/// Bytes of envelope header before the ciphertext, inside a `Put`.
// recipient, publisher, signature, from_epoch, to_epoch, prekey_id, ephemeral, len
const ENVELOPE_HEADER: usize = 32 + 32 + 64 + 4 + 4 + 4 + 32 + 4;

/// A channel key: 32 bytes, uniformly random, one per epoch.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct ChannelKey([u8; 32]);

impl ChannelKey {
    pub fn new(bytes: [u8; 32]) -> ChannelKey {
        ChannelKey(bytes)
    }

    pub fn generate() -> ChannelKey {
        use rand_core::RngCore;
        let mut b = [0u8; 32];
        rand_core::OsRng.fill_bytes(&mut b);
        ChannelKey(b)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// The subkey a device seals with, derivable by every member from the
    /// entry header alone — so there is no distribution cost beyond the
    /// channel key and no lookup.
    ///
    /// A single hash truncated to 32 bytes, as SIP-12 and SIP-5 both derive:
    /// consistency across the four constructions is worth more than the
    /// marginal argument for extract-and-expand over inputs that are already
    /// uniformly random.
    pub fn sender_key(&self, channel: &[u8; 32], epoch: u32, device: &PubKey) -> [u8; 32] {
        let mut h = Sha512::new();
        h.update(KEY_CONTEXT);
        h.update(channel);
        h.update(epoch.to_be_bytes());
        h.update(self.0);
        h.update(device.as_bytes());
        let okm = h.finalize();
        let mut key = [0u8; 32];
        key.copy_from_slice(&okm[..32]);
        key
    }

    /// Seal one entry body. `msg_seq` is the sending device's own counter and
    /// MUST NOT repeat within an epoch.
    pub fn seal(
        &self,
        channel: &[u8; 32],
        epoch: u32,
        device: &PubKey,
        msg_seq: u64,
        plaintext: &[u8],
    ) -> Result<Vec<u8>> {
        cipher(&self.sender_key(channel, epoch, device))?
            .encrypt(&nonce(msg_seq), plaintext)
            .map_err(|e| Error::Key(format!("seal entry: {e}")))
    }

    /// Open one entry body, keyed on the device that sealed it.
    pub fn open(
        &self,
        channel: &[u8; 32],
        epoch: u32,
        device: &PubKey,
        msg_seq: u64,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>> {
        cipher(&self.sender_key(channel, epoch, device))?
            .decrypt(&nonce(msg_seq), ciphertext)
            .map_err(|_| Error::Key("cannot open entry: wrong key, or altered".into()))
    }
}

impl std::fmt::Debug for ChannelKey {
    /// Never print the key. A channel key in a log is the whole channel.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ChannelKey(<redacted>)")
    }
}

fn nonce(msg_seq: u64) -> Nonce {
    let mut n = [0u8; 12];
    n[..8].copy_from_slice(&msg_seq.to_be_bytes());
    *Nonce::from_slice(&n)
}

fn cipher(key: &[u8; 32]) -> Result<ChaCha20Poly1305> {
    ChaCha20Poly1305::new_from_slice(key).map_err(|e| Error::Key(format!("cipher: {e}")))
}

/// What a receiver has already accepted, so a repeat is refused.
///
/// SIP-17 requires this and it is free: the counter is in the entry header the
/// exchange already stores, so nothing has to be decrypted to check it. A
/// repeat is a **nonce reuse** — the same `(device, epoch, msg_seq)` means the
/// same subkey and the same nonce, which costs ChaCha20-Poly1305 the
/// confidentiality of both plaintexts and its authentication.
///
/// The realistic cause is not an attacker but a client that lost its counter
/// and guessed, which is why SIP-17 tells a device to recover its high-water
/// mark from the exchange rather than start again.
#[derive(Debug, Default)]
pub struct Replay {
    seen: std::collections::HashSet<(PubKey, u32, u64)>,
}

impl Replay {
    pub fn new() -> Replay {
        Replay::default()
    }

    /// Record an entry, returning `false` if this exact counter has been seen
    /// before. A receiver **MUST** reject the entry when this is false, and
    /// MUST NOT decrypt it.
    pub fn accept(&mut self, device: &PubKey, epoch: u32, msg_seq: u64) -> bool {
        self.seen.insert((*device, epoch, msg_seq))
    }

    /// Forget an epoch once it is rotated past and nothing under it can arrive.
    pub fn forget_epoch(&mut self, epoch: u32) {
        self.seen.retain(|(_, e, _)| *e != epoch);
    }

    pub fn len(&self) -> usize {
        self.seen.len()
    }

    pub fn is_empty(&self) -> bool {
        self.seen.is_empty()
    }
}

/// One epoch key, or a run of them, sealed to one device.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Envelope {
    pub recipient: PubKey,
    /// SIP-32: the device that published this, and its signature over
    /// everything below plus the place it was published to.
    ///
    /// Per envelope rather than per `Put`, because `Get` serves one recipient
    /// the envelopes addressed to it and has to hand over something verifiable
    /// on its own.
    pub publisher: PubKey,
    pub sig: [u8; 64],
    pub from_epoch: u32,
    pub to_epoch: u32,
    /// The SIP-23 prekey this was sealed against. **Zero is invalid**: there is
    /// deliberately no static-only path, because an optional one is a downgrade
    /// a dishonest exchange could force by reporting an empty pool.
    pub prekey_id: u32,
    pub ephemeral: [u8; 32],
    pub ciphertext: Vec<u8>,
}

impl Envelope {
    fn wire_len(&self) -> usize {
        ENVELOPE_HEADER + self.ciphertext.len()
    }
}

/// Seal a run of epoch keys to one device.
///
/// Two Diffie-Hellman terms, and both are load-bearing. DH1 binds the envelope
/// to the recipient's identity — without that key it does not open. DH2 is the
/// forward secrecy: the prekey secret is destroyed on use, so nobody can
/// recompute the term afterwards. Keeping DH1 means this is strictly stronger
/// than sealing to the identity alone, and degrades to that rather than to
/// nothing if a prekey secret is somehow retained.
pub fn seal_envelope(
    recipient: &PubKey,
    prekey_id: u32,
    prekey_public: &[u8; 32],
    from_epoch: u32,
    keys: &[ChannelKey],
) -> Result<Envelope> {
    if prekey_id == 0 {
        return Err(Error::Malformed(
            "prekey id 0 is invalid: there is no static-only path".into(),
        ));
    }
    if keys.is_empty() || keys.len() as u32 > MAX_RANGE {
        return Err(Error::Malformed(format!(
            "envelope carries {} keys, want 1..={MAX_RANGE}",
            keys.len()
        )));
    }
    let recipient_static = squic::crypto::ed25519_identity_to_x25519(recipient.as_bytes())
        .map_err(|e| Error::Key(format!("recipient identity: {e}")))?;
    let prekey = x25519_dalek::PublicKey::from(*prekey_public);

    let ephemeral_secret = x25519_dalek::StaticSecret::random_from_rng(rand_core::OsRng);
    let ephemeral_pub = x25519_dalek::PublicKey::from(&ephemeral_secret);
    let dh1 = squic::crypto::x25519(&ephemeral_secret, &recipient_static)
        .map_err(|e| Error::Key(format!("envelope DH1: {e}")))?;
    let dh2 = squic::crypto::x25519(&ephemeral_secret, &prekey)
        .map_err(|e| Error::Key(format!("envelope DH2: {e}")))?;

    let (key, n) = envelope_kdf(
        &ephemeral_pub.to_bytes(),
        recipient_static.as_bytes(),
        prekey_public,
        &dh1,
        &dh2,
    );
    let mut plaintext = Vec::with_capacity(keys.len() * 32);
    for k in keys {
        plaintext.extend_from_slice(k.as_bytes());
    }
    let ciphertext = cipher(&key)?
        .encrypt(Nonce::from_slice(&n), plaintext.as_slice())
        .map_err(|e| Error::Key(format!("seal envelope: {e}")))?;

    Ok(Envelope {
        recipient: *recipient,
        // Unsigned as sealed. `sign_envelope` fills these in, because the
        // signature covers the place it is published to and sealing knows
        // nothing about that.
        publisher: PubKey::new([0; 32]),
        sig: [0; 64],
        from_epoch,
        to_epoch: from_epoch + keys.len() as u32 - 1,
        prekey_id,
        ephemeral: ephemeral_pub.to_bytes(),
        ciphertext,
    })
}

/// Open an envelope sealed to us, using the prekey secret it names.
///
/// The secret **MUST** be destroyed by the caller afterwards when the prekey
/// was one-time. Deleting it is the entire mechanism; a client that keeps
/// prekey secrets has implemented the wire format and none of the property.
pub fn open_envelope(
    my_seed: &[u8; 32],
    prekey_secret: &x25519_dalek::StaticSecret,
    envelope: &Envelope,
) -> Result<Vec<ChannelKey>> {
    if envelope.prekey_id == 0 {
        return Err(Error::Malformed(
            "envelope names prekey id 0, which is invalid".into(),
        ));
    }
    let signing = ed25519_dalek::SigningKey::from_bytes(my_seed);
    let my_static = squic::crypto::ed25519_private_to_x25519(&signing);
    let my_static_pub = x25519_dalek::PublicKey::from(&my_static);
    let prekey_public = x25519_dalek::PublicKey::from(prekey_secret);
    let ephemeral = x25519_dalek::PublicKey::from(envelope.ephemeral);

    let dh1 = squic::crypto::x25519(&my_static, &ephemeral)
        .map_err(|e| Error::Key(format!("envelope DH1: {e}")))?;
    let dh2 = squic::crypto::x25519(prekey_secret, &ephemeral)
        .map_err(|e| Error::Key(format!("envelope DH2: {e}")))?;

    let (key, n) = envelope_kdf(
        &envelope.ephemeral,
        my_static_pub.as_bytes(),
        prekey_public.as_bytes(),
        &dh1,
        &dh2,
    );
    let plaintext = cipher(&key)?
        .decrypt(Nonce::from_slice(&n), envelope.ciphertext.as_slice())
        .map_err(|_| Error::Key("cannot open envelope: wrong key, or altered".into()))?;
    if plaintext.len() % 32 != 0 || plaintext.is_empty() {
        return Err(Error::Malformed(format!(
            "envelope holds {} bytes, want a whole number of keys",
            plaintext.len()
        )));
    }
    Ok(plaintext
        .as_chunks::<32>()
        .0
        .iter()
        .map(|c| ChannelKey::new(*c))
        .collect())
}

fn envelope_kdf(
    ephemeral_pub: &[u8; 32],
    recipient_static: &[u8; 32],
    prekey_public: &[u8; 32],
    dh1: &[u8; 32],
    dh2: &[u8; 32],
) -> ([u8; 32], [u8; 12]) {
    let mut h = Sha512::new();
    h.update(ENVELOPE_CONTEXT);
    h.update(ephemeral_pub);
    h.update(recipient_static);
    h.update(prekey_public);
    h.update(dh1);
    h.update(dh2);
    let okm = h.finalize();
    let mut key = [0u8; 32];
    let mut n = [0u8; 12];
    key.copy_from_slice(&okm[..32]);
    n.copy_from_slice(&okm[32..44]);
    (key, n)
}

/// Publish envelopes for one epoch.
///
/// `epoch` is either the channel's current epoch — adding envelopes without
/// rotating, which is how a new member is handed the key already in use — or
/// exactly one greater, which is a rotation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Put {
    pub channel: [u8; 32],
    pub epoch: u32,
    pub envelopes: Vec<Envelope>,
    /// SIP-31 signature for the rotation this put performs, present exactly
    /// when `epoch` advances the channel's current one.
    ///
    /// A same-epoch put adds envelopes and writes no system entry, so it has
    /// nothing to sign for. Who published which envelope therefore remains a
    /// transport observation — SIP-31 names that as its nearest residual gap
    /// rather than closing it here.
    pub action: Option<Action>,
}

impl Put {
    pub fn encode(&self) -> Vec<u8> {
        let total: usize = self.envelopes.iter().map(|e| e.wire_len()).sum();
        let mut out = Vec::with_capacity(40 + ACTION_LEN + total);
        out.push(TYPE_PUT);
        out.extend_from_slice(&self.channel);
        out.extend_from_slice(&self.epoch.to_be_bytes());
        out.extend_from_slice(&(self.envelopes.len() as u16).to_be_bytes());
        for e in &self.envelopes {
            out.extend_from_slice(e.recipient.as_bytes());
            out.extend_from_slice(e.publisher.as_bytes());
            out.extend_from_slice(&e.sig);
            out.extend_from_slice(&e.from_epoch.to_be_bytes());
            out.extend_from_slice(&e.to_epoch.to_be_bytes());
            out.extend_from_slice(&e.prekey_id.to_be_bytes());
            out.extend_from_slice(&e.ephemeral);
            out.extend_from_slice(&(e.ciphertext.len() as u32).to_be_bytes());
            out.extend_from_slice(&e.ciphertext);
        }
        match &self.action {
            Some(a) => {
                out.push(1);
                a.write(&mut out);
            }
            None => out.push(0),
        }
        out
    }

    pub fn decode(b: &[u8]) -> Result<Put> {
        if b.len() < 39 {
            return Err(Error::Malformed(format!(
                "put is {} bytes, want at least 39",
                b.len()
            )));
        }
        if b[0] != TYPE_PUT {
            return Err(Error::Malformed(format!("not a put (type {:#x})", b[0])));
        }
        let count = u16::from_be_bytes(b[37..39].try_into().unwrap()) as usize;
        if count > MAX_ENVELOPES {
            return Err(Error::Malformed(format!(
                "put carries {count} envelopes, limit is {MAX_ENVELOPES}"
            )));
        }
        let mut o = 39;
        let mut envelopes = Vec::with_capacity(count);
        for _ in 0..count {
            let e = read_envelope(b, &mut o, true)?;
            envelopes.push(e);
        }
        if o >= b.len() {
            return Err(Error::Malformed("put carries no rotation flag".into()));
        }
        let action = match b[o] {
            0 => {
                o += 1;
                None
            }
            1 => {
                if b.len() < o + 1 + ACTION_LEN {
                    return Err(Error::Malformed("put claims a rotation and is short".into()));
                }
                let a = Action::read(b, o + 1);
                o += 1 + ACTION_LEN;
                Some(a)
            }
            other => {
                return Err(Error::Malformed(format!(
                    "put rotation flag is {other}, want 0 or 1"
                )));
            }
        };
        if o != b.len() {
            return Err(Error::Malformed(format!(
                "put has {} trailing bytes",
                b.len() - o
            )));
        }
        Ok(Put {
            channel: b[1..33].try_into().unwrap(),
            epoch: u32::from_be_bytes(b[33..37].try_into().unwrap()),
            envelopes,
            action,
        })
    }
}

fn read_envelope(b: &[u8], o: &mut usize, with_recipient: bool) -> Result<Envelope> {
    let head = if with_recipient { ENVELOPE_HEADER } else { ENVELOPE_HEADER - 32 };
    if b.len() < *o + head {
        return Err(Error::Malformed("envelope is truncated".into()));
    }
    let at = *o;
    let (recipient, at) = if with_recipient {
        (PubKey::new(b[at..at + 32].try_into().unwrap()), at + 32)
    } else {
        (PubKey::new([0; 32]), at)
    };
    let publisher = PubKey::new(b[at..at + 32].try_into().unwrap());
    let sig: [u8; 64] = b[at + 32..at + 96].try_into().unwrap();
    let at = at + 96;
    let from_epoch = u32::from_be_bytes(b[at..at + 4].try_into().unwrap());
    let to_epoch = u32::from_be_bytes(b[at + 4..at + 8].try_into().unwrap());
    let prekey_id = u32::from_be_bytes(b[at + 8..at + 12].try_into().unwrap());
    let ephemeral: [u8; 32] = b[at + 12..at + 44].try_into().unwrap();
    let len = u32::from_be_bytes(b[at + 44..at + 48].try_into().unwrap()) as usize;

    if to_epoch < from_epoch || to_epoch - from_epoch + 1 > MAX_RANGE {
        return Err(Error::Malformed(format!(
            "envelope spans epochs {from_epoch}..={to_epoch}"
        )));
    }
    let want = 16 + 32 * (to_epoch - from_epoch + 1) as usize;
    if len != want {
        return Err(Error::Malformed(format!(
            "envelope ciphertext is {len} bytes, want {want} for its range"
        )));
    }
    if b.len() < at + 48 + len {
        return Err(Error::Malformed("envelope ciphertext is truncated".into()));
    }
    *o = at + 48 + len;
    Ok(Envelope {
        recipient,
        publisher,
        sig,
        from_epoch,
        to_epoch,
        prekey_id,
        ephemeral,
        ciphertext: b[at + 48..at + 48 + len].to_vec(),
    })
}

/// Collect the envelopes addressed to us.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Get {
    pub channel: [u8; 32],
    pub since_epoch: u32,
}

impl Get {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(37);
        out.push(TYPE_GET);
        out.extend_from_slice(&self.channel);
        out.extend_from_slice(&self.since_epoch.to_be_bytes());
        out
    }

    pub fn decode(b: &[u8]) -> Result<Get> {
        if b.len() != 37 {
            return Err(Error::Malformed(format!("get is {} bytes, want 37", b.len())));
        }
        if b[0] != TYPE_GET {
            return Err(Error::Malformed(format!("not a get (type {:#x})", b[0])));
        }
        Ok(Get {
            channel: b[1..33].try_into().unwrap(),
            since_epoch: u32::from_be_bytes(b[33..37].try_into().unwrap()),
        })
    }
}

/// Answer to a put. `accepted: 0` names the epoch that actually stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PutAck {
    pub accepted: bool,
    pub epoch: u32,
    pub now: u64,
}

impl PutAck {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(13);
        out.push(u8::from(self.accepted));
        out.extend_from_slice(&self.epoch.to_be_bytes());
        out.extend_from_slice(&self.now.to_be_bytes());
        out
    }

    pub fn decode(b: &[u8]) -> Result<PutAck> {
        if b.len() != 13 {
            return Err(Error::Malformed(format!(
                "put ack is {} bytes, want 13",
                b.len()
            )));
        }
        Ok(PutAck {
            accepted: b[0] != 0,
            epoch: u32::from_be_bytes(b[1..5].try_into().unwrap()),
            now: u64::from_be_bytes(b[5..13].try_into().unwrap()),
        })
    }
}

/// The envelopes the exchange holds for the caller. It serves each only to the
/// recipient it names, stores them opaquely, and holds no key that opens one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Got {
    pub now: u64,
    pub envelopes: Vec<Envelope>,
}

impl Got {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(10);
        out.extend_from_slice(&self.now.to_be_bytes());
        out.extend_from_slice(&(self.envelopes.len() as u16).to_be_bytes());
        for e in &self.envelopes {
            // The recipient is omitted — `Got` only ever answers one — but the
            // publisher is not: naming who handed a key over is the whole point.
            out.extend_from_slice(e.publisher.as_bytes());
            out.extend_from_slice(&e.sig);
            out.extend_from_slice(&e.from_epoch.to_be_bytes());
            out.extend_from_slice(&e.to_epoch.to_be_bytes());
            out.extend_from_slice(&e.prekey_id.to_be_bytes());
            out.extend_from_slice(&e.ephemeral);
            out.extend_from_slice(&(e.ciphertext.len() as u32).to_be_bytes());
            out.extend_from_slice(&e.ciphertext);
        }
        out
    }

    pub fn decode(b: &[u8]) -> Result<Got> {
        if b.len() < 10 {
            return Err(Error::Malformed(format!("got is {} bytes, want at least 10", b.len())));
        }
        let count = u16::from_be_bytes(b[8..10].try_into().unwrap()) as usize;
        if count > MAX_ENVELOPES {
            return Err(Error::Malformed(format!(
                "got carries {count} envelopes, limit is {MAX_ENVELOPES}"
            )));
        }
        let mut o = 10;
        let mut envelopes = Vec::with_capacity(count);
        for _ in 0..count {
            envelopes.push(read_envelope(b, &mut o, false)?);
        }
        if o != b.len() {
            return Err(Error::Malformed(format!("got has {} trailing bytes", b.len() - o)));
        }
        Ok(Got {
            now: u64::from_be_bytes(b[0..8].try_into().unwrap()),
            envelopes,
        })
    }
}

/// A member device holding no envelope for the current epoch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Stranded {
    pub account: PubKey,
    pub device: PubKey,
    /// Whether it could be sealed to at all. A device that has published no
    /// prekeys is waiting on itself, not on an admin.
    pub has_prekeys: bool,
}

/// Who cannot read, so that somebody can do something about it.
///
/// Without this a device can be stranded with no way to say so: it fetches
/// entries successfully, opens none of them, and looks exactly like a member
/// who is not reading.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Absent {
    pub epoch: u32,
    pub now: u64,
    pub devices: Vec<Stranded>,
}

impl Absent {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(14 + self.devices.len() * 65);
        out.extend_from_slice(&self.epoch.to_be_bytes());
        out.extend_from_slice(&self.now.to_be_bytes());
        out.extend_from_slice(&(self.devices.len() as u16).to_be_bytes());
        for d in &self.devices {
            out.extend_from_slice(d.account.as_bytes());
            out.extend_from_slice(d.device.as_bytes());
            out.push(u8::from(d.has_prekeys));
        }
        out
    }

    pub fn decode(b: &[u8]) -> Result<Absent> {
        if b.len() < 14 {
            return Err(Error::Malformed(format!(
                "absent is {} bytes, want at least 14",
                b.len()
            )));
        }
        let count = u16::from_be_bytes(b[12..14].try_into().unwrap()) as usize;
        if b.len() != 14 + count * 65 {
            return Err(Error::Malformed(format!(
                "absent is {} bytes, want {}",
                b.len(),
                14 + count * 65
            )));
        }
        Ok(Absent {
            epoch: u32::from_be_bytes(b[0..4].try_into().unwrap()),
            now: u64::from_be_bytes(b[4..12].try_into().unwrap()),
            devices: (0..count)
                .map(|i| {
                    let at = 14 + i * 65;
                    Stranded {
                        account: PubKey::new(b[at..at + 32].try_into().unwrap()),
                        device: PubKey::new(b[at + 32..at + 64].try_into().unwrap()),
                        has_prekeys: b[at + 64] != 0,
                    }
                })
                .collect(),
        })
    }
}

/// What a SIP-32 envelope-publication signature is made over.
///
/// The first three terms are SIP-31's and are there for its reasons: an
/// envelope must not lift between exchanges, nor between incarnations of a
/// channel whose identifier is derived and therefore stable.
pub fn envelope_input(
    exchange: &PubKey,
    instance: &[u8; 32],
    channel: &[u8; 32],
    epoch: u32,
    e: &Envelope,
) -> Vec<u8> {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(exchange.as_bytes());
    h.update(instance);
    h.update(channel);
    h.update(epoch.to_be_bytes());
    h.update(e.recipient.as_bytes());
    h.update(e.from_epoch.to_be_bytes());
    h.update(e.to_epoch.to_be_bytes());
    h.update(e.prekey_id.to_be_bytes());
    h.update(e.ephemeral);
    h.update(Sha256::digest(&e.ciphertext));

    let mut out = Vec::with_capacity(ENVELOPE_PUB_CONTEXT.len() + 32);
    out.extend_from_slice(ENVELOPE_PUB_CONTEXT);
    out.extend_from_slice(&h.finalize());
    out
}

/// Sign an envelope as the publishing device, filling in `publisher` and `sig`.
pub fn sign_envelope(
    device_seed: &[u8; 32],
    exchange: &PubKey,
    instance: &[u8; 32],
    channel: &[u8; 32],
    epoch: u32,
    mut e: Envelope,
) -> Envelope {
    use ed25519_dalek::{Signer, SigningKey};
    let signing = SigningKey::from_bytes(device_seed);
    e.publisher = PubKey::new(signing.verifying_key().to_bytes());
    e.sig = signing
        .sign(&envelope_input(exchange, instance, channel, epoch, &e))
        .to_bytes();
    e
}

/// Check who published an envelope.
///
/// As everywhere else in this stack, this proves a key signed. Binding that key
/// to a person is a SIP-20 credential, and a caller that stops here knows only
/// that *some* device put the envelope there.
pub fn verify_envelope(
    exchange: &PubKey,
    instance: &[u8; 32],
    channel: &[u8; 32],
    epoch: u32,
    e: &Envelope,
) -> bool {
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};
    let Ok(vk) = VerifyingKey::from_bytes(e.publisher.as_bytes()) else {
        return false;
    };
    vk.verify(
        &envelope_input(exchange, instance, channel, epoch, e),
        &Signature::from_bytes(&e.sig),
    )
    .is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::prekey::{KIND_ONE_TIME, Prekey};
    use ed25519_dalek::SigningKey;

    fn device(b: u8) -> ([u8; 32], PubKey) {
        let sk = SigningKey::from_bytes(&[b; 32]);
        (sk.to_bytes(), PubKey::new(sk.verifying_key().to_bytes()))
    }

    #[test]
    fn an_entry_round_trips_through_its_sender_subkey() {
        let key = ChannelKey::generate();
        let (_, alice) = device(1);
        let channel = [9u8; 32];
        let sealed = key.seal(&channel, 1, &alice, 0, b"hello").unwrap();
        assert_eq!(key.open(&channel, 1, &alice, 0, &sealed).unwrap(), b"hello");
    }

    #[test]
    fn two_devices_of_one_person_do_not_collide_at_the_same_counter() {
        // The defect this construction exists to prevent. Both start at zero,
        // and a per-person subkey would have them share a key and a nonce.
        let key = ChannelKey::generate();
        let (_, phone) = device(1);
        let (_, laptop) = device(2);
        let channel = [9u8; 32];

        assert_ne!(
            key.sender_key(&channel, 1, &phone),
            key.sender_key(&channel, 1, &laptop)
        );
        let a = key.seal(&channel, 1, &phone, 0, b"from the phone").unwrap();
        let b = key.seal(&channel, 1, &laptop, 0, b"from the laptop").unwrap();
        assert_eq!(key.open(&channel, 1, &phone, 0, &a).unwrap(), b"from the phone");
        assert_eq!(key.open(&channel, 1, &laptop, 0, &b).unwrap(), b"from the laptop");
        // And neither opens under the other's subkey.
        assert!(key.open(&channel, 1, &laptop, 0, &a).is_err());
    }

    #[test]
    fn a_subkey_is_bound_to_its_channel_and_epoch() {
        let key = ChannelKey::generate();
        let (_, alice) = device(1);
        let sealed = key.seal(&[1u8; 32], 1, &alice, 0, b"scoped").unwrap();
        assert!(key.open(&[2u8; 32], 1, &alice, 0, &sealed).is_err());
        assert!(key.open(&[1u8; 32], 2, &alice, 0, &sealed).is_err());
    }

    #[test]
    fn an_entry_does_not_open_at_a_different_counter() {
        let key = ChannelKey::generate();
        let (_, alice) = device(1);
        let sealed = key.seal(&[1u8; 32], 1, &alice, 5, b"five").unwrap();
        assert!(key.open(&[1u8; 32], 1, &alice, 6, &sealed).is_err());
    }

    #[test]
    fn a_repeated_counter_is_refused_and_the_first_is_not() {
        // The check SIP-17 names as the failure mode to test for. It is free,
        // because the counter is in the header and nothing needs decrypting.
        let (_, phone) = device(1);
        let (_, laptop) = device(2);
        let mut seen = Replay::new();

        assert!(seen.accept(&phone, 1, 0));
        assert!(!seen.accept(&phone, 1, 0), "a repeat is a nonce reuse");
        assert!(seen.accept(&phone, 1, 1), "the next counter is fine");
        // Two devices of one person both start at zero and must not collide.
        assert!(seen.accept(&laptop, 1, 0));
        // Nor do epochs: a counter restarts at zero on a rotation.
        assert!(seen.accept(&phone, 2, 0));
    }

    #[test]
    fn a_rotated_epoch_can_be_forgotten() {
        let (_, phone) = device(1);
        let mut seen = Replay::new();
        seen.accept(&phone, 1, 0);
        seen.accept(&phone, 2, 0);
        seen.forget_epoch(1);
        assert_eq!(seen.len(), 1);
        // And what was forgotten is accepted again, which is safe only because
        // nothing under a rotated epoch can still arrive.
        assert!(seen.accept(&phone, 1, 0));
    }

    #[test]
    fn an_envelope_round_trips() {
        let (seed, bob) = device(2);
        let (prekey, secret) = Prekey::generate(&seed, KIND_ONE_TIME, 7);
        let keys = [ChannelKey::generate(), ChannelKey::generate()];

        let env = seal_envelope(&bob, prekey.id, &prekey.public, 3, &keys).unwrap();
        assert_eq!((env.from_epoch, env.to_epoch), (3, 4));

        let out = open_envelope(&seed, &secret, &env).unwrap();
        assert_eq!(out.len(), 2);
        assert_eq!(out[0].as_bytes(), keys[0].as_bytes());
        assert_eq!(out[1].as_bytes(), keys[1].as_bytes());
    }

    #[test]
    fn an_envelope_needs_both_the_identity_and_the_prekey() {
        // DH1 is the identity's and DH2 is the prekey's, and losing either
        // must lose the envelope. This is what makes the construction strictly
        // stronger than sealing to a long-term key alone.
        let (seed, bob) = device(2);
        let (other_seed, _) = device(3);
        let (prekey, secret) = Prekey::generate(&seed, KIND_ONE_TIME, 7);
        let (_, wrong_secret) = Prekey::generate(&seed, KIND_ONE_TIME, 8);
        let keys = [ChannelKey::generate()];
        let env = seal_envelope(&bob, prekey.id, &prekey.public, 1, &keys).unwrap();

        // Right prekey, wrong identity.
        assert!(open_envelope(&other_seed, &secret, &env).is_err());
        // Right identity, wrong prekey — which is the case that matters, since
        // it is what an attacker holding a stolen identity key has.
        assert!(open_envelope(&seed, &wrong_secret, &env).is_err());
    }

    #[test]
    fn a_static_only_envelope_cannot_be_built() {
        let (seed, bob) = device(2);
        let (prekey, _) = Prekey::generate(&seed, KIND_ONE_TIME, 7);
        let keys = [ChannelKey::generate()];
        assert!(seal_envelope(&bob, 0, &prekey.public, 1, &keys).is_err());
    }

    #[test]
    fn put_and_got_round_trip() {
        let (seed, bob) = device(2);
        let (prekey, _) = Prekey::generate(&seed, KIND_ONE_TIME, 7);
        let env = seal_envelope(&bob, prekey.id, &prekey.public, 1, &[ChannelKey::generate()])
            .unwrap();

        let put = Put {
            channel: [4u8; 32],
            epoch: 1,
            envelopes: vec![env.clone()],
            action: Some(Action { chain_seq: 3, prev: [1; 32], sig: [2; 64] }),
        };
        assert_eq!(Put::decode(&put.encode()).unwrap(), put);

        // A same-epoch put writes no system entry and signs for nothing.
        let unsigned = Put { action: None, ..put.clone() };
        assert_eq!(Put::decode(&unsigned.encode()).unwrap(), unsigned);

        // Got omits the recipient, since it only ever answers one.
        let got = Got {
            now: 5,
            envelopes: vec![Envelope {
                recipient: PubKey::new([0; 32]),
                ..env
            }],
        };
        assert_eq!(Got::decode(&got.encode()).unwrap(), got);
    }

    /// **SIP-32: a recipient can name who published its key**, and an envelope
    /// re-signed by another device does not verify.
    #[test]
    fn an_envelope_names_who_published_it() {
        let (seed, bob) = device(2);
        let (other_seed, _) = device(3);
        let (prekey, _) = Prekey::generate(&seed, KIND_ONE_TIME, 7);
        let exchange = PubKey::new([9u8; 32]);
        let instance = [4u8; 32];
        let channel = [7u8; 32];

        let sealed =
            seal_envelope(&bob, prekey.id, &prekey.public, 1, &[ChannelKey::generate()]).unwrap();
        let published = sign_envelope(&seed, &exchange, &instance, &channel, 1, sealed.clone());
        assert!(verify_envelope(&exchange, &instance, &channel, 1, &published));
        assert_ne!(published.publisher, PubKey::new([0; 32]));

        // Somebody else's signature over the same envelope.
        let forged = sign_envelope(&other_seed, &exchange, &instance, &channel, 1, sealed.clone());
        assert_ne!(forged.publisher, published.publisher);
        let claimed = Envelope { publisher: published.publisher, ..forged };
        assert!(
            !verify_envelope(&exchange, &instance, &channel, 1, &claimed),
            "an envelope verified under a publisher that did not sign it"
        );

        // And it does not travel: not to another exchange, another
        // incarnation, another channel, or another epoch.
        for (what, ok) in [
            ("exchange", verify_envelope(&PubKey::new([8; 32]), &instance, &channel, 1, &published)),
            ("instance", verify_envelope(&exchange, &[5; 32], &channel, 1, &published)),
            ("channel", verify_envelope(&exchange, &instance, &[8; 32], 1, &published)),
            ("epoch", verify_envelope(&exchange, &instance, &channel, 2, &published)),
        ] {
            assert!(!ok, "an envelope verified under a changed {what}");
        }
    }

    /// SIP-32 halved `MAX_ENVELOPES` to pay for the publisher and signature.
    ///
    /// The number that matters is **not** whether a full `Put` of single-epoch
    /// envelopes fits — it does either way, at 56 KiB inside 64 — but whether
    /// there is room for what SIP-17 promised: "the range to be wider than
    /// one". A two-epoch envelope is 256 bytes, so 256 of them come to exactly
    /// the request cap and 128 come to half of it. A test that only asked
    /// whether the narrowest case fits would pass at the old cap and say
    /// nothing, which is what a control caught it doing.
    #[test]
    fn a_full_put_leaves_room_for_a_wider_range() {
        let (seed, bob) = device(2);
        let exchange = PubKey::new([9u8; 32]);
        let mut envelopes = Vec::with_capacity(MAX_ENVELOPES);
        for i in 0..MAX_ENVELOPES {
            let (prekey, _) = Prekey::generate(&seed, KIND_ONE_TIME, i as u32 + 1);
            // Two epochs, which is the case SIP-17 says must have room.
            let sealed = seal_envelope(
                &bob,
                prekey.id,
                &prekey.public,
                1,
                &[ChannelKey::generate(), ChannelKey::generate()],
            )
            .unwrap();
            envelopes.push(sign_envelope(&seed, &exchange, &[0; 32], &[0; 32], 1, sealed));
        }
        let put = Put { channel: [0; 32], epoch: 1, envelopes, action: None };
        let bytes = put.encode();
        // At the old cap of 256 this comes to 65,576 bytes — over the request
        // limit outright, not merely tight. Half of it leaves the margin
        // SIP-17's arithmetic assumed.
        assert!(
            bytes.len() < 34 * 1024,
            "a full put of two-epoch envelopes is {} bytes, which leaves no margin \
             inside the 64 KiB request cap",
            bytes.len()
        );
        assert_eq!(Put::decode(&bytes).unwrap().envelopes.len(), MAX_ENVELOPES);

        // One more is refused rather than truncated.
        let mut over = Put::decode(&bytes).unwrap();
        over.envelopes.push(over.envelopes[0].clone());
        assert!(Put::decode(&over.encode()).is_err());
    }

    #[test]
    fn an_envelope_whose_length_contradicts_its_range_is_refused() {
        let (seed, bob) = device(2);
        let (prekey, _) = Prekey::generate(&seed, KIND_ONE_TIME, 7);
        let mut env =
            seal_envelope(&bob, prekey.id, &prekey.public, 1, &[ChannelKey::generate()]).unwrap();
        // Claim two epochs while carrying one key's worth of ciphertext.
        env.to_epoch = 2;
        let put = Put {
            channel: [4u8; 32],
            epoch: 1,
            envelopes: vec![env],
            action: None,
        };
        assert!(Put::decode(&put.encode()).is_err());
    }

    #[test]
    fn absent_round_trips() {
        let (_, a) = device(1);
        let (_, d) = device(2);
        let absent = Absent {
            epoch: 3,
            now: 9,
            devices: vec![Stranded {
                account: a,
                device: d,
                has_prekeys: true,
            }],
        };
        assert_eq!(Absent::decode(&absent.encode()).unwrap(), absent);
    }

    #[test]
    fn get_and_put_ack_round_trip() {
        let g = Get {
            channel: [1u8; 32],
            since_epoch: 2,
        };
        assert_eq!(Get::decode(&g.encode()).unwrap(), g);
        let p = PutAck {
            accepted: false,
            epoch: 4,
            now: 7,
        };
        assert_eq!(PutAck::decode(&p.encode()).unwrap(), p);
    }
}

