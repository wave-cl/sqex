//! YubiKey access on a dedicated thread that owns the card.
//!
//! The card is opened once and a single OpenPGP session is held for the app's
//! lifetime, so PW1 (the user PIN) is verified once and later signatures need
//! only a touch. PC/SC and openpgp-card are blocking and not `Send`-friendly,
//! so all card work stays on this one thread; the async worker talks to it over
//! channels.

use std::sync::mpsc::{Receiver, Sender, channel};

use card_backend_pcsc::PcscBackend;
use openpgp_card::ocard::crypto::PublicKeyMaterial;
use openpgp_card::ocard::{KeyType, OpenPGP, Transaction};
use secrecy::SecretBox;
use tokio::sync::oneshot;

enum Req {
    Pubkey(oneshot::Sender<Result<[u8; 32], String>>),
    Unlock(String, oneshot::Sender<Result<(), String>>),
    Sign(Vec<u8>, oneshot::Sender<Result<[u8; 64], String>>),
}

/// A handle to the card thread. Cheap to clone; all clones drive the one card.
#[derive(Clone)]
pub struct Card {
    tx: Sender<Req>,
}

impl Card {
    pub fn spawn() -> Card {
        let (tx, rx) = channel();
        std::thread::spawn(move || card_loop(rx));
        Card { tx }
    }

    /// Read the Authentication slot's Ed25519 public key (no PIN).
    pub async fn pubkey(&self) -> Result<[u8; 32], String> {
        let (reply, rx) = oneshot::channel();
        self.tx
            .send(Req::Pubkey(reply))
            .map_err(|_| "card thread stopped".to_string())?;
        rx.await
            .map_err(|_| "card thread dropped the request".to_string())?
    }

    /// Verify the user PIN once for the session.
    pub async fn unlock(&self, pin: String) -> Result<(), String> {
        let (reply, rx) = oneshot::channel();
        self.tx
            .send(Req::Unlock(pin, reply))
            .map_err(|_| "card thread stopped".to_string())?;
        rx.await
            .map_err(|_| "card thread dropped the request".to_string())?
    }

    /// Sign `msg` with the Authentication key. Requires an earlier `unlock`;
    /// with touch enabled the card blocks here until tapped.
    pub async fn sign(&self, msg: Vec<u8>) -> Result<[u8; 64], String> {
        let (reply, rx) = oneshot::channel();
        self.tx
            .send(Req::Sign(msg, reply))
            .map_err(|_| "card thread stopped".to_string())?;
        rx.await
            .map_err(|_| "card thread dropped the request".to_string())?
    }
}

fn open() -> Result<OpenPGP, String> {
    let backend = PcscBackend::cards(None)
        .map_err(|e| e.to_string())?
        .next()
        .ok_or_else(|| "no OpenPGP card found (is the YubiKey inserted?)".to_string())?
        .map_err(|e| e.to_string())?;
    OpenPGP::new(backend).map_err(|e| e.to_string())
}

/// Own the card across requests. One open session holds PW1 for its lifetime;
/// a communication failure (card removed/reset) drops the session and the next
/// request reopens it — re-locking, so the PIN is asked again.
fn card_loop(rx: Receiver<Req>) {
    loop {
        // Block until there is work, so we don't open the card speculatively.
        let Ok(first) = rx.recv() else { return };

        let mut card = match open() {
            Ok(c) => c,
            Err(e) => {
                reply_err(first, &e);
                continue;
            }
        };
        let mut tx = match card.transaction() {
            Ok(t) => t,
            Err(e) => {
                reply_err(first, &e.to_string());
                continue;
            }
        };

        if !handle(&mut tx, first) {
            continue; // card went away mid-request; reopen on the next one
        }
        loop {
            let Ok(req) = rx.recv() else { return };
            if !handle(&mut tx, req) {
                break;
            }
        }
    }
}

/// Handle one request. Returns false if the session should be reopened.
fn handle(tx: &mut Transaction<'_>, req: Req) -> bool {
    match req {
        Req::Pubkey(reply) => {
            let r = read_pubkey(tx);
            let keep = !is_comm_failure(&r);
            let _ = reply.send(r);
            keep
        }
        Req::Unlock(pin, reply) => {
            let r = tx
                .verify_pw1_user(SecretBox::new(pin.into_bytes().into_boxed_slice()))
                .map_err(|e| format!("PIN rejected: {e}"));
            let keep = !is_comm_failure(&r);
            let _ = reply.send(r);
            keep
        }
        Req::Sign(msg, reply) => {
            let r = tx
                .internal_authenticate(msg)
                .map_err(|e| format!("sign failed: {e}"))
                .and_then(|s| {
                    <[u8; 64]>::try_from(s.as_slice())
                        .map_err(|_| "card returned a non-64-byte signature".to_string())
                });
            let keep = !is_comm_failure(&r);
            let _ = reply.send(r);
            keep
        }
    }
}

fn read_pubkey(tx: &mut Transaction<'_>) -> Result<[u8; 32], String> {
    match tx.public_key(KeyType::Authentication) {
        Ok(PublicKeyMaterial::E(ecc)) => <[u8; 32]>::try_from(ecc.data())
            .map_err(|_| "auth key is not a 32-byte Ed25519 point".to_string()),
        Ok(PublicKeyMaterial::R(_)) => Err("auth key is RSA, not Ed25519".to_string()),
        Err(e) => Err(format!(
            "no Ed25519 auth key ({e}); provision with `yubikey_spike --provision`"
        )),
    }
}

/// Whether an error looks like the card is gone (removed/reset/transport lost),
/// as opposed to a logical rejection like a bad PIN. Only the former should
/// tear down and reopen the session.
fn is_comm_failure<T>(r: &Result<T, String>) -> bool {
    match r {
        Ok(_) => false,
        Err(e) => {
            let e = e.to_ascii_lowercase();
            [
                "removed",
                "reset",
                "transmit",
                "no smart card",
                "not transacted",
                "disconnected",
            ]
            .iter()
            .any(|needle| e.contains(needle))
        }
    }
}

fn reply_err(req: Req, err: &str) {
    match req {
        Req::Pubkey(reply) => {
            let _ = reply.send(Err(err.to_string()));
        }
        Req::Unlock(_, reply) => {
            let _ = reply.send(Err(err.to_string()));
        }
        Req::Sign(_, reply) => {
            let _ = reply.send(Err(err.to_string()));
        }
    }
}
