//! The signed admin-command protocol.
//!
//! An administrator proves authority not by the connection's transport key —
//! a YubiKey cannot produce that — but by an Ed25519 signature over the command
//! itself. The signed bytes are a canonical, byte-stable encoding, and they
//! bind three things that together defeat replay and misdirection:
//!
//! - the **action** (what to do),
//! - a single-use **nonce** the server issued (defeats replay), and
//! - the **server's own public key** (defeats replaying a command captured
//!   against one server onto another).
//!
//! The signature is domain-separated by [`SIG_CONTEXT`] so it can never be
//! mistaken for a signature from any other sQUIC-ecosystem context.

use ed25519_dalek::{Signature, Signer as _, SigningKey, Verifier};

use crate::error::{Error, Result};
use crate::key::PubKey;

/// Domain separator prepended to every admin-command signature.
pub const SIG_CONTEXT: &[u8] = b"sqex-admin-v1";

/// A single-use challenge issued by the server.
pub type Nonce = [u8; 32];

/// What an administrator is asking the server to do.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    /// Turn the managed whitelist on (enforce it on protected endpoints).
    WhitelistEnable,
    /// Turn the managed whitelist off (allow all who hold the server key).
    WhitelistDisable,
    /// Add a peer's Ed25519 key to the managed whitelist.
    WhitelistAdd(PubKey),
    /// Remove a peer's Ed25519 key from the managed whitelist.
    WhitelistRemove(PubKey),
    /// Read the current whitelist (enabled flag + keys).
    WhitelistList,
    /// Read server status (version, uptime, connection counters).
    Status,
    /// Re-read the admin list from the config file without restarting.
    ReloadAdmins,
    /// Read the last `n` audit entries.
    AuditTail(u32),
}

impl Action {
    fn tag(&self) -> u8 {
        match self {
            Action::WhitelistEnable => 0x01,
            Action::WhitelistDisable => 0x02,
            Action::WhitelistAdd(_) => 0x03,
            Action::WhitelistRemove(_) => 0x04,
            Action::WhitelistList => 0x05,
            Action::Status => 0x06,
            Action::ReloadAdmins => 0x07,
            Action::AuditTail(_) => 0x08,
        }
    }

    fn encode(&self, out: &mut Vec<u8>) {
        out.push(self.tag());
        match self {
            Action::WhitelistAdd(k) | Action::WhitelistRemove(k) => {
                out.extend_from_slice(k.as_bytes());
            }
            Action::AuditTail(n) => out.extend_from_slice(&n.to_be_bytes()),
            _ => {}
        }
    }

    fn decode(r: &mut Reader) -> Result<Action> {
        let tag = r.u8()?;
        Ok(match tag {
            0x01 => Action::WhitelistEnable,
            0x02 => Action::WhitelistDisable,
            0x03 => Action::WhitelistAdd(PubKey::new(r.array::<32>()?)),
            0x04 => Action::WhitelistRemove(PubKey::new(r.array::<32>()?)),
            0x05 => Action::WhitelistList,
            0x06 => Action::Status,
            0x07 => Action::ReloadAdmins,
            0x08 => Action::AuditTail(u32::from_be_bytes(r.array::<4>()?)),
            other => return Err(Error::Malformed(format!("unknown action tag {other:#x}"))),
        })
    }

    /// A short, stable name for logs and audit records.
    pub fn name(&self) -> &'static str {
        match self {
            Action::WhitelistEnable => "whitelist-enable",
            Action::WhitelistDisable => "whitelist-disable",
            Action::WhitelistAdd(_) => "whitelist-add",
            Action::WhitelistRemove(_) => "whitelist-remove",
            Action::WhitelistList => "whitelist-list",
            Action::Status => "status",
            Action::ReloadAdmins => "reload-admins",
            Action::AuditTail(_) => "audit-tail",
        }
    }

    /// Whether the action changes server state (vs. a pure read). Reads still
    /// require a valid signature and nonce, but only mutations are audited.
    pub fn is_mutation(&self) -> bool {
        matches!(
            self,
            Action::WhitelistEnable
                | Action::WhitelistDisable
                | Action::WhitelistAdd(_)
                | Action::WhitelistRemove(_)
                | Action::ReloadAdmins
        )
    }
}

/// The bytes an administrator signs: the action, the server's nonce, and the
/// server's identity, in a fixed order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Command {
    pub action: Action,
    pub nonce: Nonce,
    pub server: PubKey,
}

impl Command {
    /// Canonical encoding. The same bytes are both the wire form and the
    /// signature input, so there is exactly one representation to sign or check.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(1 + 32 + 32 + 32);
        self.action.encode(&mut out);
        out.extend_from_slice(&self.nonce);
        out.extend_from_slice(self.server.as_bytes());
        out
    }

    fn decode(r: &mut Reader) -> Result<Command> {
        let action = Action::decode(r)?;
        let nonce = r.array::<32>()?;
        let server = PubKey::new(r.array::<32>()?);
        Ok(Command {
            action,
            nonce,
            server,
        })
    }

    /// The domain-separated bytes actually passed to Ed25519. Public so a
    /// fallible hardware signer (a YubiKey) can obtain them, sign out of band,
    /// and assemble a [`SignedCommand`] directly — the infallible [`Signer`]
    /// trait does not fit a card that can fail or need a PIN.
    pub fn signing_bytes(&self) -> Vec<u8> {
        let body = self.encode();
        let mut msg = Vec::with_capacity(SIG_CONTEXT.len() + body.len());
        msg.extend_from_slice(SIG_CONTEXT);
        msg.extend_from_slice(&body);
        msg
    }
}

/// Anything that can produce an Ed25519 signature for an admin. Implemented by
/// a software key for tests and by a YubiKey in the desktop app; the protocol
/// is identical either way.
pub trait Signer {
    /// The admin's Ed25519 public key.
    fn public(&self) -> [u8; 32];
    /// A raw RFC 8032 Ed25519 signature over `msg`.
    fn sign(&self, msg: &[u8]) -> [u8; 64];
}

/// A signer backed by an in-memory Ed25519 key. Used by tests and any CLI path;
/// the YubiKey backend lives in the desktop app.
pub struct SoftwareSigner {
    key: SigningKey,
}

impl SoftwareSigner {
    pub fn new(key: SigningKey) -> Self {
        Self { key }
    }
}

impl Signer for SoftwareSigner {
    fn public(&self) -> [u8; 32] {
        self.key.verifying_key().to_bytes()
    }

    fn sign(&self, msg: &[u8]) -> [u8; 64] {
        self.key.sign(msg).to_bytes()
    }
}

/// A command plus the administrator's key and signature over it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedCommand {
    pub command: Command,
    pub admin: PubKey,
    pub signature: [u8; 64],
}

impl SignedCommand {
    /// Sign `command` with `signer`. The signer's public key is recorded as the
    /// claimed admin identity; [`verify`](Self::verify) confirms the signature
    /// matches it.
    pub fn create(command: Command, signer: &dyn Signer) -> Self {
        let signature = signer.sign(&command.signing_bytes());
        SignedCommand {
            command,
            admin: PubKey::new(signer.public()),
            signature,
        }
    }

    /// Verify the signature and the server binding.
    ///
    /// On success the caller still must (1) confirm the nonce is one it issued
    /// and has not seen, and (2) confirm `self.admin` is an authorized admin —
    /// both are stateful and live in the server. This method proves only that
    /// the bytes were signed by the holder of `self.admin`'s private key, for
    /// this server.
    pub fn verify(&self, expected_server: &PubKey) -> Result<()> {
        if self.command.server != *expected_server {
            return Err(Error::WrongServer);
        }
        let vk = self.admin.verifying_key()?;
        let sig = Signature::from_bytes(&self.signature);
        vk.verify(&self.command.signing_bytes(), &sig)
            .map_err(|_| Error::BadSignature)
    }

    /// Wire form: canonical command bytes, then the admin key, then the
    /// signature. This is the HTTP/3 request body.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = self.command.encode();
        out.extend_from_slice(self.admin.as_bytes());
        out.extend_from_slice(&self.signature);
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<SignedCommand> {
        let mut r = Reader::new(bytes);
        let command = Command::decode(&mut r)?;
        let admin = PubKey::new(r.array::<32>()?);
        let signature = r.array::<64>()?;
        r.finish()?;
        Ok(SignedCommand {
            command,
            admin,
            signature,
        })
    }
}

/// A minimal big-endian byte cursor for decoding, bounds-checked throughout.
struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let end = self
            .pos
            .checked_add(n)
            .ok_or_else(|| Error::Malformed("length overflow".into()))?;
        if end > self.buf.len() {
            return Err(Error::Malformed("unexpected end of message".into()));
        }
        let slice = &self.buf[self.pos..end];
        self.pos = end;
        Ok(slice)
    }

    fn u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N]> {
        let mut out = [0u8; N];
        out.copy_from_slice(self.take(N)?);
        Ok(out)
    }

    fn finish(self) -> Result<()> {
        if self.pos != self.buf.len() {
            return Err(Error::Malformed(format!(
                "{} trailing bytes",
                self.buf.len() - self.pos
            )));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;

    fn signer() -> SoftwareSigner {
        SoftwareSigner::new(SigningKey::from_bytes(&[9u8; 32]))
    }

    fn cmd(action: Action, server: PubKey) -> Command {
        Command {
            action,
            nonce: [3u8; 32],
            server,
        }
    }

    #[test]
    fn command_encode_round_trip() {
        let server = PubKey::new([1u8; 32]);
        for action in [
            Action::WhitelistEnable,
            Action::WhitelistDisable,
            Action::WhitelistAdd(PubKey::new([5u8; 32])),
            Action::WhitelistRemove(PubKey::new([6u8; 32])),
            Action::WhitelistList,
            Action::Status,
            Action::ReloadAdmins,
            Action::AuditTail(42),
        ] {
            let signed = SignedCommand::create(cmd(action.clone(), server), &signer());
            let bytes = signed.encode();
            let back = SignedCommand::decode(&bytes).unwrap();
            assert_eq!(signed, back);
            assert_eq!(back.command.action, action);
        }
    }

    #[test]
    fn valid_signature_verifies() {
        let server = PubKey::new([1u8; 32]);
        let signed = SignedCommand::create(cmd(Action::Status, server), &signer());
        assert!(signed.verify(&server).is_ok());
    }

    #[test]
    fn rejects_wrong_server() {
        let server = PubKey::new([1u8; 32]);
        let other = PubKey::new([2u8; 32]);
        let signed = SignedCommand::create(cmd(Action::Status, server), &signer());
        assert!(matches!(signed.verify(&other), Err(Error::WrongServer)));
    }

    #[test]
    fn rejects_tampered_action() {
        let server = PubKey::new([1u8; 32]);
        let mut signed = SignedCommand::create(cmd(Action::WhitelistEnable, server), &signer());
        signed.command.action = Action::WhitelistDisable; // tamper after signing
        assert!(matches!(signed.verify(&server), Err(Error::BadSignature)));
    }

    #[test]
    fn rejects_tampered_nonce() {
        let server = PubKey::new([1u8; 32]);
        let mut signed = SignedCommand::create(cmd(Action::Status, server), &signer());
        signed.command.nonce = [0xff; 32];
        assert!(matches!(signed.verify(&server), Err(Error::BadSignature)));
    }

    #[test]
    fn rejects_signature_from_other_key() {
        let server = PubKey::new([1u8; 32]);
        let mut signed = SignedCommand::create(cmd(Action::Status, server), &signer());
        // Claim a different admin identity than the one that signed.
        signed.admin = PubKey::new(
            SigningKey::from_bytes(&[11u8; 32])
                .verifying_key()
                .to_bytes(),
        );
        assert!(matches!(signed.verify(&server), Err(Error::BadSignature)));
    }

    #[test]
    fn decode_rejects_trailing_bytes() {
        let server = PubKey::new([1u8; 32]);
        let mut bytes = SignedCommand::create(cmd(Action::Status, server), &signer()).encode();
        bytes.push(0);
        assert!(SignedCommand::decode(&bytes).is_err());
    }
}
