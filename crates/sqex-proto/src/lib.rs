//! The sqex admin command vocabulary.
//!
//! This is the part that changes when sqex gains a command — deliberately kept
//! out of the signer. An [`Op`] knows three things: how to encode itself as an
//! opaque **payload** (the bytes sqexd will act on), how to **decode** that
//! payload back, and how to describe itself in **human** terms (`summary` +
//! `detail`). The client turns chosen `Op`s into [`sqnr_core::Operation`]s and
//! signs the batch; sqexd decodes each payload and applies it. Because the
//! summary is carried in the signed transaction, sqexd re-renders it from the
//! decoded payload and checks it matches — so the operator's displayed context
//! provably corresponds to what executes.

use sqnr_core::{Error, Operation, PubKey, Result};

/// A single administrative operation against sqex.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Op {
    /// Turn the managed whitelist on (enforce it on protected endpoints).
    WhitelistEnable,
    /// Turn the managed whitelist off.
    WhitelistDisable,
    /// Add a peer's Ed25519 key to the managed whitelist.
    WhitelistAdd(PubKey),
    /// Remove a peer's Ed25519 key from the managed whitelist.
    WhitelistRemove(PubKey),
    /// Read the current whitelist (enabled flag + keys).
    WhitelistList,
    /// Read server status.
    Status,
    /// Re-read the admin list from the config file without restarting.
    ReloadAdmins,
    /// Read the last `n` audit entries.
    AuditTail(u32),
}

impl Op {
    fn tag(&self) -> u8 {
        match self {
            Op::WhitelistEnable => 0x01,
            Op::WhitelistDisable => 0x02,
            Op::WhitelistAdd(_) => 0x03,
            Op::WhitelistRemove(_) => 0x04,
            Op::WhitelistList => 0x05,
            Op::Status => 0x06,
            Op::ReloadAdmins => 0x07,
            Op::AuditTail(_) => 0x08,
        }
    }

    /// The opaque payload sqexd acts on: a tag byte plus any argument.
    pub fn payload(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(1 + 32);
        out.push(self.tag());
        match self {
            Op::WhitelistAdd(k) | Op::WhitelistRemove(k) => out.extend_from_slice(k.as_bytes()),
            Op::AuditTail(n) => out.extend_from_slice(&n.to_be_bytes()),
            _ => {}
        }
        out
    }

    /// Decode a payload produced by [`payload`](Self::payload).
    pub fn decode(payload: &[u8]) -> Result<Op> {
        let tag = *payload
            .first()
            .ok_or_else(|| Error::Malformed("empty op payload".into()))?;
        let rest = &payload[1..];
        let op = match tag {
            0x01 => Op::WhitelistEnable,
            0x02 => Op::WhitelistDisable,
            0x03 => Op::WhitelistAdd(key(rest)?),
            0x04 => Op::WhitelistRemove(key(rest)?),
            0x05 => Op::WhitelistList,
            0x06 => Op::Status,
            0x07 => Op::ReloadAdmins,
            0x08 => Op::AuditTail(u32_arg(rest)?),
            other => return Err(Error::Malformed(format!("unknown op tag {other:#x}"))),
        };
        // No op takes trailing bytes beyond what it consumed.
        let expected = op.payload().len();
        if payload.len() != expected {
            return Err(Error::Malformed(format!(
                "op payload is {} bytes, expected {expected}",
                payload.len()
            )));
        }
        Ok(op)
    }

    /// A short, stable name for logs and audit records.
    pub fn name(&self) -> &'static str {
        match self {
            Op::WhitelistEnable => "whitelist-enable",
            Op::WhitelistDisable => "whitelist-disable",
            Op::WhitelistAdd(_) => "whitelist-add",
            Op::WhitelistRemove(_) => "whitelist-remove",
            Op::WhitelistList => "whitelist-list",
            Op::Status => "status",
            Op::ReloadAdmins => "reload-admins",
            Op::AuditTail(_) => "audit-tail",
        }
    }

    /// A one-line human description shown to the operator before signing.
    pub fn summary(&self) -> String {
        match self {
            Op::WhitelistEnable => "Enable the connection whitelist".into(),
            Op::WhitelistDisable => "Disable the connection whitelist".into(),
            Op::WhitelistAdd(_) => "Add a peer to the whitelist".into(),
            Op::WhitelistRemove(_) => "Remove a peer from the whitelist".into(),
            Op::WhitelistList => "Read the whitelist".into(),
            Op::Status => "Read server status".into(),
            Op::ReloadAdmins => "Reload the admin list from config".into(),
            Op::AuditTail(n) => format!("Read the last {n} audit entries"),
        }
    }

    /// Extra context lines (e.g. the affected key).
    pub fn detail(&self) -> Vec<String> {
        match self {
            Op::WhitelistAdd(k) | Op::WhitelistRemove(k) => vec![format!("peer: {}", k.to_base58())],
            _ => vec![],
        }
    }

    /// Whether the op changes server state (only mutations are audited).
    pub fn is_mutation(&self) -> bool {
        matches!(
            self,
            Op::WhitelistEnable
                | Op::WhitelistDisable
                | Op::WhitelistAdd(_)
                | Op::WhitelistRemove(_)
                | Op::ReloadAdmins
        )
    }

    /// The affected key, if this op names one (for audit records).
    pub fn target(&self) -> Option<String> {
        match self {
            Op::WhitelistAdd(k) | Op::WhitelistRemove(k) => Some(k.to_base58()),
            _ => None,
        }
    }

    /// Turn this op into a signer [`Operation`]: opaque payload + human context.
    pub fn to_operation(&self) -> Operation {
        Operation {
            summary: self.summary(),
            detail: self.detail(),
            payload: self.payload(),
        }
    }
}

fn key(rest: &[u8]) -> Result<PubKey> {
    let arr: [u8; 32] = rest
        .try_into()
        .map_err(|_| Error::Malformed("op expects a 32-byte key".into()))?;
    Ok(PubKey::new(arr))
}

fn u32_arg(rest: &[u8]) -> Result<u32> {
    let arr: [u8; 4] = rest
        .try_into()
        .map_err(|_| Error::Malformed("op expects a 4-byte count".into()))?;
    Ok(u32::from_be_bytes(arr))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn all() -> Vec<Op> {
        vec![
            Op::WhitelistEnable,
            Op::WhitelistDisable,
            Op::WhitelistAdd(PubKey::new([5u8; 32])),
            Op::WhitelistRemove(PubKey::new([6u8; 32])),
            Op::WhitelistList,
            Op::Status,
            Op::ReloadAdmins,
            Op::AuditTail(42),
        ]
    }

    #[test]
    fn payload_round_trip() {
        for op in all() {
            let back = Op::decode(&op.payload()).unwrap();
            assert_eq!(op, back);
        }
    }

    #[test]
    fn rejects_trailing_bytes() {
        let mut p = Op::WhitelistEnable.payload();
        p.push(0);
        assert!(Op::decode(&p).is_err());
    }

    #[test]
    fn add_remove_detail_names_key() {
        let k = PubKey::new([7u8; 32]);
        let op = Op::WhitelistAdd(k);
        assert_eq!(op.detail(), vec![format!("peer: {}", k.to_base58())]);
        assert!(op.to_operation().summary.contains("Add a peer"));
    }

    #[test]
    fn empty_payload_rejected() {
        assert!(Op::decode(&[]).is_err());
    }
}
