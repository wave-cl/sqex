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

pub mod attest;
pub mod beacon;
pub mod blob;
pub mod blob_store;
pub mod channel;
pub mod channel_key;
pub mod credential;
pub mod device;
pub mod entry_sig;
pub mod h3;
pub mod events;
pub mod exchange;
pub mod mailbox;
pub mod message;
pub mod peer;
pub mod prekey;
pub mod profile;
pub mod receipt;
pub mod refusal;
pub mod rendezvous;
pub mod resolve;
pub mod room;
pub mod session;
pub mod timeline;

use sqnr_core::{Error, Operation, PubKey, Result};

/// Longest label accepted on a whitelist add.
pub const MAX_LABEL: usize = 256;

/// A single administrative operation against sqex.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Op {
    /// Turn the managed whitelist on (enforce it on protected endpoints).
    WhitelistEnable,
    /// Turn the managed whitelist off.
    WhitelistDisable,
    /// Add a peer's Ed25519 key to the managed whitelist, with an optional
    /// human label recorded as provenance.
    WhitelistAdd { key: PubKey, label: Option<String> },
    /// Remove a peer's Ed25519 key from the managed whitelist.
    WhitelistRemove(PubKey),
    /// Read the current whitelist (enabled flag + entries).
    WhitelistList,
    /// Read server status.
    Status,
    /// Re-read the admin list from the config file without restarting.
    ReloadAdmins,
    /// Read the last `n` audit entries.
    AuditTail(u32),
    /// Read the pending SIP-24 admission requests.
    ///
    /// A credential is evidence and not authority: it tells an administrator
    /// which account vouches for a key, and does not entitle that key to
    /// anything. That is why admission is a decision rather than a rule.
    AdmissionList,
    /// Admit a device to the whitelist, with an optional label of the
    /// administrator's own.
    AdmissionApprove { device: PubKey, label: Option<String> },
    /// Decline one, and remember the decision so it does not requeue.
    AdmissionDeny(PubKey),
}

impl Op {
    fn tag(&self) -> u8 {
        match self {
            Op::WhitelistEnable => 0x01,
            Op::WhitelistDisable => 0x02,
            Op::WhitelistAdd { .. } => 0x03,
            Op::WhitelistRemove(_) => 0x04,
            Op::WhitelistList => 0x05,
            Op::Status => 0x06,
            Op::ReloadAdmins => 0x07,
            Op::AuditTail(_) => 0x08,
            Op::AdmissionList => 0x09,
            Op::AdmissionApprove { .. } => 0x0a,
            Op::AdmissionDeny(_) => 0x0b,
        }
    }

    /// The opaque payload sqexd acts on: a tag byte plus any argument.
    pub fn payload(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(1 + 32);
        out.push(self.tag());
        match self {
            Op::WhitelistAdd { key, label } => {
                out.extend_from_slice(key.as_bytes());
                match label {
                    Some(s) => {
                        out.push(1);
                        out.extend_from_slice(&(s.len() as u32).to_be_bytes());
                        out.extend_from_slice(s.as_bytes());
                    }
                    None => out.push(0),
                }
            }
            Op::AdmissionApprove { device, label } => {
                out.extend_from_slice(device.as_bytes());
                match label {
                    Some(s) => {
                        out.push(1);
                        out.extend_from_slice(&(s.len() as u32).to_be_bytes());
                        out.extend_from_slice(s.as_bytes());
                    }
                    None => out.push(0),
                }
            }
            Op::WhitelistRemove(k) | Op::AdmissionDeny(k) => out.extend_from_slice(k.as_bytes()),
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
            0x03 => decode_add(rest)?,
            0x04 => Op::WhitelistRemove(key(rest)?),
            0x05 => Op::WhitelistList,
            0x06 => Op::Status,
            0x07 => Op::ReloadAdmins,
            0x08 => Op::AuditTail(u32_arg(rest)?),
            0x09 => Op::AdmissionList,
            0x0a => decode_approve(rest)?,
            0x0b => Op::AdmissionDeny(key(rest)?),
            other => return Err(Error::Malformed(format!("unknown op tag {other:#x}"))),
        };
        // Every op consumes its payload exactly; reject trailing bytes.
        if payload.len() != op.payload().len() {
            return Err(Error::Malformed("op payload has trailing bytes".into()));
        }
        Ok(op)
    }

    /// A short, stable name for logs and audit records.
    pub fn name(&self) -> &'static str {
        match self {
            Op::WhitelistEnable => "whitelist-enable",
            Op::WhitelistDisable => "whitelist-disable",
            Op::WhitelistAdd { .. } => "whitelist-add",
            Op::WhitelistRemove(_) => "whitelist-remove",
            Op::WhitelistList => "whitelist-list",
            Op::Status => "status",
            Op::ReloadAdmins => "reload-admins",
            Op::AuditTail(_) => "audit-tail",
            Op::AdmissionList => "admission-list",
            Op::AdmissionApprove { .. } => "admission-approve",
            Op::AdmissionDeny(_) => "admission-deny",
        }
    }

    /// A one-line human description shown to the operator before signing.
    pub fn summary(&self) -> String {
        match self {
            Op::WhitelistEnable => "Enable the connection whitelist".into(),
            Op::WhitelistDisable => "Disable the connection whitelist".into(),
            Op::WhitelistAdd { .. } => "Add a peer to the whitelist".into(),
            Op::WhitelistRemove(_) => "Remove a peer from the whitelist".into(),
            Op::WhitelistList => "Read the whitelist".into(),
            Op::Status => "Read server status".into(),
            Op::ReloadAdmins => "Reload the admin list from config".into(),
            Op::AuditTail(n) => format!("Read the last {n} audit entries"),
            Op::AdmissionList => "Read pending admission requests".into(),
            Op::AdmissionApprove { .. } => "Admit a device to the whitelist".into(),
            Op::AdmissionDeny(_) => "Decline an admission request".into(),
        }
    }

    /// Extra context lines (e.g. the affected key and its label).
    pub fn detail(&self) -> Vec<String> {
        match self {
            Op::WhitelistAdd { key, label } => {
                let mut d = vec![format!("peer: {}", key.to_base58())];
                if let Some(s) = label {
                    d.push(format!("label: {s}"));
                }
                d
            }
            Op::WhitelistRemove(k) => vec![format!("peer: {}", k.to_base58())],
            // The verifiable fact is the key. A requester's own label is
            // evidence shown to an administrator and is not carried over
            // unless they repeat it here as their own.
            Op::AdmissionApprove { device, label } => {
                let mut d = vec![format!("device: {}", device.to_base58())];
                if let Some(s) = label {
                    d.push(format!("label: {s}"));
                }
                d
            }
            Op::AdmissionDeny(k) => vec![format!("device: {}", k.to_base58())],
            _ => vec![],
        }
    }

    /// Whether the op changes server state (only mutations are audited).
    pub fn is_mutation(&self) -> bool {
        matches!(
            self,
            Op::WhitelistEnable
                | Op::WhitelistDisable
                | Op::WhitelistAdd { .. }
                | Op::WhitelistRemove(_)
                | Op::ReloadAdmins
        )
    }

    /// The affected key, if this op names one (for audit records).
    pub fn target(&self) -> Option<String> {
        match self {
            Op::WhitelistAdd { key, .. } => Some(key.to_base58()),
            Op::WhitelistRemove(k) => Some(k.to_base58()),
            Op::AdmissionApprove { device, .. } => Some(device.to_base58()),
            Op::AdmissionDeny(k) => Some(k.to_base58()),
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

fn decode_approve(rest: &[u8]) -> Result<Op> {
    match decode_add(rest)? {
        Op::WhitelistAdd { key, label } => Ok(Op::AdmissionApprove { device: key, label }),
        _ => unreachable!("decode_add returns a whitelist add"),
    }
}

fn decode_add(rest: &[u8]) -> Result<Op> {
    if rest.len() < 33 {
        return Err(Error::Malformed("whitelist-add: too short".into()));
    }
    let key = PubKey::new(rest[0..32].try_into().unwrap());
    let tail = &rest[32..];
    let label = match tail[0] {
        0 if tail.len() == 1 => None,
        1 => {
            if tail.len() < 5 {
                return Err(Error::Malformed("whitelist-add: truncated label".into()));
            }
            let len = u32::from_be_bytes(tail[1..5].try_into().unwrap()) as usize;
            if len > MAX_LABEL {
                return Err(Error::Malformed(format!("label of {len} bytes exceeds {MAX_LABEL}")));
            }
            let body = &tail[5..];
            if body.len() != len {
                return Err(Error::Malformed("whitelist-add: label length mismatch".into()));
            }
            Some(String::from_utf8(body.to_vec()).map_err(|_| Error::Malformed("label is not utf-8".into()))?)
        }
        _ => return Err(Error::Malformed("whitelist-add: bad label marker".into())),
    };
    Ok(Op::WhitelistAdd { key, label })
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
            Op::WhitelistAdd {
                key: PubKey::new([5u8; 32]),
                label: None,
            },
            Op::WhitelistAdd {
                key: PubKey::new([5u8; 32]),
                label: Some("colin-laptop".into()),
            },
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
    fn add_detail_names_key_and_label() {
        let k = PubKey::new([7u8; 32]);
        let op = Op::WhitelistAdd {
            key: k,
            label: Some("ci-runner".into()),
        };
        let d = op.detail();
        assert_eq!(d[0], format!("peer: {}", k.to_base58()));
        assert_eq!(d[1], "label: ci-runner");
        assert_eq!(op.target(), Some(k.to_base58()));
    }

    #[test]
    fn oversized_label_rejected() {
        let op = Op::WhitelistAdd {
            key: PubKey::new([1u8; 32]),
            label: Some("x".repeat(MAX_LABEL + 1)),
        };
        assert!(Op::decode(&op.payload()).is_err());
    }

    #[test]
    fn empty_payload_rejected() {
        assert!(Op::decode(&[]).is_err());
    }
}
