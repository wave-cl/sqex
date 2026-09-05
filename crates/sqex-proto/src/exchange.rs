//! Exchange-level answers that belong to no service.
//!
//! Today that is one route. `/exchange/ping` exists to demonstrate SIP-9
//! whitelist enforcement, and used to answer `{"pong": true}` — a constant that
//! said nothing a 200 had not already said. The clock is worth more: a caller
//! checking whether it is allowed in generally wants to know the exchange is
//! awake and roughly when it thinks it is, and every other acknowledgement here
//! (`BeatAck`, `ChannelAck`) carries the same field for the same reason.

use sqnr_core::{Error, Result};

pub const TYPE_PONG: u8 = 0x01;

/// The answer to a ping: you are allowed, and this is my clock.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Pong {
    pub now: u64,
}

impl Pong {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(9);
        out.push(TYPE_PONG);
        out.extend_from_slice(&self.now.to_be_bytes());
        out
    }

    pub fn decode(b: &[u8]) -> Result<Pong> {
        if b.len() != 9 {
            return Err(Error::Malformed(format!(
                "pong is {} bytes, want 9",
                b.len()
            )));
        }
        if b[0] != TYPE_PONG {
            return Err(Error::Malformed(format!("not a pong (type {:#x})", b[0])));
        }
        Ok(Pong {
            now: u64::from_be_bytes(b[1..9].try_into().unwrap()),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_pong_round_trips() {
        let p = Pong { now: 1_788_000_000 };
        assert_eq!(Pong::decode(&p.encode()).unwrap(), p);
        assert_eq!(p.encode().len(), 9);
    }

    #[test]
    fn a_wrong_shape_is_refused() {
        assert!(Pong::decode(&[TYPE_PONG, 0, 0]).is_err());
        assert!(Pong::decode(&[0x02, 0, 0, 0, 0, 0, 0, 0, 0]).is_err());
    }
}
