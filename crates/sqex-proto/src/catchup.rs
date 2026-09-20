//! SIP-47 §Catching up in one round trip: catching up in one round trip.
//!
//! A device that has been away names the channels it holds, with where it
//! got to in each, and receives for each **the bytes `Fetch` and `Get` would
//! have answered** -- literally: two length-prefixed replies of the existing
//! shapes, so the route stays the authority and a client decodes them with
//! the decoders it already has. Around them: the channels the account is in
//! that the device did not name, and the device's prekey count.
//!
//! Nothing here is a new authority. The exchange answers this from the same
//! functions that answer the routes it composes, and the test for the route
//! is byte equality against them.

use sqnr_core::{Error, Result};

pub const TYPE_CATCHUP: u8 = 0x01;

/// Channels one request may name.
pub const MAX_NAMED: usize = 256;
/// Unnamed channels one answer lists.
pub const MAX_UNNAMED: usize = 256;
/// The most an answer carries in entries and envelopes, whatever was asked.
pub const MAX_CATCHUP_BYTES: u32 = 1024 * 1024;

/// The channel was read and answered from `Fetch` and `Get`.
pub const STATUS_OK: u8 = 0x00;
/// The caller may not read it, or it does not exist -- one value for both.
pub const STATUS_ABSENT: u8 = 0x01;
/// Not looked at: the budget ran out before it. Nothing is claimed about it
/// either way; the device asks again.
pub const STATUS_DEFERRED: u8 = 0x02;

/// One channel the device holds, and where it got to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Named {
    pub channel: [u8; 32],
    /// `Fetch`'s `since`: entries above it.
    pub since: u64,
    /// `Get`'s `since_epoch`: envelopes at or above it.
    pub since_epoch: u32,
}

/// `POST /channel/catchup`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Catchup {
    /// Bytes of entries and envelopes the caller wants at most. Clamped to
    /// [`MAX_CATCHUP_BYTES`].
    pub budget: u32,
    /// In the caller's order, which is the order the answer comes in and the
    /// order the budget is spent in.
    pub named: Vec<Named>,
}

impl Catchup {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(7 + self.named.len() * 44);
        out.push(TYPE_CATCHUP);
        out.extend_from_slice(&self.budget.to_be_bytes());
        out.extend_from_slice(&(self.named.len() as u16).to_be_bytes());
        for n in &self.named {
            out.extend_from_slice(&n.channel);
            out.extend_from_slice(&n.since.to_be_bytes());
            out.extend_from_slice(&n.since_epoch.to_be_bytes());
        }
        out
    }

    pub fn decode(b: &[u8]) -> Result<Catchup> {
        if b.len() < 7 || b[0] != TYPE_CATCHUP {
            return Err(Error::Malformed("not a catchup".into()));
        }
        let budget = u32::from_be_bytes(b[1..5].try_into().unwrap());
        let count = u16::from_be_bytes([b[5], b[6]]) as usize;
        if count > MAX_NAMED {
            return Err(Error::Malformed(format!(
                "catchup names {count} channels, limit is {MAX_NAMED}"
            )));
        }
        if b.len() != 7 + count * 44 {
            return Err(Error::Malformed(format!(
                "catchup is {} bytes, want {} for {count} channels",
                b.len(),
                7 + count * 44
            )));
        }
        let mut named = Vec::with_capacity(count);
        for i in 0..count {
            let o = 7 + i * 44;
            named.push(Named {
                channel: b[o..o + 32].try_into().unwrap(),
                since: u64::from_be_bytes(b[o + 32..o + 40].try_into().unwrap()),
                since_epoch: u32::from_be_bytes(b[o + 40..o + 44].try_into().unwrap()),
            });
        }
        Ok(Catchup { budget, named })
    }
}

/// One named channel, answered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Caught {
    pub channel: [u8; 32],
    /// One of `STATUS_*`.
    pub status: u8,
    /// Entries exist that this answer does not carry: the batch or the
    /// budget cut them. The device comes back for them.
    pub more: bool,
    /// A SIP-16 `Entries` reply, exactly as `Fetch { since, wait_secs: 0 }`
    /// would have answered, except cut at the budget. Empty unless `status`
    /// is [`STATUS_OK`].
    pub fetched: Vec<u8>,
    /// A SIP-17 `Got` reply, exactly as `Get { since_epoch }` would have
    /// answered, in full. Empty unless `status` is [`STATUS_OK`].
    pub got: Vec<u8>,
}

/// A channel the account is in that the request did not name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Unnamed {
    pub channel: [u8; 32],
    pub last: u64,
}

/// The answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CaughtUp {
    pub now: u64,
    /// SIP-23's `one_time`, for the calling device.
    pub prekeys: u16,
    /// One per named channel, in order.
    pub caught: Vec<Caught>,
    /// Up to [`MAX_UNNAMED`], as `Mine` lists them.
    pub unnamed: Vec<Unnamed>,
}

impl CaughtUp {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(14);
        out.extend_from_slice(&self.now.to_be_bytes());
        out.extend_from_slice(&self.prekeys.to_be_bytes());
        out.extend_from_slice(&(self.caught.len() as u16).to_be_bytes());
        for c in &self.caught {
            out.extend_from_slice(&c.channel);
            out.push(c.status);
            out.push(u8::from(c.more));
            out.extend_from_slice(&(c.fetched.len() as u32).to_be_bytes());
            out.extend_from_slice(&c.fetched);
            out.extend_from_slice(&(c.got.len() as u32).to_be_bytes());
            out.extend_from_slice(&c.got);
        }
        out.extend_from_slice(&(self.unnamed.len() as u16).to_be_bytes());
        for u in &self.unnamed {
            out.extend_from_slice(&u.channel);
            out.extend_from_slice(&u.last.to_be_bytes());
        }
        out
    }

    pub fn decode(b: &[u8]) -> Result<CaughtUp> {
        fn want(b: &[u8], n: usize) -> Result<()> {
            if b.len() < n {
                return Err(Error::Malformed(format!(
                    "caughtup is {} bytes, want at least {n}",
                    b.len()
                )));
            }
            Ok(())
        }
        want(b, 12)?;
        let now = u64::from_be_bytes(b[0..8].try_into().unwrap());
        let prekeys = u16::from_be_bytes([b[8], b[9]]);
        let count = u16::from_be_bytes([b[10], b[11]]) as usize;
        if count > MAX_NAMED {
            return Err(Error::Malformed(format!(
                "caughtup answers {count} channels, limit is {MAX_NAMED}"
            )));
        }
        let mut o = 12;
        let mut caught = Vec::with_capacity(count);
        for _ in 0..count {
            want(b, o + 38)?;
            let channel: [u8; 32] = b[o..o + 32].try_into().unwrap();
            let status = b[o + 32];
            let more = match b[o + 33] {
                0 => false,
                1 => true,
                other => {
                    return Err(Error::Malformed(format!("more is {other}, want 0 or 1")));
                }
            };
            let flen = u32::from_be_bytes(b[o + 34..o + 38].try_into().unwrap()) as usize;
            if flen > MAX_CATCHUP_BYTES as usize {
                return Err(Error::Malformed(format!(
                    "fetched is {flen} bytes, over the limit"
                )));
            }
            o += 38;
            want(b, o + flen + 4)?;
            let fetched = b[o..o + flen].to_vec();
            o += flen;
            let glen = u32::from_be_bytes(b[o..o + 4].try_into().unwrap()) as usize;
            if glen > MAX_CATCHUP_BYTES as usize {
                return Err(Error::Malformed(format!(
                    "got is {glen} bytes, over the limit"
                )));
            }
            o += 4;
            want(b, o + glen)?;
            let got = b[o..o + glen].to_vec();
            o += glen;
            caught.push(Caught {
                channel,
                status,
                more,
                fetched,
                got,
            });
        }
        want(b, o + 2)?;
        let count = u16::from_be_bytes([b[o], b[o + 1]]) as usize;
        o += 2;
        if count > MAX_UNNAMED {
            return Err(Error::Malformed(format!(
                "caughtup lists {count} unnamed channels, limit is {MAX_UNNAMED}"
            )));
        }
        let mut unnamed = Vec::with_capacity(count);
        for _ in 0..count {
            want(b, o + 40)?;
            unnamed.push(Unnamed {
                channel: b[o..o + 32].try_into().unwrap(),
                last: u64::from_be_bytes(b[o + 32..o + 40].try_into().unwrap()),
            });
            o += 40;
        }
        if o != b.len() {
            return Err(Error::Malformed(format!(
                "caughtup has {} trailing bytes",
                b.len() - o
            )));
        }
        Ok(CaughtUp {
            now,
            prekeys,
            caught,
            unnamed,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn a_request() -> Catchup {
        Catchup {
            budget: 4096,
            named: vec![
                Named {
                    channel: [1; 32],
                    since: 7,
                    since_epoch: 2,
                },
                Named {
                    channel: [2; 32],
                    since: 0,
                    since_epoch: 0,
                },
            ],
        }
    }

    fn an_answer() -> CaughtUp {
        CaughtUp {
            now: 1_700_000_000,
            prekeys: 61,
            caught: vec![
                Caught {
                    channel: [1; 32],
                    status: STATUS_OK,
                    more: true,
                    fetched: vec![9; 30],
                    got: vec![8; 12],
                },
                Caught {
                    channel: [2; 32],
                    status: STATUS_ABSENT,
                    more: false,
                    fetched: Vec::new(),
                    got: Vec::new(),
                },
            ],
            unnamed: vec![Unnamed {
                channel: [3; 32],
                last: 44,
            }],
        }
    }

    #[test]
    fn a_request_round_trips_in_the_callers_order() {
        let req = a_request();
        let back = Catchup::decode(&req.encode()).unwrap();
        assert_eq!(back, req);
        assert_eq!(back.named[0].channel, [1; 32]);
        assert_eq!(
            Catchup::decode(
                &Catchup {
                    budget: 1,
                    named: vec![]
                }
                .encode()
            )
            .unwrap()
            .named
            .len(),
            0
        );
    }

    #[test]
    fn an_answer_round_trips() {
        let ans = an_answer();
        assert_eq!(CaughtUp::decode(&ans.encode()).unwrap(), ans);
    }

    /// Every way a body can lie about its own length is refused, without a
    /// panic: a truncation anywhere, a count over the limit, a length
    /// prefix promising more than there is, and trailing bytes.
    #[test]
    fn a_lying_body_is_refused_not_panicked_on() {
        let req = a_request().encode();
        for cut in 0..req.len() {
            assert!(Catchup::decode(&req[..cut]).is_err(), "cut at {cut}");
        }
        let mut too_many = req.clone();
        too_many[5..7].copy_from_slice(&(MAX_NAMED as u16 + 1).to_be_bytes());
        assert!(Catchup::decode(&too_many).is_err());
        let mut wrong_type = req.clone();
        wrong_type[0] = 0x02;
        assert!(Catchup::decode(&wrong_type).is_err());

        let ans = an_answer().encode();
        for cut in 0..ans.len() {
            assert!(CaughtUp::decode(&ans[..cut]).is_err(), "cut at {cut}");
        }
        let mut trailing = ans.clone();
        trailing.push(0);
        assert!(CaughtUp::decode(&trailing).is_err());
        let mut lying = ans.clone();
        // The first caught's fetched length, at 12 + 34.
        lying[46..50].copy_from_slice(&u32::MAX.to_be_bytes());
        assert!(CaughtUp::decode(&lying).is_err());
        let mut bad_more = ans.clone();
        bad_more[12 + 33] = 7;
        assert!(CaughtUp::decode(&bad_more).is_err());
    }
}
