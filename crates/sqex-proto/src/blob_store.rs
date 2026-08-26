//! SIP-18 blob storage: the wire for putting a file somewhere the exchange
//! cannot read it.
//!
//! [`crate::blob`] holds the *reference* a message carries. This is the service
//! that holds the bytes: chunked because nothing in this stack streams, sealed
//! before upload under a key the exchange never receives, and named by the hash
//! of the ciphertext so the exchange can verify a name for bytes it cannot open.
//!
//! # The key is not here, and no operation may carry it
//!
//! Every message below moves ciphertext, an identifier, or a channel. None has
//! a field for the key and none may be given one: a convenience endpoint that
//! accepted one — for server-side thumbnailing, scanning or transcoding — would
//! break SIP-18 while conforming to every other rule in it.

use sqnr_core::{Error, Result};

/// Domain separator for a blob's name.
pub const BLOB_CONTEXT: &[u8] = b"sqex-blob-v1";

pub const TYPE_BEGIN: u8 = 0x01;
pub const TYPE_PUT: u8 = 0x02;
pub const TYPE_COMMIT: u8 = 0x03;
pub const TYPE_ABORT: u8 = 0x04;
pub const TYPE_HEAD: u8 = 0x05;
pub const TYPE_GET: u8 = 0x06;
pub const TYPE_ATTACH: u8 = 0x07;
pub const TYPE_DETACH: u8 = 0x08;
pub const TYPE_LIMITS: u8 = 0x09;

/// Bytes per chunk. Larger than the uniform request cap, which is why an
/// exchange raises that limit on the blob routes and only there.
pub const CHUNK: usize = 256 * 1024;
/// 100 MiB, which is 400 chunks.
pub const MAX_BLOB: u64 = 100 * 1024 * 1024;
pub const MAX_CHUNKS: u32 = 400;
/// Stored blob bytes per channel.
pub const MAX_CHANNEL_BLOB_BYTES: u64 = 2 * 1024 * 1024 * 1024;
/// Uploads one identity may have open at once.
pub const MAX_UPLOADS: usize = 8;
/// How long an incomplete upload is kept.
pub const UPLOAD_TTL: u64 = 60 * 60;

/// Name a blob from its sealed chunks.
///
/// Over the **ciphertext**, not the plaintext, and that does a specific piece
/// of work: the exchange can verify the name it is asked to store, so nobody
/// can claim a name they do not have the bytes for, and a fetched blob is
/// self-verifying against a name that arrived inside a sealed message.
pub fn blob_id(sealed_chunks: &[Vec<u8>]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(BLOB_CONTEXT);
    for c in sealed_chunks {
        h.update(c);
    }
    h.finalize().into()
}

/// The nonce for one chunk. Each is sealed independently, which is what lets a
/// client verify and render as it goes — a video plays before it has finished
/// downloading, and a chunk that fails to open is one to re-request rather than
/// a whole file to discard.
pub fn chunk_nonce(index: u32) -> [u8; 12] {
    let mut n = [0u8; 12];
    n[..8].copy_from_slice(&(index as u64).to_be_bytes());
    n
}

/// Reserve an upload against a channel's quota.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Begin {
    pub channel: [u8; 32],
    /// Plaintext length. The stored length is this plus 16 bytes per chunk.
    pub size: u64,
    pub chunks: u32,
    /// A disappearing-message timer, so an attachment goes when the message
    /// carrying it does. The exchange cannot infer this — the reference is
    /// inside an entry it cannot read — so the uploader declares it.
    pub expires_after: u32,
}

impl Begin {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(49);
        out.push(TYPE_BEGIN);
        out.extend_from_slice(&self.channel);
        out.extend_from_slice(&self.size.to_be_bytes());
        out.extend_from_slice(&self.chunks.to_be_bytes());
        out.extend_from_slice(&self.expires_after.to_be_bytes());
        out
    }

    pub fn decode(b: &[u8]) -> Result<Begin> {
        if b.len() != 49 {
            return Err(Error::Malformed(format!(
                "begin is {} bytes, want 49",
                b.len()
            )));
        }
        if b[0] != TYPE_BEGIN {
            return Err(Error::Malformed(format!("not a begin (type {:#x})", b[0])));
        }
        let size = u64::from_be_bytes(b[33..41].try_into().unwrap());
        let chunks = u32::from_be_bytes(b[41..45].try_into().unwrap());
        if size > MAX_BLOB {
            return Err(Error::Malformed(format!(
                "blob is {size} bytes, limit is {MAX_BLOB}"
            )));
        }
        if chunks == 0 || chunks > MAX_CHUNKS {
            return Err(Error::Malformed(format!(
                "blob claims {chunks} chunks, want 1..={MAX_CHUNKS}"
            )));
        }
        Ok(Begin {
            channel: b[1..33].try_into().unwrap(),
            size,
            chunks,
            expires_after: u32::from_be_bytes(b[45..49].try_into().unwrap()),
        })
    }
}

/// One sealed chunk. Chunks may arrive in any order and a repeat overwrites.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PutChunk {
    pub upload: u64,
    pub index: u32,
    pub sealed: Vec<u8>,
}

impl PutChunk {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(13 + self.sealed.len());
        out.push(TYPE_PUT);
        out.extend_from_slice(&self.upload.to_be_bytes());
        out.extend_from_slice(&self.index.to_be_bytes());
        out.extend_from_slice(&self.sealed);
        out
    }

    pub fn decode(b: &[u8]) -> Result<PutChunk> {
        if b.len() < 13 {
            return Err(Error::Malformed(format!(
                "put is {} bytes, want at least 13",
                b.len()
            )));
        }
        if b[0] != TYPE_PUT {
            return Err(Error::Malformed(format!("not a put (type {:#x})", b[0])));
        }
        let sealed = b[13..].to_vec();
        // The AEAD tag is what the plaintext cap becomes on the wire.
        if sealed.len() > CHUNK + 16 {
            return Err(Error::Malformed(format!(
                "chunk is {} bytes, limit is {}",
                sealed.len(),
                CHUNK + 16
            )));
        }
        Ok(PutChunk {
            upload: u64::from_be_bytes(b[1..9].try_into().unwrap()),
            index: u32::from_be_bytes(b[9..13].try_into().unwrap()),
            sealed,
        })
    }
}

/// Finish an upload, naming what it should have come to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Commit {
    pub upload: u64,
    pub blob: [u8; 32],
}

impl Commit {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(41);
        out.push(TYPE_COMMIT);
        out.extend_from_slice(&self.upload.to_be_bytes());
        out.extend_from_slice(&self.blob);
        out
    }

    pub fn decode(b: &[u8]) -> Result<Commit> {
        if b.len() != 41 {
            return Err(Error::Malformed(format!(
                "commit is {} bytes, want 41",
                b.len()
            )));
        }
        if b[0] != TYPE_COMMIT {
            return Err(Error::Malformed(format!("not a commit (type {:#x})", b[0])));
        }
        Ok(Commit {
            upload: u64::from_be_bytes(b[1..9].try_into().unwrap()),
            blob: b[9..41].try_into().unwrap(),
        })
    }
}

/// A request naming an upload: abort.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ByUpload {
    pub upload: u64,
}

impl ByUpload {
    pub fn encode(&self, type_byte: u8) -> Vec<u8> {
        let mut out = Vec::with_capacity(9);
        out.push(type_byte);
        out.extend_from_slice(&self.upload.to_be_bytes());
        out
    }

    pub fn decode(b: &[u8], type_byte: u8) -> Result<ByUpload> {
        if b.len() != 9 || b[0] != type_byte {
            return Err(Error::Malformed("malformed upload reference".into()));
        }
        Ok(ByUpload {
            upload: u64::from_be_bytes(b[1..9].try_into().unwrap()),
        })
    }
}

/// A request naming a blob and a channel: attach, detach.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ByChannelBlob {
    pub channel: [u8; 32],
    pub blob: [u8; 32],
    pub expires_after: u32,
}

impl ByChannelBlob {
    pub fn encode(&self, type_byte: u8) -> Vec<u8> {
        let mut out = Vec::with_capacity(69);
        out.push(type_byte);
        out.extend_from_slice(&self.channel);
        out.extend_from_slice(&self.blob);
        if type_byte == TYPE_ATTACH {
            out.extend_from_slice(&self.expires_after.to_be_bytes());
        }
        out
    }

    pub fn decode(b: &[u8], type_byte: u8) -> Result<ByChannelBlob> {
        let want = if type_byte == TYPE_ATTACH { 69 } else { 65 };
        if b.len() != want || b[0] != type_byte {
            return Err(Error::Malformed(format!(
                "malformed channel-blob request ({} bytes, want {want})",
                b.len()
            )));
        }
        Ok(ByChannelBlob {
            channel: b[1..33].try_into().unwrap(),
            blob: b[33..65].try_into().unwrap(),
            expires_after: if type_byte == TYPE_ATTACH {
                u32::from_be_bytes(b[65..69].try_into().unwrap())
            } else {
                0
            },
        })
    }
}

/// Ask for one chunk, or for a blob's shape.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GetChunk {
    pub blob: [u8; 32],
    pub index: u32,
}

impl GetChunk {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(37);
        out.push(TYPE_GET);
        out.extend_from_slice(&self.blob);
        out.extend_from_slice(&self.index.to_be_bytes());
        out
    }

    pub fn decode(b: &[u8]) -> Result<GetChunk> {
        if b.len() != 37 || b[0] != TYPE_GET {
            return Err(Error::Malformed(format!(
                "get is {} bytes, want 37",
                b.len()
            )));
        }
        Ok(GetChunk {
            blob: b[1..33].try_into().unwrap(),
            index: u32::from_be_bytes(b[33..37].try_into().unwrap()),
        })
    }
}

/// A blob identifier alone: head.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ByBlob {
    pub blob: [u8; 32],
}

impl ByBlob {
    pub fn encode(&self, type_byte: u8) -> Vec<u8> {
        let mut out = Vec::with_capacity(33);
        out.push(type_byte);
        out.extend_from_slice(&self.blob);
        out
    }

    pub fn decode(b: &[u8], type_byte: u8) -> Result<ByBlob> {
        if b.len() != 33 || b[0] != type_byte {
            return Err(Error::Malformed("malformed blob reference".into()));
        }
        Ok(ByBlob {
            blob: b[1..33].try_into().unwrap(),
        })
    }
}

/// An upload was reserved.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Begun {
    pub upload: u64,
    pub now: u64,
}

/// The result of a commit. `stored: 0` means the assembled bytes did not hash
/// to the claimed name, or a chunk was missing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Committed {
    pub stored: bool,
    pub blob: [u8; 32],
    pub now: u64,
}

/// A blob's shape, or its absence in the same shape.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Headed {
    pub found: bool,
    pub size: u64,
    pub chunks: u32,
    pub attached: u64,
    pub now: u64,
}

/// One chunk, or its absence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Chunk {
    pub found: bool,
    pub index: u32,
    pub sealed: Vec<u8>,
}

/// What this exchange will accept.
///
/// SIP-18 says a client discovers `CHUNK` from the exchange rather than
/// assuming it, and this is where. Without it the sentence is unactionable: a
/// client choosing 256 KiB against an exchange that kept the uniform 64 KiB cap
/// would fail on its first `Put` with nothing to tell it why.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    pub chunk: u32,
    pub max_blob: u64,
    pub max_chunks: u32,
    pub now: u64,
}

impl Begun {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = self.upload.to_be_bytes().to_vec();
        out.extend_from_slice(&self.now.to_be_bytes());
        out
    }

    pub fn decode(b: &[u8]) -> Result<Begun> {
        want(b, 16, "begun")?;
        Ok(Begun {
            upload: u64::from_be_bytes(b[0..8].try_into().unwrap()),
            now: u64::from_be_bytes(b[8..16].try_into().unwrap()),
        })
    }
}

impl Committed {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(41);
        out.push(u8::from(self.stored));
        out.extend_from_slice(&self.blob);
        out.extend_from_slice(&self.now.to_be_bytes());
        out
    }

    pub fn decode(b: &[u8]) -> Result<Committed> {
        want(b, 41, "committed")?;
        Ok(Committed {
            stored: b[0] != 0,
            blob: b[1..33].try_into().unwrap(),
            now: u64::from_be_bytes(b[33..41].try_into().unwrap()),
        })
    }
}

impl Headed {
    pub fn none(now: u64) -> Headed {
        Headed {
            found: false,
            size: 0,
            chunks: 0,
            attached: 0,
            now,
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(29);
        out.push(u8::from(self.found));
        out.extend_from_slice(&self.size.to_be_bytes());
        out.extend_from_slice(&self.chunks.to_be_bytes());
        out.extend_from_slice(&self.attached.to_be_bytes());
        out.extend_from_slice(&self.now.to_be_bytes());
        out
    }

    pub fn decode(b: &[u8]) -> Result<Headed> {
        want(b, 29, "headed")?;
        Ok(Headed {
            found: b[0] != 0,
            size: u64::from_be_bytes(b[1..9].try_into().unwrap()),
            chunks: u32::from_be_bytes(b[9..13].try_into().unwrap()),
            attached: u64::from_be_bytes(b[13..21].try_into().unwrap()),
            now: u64::from_be_bytes(b[21..29].try_into().unwrap()),
        })
    }
}

impl Limits {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(24);
        out.extend_from_slice(&self.chunk.to_be_bytes());
        out.extend_from_slice(&self.max_blob.to_be_bytes());
        out.extend_from_slice(&self.max_chunks.to_be_bytes());
        out.extend_from_slice(&self.now.to_be_bytes());
        out
    }

    pub fn decode(b: &[u8]) -> Result<Limits> {
        want(b, 24, "limits")?;
        Ok(Limits {
            chunk: u32::from_be_bytes(b[0..4].try_into().unwrap()),
            max_blob: u64::from_be_bytes(b[4..12].try_into().unwrap()),
            max_chunks: u32::from_be_bytes(b[12..16].try_into().unwrap()),
            now: u64::from_be_bytes(b[16..24].try_into().unwrap()),
        })
    }
}

fn want(b: &[u8], n: usize, what: &str) -> Result<()> {
    if b.len() != n {
        return Err(Error::Malformed(format!(
            "{what} is {} bytes, want {n}",
            b.len()
        )));
    }
    Ok(())
}

impl Chunk {
    pub fn none(index: u32) -> Chunk {
        Chunk {
            found: false,
            index,
            sealed: Vec::new(),
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(9 + self.sealed.len());
        out.push(u8::from(self.found));
        out.extend_from_slice(&self.index.to_be_bytes());
        out.extend_from_slice(&(self.sealed.len() as u32).to_be_bytes());
        out.extend_from_slice(&self.sealed);
        out
    }

    pub fn decode(b: &[u8]) -> Result<Chunk> {
        if b.len() < 9 {
            return Err(Error::Malformed(format!(
                "chunk is {} bytes, want at least 9",
                b.len()
            )));
        }
        let len = u32::from_be_bytes(b[5..9].try_into().unwrap()) as usize;
        if b.len() != 9 + len {
            return Err(Error::Malformed(format!(
                "chunk is {} bytes, want {}",
                b.len(),
                9 + len
            )));
        }
        if len > CHUNK + 16 {
            return Err(Error::Malformed(format!(
                "chunk is {len} bytes, limit is {}",
                CHUNK + 16
            )));
        }
        Ok(Chunk {
            found: b[0] != 0,
            index: u32::from_be_bytes(b[1..5].try_into().unwrap()),
            sealed: b[9..].to_vec(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_name_covers_every_chunk_in_order() {
        let a = vec![b"one".to_vec(), b"two".to_vec()];
        let b = vec![b"two".to_vec(), b"one".to_vec()];
        assert_ne!(blob_id(&a), blob_id(&b), "order is part of the name");
        assert_eq!(blob_id(&a), blob_id(&a.clone()));
        // And a domain separator, so a blob name is never some other hash.
        assert_ne!(blob_id(&[]), [0u8; 32]);
    }

    #[test]
    fn chunk_nonces_are_distinct_per_index() {
        assert_ne!(chunk_nonce(0), chunk_nonce(1));
        assert_eq!(chunk_nonce(7)[..8], (7u64).to_be_bytes());
    }

    #[test]
    fn begin_round_trips_and_bounds_what_it_claims() {
        let b = Begin {
            channel: [1; 32],
            size: 1024,
            chunks: 1,
            expires_after: 300,
        };
        assert_eq!(Begin::decode(&b.encode()).unwrap(), b);

        assert!(Begin::decode(&Begin { size: MAX_BLOB + 1, ..b }.encode()).is_err());
        assert!(Begin::decode(&Begin { chunks: 0, ..b }.encode()).is_err());
        assert!(Begin::decode(&Begin { chunks: MAX_CHUNKS + 1, ..b }.encode()).is_err());
    }

    #[test]
    fn a_chunk_is_bounded_by_the_cap_plus_its_tag() {
        let ok = PutChunk {
            upload: 1,
            index: 0,
            sealed: vec![0; CHUNK + 16],
        };
        assert_eq!(PutChunk::decode(&ok.encode()).unwrap(), ok);
        let big = PutChunk {
            sealed: vec![0; CHUNK + 17],
            ..ok
        };
        assert!(PutChunk::decode(&big.encode()).is_err());
    }

    #[test]
    fn replies_round_trip_and_absence_keeps_its_shape() {
        let b = Begun { upload: 4, now: 9 };
        assert_eq!(Begun::decode(&b.encode()).unwrap(), b);
        let c = Committed {
            stored: true,
            blob: [2; 32],
            now: 9,
        };
        assert_eq!(Committed::decode(&c.encode()).unwrap(), c);
        let h = Headed {
            found: false,
            size: 0,
            chunks: 0,
            attached: 0,
            now: 9,
        };
        assert_eq!(Headed::decode(&h.encode()).unwrap(), h);
        // Absence and presence are the same length, as SIP-4 and SIP-5 do.
        assert_eq!(
            h.encode().len(),
            Headed {
                found: true,
                size: 99,
                chunks: 1,
                attached: 5,
                now: 9
            }
            .encode()
            .len()
        );

        let missing = Chunk::none(3);
        assert_eq!(Chunk::decode(&missing.encode()).unwrap(), missing);
    }

    #[test]
    fn limits_round_trip() {
        let l = Limits {
            chunk: CHUNK as u32,
            max_blob: MAX_BLOB,
            max_chunks: MAX_CHUNKS,
            now: 1,
        };
        assert_eq!(Limits::decode(&l.encode()).unwrap(), l);
    }

    #[test]
    fn requests_check_the_type_they_were_asked_for() {
        let a = ByChannelBlob {
            channel: [1; 32],
            blob: [2; 32],
            expires_after: 60,
        };
        assert_eq!(
            ByChannelBlob::decode(&a.encode(TYPE_ATTACH), TYPE_ATTACH).unwrap(),
            a
        );
        // Detach carries no timer, so the shapes differ and cannot be confused.
        assert!(ByChannelBlob::decode(&a.encode(TYPE_ATTACH), TYPE_DETACH).is_err());
    }
}
