//! SIP-18 attachment references: what a message carries in place of a file.
//!
//! An entry body is capped at 32 KiB and a video is four thousand times that,
//! so a message carries a **reference** — the blob's name, the key that opens
//! it, its shape, and a small preview that renders before a byte has been
//! fetched. The bytes live in a separate chunked store.
//!
//! Only the reference is here. The blob service itself — upload, fetch,
//! attach, detach — is not implemented yet, and this module deliberately does
//! not pretend otherwise: it is the layout a SIP-19 message embeds, and it is
//! needed before the store exists because the message format is what needs it.
//!
//! # The key travels in the reference, and that is the whole design
//!
//! A blob is sealed before it is uploaded, under a key the exchange never
//! receives. Anyone who can read the message can open the file and nobody else
//! can — including the exchange, which is holding the bytes. In a *public*
//! channel the message is plaintext, so the key sits beside the ciphertext it
//! opens and the encryption protects nothing from the exchange; that follows
//! from public channels being plaintext and is not a flaw, but it is why
//! "attachments are encrypted so the exchange cannot see them" is true of
//! private channels only.

use sqnr_core::{Error, Result};

/// Kinds a reader might know. Anything else is treated as [`KIND_FILE`], which
/// can still be named, sized, fetched and saved.
pub const KIND_IMAGE: u8 = 0x01;
pub const KIND_VIDEO: u8 = 0x02;
pub const KIND_VOICE: u8 = 0x03;
pub const KIND_FILE: u8 = 0x04;

/// Bytes of inline preview. The entry body is 32 KiB and must also hold the
/// text, so four attachments each carrying a full one will not fit — a client
/// sizes previews to what it is actually sending.
pub const MAX_PREVIEW: usize = 8 * 1024;
pub const MAX_MIME: usize = 128;
pub const MAX_META: usize = 1024;
/// Chunks a blob may hold: 100 MiB at 256 KiB each.
pub const MAX_CHUNKS: u32 = 400;

/// A file, by reference.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Attachment {
    pub kind: u8,
    /// SHA-256 over the *ciphertext*, so the exchange can verify a name for
    /// bytes it cannot read.
    pub blob: [u8; 32],
    pub key: [u8; 32],
    pub size: u64,
    pub chunks: u32,
    /// The sender's claim and nothing more. A receiver MUST NOT dispatch on it
    /// beyond choosing how to display, MUST NOT execute a blob, and MUST NOT
    /// hand one to a handler selected by this string.
    pub mime: String,
    /// Shape, by kind. Opaque for a kind the reader does not know.
    pub meta: Vec<u8>,
    /// A thumbnail or poster frame, rendered while the blob is fetched.
    pub preview: Vec<u8>,
}

impl Attachment {
    /// The kind to render as: an unknown one is a file.
    pub fn effective_kind(&self) -> u8 {
        match self.kind {
            KIND_IMAGE | KIND_VIDEO | KIND_VOICE => self.kind,
            _ => KIND_FILE,
        }
    }

    /// Pixel dimensions, for a kind that has them.
    pub fn dimensions(&self) -> Option<(u16, u16)> {
        match (self.effective_kind(), self.meta.len()) {
            (KIND_IMAGE, n) if n >= 4 => Some((
                u16::from_be_bytes(self.meta[0..2].try_into().unwrap()),
                u16::from_be_bytes(self.meta[2..4].try_into().unwrap()),
            )),
            (KIND_VIDEO, n) if n >= 8 => Some((
                u16::from_be_bytes(self.meta[0..2].try_into().unwrap()),
                u16::from_be_bytes(self.meta[2..4].try_into().unwrap()),
            )),
            _ => None,
        }
    }

    /// How long it runs, for video and voice.
    pub fn duration_ms(&self) -> Option<u32> {
        match (self.effective_kind(), self.meta.len()) {
            (KIND_VIDEO, n) if n >= 8 => {
                Some(u32::from_be_bytes(self.meta[4..8].try_into().unwrap()))
            }
            (KIND_VOICE, n) if n >= 4 => {
                Some(u32::from_be_bytes(self.meta[0..4].try_into().unwrap()))
            }
            _ => None,
        }
    }

    /// A voice note's waveform, so it draws before any audio is fetched.
    ///
    /// Each level is SIP-15's scale — half a decibel below full scale per unit,
    /// 255 for digital silence — so one function in a client renders both a
    /// live call and a voice note.
    pub fn waveform(&self) -> Option<&[u8]> {
        if self.effective_kind() != KIND_VOICE || self.meta.len() < 5 {
            return None;
        }
        let bars = self.meta[4] as usize;
        self.meta.get(5..5 + bars)
    }

    pub fn wire_len(&self) -> usize {
        1 + 32 + 32 + 8 + 4 + 1 + self.mime.len() + 2 + self.meta.len() + 2 + self.preview.len()
    }

    pub fn write(&self, out: &mut Vec<u8>) {
        out.push(self.kind);
        out.extend_from_slice(&self.blob);
        out.extend_from_slice(&self.key);
        out.extend_from_slice(&self.size.to_be_bytes());
        out.extend_from_slice(&self.chunks.to_be_bytes());
        out.push(self.mime.len() as u8);
        out.extend_from_slice(self.mime.as_bytes());
        out.extend_from_slice(&(self.meta.len() as u16).to_be_bytes());
        out.extend_from_slice(&self.meta);
        out.extend_from_slice(&(self.preview.len() as u16).to_be_bytes());
        out.extend_from_slice(&self.preview);
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.wire_len());
        self.write(&mut out);
        out
    }

    /// Read one, advancing `o`.
    pub fn read(b: &[u8], o: &mut usize) -> Result<Attachment> {
        let at = *o;
        if b.len() < at + 78 {
            return Err(Error::Malformed("attachment is truncated".into()));
        }
        let chunks = u32::from_be_bytes(b[at + 73..at + 77].try_into().unwrap());
        if chunks > MAX_CHUNKS {
            return Err(Error::Malformed(format!(
                "attachment claims {chunks} chunks, limit is {MAX_CHUNKS}"
            )));
        }
        let mime_len = b[at + 77] as usize;
        if mime_len > MAX_MIME {
            return Err(Error::Malformed(format!(
                "mime is {mime_len} bytes, limit is {MAX_MIME}"
            )));
        }
        let mut p = at + 78;
        if b.len() < p + mime_len + 2 {
            return Err(Error::Malformed("attachment is truncated".into()));
        }
        let mime = utf8(&b[p..p + mime_len], "mime")?;
        p += mime_len;

        let meta_len = u16::from_be_bytes(b[p..p + 2].try_into().unwrap()) as usize;
        p += 2;
        if meta_len > MAX_META {
            return Err(Error::Malformed(format!(
                "meta is {meta_len} bytes, limit is {MAX_META}"
            )));
        }
        if b.len() < p + meta_len + 2 {
            return Err(Error::Malformed("attachment is truncated".into()));
        }
        let meta = b[p..p + meta_len].to_vec();
        p += meta_len;

        let prev_len = u16::from_be_bytes(b[p..p + 2].try_into().unwrap()) as usize;
        p += 2;
        if prev_len > MAX_PREVIEW {
            return Err(Error::Malformed(format!(
                "preview is {prev_len} bytes, limit is {MAX_PREVIEW}"
            )));
        }
        if b.len() < p + prev_len {
            return Err(Error::Malformed("attachment preview is truncated".into()));
        }
        let preview = b[p..p + prev_len].to_vec();
        *o = p + prev_len;

        Ok(Attachment {
            kind: b[at],
            blob: b[at + 1..at + 33].try_into().unwrap(),
            key: b[at + 33..at + 65].try_into().unwrap(),
            size: u64::from_be_bytes(b[at + 65..at + 73].try_into().unwrap()),
            chunks,
            mime,
            meta,
            preview,
        })
    }
}

pub(crate) fn utf8(b: &[u8], what: &str) -> Result<String> {
    String::from_utf8(b.to_vec()).map_err(|_| Error::Malformed(format!("{what} is not UTF-8")))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn image() -> Attachment {
        Attachment {
            kind: KIND_IMAGE,
            blob: [1; 32],
            key: [2; 32],
            size: 4096,
            chunks: 1,
            mime: "image/jpeg".into(),
            meta: {
                let mut m = 800u16.to_be_bytes().to_vec();
                m.extend_from_slice(&600u16.to_be_bytes());
                m
            },
            preview: vec![0xff; 64],
        }
    }

    #[test]
    fn an_attachment_round_trips() {
        let a = image();
        let mut o = 0;
        assert_eq!(Attachment::read(&a.encode(), &mut o).unwrap(), a);
        assert_eq!(o, a.wire_len());
    }

    #[test]
    fn dimensions_and_duration_read_from_meta() {
        assert_eq!(image().dimensions(), Some((800, 600)));

        let mut video = image();
        video.kind = KIND_VIDEO;
        video.meta.extend_from_slice(&12_345u32.to_be_bytes());
        assert_eq!(video.dimensions(), Some((800, 600)));
        assert_eq!(video.duration_ms(), Some(12_345));
    }

    #[test]
    fn a_voice_note_carries_its_waveform() {
        let voice = Attachment {
            kind: KIND_VOICE,
            meta: {
                let mut m = 3_000u32.to_be_bytes().to_vec();
                m.push(4);
                m.extend_from_slice(&[10, 20, 30, 40]);
                m
            },
            ..image()
        };
        assert_eq!(voice.duration_ms(), Some(3_000));
        assert_eq!(voice.waveform(), Some(&[10, 20, 30, 40][..]));
    }

    #[test]
    fn an_unknown_kind_is_a_file() {
        // The same promise SIP-19 makes about message types, at the place
        // inside a message where a new kind is most likely to be wanted.
        let odd = Attachment {
            kind: 0x7f,
            ..image()
        };
        assert_eq!(odd.effective_kind(), KIND_FILE);
        // It still round-trips, so nothing is lost by not knowing it.
        let mut o = 0;
        assert_eq!(Attachment::read(&odd.encode(), &mut o).unwrap(), odd);
        // And a reader does not invent dimensions for it.
        assert_eq!(odd.dimensions(), None);
    }

    #[test]
    fn an_oversized_preview_is_refused() {
        let big = Attachment {
            preview: vec![0; MAX_PREVIEW + 1],
            ..image()
        };
        let mut o = 0;
        assert!(Attachment::read(&big.encode(), &mut o).is_err());
    }

    #[test]
    fn a_truncated_attachment_is_refused() {
        let a = image();
        let bytes = a.encode();
        for cut in [0, 10, 77, bytes.len() - 1] {
            let mut o = 0;
            assert!(
                Attachment::read(&bytes[..cut], &mut o).is_err(),
                "cut at {cut} should not decode"
            );
        }
    }
}
