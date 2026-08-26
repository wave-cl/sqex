//! Sending and fetching files (SIP-18), and describing them (SIP-19).
//!
//! A blob is sealed by the client under a key of its own, chunk by chunk, and
//! named by the hash of the **ciphertext** — so the exchange can verify the
//! name for bytes it cannot read. The key travels inside the sealed message
//! that references it, which is how a file the exchange stores is a file the
//! exchange cannot open.
//!
//! # The chunk size is not ours to pick
//!
//! `CHUNK` is a recommended value and an exchange that has not raised its
//! request cap conforms by choosing a smaller one. SIP-18 therefore says a
//! client MUST ask rather than assume, and this module does: without it, a
//! client picking 256 KiB against an exchange holding 64 KiB fails on its first
//! `Put` with nothing to say why.

use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use sqex_proto::blob::{
    Attachment, KIND_FILE, KIND_IMAGE, KIND_VIDEO, KIND_VOICE, MAX_MIME,
};
use sqex_proto::blob_store::{
    Begin, Begun, ByBlob, Chunk, Commit, Committed, GetChunk, Headed, Limits, MAX_BLOB,
    PutChunk, TYPE_HEAD, TYPE_LIMITS, blob_id, chunk_nonce,
};

use crate::client::{Chat, ChatError};

type Result<T> = std::result::Result<T, ChatError>;

/// What a file turned out to be, once read.
pub struct Prepared {
    pub attachment: Attachment,
    sealed: Vec<Vec<u8>>,
}

impl Prepared {
    pub fn chunks(&self) -> usize {
        self.sealed.len()
    }
}

/// Guess a kind and a media type from the name alone.
///
/// Deliberately shallow. The `mime` is the sender's claim and nothing more —
/// SIP-18 says a receiver MUST NOT dispatch on it beyond choosing how to
/// display — so sniffing content to make it more accurate would buy precision
/// in a field nobody is allowed to trust.
pub fn kind_of(name: &str) -> (u8, String) {
    let ext = name
        .rsplit('.')
        .next()
        .unwrap_or("")
        .to_ascii_lowercase();
    match ext.as_str() {
        "png" => (KIND_IMAGE, "image/png".into()),
        "jpg" | "jpeg" => (KIND_IMAGE, "image/jpeg".into()),
        "gif" => (KIND_IMAGE, "image/gif".into()),
        "webp" => (KIND_IMAGE, "image/webp".into()),
        "mp4" => (KIND_VIDEO, "video/mp4".into()),
        "mov" => (KIND_VIDEO, "video/quicktime".into()),
        "webm" => (KIND_VIDEO, "video/webm".into()),
        "opus" => (KIND_VOICE, "audio/opus".into()),
        "ogg" => (KIND_VOICE, "audio/ogg".into()),
        "wav" => (KIND_VOICE, "audio/wav".into()),
        "txt" | "md" => (KIND_FILE, "text/plain".into()),
        "pdf" => (KIND_FILE, "application/pdf".into()),
        _ => (KIND_FILE, "application/octet-stream".into()),
    }
}

/// The file name, for a kind that carries one.
///
/// `KIND_FILE`'s `meta` is a length-prefixed name, which is the only place a
/// filename survives — nothing else in the reference is a name, and the blob id
/// deliberately is not.
pub fn file_name(a: &Attachment) -> Option<String> {
    if a.effective_kind() != KIND_FILE || a.meta.is_empty() {
        return None;
    }
    let len = a.meta[0] as usize;
    a.meta
        .get(1..1 + len)
        .map(|b| String::from_utf8_lossy(b).into_owned())
}

impl Chat {
    /// What this exchange will accept. Asked, never assumed.
    pub async fn blob_limits(&mut self) -> Result<Limits> {
        let body = self.post_raw("/blob/limits", vec![TYPE_LIMITS]).await?;
        Limits::decode(&body).map_err(|e| ChatError::Protocol(e.to_string()))
    }

    /// Read a file and seal it, ready to upload.
    ///
    /// The key is fresh per blob and random, not derived from the plaintext.
    /// Deriving it would deduplicate globally and let anyone holding a candidate
    /// file confirm whether it is stored, which is precisely the attack that
    /// matters for images; SIP-18 rejected convergent encryption for that
    /// reason, and forwarding still deduplicates because the key rides inside
    /// the reference.
    pub fn prepare_file(&self, path: &std::path::Path, chunk: usize) -> Result<Prepared> {
        let plaintext = std::fs::read(path)
            .map_err(|e| ChatError::Protocol(format!("{}: {e}", path.display())))?;
        if plaintext.len() as u64 > MAX_BLOB {
            return Err(ChatError::Protocol(format!(
                "{} is {} bytes; the limit is {MAX_BLOB}",
                path.display(),
                plaintext.len()
            )));
        }
        if plaintext.is_empty() {
            return Err(ChatError::Protocol(format!("{} is empty", path.display())));
        }

        let mut key = [0u8; 32];
        {
            use rand_core::RngCore;
            rand_core::OsRng.fill_bytes(&mut key);
        }
        let cipher = ChaCha20Poly1305::new_from_slice(&key)
            .map_err(|e| ChatError::Protocol(format!("blob key: {e}")))?;
        let sealed: Vec<Vec<u8>> = plaintext
            .chunks(chunk)
            .enumerate()
            .map(|(i, c)| {
                cipher
                    .encrypt(Nonce::from_slice(&chunk_nonce(i as u32)), c)
                    .map_err(|e| ChatError::Protocol(format!("seal chunk {i}: {e}")))
            })
            .collect::<Result<Vec<_>>>()?;

        let name = path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        let (kind, mut mime) = kind_of(&name);
        mime.truncate(MAX_MIME);
        // Only a file carries its name. An image or a video is displayed, not
        // opened by name, and SIP-18 gives those kinds their meta for shape.
        let meta = if kind == KIND_FILE {
            let mut m = Vec::new();
            let n: Vec<u8> = name.bytes().take(255).collect();
            m.push(n.len() as u8);
            m.extend_from_slice(&n);
            m
        } else {
            Vec::new()
        };

        Ok(Prepared {
            attachment: Attachment {
                kind,
                blob: blob_id(&sealed),
                key,
                size: plaintext.len() as u64,
                chunks: sealed.len() as u32,
                mime,
                meta,
                // No thumbnail: rendering one means decoding the image, and a
                // terminal client has nothing to show it on. The field exists
                // for a client that does.
                preview: Vec::new(),
            },
            sealed,
        })
    }

    /// Upload a prepared file to a channel and return its reference.
    ///
    /// An upload that fails partway is aborted rather than left to expire, so
    /// the caller's next attempt is not refused for holding too many open.
    pub async fn upload(
        &mut self,
        channel: &[u8; 32],
        prepared: &Prepared,
    ) -> Result<Attachment> {
        let body = self
            .post_raw(
                "/blob/begin",
                Begin {
                    channel: *channel,
                    size: prepared.attachment.size,
                    chunks: prepared.attachment.chunks,
                    expires_after: 0,
                }
                .encode(),
            )
            .await?;
        let upload = Begun::decode(&body)
            .map_err(|e| ChatError::Protocol(e.to_string()))?
            .upload;

        if let Err(e) = self.put_chunks(upload, prepared).await {
            let _ = self
                .post_raw(
                    "/blob/abort",
                    sqex_proto::blob_store::ByUpload { upload }.encode(
                        sqex_proto::blob_store::TYPE_ABORT,
                    ),
                )
                .await;
            return Err(e);
        }

        let body = self
            .post_raw(
                "/blob/commit",
                Commit {
                    upload,
                    blob: prepared.attachment.blob,
                }
                .encode(),
            )
            .await?;
        let committed =
            Committed::decode(&body).map_err(|e| ChatError::Protocol(e.to_string()))?;
        if !committed.stored {
            // The exchange hashed what arrived and it did not equal the name we
            // claimed. Refused rather than stored under the wrong name, which
            // is the property that makes a fetched blob self-verifying.
            return Err(ChatError::Protocol(
                "the exchange refused the upload: what arrived did not hash to its name".into(),
            ));
        }
        Ok(prepared.attachment.clone())
    }

    async fn put_chunks(&mut self, upload: u64, prepared: &Prepared) -> Result<()> {
        for (i, s) in prepared.sealed.iter().enumerate() {
            self.post_raw(
                "/blob/put",
                PutChunk {
                    upload,
                    index: i as u32,
                    sealed: s.clone(),
                }
                .encode(),
            )
            .await?;
        }
        Ok(())
    }

    /// Whether the exchange still holds a blob, and how big it is.
    pub async fn head(&mut self, blob: &[u8; 32]) -> Result<Headed> {
        let body = self
            .post_raw("/blob/head", ByBlob { blob: *blob }.encode(TYPE_HEAD))
            .await?;
        Headed::decode(&body).map_err(|e| ChatError::Protocol(e.to_string()))
    }

    /// Fetch a blob and open it.
    ///
    /// The name is checked against what arrived before anything is decrypted:
    /// the id is the hash of the ciphertext, so a client can tell it got the
    /// bytes it asked for without trusting the exchange to have served them
    /// honestly.
    pub async fn download(&mut self, a: &Attachment) -> Result<Vec<u8>> {
        let mut sealed = Vec::with_capacity(a.chunks as usize);
        for index in 0..a.chunks {
            let body = self
                .post_raw("/blob/get", GetChunk { blob: a.blob, index }.encode())
                .await?;
            let chunk = Chunk::decode(&body).map_err(|e| ChatError::Protocol(e.to_string()))?;
            if !chunk.found {
                return Err(ChatError::Protocol(format!(
                    "the exchange no longer holds chunk {index} — the attachment has \
                     passed its retention window"
                )));
            }
            sealed.push(chunk.sealed);
        }
        if blob_id(&sealed) != a.blob {
            return Err(ChatError::Protocol(
                "what the exchange served does not hash to the name the message gave".into(),
            ));
        }

        let cipher = ChaCha20Poly1305::new_from_slice(&a.key)
            .map_err(|e| ChatError::Protocol(format!("blob key: {e}")))?;
        let mut out = Vec::with_capacity(a.size as usize);
        for (i, c) in sealed.iter().enumerate() {
            let plain = cipher
                .decrypt(Nonce::from_slice(&chunk_nonce(i as u32)), c.as_slice())
                .map_err(|_| {
                    ChatError::Protocol(format!("chunk {i} would not open under the message's key"))
                })?;
            out.extend_from_slice(&plain);
        }
        if out.len() as u64 != a.size {
            return Err(ChatError::Protocol(format!(
                "the attachment says {} bytes and opened to {}",
                a.size,
                out.len()
            )));
        }
        Ok(out)
    }
}

/// How to describe an attachment in one line of a transcript.
pub fn describe(a: &Attachment) -> String {
    let size = human(a.size);
    match a.effective_kind() {
        KIND_IMAGE => match a.dimensions() {
            Some((w, h)) => format!("[image {w}×{h}, {size}]"),
            None => format!("[image, {size}]"),
        },
        KIND_VIDEO => match a.duration_ms() {
            Some(ms) => format!("[video {}s, {size}]", ms / 1000),
            None => format!("[video, {size}]"),
        },
        KIND_VOICE => match a.duration_ms() {
            Some(ms) => format!("[voice note {}s]", ms / 1000),
            None => format!("[voice note, {size}]"),
        },
        _ => match file_name(a) {
            Some(n) => format!("[{n}, {size}]"),
            None => format!("[file, {size}]"),
        },
    }
}

fn human(bytes: u64) -> String {
    const K: u64 = 1024;
    match bytes {
        b if b < K => format!("{b} B"),
        b if b < K * K => format!("{:.0} KiB", b as f64 / K as f64),
        b => format!("{:.1} MiB", b as f64 / (K * K) as f64),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn attachment(kind: u8, size: u64, meta: Vec<u8>) -> Attachment {
        Attachment {
            kind,
            blob: [1; 32],
            key: [2; 32],
            size,
            chunks: 1,
            mime: String::new(),
            meta,
            preview: Vec::new(),
        }
    }

    #[test]
    fn a_name_decides_the_kind_and_an_unknown_one_is_a_file() {
        assert_eq!(kind_of("holiday.PNG").0, KIND_IMAGE);
        assert_eq!(kind_of("clip.mp4").0, KIND_VIDEO);
        assert_eq!(kind_of("note.opus").0, KIND_VOICE);
        assert_eq!(kind_of("accounts.xlsx").0, KIND_FILE);
        // No extension at all, and a dotfile, are both just files.
        assert_eq!(kind_of("Makefile").0, KIND_FILE);
        assert_eq!(kind_of(".bashrc").0, KIND_FILE);
    }

    #[test]
    fn a_file_carries_its_name_and_other_kinds_do_not() {
        let a = attachment(KIND_FILE, 10, {
            let mut m = vec![8];
            m.extend_from_slice(b"notes.md");
            m
        });
        assert_eq!(file_name(&a).as_deref(), Some("notes.md"));
        assert!(file_name(&attachment(KIND_IMAGE, 10, vec![0, 1, 0, 2])).is_none());
    }

    #[test]
    fn a_truncated_name_does_not_panic() {
        // meta is somebody else's bytes; a length byte that overruns must not
        // take the reader down with it.
        let a = attachment(KIND_FILE, 10, vec![200, b'h', b'i']);
        assert!(file_name(&a).is_none());
    }

    #[test]
    fn an_unknown_kind_is_described_as_a_file() {
        let a = attachment(0x7f, 2048, Vec::new());
        assert_eq!(describe(&a), "[file, 2 KiB]");
    }

    #[test]
    fn descriptions_carry_the_shape_when_it_is_there() {
        assert_eq!(
            describe(&attachment(KIND_IMAGE, 1024, vec![0x04, 0x00, 0x03, 0x00])),
            "[image 1024×768, 1 KiB]"
        );
        assert_eq!(
            describe(&attachment(KIND_VOICE, 5000, vec![0, 0, 0x1d, 0x4c])),
            "[voice note 7s]"
        );
    }

    #[test]
    fn sizes_read_the_way_a_person_expects() {
        assert_eq!(human(512), "512 B");
        assert_eq!(human(2048), "2 KiB");
        assert_eq!(human(5 * 1024 * 1024), "5.0 MiB");
    }
}
