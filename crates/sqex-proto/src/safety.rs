//! SIP-41: the safety number two people compare.
//!
//! A number from both keys, the same whichever side computes it; six words
//! from a fixed list, read aloud; and the same thing as text for a camera.
//! Nothing here touches the exchange: the comparison is between two people,
//! by a channel the exchange is not in, and the mark it ends in is theirs.

use sha2::{Digest, Sha256};
use sqnr_core::PubKey;

/// Domain separator for the number.
pub const SAFETY_CONTEXT: &[u8] = b"sip41-v1";

/// The wordlist: BIP-39's English list, verbatim, whose digest SIP-41 fixes.
const WORDS_FILE: &str = include_str!("safety-words.txt");

/// How many words two people read to each other.
pub const WORD_COUNT: usize = 6;

/// The list, one word per index, 2048 of them.
pub fn wordlist() -> Vec<&'static str> {
    WORDS_FILE.lines().collect()
}

/// The number for a pair of keys: `SHA-256(context || min || max)`, the
/// same for either side.
pub fn number(a: &PubKey, b: &PubKey) -> [u8; 32] {
    let (lo, hi) = ordered(a, b);
    let mut h = Sha256::new();
    h.update(SAFETY_CONTEXT);
    h.update(lo.as_bytes());
    h.update(hi.as_bytes());
    h.finalize().into()
}

/// The pair by their bytes: the lower first.
pub fn ordered<'a>(a: &'a PubKey, b: &'a PubKey) -> (&'a PubKey, &'a PubKey) {
    if a.as_bytes() <= b.as_bytes() {
        (a, b)
    } else {
        (b, a)
    }
}

/// The six words: the first 66 bits of the number, eleven at a time, most
/// significant first.
pub fn words(number: &[u8; 32]) -> [&'static str; WORD_COUNT] {
    let list = wordlist();
    let mut out = [""; WORD_COUNT];
    for (i, word) in out.iter_mut().enumerate() {
        let start = 11 * i;
        let mut index = 0usize;
        for bit in start..start + 11 {
            let byte = number[bit / 8];
            let on = (byte >> (7 - (bit % 8))) & 1;
            index = (index << 1) | usize::from(on);
        }
        *word = list[index];
    }
    out
}

/// The words for a pair, in one call.
pub fn words_for(a: &PubKey, b: &PubKey) -> [&'static str; WORD_COUNT] {
    words(&number(a, b))
}

/// The same thing as text, for a QR: `sip41:<A>:<B>:<hex>`, the lower key
/// first.
pub fn code(a: &PubKey, b: &PubKey) -> String {
    let (lo, hi) = ordered(a, b);
    format!("sip41:{lo}:{hi}:{}", hex::encode(number(a, b)))
}

/// What a scanned code says, if it is one and its number is right: the two
/// keys it names. A code whose number does not recompute is refused; so is
/// one that does not name `me` and `them` -- it is somebody else's
/// conversation.
pub fn scanned(text: &str, me: &PubKey, them: &PubKey) -> Result<(PubKey, PubKey), String> {
    let rest = text
        .trim()
        .strip_prefix("sip41:")
        .ok_or("not a safety code")?;
    let mut parts = rest.split(':');
    let (a, b, hex_number) = match (parts.next(), parts.next(), parts.next(), parts.next()) {
        (Some(a), Some(b), Some(n), None) => (a, b, n),
        _ => return Err("a safety code has three parts".into()),
    };
    let a: PubKey = a.parse().map_err(|_| "the first key is not a key")?;
    let b: PubKey = b.parse().map_err(|_| "the second key is not a key")?;
    if hex::encode(number(&a, &b)) != hex_number.to_lowercase() {
        return Err("the code's number is not the number for its keys".into());
    }
    let (lo, hi) = ordered(me, them);
    if (&a, &b) != (lo, hi) {
        return Err("this code is for two other people".into());
    }
    Ok((a, b))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(b: u8) -> PubKey {
        PubKey::new([b; 32])
    }

    /// The list is the one SIP-41 fixes: 2048 words, and the file's digest.
    #[test]
    fn the_list_is_the_one_the_sip_fixes() {
        let list = wordlist();
        assert_eq!(list.len(), 2048);
        assert_eq!(list[0], "abandon");
        assert_eq!(list[2047], "zoo");
        let digest = Sha256::digest(WORDS_FILE.as_bytes());
        assert_eq!(
            hex::encode(digest),
            "2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda"
        );
    }

    /// SIP-41's test vector, both ways round.
    #[test]
    fn the_test_vector() {
        let (a, b) = (key(1), key(2));
        assert_eq!(a.to_string(), "4vJ9JU1bJJE96FWSJKvHsmmFADCg4gpZQff4P3bkLKi");
        let n = number(&a, &b);
        assert_eq!(
            hex::encode(n),
            "96e3d24e9334665f6d7aa5ae102c2bcd0a6b849a7d91548c23bfd0cd64809421"
        );
        assert_eq!(number(&b, &a), n, "the same from either side");
        assert_eq!(
            words(&n),
            ["notice", "burden", "neck", "chapter", "edit", "cook"]
        );
        assert_eq!(words_for(&b, &a), words_for(&a, &b));
        assert_eq!(
            code(&b, &a),
            "sip41:4vJ9JU1bJJE96FWSJKvHsmmFADCg4gpZQff4P3bkLKi:\
             8qbHbw2BbbTHBW1sbeqakYXVKRQM8Ne7pLK7m6CVfeR:\
             96e3d24e9334665f6d7aa5ae102c2bcd0a6b849a7d91548c23bfd0cd64809421"
        );
    }

    /// A pair's words are theirs: a third key with either gives others.
    #[test]
    fn the_words_are_the_pairs() {
        let (a, b, c) = (key(1), key(2), key(3));
        assert_ne!(words_for(&a, &b), words_for(&a, &c));
        assert_ne!(words_for(&a, &b), words_for(&b, &c));
    }

    /// A scanned code is taken only when its number recomputes and it
    /// names the two people looking at it.
    #[test]
    fn a_scanned_code_is_checked_not_believed() {
        let (a, b, c) = (key(1), key(2), key(3));
        let good = code(&a, &b);
        assert_eq!(scanned(&good, &a, &b).unwrap(), (a, b));
        assert_eq!(
            scanned(&good, &b, &a).unwrap(),
            (a, b),
            "either side scans it"
        );
        assert!(
            scanned(&good, &a, &c)
                .unwrap_err()
                .contains("two other people")
        );
        let mut forged = good.clone();
        forged.replace_range(forged.len() - 2.., "00");
        assert!(
            scanned(&forged, &a, &b)
                .unwrap_err()
                .contains("not the number")
        );
        assert!(scanned("hello", &a, &b).is_err());
        assert!(scanned("sip41:x:y:z", &a, &b).is_err());
    }
}
