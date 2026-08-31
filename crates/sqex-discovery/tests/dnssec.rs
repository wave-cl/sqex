//! Live DNSSEC discovery.
//!
//! These talk to the real DNS, so they are `#[ignore]`d to keep CI hermetic and
//! offline builds quiet. Run them deliberately:
//!
//! ```text
//! cargo test -p sqex-discovery --test dnssec -- --ignored --nocapture
//! ```
//!
//! The three cases they separate are the three an operator will actually hit,
//! and confusing any two of them sends somebody looking in the wrong place:
//! the zone is unsigned, the signatures are broken, or the zone is fine and
//! simply does not advertise an exchange.

use sqex_discovery::{Error, dns};

/// Signed, and publishes no exchange. Verified with `dig`, not assumed.
///
/// This was `squic.org` until it started publishing one — a test whose premise
/// is somebody else's zone expires when that zone changes, which is exactly
/// what happened and why the domain is now one nobody here operates.
const SIGNED_WITHOUT_RECORD: &str = "nlnetlabs.nl";

/// Signed, and has apex TXT — checked with `dig +dnssec`, not assumed.
const SIGNED_WITH_TXT: &str = "ietf.org";

/// Not signed. An `Insecure` proof is a valid DNSSEC answer, which is exactly
/// why it has to be refused deliberately rather than left to fail on its own.
const UNSIGNED: &str = "google.com";

/// Signatures that do not verify. Run by Comcast for this purpose.
const BOGUS: &str = "dnssec-failed.org";

#[tokio::test]
#[ignore = "needs the real DNS"]
async fn an_unsigned_zone_is_refused_and_says_why() {
    // The apex, not `_sqex.` — deliberately. An unsigned zone with no record at
    // `_sqex` ends at "not published" without the Proof filter ever running, so
    // asserting on that name would prove nothing and would keep passing after
    // the filter was deleted. google.com has TXT at its apex and is unsigned,
    // which is the only combination that reaches the branch under test.
    let err = dns::lookup_txt(UNSIGNED)
        .await
        .expect_err("an unsigned zone must not satisfy discovery");
    println!("unsigned refused with: {err}");
    assert!(
        matches!(err, Error::Unsigned { .. }),
        "wanted Unsigned, got {err:?}"
    );
    assert!(
        err.to_string().contains("not signed"),
        "the message should name the reason: {err}"
    );
}

/// The control for the test above, standing on its own: the same name in a
/// *signed* zone yields records rather than a refusal, so the refusal is about
/// the proof and not about the name.
#[tokio::test]
#[ignore = "needs the real DNS"]
async fn the_same_lookup_against_a_signed_zone_returns_records() {
    let txts = dns::lookup_txt(SIGNED_WITH_TXT)
        .await
        .unwrap_or_else(|e| panic!("{SIGNED_WITH_TXT} has signed apex TXT: {e}"));
    println!("{SIGNED_WITH_TXT} apex TXT: {} record(s)", txts.len());
    assert!(!txts.is_empty());
}

#[tokio::test]
#[ignore = "needs the real DNS"]
async fn a_zone_with_broken_signatures_is_refused() {
    let err = dns::lookup(BOGUS)
        .await
        .expect_err("a bogus signature must not satisfy discovery");
    println!("bogus refused with: {err}");
    // A validating resolver fails the lookup outright here rather than handing
    // back records with a Bogus proof, so this lands in Resolve rather than
    // Unsigned. Either would be correct; what must not happen is success.
    assert!(
        !matches!(err, Error::NotPublished { .. }),
        "a broken signature must not read as an absent record: {err:?}"
    );
}

/// The distinction this design turns on: a properly signed zone that publishes
/// no exchange is **not** the same failure as an unsigned one. One means "they
/// do not run an exchange", the other means "I cannot trust the answer" — and
/// the fixes are publishing a record versus signing a zone.
#[tokio::test]
#[ignore = "needs the real DNS"]
async fn a_signed_zone_without_a_record_is_not_published_rather_than_unsigned() {
    let err = dns::lookup(SIGNED_WITHOUT_RECORD)
        .await
        .expect_err("squic.org publishes no _sqex record yet");
    println!("signed-but-absent refused with: {err}");
    assert!(
        matches!(err, Error::NotPublished { .. }),
        "a signed zone with no record must not be reported as unsigned: {err:?}"
    );
    assert!(
        err.to_string().contains("_sqex"),
        "the message should name the record that is missing: {err}"
    );
}


/// The reference deployment, end to end: a real signed record, parsed into the
/// key and address a client would dial.
///
/// This depends on `squic.org` continuing to publish an exchange, which is a
/// dependency on a live deployment rather than on the code. That is deliberate
/// — it is the only test that proves the whole path against something a DNS
/// operator actually typed — but when it fails, suspect the zone before the
/// parser. The test above used to point here for the opposite case and broke
/// the day this record appeared.
#[tokio::test]
#[ignore = "needs the real DNS"]
async fn the_reference_exchange_is_discoverable() {
    let records = dns::lookup("squic.org")
        .await
        .expect("squic.org publishes an exchange");
    assert_eq!(records.len(), 1, "{records:?}");
    let r = &records[0];
    println!("squic.org -> {} at {:?}:{}", r.key, r.host, r.port);
    assert_eq!(
        r.key.to_string(),
        "2j68p8rZKXE6W1f6LerRGB2SPTH8JkbfMmZRFTzcLKyW"
    );
    assert_eq!(r.host.as_deref(), Some("ex.squic.org"));
    // The record names no port, so this is the default arriving — which is the
    // half of the 443 change that a parser test cannot reach.
    assert_eq!(r.port, sqex_discovery::DEFAULT_PORT);
    assert_eq!(r.port, 443);
}
