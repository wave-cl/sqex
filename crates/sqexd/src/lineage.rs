//! SIP-40 §Lineage: the handovers this exchange has signed, kept beside its key.
//!
//! One per line, `<domain> <record>`, the record being the SIP-40 TXT
//! value `sqexd handover` printed -- the domain is not in the record (it
//! is the zone's), so the file carries it. Read on start, verified as a
//! chain ending at this exchange's own key, and served whole at
//! `/exchange/lineage`.

use std::path::Path;

use sqex_discovery::{Handover, Parsed};
use sqex_proto::lineage::{Lineage, Link};
use sqnr_core::PubKey;

/// Read and verify the lineage file. A missing file is an empty lineage;
/// anything else that is wrong is an error the operator has to see, since
/// a wrong line here would have every peer refuse this exchange's past.
pub fn load(path: &Path, own: &PubKey) -> Result<Lineage, String> {
    let text = match std::fs::read_to_string(path) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Lineage::default()),
        Err(e) => return Err(format!("cannot read {}: {e}", path.display())),
    };
    let mut links = Vec::new();
    for (n, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((domain, record)) = line.split_once(char::is_whitespace) else {
            return Err(format!(
                "{}:{}: expected `<domain> <record>`",
                path.display(),
                n + 1
            ));
        };
        let domain = sqex_proto::lineage::canonical(domain);
        let Parsed::Handover(h) = sqex_discovery::record::parse(record.trim()) else {
            return Err(format!(
                "{}:{}: not a SIP-40 handover record",
                path.display(),
                n + 1
            ));
        };
        if !h.verify(&domain) {
            return Err(format!(
                "{}:{}: the handover is not signed by {} for {domain}",
                path.display(),
                n + 1,
                h.from
            ));
        }
        links.push(link_of(&domain, &h));
    }
    let lineage = Lineage { links };
    lineage
        .predecessors_for(own, None)
        .map_err(|e| format!("{}: {e}", path.display()))?;
    Ok(lineage)
}

/// The file's modification time, `None` when there is no file.
pub fn modified(path: &Path) -> Option<std::time::SystemTime> {
    std::fs::metadata(path).ok().and_then(|m| m.modified().ok())
}

/// Keep a handover this exchange just signed.
pub fn append(path: &Path, domain: &str, h: &Handover) -> std::io::Result<()> {
    use std::io::Write;
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)?;
    writeln!(
        f,
        "{} {}",
        sqex_proto::lineage::canonical(domain),
        h.render()
    )
}

fn link_of(domain: &str, h: &Handover) -> Link {
    Link {
        domain: domain.to_string(),
        from: h.from,
        to: h.to,
        until: h.until,
        sig: h.sig,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    fn key(b: u8) -> (SigningKey, PubKey) {
        let sk = SigningKey::from_bytes(&[b; 32]);
        let pk = PubKey::new(sk.verifying_key().to_bytes());
        (sk, pk)
    }

    fn handover(from: &SigningKey, to: &PubKey, domain: &str) -> Handover {
        let f = PubKey::new(from.verifying_key().to_bytes());
        let until = 1_800_000_000;
        let sig = from
            .sign(&Handover::signing_input(domain, &f, to, until))
            .to_bytes();
        Handover {
            from: f,
            to: *to,
            until,
            sig,
        }
    }

    #[test]
    fn the_file_round_trips_through_the_signing_command_and_the_daemon() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("lineage");
        let (a, pa) = key(1);
        let (b, pb) = key(2);
        let (_, pc) = key(3);
        assert_eq!(
            load(&path, &pc).unwrap().links.len(),
            0,
            "no file is no lineage"
        );
        append(&path, "X.test.", &handover(&a, &pb, "x.test")).unwrap();
        append(&path, "x.test", &handover(&b, &pc, "x.test")).unwrap();
        let l = load(&path, &pc).unwrap();
        assert_eq!(
            l.predecessors_for(&pc, Some("x.test")).unwrap(),
            vec![pb, pa]
        );
        // The daemon for the wrong key refuses the file rather than serving
        // a history that is not its own.
        assert!(load(&path, &pb).unwrap_err().contains("does not end"));
        // The two signing inputs -- discovery's and proto's -- agree, or the
        // daemon would refuse every record the command wrote.
        assert_eq!(
            Handover::signing_input("x.test", &pa, &pb, 5),
            Link::signing_input("x.test", &pa, &pb, 5)
        );
    }

    #[test]
    fn a_bad_line_is_an_error_with_its_number() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("lineage");
        let (a, _) = key(1);
        let (_, pb) = key(2);
        std::fs::write(
            &path,
            format!(
                "# a comment\n\ny.test {}\n",
                handover(&a, &pb, "x.test").render()
            ),
        )
        .unwrap();
        let err = load(&path, &pb).unwrap_err();
        assert!(err.contains(":3:"), "{err}");
        assert!(err.contains("not signed"), "{err}");
        std::fs::write(&path, "x.test v=sqex1; k=abc\n").unwrap();
        assert!(load(&path, &pb).unwrap_err().contains("not a SIP-40"));
        std::fs::write(&path, "nodomainhere\n").unwrap();
        assert!(load(&path, &pb).unwrap_err().contains("expected"));
    }
}
