//! Which exchange key a stored key envelope verifies under.
//!
//! The diagnostic that found the 2026-09-19 defect: every envelope trunk
//! served for one channel was refused at ex, and the question was whether
//! the bytes were bad or the key was. Reads, on stdin, one `instance <hex>`
//! line and then one line per envelope as sqexd's `envelope` table holds
//! it -- `env <epoch> <recipient> <publisher> <sig> <from> <to> <prekey_id>
//! <ephemeral> <ciphertext>`, all hex -- and tries each key given:
//!
//!     envelope_under <channel-base58> <key-base58>...
use sqex_proto::channel_key::{Envelope, verify_envelope};
use sqnr_core::PubKey;

fn hex32(s: &str) -> [u8; 32] {
    hex::decode(s).unwrap().try_into().unwrap()
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let channel = PubKey::from_base58(&args[1]).unwrap();
    let keys: Vec<PubKey> = args[2..]
        .iter()
        .map(|k| PubKey::from_base58(k).unwrap())
        .collect();
    let text = std::io::read_to_string(std::io::stdin()).unwrap();
    let mut instance = [0u8; 32];
    for line in text.lines() {
        let f: Vec<&str> = line.split_whitespace().collect();
        match f[0] {
            "instance" => instance = hex32(f[1]),
            "env" => {
                let e = Envelope {
                    recipient: PubKey::new(hex32(f[2])),
                    publisher: PubKey::new(hex32(f[3])),
                    sig: hex::decode(f[4]).unwrap().try_into().unwrap(),
                    from_epoch: f[5].parse().unwrap(),
                    to_epoch: f[6].parse().unwrap(),
                    prekey_id: f[7].parse().unwrap(),
                    ephemeral: hex32(f[8]),
                    ciphertext: hex::decode(f[9]).unwrap(),
                };
                let epoch: u32 = f[1].parse().unwrap();
                for k in &keys {
                    println!(
                        "recipient {} epoch {epoch}: under {k}: {}",
                        e.recipient,
                        verify_envelope(k, &instance, channel.as_bytes(), epoch, &e)
                    );
                }
            }
            _ => {}
        }
    }
}
