//! Spike: does the YubiKey's OpenPGP Authentication key produce a raw RFC 8032
//! Ed25519 signature over arbitrary bytes that `ed25519-dalek` accepts?
//!
//! This is the one unknown in the Phase-5 desktop app. If it holds, the admin
//! app signs sqex commands with the card via INTERNAL AUTHENTICATE and the
//! server verifies them with the same plain Ed25519 path a software signer uses
//! — no OpenPGP signature-packet framing involved.
//!
//! Usage:
//!   yubikey_spike              read the auth key and (if present) sign+verify
//!   yubikey_spike --provision  generate an Ed25519 auth key on-card first
//!
//! `--provision` permanently writes a new key to the card's Authentication
//! slot. It needs the admin PIN (PW3, default 12345678); signing needs the user
//! PIN (PW1, default 123456). Both are prompted with no echo and never taken
//! from arguments or the environment. Run this in your own terminal.

use card_backend_pcsc::PcscBackend;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use openpgp_card::Error as CardError;
use openpgp_card::ocard::algorithm::{AlgorithmAttributes, Curve, EccAttributes};
use openpgp_card::ocard::crypto::{EccType, PublicKeyMaterial};
use openpgp_card::ocard::data::{Fingerprint, KeyGenerationTime};
use openpgp_card::ocard::{KeyType, OpenPGP};
use secrecy::SecretBox;
use sha1::{Digest, Sha1};

fn main() {
    if let Err(e) = run() {
        eprintln!("spike failed: {e}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let _ = env_logger::try_init();
    let provision = std::env::args().any(|a| a == "--provision");

    let backend = PcscBackend::cards(None)?
        .next()
        .ok_or("no OpenPGP card found (is the YubiKey inserted?)")??;
    let mut card = OpenPGP::new(backend)?;
    let mut tx = card.transaction()?;

    if provision {
        provision_auth_ed25519(&mut tx)?;
    }

    // Read the Authentication key's public key.
    let ed_pub = match tx.public_key(KeyType::Authentication) {
        Ok(PublicKeyMaterial::E(ecc)) => {
            let data = ecc.data();
            <[u8; 32]>::try_from(data)
                .map_err(|_| format!("auth key is {} bytes, not an Ed25519 point", data.len()))?
        }
        Ok(PublicKeyMaterial::R(_)) => return Err("auth key is RSA, not Ed25519".into()),
        Err(e) => {
            return Err(format!(
                "no readable Ed25519 auth key ({e}). Run with --provision to generate one."
            )
            .into());
        }
    };
    let verifying = VerifyingKey::from_bytes(&ed_pub)?;
    println!("auth key (Ed25519): {}", bs58::encode(ed_pub).into_string());
    println!("  hex: {}", hex::encode(ed_pub));

    // Sign a message shaped like a real sqex command signing input, then verify.
    let message = {
        let mut m = sqex_core::SIG_CONTEXT.to_vec();
        m.extend_from_slice(b"yubikey-spike test payload");
        m
    };

    let pin = match rpassword::prompt_password("YubiKey user PIN (empty to skip signing): ") {
        Ok(p) if !p.is_empty() => p,
        _ => {
            println!("\nno PIN entered — public-key read succeeded, signing not exercised.");
            return Ok(());
        }
    };

    tx.verify_pw1_user(secret(pin))?;
    let sig_bytes = tx.internal_authenticate(message.clone())?;
    println!("\nINTERNAL AUTHENTICATE returned {} bytes", sig_bytes.len());

    let sig = Signature::from_bytes(
        &<[u8; 64]>::try_from(sig_bytes.as_slice())
            .map_err(|_| format!("signature is {} bytes, expected 64", sig_bytes.len()))?,
    );

    match verifying.verify(&message, &sig) {
        Ok(()) => {
            println!("\n✅ PASS: the card's Ed25519 signature verifies with ed25519-dalek.");
            println!("   The YubiKey is a drop-in Signer for sqex admin commands.");
            Ok(())
        }
        Err(e) => Err(format!(
            "❌ FAIL: card signature did NOT verify ({e}).\n\
             The card may wrap the message rather than signing it raw; the app\n\
             would then need to match that framing or verify differently."
        )
        .into()),
    }
}

/// Set the Authentication slot to Ed25519 and generate a key on-card. Requires
/// the admin PIN (PW3). Permanent.
fn provision_auth_ed25519(
    tx: &mut openpgp_card::ocard::Transaction,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("provisioning: generating an Ed25519 Authentication key on-card…");
    let admin =
        rpassword::prompt_password("YubiKey admin PIN (PW3, 8+ digits, default 12345678): ")?;
    println!("  (read {} characters)", admin.chars().count());
    if admin.len() < 8 {
        return Err(format!(
            "admin PIN is {} characters; PW3 needs at least 8. Enter the ADMIN PIN \
             (default 12345678), not the 6-digit user PIN.",
            admin.len()
        )
        .into());
    }
    tx.verify_pw3(secret(admin))?;

    let attrs = AlgorithmAttributes::Ecc(EccAttributes::new(EccType::EdDSA, Curve::Ed25519, None));
    tx.set_algorithm_attributes(KeyType::Authentication, &attrs)?;

    let (pk, _ts) = tx.generate_key(ed25519_fingerprint, KeyType::Authentication)?;
    if let PublicKeyMaterial::E(ecc) = &pk {
        println!("  generated: {}", bs58::encode(ecc.data()).into_string());
    }
    Ok(())
}

/// Compute the OpenPGP v4 fingerprint of an Ed25519 public key. The card stores
/// it as metadata; INTERNAL AUTHENTICATE does not depend on it, but a correct
/// value keeps the card legible to gpg/ykman. Must be a plain `fn` (the API
/// takes a function pointer, not a closure).
fn ed25519_fingerprint(
    pk: &PublicKeyMaterial,
    ts: KeyGenerationTime,
    _kt: KeyType,
) -> Result<Fingerprint, CardError> {
    let point = match pk {
        PublicKeyMaterial::E(ecc) => ecc.data(),
        _ => {
            return Err(CardError::InternalError(
                "expected an ECC public key".into(),
            ));
        }
    };

    // v4 public-key packet body for EdDSA (RFC 4880bis).
    let mut body = Vec::new();
    body.push(0x04); // version
    body.extend_from_slice(&ts.get().to_be_bytes()); // creation time
    body.push(0x16); // algorithm 22 = EdDSA
    let oid: [u8; 9] = [0x2b, 0x06, 0x01, 0x04, 0x01, 0xda, 0x47, 0x0f, 0x01]; // Ed25519
    body.push(oid.len() as u8);
    body.extend_from_slice(&oid);
    // Public point as an MPI: 0x40 prefix + 32 bytes = 263 bits.
    body.extend_from_slice(&263u16.to_be_bytes());
    body.push(0x40);
    body.extend_from_slice(point);

    let mut hasher = Sha1::new();
    hasher.update([0x99]);
    hasher.update((body.len() as u16).to_be_bytes());
    hasher.update(&body);
    let digest: [u8; 20] = hasher.finalize().into();
    Ok(Fingerprint::from(digest))
}

fn secret(pin: String) -> SecretBox<[u8]> {
    SecretBox::new(pin.into_bytes().into_boxed_slice())
}
