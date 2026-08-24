//! YubiKey access: read the Authentication public key, and sign with it.
//!
//! Blocking (PC/SC). Each call opens a fresh card session, matching the pattern
//! proven in the spike. Errors are strings for the GUI to display.

use card_backend_pcsc::PcscBackend;
use openpgp_card::ocard::crypto::PublicKeyMaterial;
use openpgp_card::ocard::{KeyType, OpenPGP};
use secrecy::SecretBox;

fn open() -> Result<OpenPGP, String> {
    let backend = PcscBackend::cards(None)
        .map_err(|e| e.to_string())?
        .next()
        .ok_or_else(|| "no OpenPGP card found (is the YubiKey inserted?)".to_string())?
        .map_err(|e| e.to_string())?;
    OpenPGP::new(backend).map_err(|e| e.to_string())
}

/// Read the Authentication slot's Ed25519 public key.
pub fn read_auth_pubkey() -> Result<[u8; 32], String> {
    let mut card = open()?;
    let mut tx = card.transaction().map_err(|e| e.to_string())?;
    match tx.public_key(KeyType::Authentication) {
        Ok(PublicKeyMaterial::E(ecc)) => <[u8; 32]>::try_from(ecc.data())
            .map_err(|_| "auth key is not a 32-byte Ed25519 point".to_string()),
        Ok(PublicKeyMaterial::R(_)) => Err("auth key is RSA, not Ed25519".to_string()),
        Err(e) => Err(format!(
            "no Ed25519 auth key ({e}); provision with `yubikey_spike --provision`"
        )),
    }
}

/// Verify the user PIN and sign `msg` with the Authentication key
/// (INTERNAL AUTHENTICATE → raw Ed25519).
pub fn sign(pin: &str, msg: &[u8]) -> Result<[u8; 64], String> {
    let mut card = open()?;
    let mut tx = card.transaction().map_err(|e| e.to_string())?;
    tx.verify_pw1_user(SecretBox::new(pin.as_bytes().to_vec().into_boxed_slice()))
        .map_err(|e| format!("PIN rejected: {e}"))?;
    let sig = tx
        .internal_authenticate(msg.to_vec())
        .map_err(|e| format!("sign failed: {e}"))?;
    <[u8; 64]>::try_from(sig.as_slice())
        .map_err(|_| "card returned a non-64-byte signature".to_string())
}
