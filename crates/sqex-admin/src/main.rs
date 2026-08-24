//! sqex-admin — the desktop administrator app.
//!
//! Phase 5 (see the plan): an eframe/egui GUI that connects to sqexd over
//! HTTP/3 and signs admin commands with a YubiKey (OpenPGP Ed25519
//! Authentication key via INTERNAL AUTHENTICATE, yielding a raw Ed25519
//! signature verifiable by the server). The command protocol it will speak is
//! already defined and tested in `sqex-core`.

fn main() {
    eprintln!(
        "sqex-admin {}: the desktop admin app is not built yet.\n\
         The signed-command protocol it will use lives in sqex-core; the server \
         (sqexd) implements the matching endpoints.",
        sqex_core::VERSION
    );
}
