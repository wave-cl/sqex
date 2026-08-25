//! sqex-admin — the desktop administrator app.
//!
//! Connects to sqexd over HTTP/3 and signs whitelist-management commands with a
//! YubiKey (OpenPGP Ed25519 Authentication key). Admin authority is the command
//! signature, verified against the server's config admin list; the connection's
//! transport key is irrelevant. The command protocol and the signing/client
//! machinery now live in `sqnr`; this crate is the egui front end over it. The
//! YubiKey path is the one proven by `yubikey_spike`.

mod app;
mod worker;

fn main() -> eframe::Result<()> {
    let _ = env_logger::try_init();
    let options = eframe::NativeOptions {
        viewport: eframe::egui::ViewportBuilder::default().with_inner_size([720.0, 640.0]),
        ..Default::default()
    };
    eframe::run_native(
        "sqex admin",
        options,
        Box::new(|cc| Ok(Box::new(app::App::new(cc)))),
    )
}
