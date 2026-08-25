//! The egui desktop UI.

use std::sync::mpsc::{Receiver, channel};

use eframe::egui;
use sqnr_core::PubKey;
use sqnr_core::protocol::Action;
use tokio::sync::mpsc::UnboundedSender;

use crate::worker::{self, Cmd, Msg};

pub struct App {
    cmd_tx: UnboundedSender<Cmd>,
    msg_rx: Receiver<Msg>,

    // Connection inputs.
    server_addr: String,
    server_key: String,
    connected: bool,
    admin_key: Option<String>,

    // Card unlock.
    pin: String,

    // Views.
    status: String,
    whitelist_enabled: bool,
    whitelist: Vec<String>,
    audit: Vec<String>,
    new_key: String,
    log: Vec<String>,
    awaiting_touch: bool,
}

impl App {
    pub fn new(cc: &eframe::CreationContext<'_>) -> Self {
        let (msg_tx, msg_rx) = channel();
        let cmd_tx = worker::spawn(msg_tx, cc.egui_ctx.clone());
        Self {
            cmd_tx,
            msg_rx,
            server_addr: "127.0.0.1:5400".to_string(),
            server_key: String::new(),
            connected: false,
            admin_key: None,
            pin: String::new(),
            status: "not connected".to_string(),
            whitelist_enabled: false,
            whitelist: Vec::new(),
            audit: Vec::new(),
            new_key: String::new(),
            log: Vec::new(),
            awaiting_touch: false,
        }
    }

    fn drain_messages(&mut self) {
        while let Ok(msg) = self.msg_rx.try_recv() {
            // Any message other than the touch prompt itself means the wait is
            // over (the signature completed, failed, or produced a result).
            if !matches!(msg, Msg::AwaitingTouch) {
                self.awaiting_touch = false;
            }
            match msg {
                Msg::AwaitingTouch => self.awaiting_touch = true,
                Msg::Status(s) => {
                    self.status = s.clone();
                    self.push_log(s);
                }
                Msg::Connected { admin_key } => {
                    self.connected = true;
                    self.admin_key = Some(admin_key.clone());
                    self.push_log(format!("connected; admin key {admin_key}"));
                }
                Msg::Whitelist { enabled, keys } => {
                    self.whitelist_enabled = enabled;
                    self.whitelist = keys;
                    self.push_log(format!(
                        "whitelist {} ({} keys)",
                        if enabled { "enabled" } else { "disabled" },
                        self.whitelist.len()
                    ));
                }
                Msg::Audit(rows) => {
                    self.audit = rows;
                    self.push_log("audit refreshed".into());
                }
                Msg::Error(e) => self.push_log(format!("error: {e}")),
            }
        }
    }

    fn push_log(&mut self, line: String) {
        self.log.push(line);
        if self.log.len() > 200 {
            let drop = self.log.len() - 200;
            self.log.drain(0..drop);
        }
    }

    /// Issue a signed admin command, if the PIN is present.
    fn admin(&mut self, action: Action) {
        if self.pin.is_empty() {
            self.push_log("enter the YubiKey user PIN first".into());
            return;
        }
        let _ = self.cmd_tx.send(Cmd::Admin {
            action,
            pin: self.pin.clone(),
        });
    }
}

impl eframe::App for App {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.drain_messages();

        egui::TopBottomPanel::top("conn").show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.label("Server");
                ui.text_edit_singleline(&mut self.server_addr);
                ui.label("Key");
                ui.add(egui::TextEdit::singleline(&mut self.server_key).hint_text("base58 pubkey"));
                if ui.button("Connect").clicked() {
                    let _ = self.cmd_tx.send(Cmd::Connect {
                        addr: self.server_addr.clone(),
                        server_pub: self.server_key.clone(),
                    });
                }
                let dot = if self.connected {
                    "● connected"
                } else {
                    "○ offline"
                };
                ui.label(dot);
            });
            ui.label(&self.status);
        });

        egui::TopBottomPanel::bottom("log")
            .resizable(true)
            .default_height(200.0)
            .show(ctx, |ui| {
                ui.label("Log");
                egui::ScrollArea::vertical()
                    .auto_shrink([false, false]) // fill width and the panel's height
                    .stick_to_bottom(true)
                    .show(ui, |ui| {
                        for line in &self.log {
                            ui.monospace(line);
                        }
                    });
            });

        egui::CentralPanel::default().show(ctx, |ui| {
            if self.awaiting_touch {
                egui::Frame::none()
                    .fill(egui::Color32::from_rgb(0x33, 0x2b, 0x00))
                    .inner_margin(8.0)
                    .show(ui, |ui| {
                        ui.colored_label(
                            egui::Color32::from_rgb(0xff, 0xd5, 0x4f),
                            "👆  Touch your YubiKey to sign…",
                        );
                    });
                ui.add_space(4.0);
            }
            ui.horizontal(|ui| {
                ui.label("YubiKey user PIN");
                ui.add(
                    egui::TextEdit::singleline(&mut self.pin)
                        .password(true)
                        .desired_width(120.0),
                );
                if let Some(k) = &self.admin_key {
                    ui.label(format!(
                        "admin: {}…",
                        k.chars().take(10).collect::<String>()
                    ));
                }
            });
            ui.separator();

            ui.add_enabled_ui(self.connected, |ui| {
                ui.horizontal(|ui| {
                    ui.strong("Whitelist");
                    ui.label(if self.whitelist_enabled {
                        "(enabled)"
                    } else {
                        "(disabled)"
                    });
                    if ui.button("Refresh").clicked() {
                        self.admin(Action::WhitelistList);
                    }
                    if ui.button("Enable").clicked() {
                        self.admin(Action::WhitelistEnable);
                    }
                    if ui.button("Disable").clicked() {
                        self.admin(Action::WhitelistDisable);
                    }
                });

                ui.horizontal(|ui| {
                    ui.add(
                        egui::TextEdit::singleline(&mut self.new_key)
                            .hint_text("peer base58 key")
                            .desired_width(320.0),
                    );
                    if ui.button("Add").clicked() {
                        self.add_or_remove(true);
                    }
                    if ui.button("Remove").clicked() {
                        self.add_or_remove(false);
                    }
                });

                egui::ScrollArea::vertical()
                    .max_height(140.0)
                    .auto_shrink([false, false]) // full width; capped so audit gets the rest
                    .id_salt("wl")
                    .show(ui, |ui| {
                        for k in &self.whitelist {
                            ui.monospace(k);
                        }
                    });

                ui.separator();
                ui.horizontal(|ui| {
                    ui.strong("Audit");
                    if ui.button("Refresh").clicked() {
                        self.admin(Action::AuditTail(50));
                    }
                });
                // Fill the rest of the central panel with the audit view.
                egui::ScrollArea::vertical()
                    .auto_shrink([false, false])
                    .stick_to_bottom(true)
                    .id_salt("audit")
                    .show(ui, |ui| {
                        for row in &self.audit {
                            ui.monospace(row);
                        }
                    });
            });
        });
    }
}

impl App {
    fn add_or_remove(&mut self, add: bool) {
        let key = self.new_key.trim().to_string();
        match key.parse::<PubKey>() {
            Ok(k) => {
                let action = if add {
                    Action::WhitelistAdd(k)
                } else {
                    Action::WhitelistRemove(k)
                };
                self.admin(action);
            }
            Err(e) => self.push_log(format!("bad key: {e}")),
        }
    }
}
