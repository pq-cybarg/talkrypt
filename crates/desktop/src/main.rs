//! talkrypt-desktop — a native GUI chat client (egui/eframe) over the same Rust
//! core as the CLI/TUI and the mobile app. No FFI: it links `talkrypt-core`,
//! `talkrypt-crypto`, and `talkrypt-transport` directly.
//!
//! Onboarding is QR-first: hosting shows a large QR encoding the `talkrypt://`
//! invite, and advertises this machine's LAN IP, so a phone on the same Wi-Fi
//! scans it with its camera and joins in seconds — no typing. Joining accepts a
//! pasted invite too.
//!
//! NOT certified / NOT audited — experimental.

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::sync::Arc;

use eframe::egui;
use talkrypt_core::{ChatDescriptor, Core, Event, Persistence, TopologyKind};
use talkrypt_crypto::{IdentityKeyPair, SuiteRegistry, DEFAULT_SUITE_ID};
use talkrypt_transport::TcpTransport;
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender};

const LAN_PORT: u16 = 9779;

/// Commands from the UI thread to the async worker that owns the `Core`.
enum Cmd {
    Host { channel: String },
    Join { uri: String },
    Send(String),
}

/// Updates from the worker back to the UI.
enum UiEvt {
    Invite(String),
    Status(String),
    Connected(String),
    Disconnected(String),
    /// `mine = true` for our own echoed line; else an inbound peer message.
    Line { mine: bool, who: String, text: String },
}

/// LAN IPv4 to advertise, found via the default route (no packets sent). Falls
/// back to loopback so local-only testing still works.
fn lan_ip() -> String {
    use std::net::UdpSocket;
    UdpSocket::bind("0.0.0.0:0")
        .and_then(|s| {
            s.connect("8.8.8.8:80")?;
            Ok(s.local_addr()?.ip().to_string())
        })
        .unwrap_or_else(|_| "127.0.0.1".to_string())
}

fn short(fp: &[u8; 48]) -> String {
    fp[..4].iter().map(|b| format!("{b:02x}")).collect()
}

/// Spawn the async worker (its own Tokio runtime + the `Core`). Returns the
/// command sender and a std receiver the UI drains each frame.
fn spawn_worker(ctx: egui::Context) -> (UnboundedSender<Cmd>, std::sync::mpsc::Receiver<UiEvt>) {
    let (cmd_tx, mut cmd_rx) = tokio::sync::mpsc::unbounded_channel::<Cmd>();
    let (ui_tx, ui_rx) = std::sync::mpsc::channel::<UiEvt>();

    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("tokio runtime");
        rt.block_on(async move {
            let mut core: Option<Core> = None;
            let mut events: Option<UnboundedReceiver<Event>> = None;
            let suite = SuiteRegistry::with_defaults()
                .get(DEFAULT_SUITE_ID)
                .expect("default suite");

            loop {
                tokio::select! {
                    cmd = cmd_rx.recv() => {
                        let Some(cmd) = cmd else { break };
                        match cmd {
                            Cmd::Host { channel } => {
                                let listen = format!("0.0.0.0:{LAN_PORT}");
                                let advertised = format!("{}:{LAN_PORT}", lan_ip());
                                let desc = ChatDescriptor::new(
                                    TopologyKind::P2P,
                                    Persistence::Ephemeral,
                                    DEFAULT_SUITE_ID,
                                    vec![listen.clone()],
                                    channel,
                                );
                                let transport = Arc::new(TcpTransport::new(listen.as_str()));
                                let (c, rx) = Core::new(IdentityKeyPair::generate(), suite.clone(), transport, desc);
                                match c.host().await {
                                    Ok(_) => {
                                        // Advertise the reachable LAN address in the invite.
                                        let mut d = c.descriptor().clone();
                                        d.endpoints = vec![advertised];
                                        let _ = ui_tx.send(UiEvt::Invite(d.to_uri()));
                                        let _ = ui_tx.send(UiEvt::Status("hosting — share the QR".into()));
                                        core = Some(c);
                                        events = Some(rx);
                                    }
                                    Err(e) => { let _ = ui_tx.send(UiEvt::Status(format!("host failed: {e}"))); }
                                }
                            }
                            Cmd::Join { uri } => {
                                match ChatDescriptor::from_uri(&uri) {
                                    Ok(desc) => {
                                        let endpoint = desc.endpoints.first().cloned().unwrap_or_default();
                                        let transport = Arc::new(TcpTransport::new("0.0.0.0:0"));
                                        let (c, rx) = Core::new(IdentityKeyPair::generate(), suite.clone(), transport, desc);
                                        match c.connect(&endpoint).await {
                                            Ok(_) => {
                                                let _ = ui_tx.send(UiEvt::Status(format!("joined — connected to {endpoint}")));
                                                core = Some(c);
                                                events = Some(rx);
                                            }
                                            Err(e) => { let _ = ui_tx.send(UiEvt::Status(format!("join failed: {e}"))); }
                                        }
                                    }
                                    Err(e) => { let _ = ui_tx.send(UiEvt::Status(format!("bad invite: {e}"))); }
                                }
                            }
                            Cmd::Send(text) => {
                                if let Some(c) = &core {
                                    match c.send(&text).await {
                                        Ok(_) => { let _ = ui_tx.send(UiEvt::Line { mine: true, who: "me".into(), text }); }
                                        Err(e) => { let _ = ui_tx.send(UiEvt::Status(format!("send failed: {e}"))); }
                                    }
                                }
                            }
                        }
                        ctx.request_repaint();
                    }
                    ev = async {
                        match &mut events {
                            Some(rx) => rx.recv().await,
                            None => std::future::pending().await,
                        }
                    } => {
                        match ev {
                            Some(Event::Message { from, text, .. }) =>
                                { let _ = ui_tx.send(UiEvt::Line { mine: false, who: short(&from), text }); }
                            Some(Event::Connected { fingerprint }) =>
                                { let _ = ui_tx.send(UiEvt::Connected(short(&fingerprint))); }
                            Some(Event::Disconnected { fingerprint }) =>
                                { let _ = ui_tx.send(UiEvt::Disconnected(short(&fingerprint))); }
                            Some(Event::Identity { account_fingerprint, username, .. }) => {
                                let who = username.unwrap_or_else(|| short(&account_fingerprint));
                                let _ = ui_tx.send(UiEvt::Status(format!("identity: {who}")));
                            }
                            Some(Event::Error(m)) => { let _ = ui_tx.send(UiEvt::Status(format!("! {m}"))); }
                            _ => {}
                        }
                        ctx.request_repaint();
                    }
                }
            }
        });
    });

    (cmd_tx, ui_rx)
}

#[derive(PartialEq)]
enum Screen {
    Home,
    Hosting,
    Chat,
}

struct App {
    cmd_tx: UnboundedSender<Cmd>,
    ui_rx: std::sync::mpsc::Receiver<UiEvt>,
    screen: Screen,
    channel_input: String,
    join_input: String,
    msg_input: String,
    invite: Option<String>,
    qr: Option<egui::TextureHandle>,
    status: String,
    transcript: Vec<(bool, String, String)>, // (mine, who, text)
    peers: usize,
}

impl App {
    fn new(cc: &eframe::CreationContext<'_>) -> Self {
        let (cmd_tx, ui_rx) = spawn_worker(cc.egui_ctx.clone());
        Self {
            cmd_tx,
            ui_rx,
            screen: Screen::Home,
            channel_input: "#general".into(),
            join_input: String::new(),
            msg_input: String::new(),
            invite: None,
            qr: None,
            status: "ML-KEM-1024 · ML-DSA-87 · AES-256-GCM · NOT audited".into(),
            transcript: Vec::new(),
            peers: 0,
        }
    }

    /// Render the invite as a QR texture (black/white module grid).
    fn build_qr(&mut self, ctx: &egui::Context, invite: &str) {
        let Ok(code) = qrcode::QrCode::new(invite.as_bytes()) else { return };
        let modules = code.to_colors();
        let dim = (modules.len() as f64).sqrt() as usize;
        let scale = 6usize;
        let quiet = 4usize;
        let px = (dim + quiet * 2) * scale;
        let mut img = egui::ColorImage::new([px, px], egui::Color32::WHITE);
        for y in 0..dim {
            for x in 0..dim {
                let dark = modules[y * dim + x] == qrcode::Color::Dark;
                if !dark {
                    continue;
                }
                for dy in 0..scale {
                    for dx in 0..scale {
                        let ix = (x + quiet) * scale + dx;
                        let iy = (y + quiet) * scale + dy;
                        img.pixels[iy * px + ix] = egui::Color32::BLACK;
                    }
                }
            }
        }
        self.qr = Some(ctx.load_texture("invite-qr", img, egui::TextureOptions::NEAREST));
    }

    fn drain(&mut self, ctx: &egui::Context) {
        while let Ok(evt) = self.ui_rx.try_recv() {
            match evt {
                UiEvt::Invite(uri) => {
                    self.build_qr(ctx, &uri);
                    self.invite = Some(uri);
                }
                UiEvt::Status(s) => self.status = s,
                UiEvt::Connected(w) => {
                    self.peers += 1;
                    self.transcript.push((false, "•".into(), format!("{w} connected")));
                    self.screen = Screen::Chat;
                }
                UiEvt::Disconnected(w) => {
                    self.peers = self.peers.saturating_sub(1);
                    self.transcript.push((false, "•".into(), format!("{w} left")));
                }
                UiEvt::Line { mine, who, text } => self.transcript.push((mine, who, text)),
            }
        }
    }
}

impl eframe::App for App {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.drain(ctx);
        egui::TopBottomPanel::top("top").show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.heading("talkrypt");
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    ui.label(egui::RichText::new(&self.status).small().weak());
                });
            });
        });

        egui::CentralPanel::default().show(ctx, |ui| match self.screen {
            Screen::Home => {
                ui.add_space(8.0);
                ui.label("Host a chat — share the QR to bring someone in:");
                ui.horizontal(|ui| {
                    ui.label("channel");
                    ui.text_edit_singleline(&mut self.channel_input);
                });
                if ui.button("▶  Host").clicked() {
                    let ch = if self.channel_input.trim().is_empty() {
                        "#general".into()
                    } else {
                        self.channel_input.clone()
                    };
                    let _ = self.cmd_tx.send(Cmd::Host { channel: ch });
                    self.screen = Screen::Hosting;
                }
                ui.separator();
                ui.label("…or join with an invite:");
                ui.text_edit_multiline(&mut self.join_input);
                if ui.button("Join").clicked() {
                    let uri = self.join_input.trim().to_string();
                    if uri.starts_with("talkrypt://") {
                        let _ = self.cmd_tx.send(Cmd::Join { uri });
                        self.status = "joining…".into();
                    } else {
                        self.status = "paste a talkrypt:// invite".into();
                    }
                }
            }
            Screen::Hosting => {
                ui.vertical_centered(|ui| {
                    ui.add_space(8.0);
                    ui.label(egui::RichText::new("Scan to join").heading());
                    ui.label("point a phone camera at this code");
                    ui.add_space(8.0);
                    if let Some(tex) = &self.qr {
                        ui.image((tex.id(), tex.size_vec2()));
                    } else {
                        ui.spinner();
                        ui.label("publishing invite…");
                    }
                    ui.add_space(8.0);
                    if let Some(inv) = &self.invite {
                        ui.collapsing("invite text", |ui| {
                            ui.label(egui::RichText::new(inv).monospace().small());
                        });
                    }
                    if ui.button("open chat").clicked() {
                        self.screen = Screen::Chat;
                    }
                });
            }
            Screen::Chat => {
                ui.label(format!("peers: {}", self.peers));
                ui.separator();
                egui::ScrollArea::vertical()
                    .auto_shrink([false, false])
                    .max_height(ui.available_height() - 40.0)
                    .stick_to_bottom(true)
                    .show(ui, |ui| {
                        for (mine, who, text) in &self.transcript {
                            if *mine {
                                ui.with_layout(egui::Layout::right_to_left(egui::Align::Min), |ui| {
                                    ui.label(egui::RichText::new(text).strong());
                                });
                            } else if who == "•" {
                                ui.label(egui::RichText::new(text).italics().weak());
                            } else {
                                ui.label(format!("{who}: {text}"));
                            }
                        }
                    });
                ui.horizontal(|ui| {
                    let resp = ui.text_edit_singleline(&mut self.msg_input);
                    let send = ui.button("send").clicked()
                        || (resp.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)));
                    if send && !self.msg_input.trim().is_empty() {
                        let _ = self.cmd_tx.send(Cmd::Send(self.msg_input.trim().to_string()));
                        self.msg_input.clear();
                    }
                });
            }
        });
    }
}

fn main() -> eframe::Result<()> {
    let opts = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([420.0, 640.0])
            .with_title("talkrypt"),
        ..Default::default()
    };
    eframe::run_native("talkrypt", opts, Box::new(|cc| Ok(Box::new(App::new(cc)))))
}
