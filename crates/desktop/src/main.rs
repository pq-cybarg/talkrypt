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
use talkrypt_crypto::{dr_suite_id, IdentityKeyPair, KemProfile, SuiteRegistry, DEFAULT_SUITE_ID};
use talkrypt_transport::TcpTransport;
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender};

const LAN_PORT: u16 = 9779;

// Palette mirrored from the Android app (MainActivity) so desktop and mobile
// look like the same product.
const BG: egui::Color32 = egui::Color32::from_rgb(0x0B, 0x0E, 0x13);
const PANEL: egui::Color32 = egui::Color32::from_rgb(0x16, 0x1B, 0x22);
const FIELD: egui::Color32 = egui::Color32::from_rgb(0x1C, 0x22, 0x30);
const FG: egui::Color32 = egui::Color32::from_rgb(0xE6, 0xED, 0xF3);
const MUTED: egui::Color32 = egui::Color32::from_rgb(0x8B, 0x94, 0x9E);
const ACCENT: egui::Color32 = egui::Color32::from_rgb(0x2E, 0xA0, 0x43);
const PEER_BUBBLE: egui::Color32 = egui::Color32::from_rgb(0x22, 0x2B, 0x36);

/// Apply the mobile dark theme to egui's visuals.
fn apply_theme(ctx: &egui::Context) {
    let mut v = egui::Visuals::dark();
    v.override_text_color = Some(FG);
    v.panel_fill = BG;
    v.window_fill = BG;
    v.faint_bg_color = PANEL;
    v.extreme_bg_color = FIELD; // text-edit background
    v.selection.bg_fill = ACCENT.linear_multiply(0.5);
    let r = egui::CornerRadius::same(12);
    v.widgets.noninteractive.bg_fill = PANEL;
    v.widgets.noninteractive.corner_radius = r;
    v.widgets.inactive.bg_fill = FIELD;
    v.widgets.inactive.weak_bg_fill = FIELD;
    v.widgets.inactive.corner_radius = r;
    v.widgets.inactive.fg_stroke = egui::Stroke::new(1.0, FG);
    v.widgets.hovered.bg_fill = PEER_BUBBLE;
    v.widgets.hovered.weak_bg_fill = PEER_BUBBLE;
    v.widgets.hovered.corner_radius = r;
    v.widgets.active.bg_fill = ACCENT;
    v.widgets.active.weak_bg_fill = ACCENT;
    v.widgets.active.corner_radius = r;
    ctx.set_visuals(v);
    let mut style = (*ctx.style()).clone();
    style.spacing.button_padding = egui::vec2(14.0, 10.0);
    style.spacing.item_spacing = egui::vec2(8.0, 8.0);
    ctx.set_style(style);
}

/// A full-width green "pill" primary button (matches the mobile accent button).
fn pill(ui: &mut egui::Ui, label: &str, fill: egui::Color32, text: egui::Color32) -> egui::Response {
    let text = egui::RichText::new(label).color(text).strong();
    ui.add_sized(
        [ui.available_width(), 46.0],
        egui::Button::new(text).fill(fill).corner_radius(egui::CornerRadius::same(14)),
    )
}

/// A labeled, full-width dropdown section (mobile: muted caption + dark field),
/// with the mobile's generous vertical spacing.
fn combo_section(ui: &mut egui::Ui, label: &str, id: &str, value: &mut String, options: &[&str]) {
    ui.add_space(18.0);
    ui.label(egui::RichText::new(label).size(12.0).strong().color(MUTED));
    ui.add_space(6.0);
    egui::ComboBox::from_id_salt(id)
        .selected_text(egui::RichText::new(value.clone()).color(FG))
        .width(ui.available_width() - 8.0)
        .show_ui(ui, |ui| {
            for opt in options {
                ui.selectable_value(value, (*opt).to_string(), *opt);
            }
        });
}

/// A rounded chat bubble (Signal/Telegram style) with optional sender label.
fn bubble(ui: &mut egui::Ui, fill: egui::Color32, who: Option<&str>, text: &str, txt: egui::Color32) {
    egui::Frame::default()
        .fill(fill)
        .corner_radius(egui::CornerRadius::same(14))
        .inner_margin(egui::Margin::symmetric(12, 8))
        .show(ui, |ui| {
            ui.set_max_width(ui.available_width() * 0.78);
            ui.vertical(|ui| {
                if let Some(w) = who {
                    ui.label(egui::RichText::new(w).small().strong().color(ACCENT));
                }
                ui.label(egui::RichText::new(text).color(txt));
            });
        });
}

/// Commands from the UI thread to the async worker that owns the `Core`.
enum Cmd {
    Host {
        channel: String,
        posture: String,
        access: String,
    },
    Join {
        uri: String,
    },
    Send(String),
}

/// Map a posture label to a KEM profile (mirrors the CLI / mobile postures).
fn profile_from(posture: &str) -> KemProfile {
    match posture {
        "hybrid" => KemProfile::hybrid(),
        "pq-pure-compact" => KemProfile::pq_pure_compact(),
        _ => KemProfile::pq_pure(),
    }
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
                            Cmd::Host { channel, posture, access } => {
                                // Posture selects the suite; access sets who's heard.
                                let suite_id = dr_suite_id(profile_from(&posture));
                                let host_suite = match SuiteRegistry::with_defaults().get(&suite_id) {
                                    Ok(s) => s,
                                    Err(e) => { let _ = ui_tx.send(UiEvt::Status(format!("bad posture: {e}"))); ctx.request_repaint(); continue; }
                                };
                                let listen = format!("0.0.0.0:{LAN_PORT}");
                                let advertised = format!("{}:{LAN_PORT}", lan_ip());
                                let desc = ChatDescriptor::new(
                                    TopologyKind::P2P,
                                    Persistence::Ephemeral,
                                    &suite_id,
                                    vec![listen.clone()],
                                    channel,
                                );
                                let transport = Arc::new(TcpTransport::new(listen.as_str()));
                                let (c, rx) = Core::new(IdentityKeyPair::generate(), host_suite, transport, desc);
                                match c.host().await {
                                    Ok(_) => {
                                        match access.as_str() {
                                            "contacts" => c.restrict_to_contacts(),
                                            "friends" => c.restrict_to_friends(),
                                            _ => c.open_access(),
                                        }
                                        // Advertise the reachable LAN address in the invite.
                                        let mut d = c.descriptor().clone();
                                        d.endpoints = vec![advertised];
                                        let _ = ui_tx.send(UiEvt::Invite(d.to_uri()));
                                        let _ = ui_tx.send(UiEvt::Status(format!("hosting · {posture} · {access}")));
                                        core = Some(c);
                                        events = Some(rx);
                                    }
                                    Err(e) => { let _ = ui_tx.send(UiEvt::Status(format!("host failed: {e}"))); }
                                }
                            }
                            Cmd::Join { uri } => {
                                match ChatDescriptor::from_uri(&uri) {
                                    Ok(desc) => {
                                        // Use the invite's own suite (posture), falling back to default.
                                        let sid = desc.resolved_suite_id().to_string();
                                        let join_suite = SuiteRegistry::with_defaults().get(&sid).unwrap_or_else(|_| suite.clone());
                                        let endpoint = desc.endpoints.first().cloned().unwrap_or_default();
                                        let transport = Arc::new(TcpTransport::new("0.0.0.0:0"));
                                        let (c, rx) = Core::new(IdentityKeyPair::generate(), join_suite, transport, desc);
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
    posture: String,
    access: String,
    persistence: String,
    use_tor: bool,
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
        apply_theme(&cc.egui_ctx);
        let (cmd_tx, ui_rx) = spawn_worker(cc.egui_ctx.clone());
        Self {
            cmd_tx,
            ui_rx,
            screen: Screen::Home,
            channel_input: "#general".into(),
            posture: "pq-pure".into(),
            access: "open".into(),
            persistence: "Persistent".into(), // default Persistent, matching mobile
            use_tor: false,
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
        // Header: title + crypto subtitle (mirrors the mobile header), status right.
        egui::TopBottomPanel::top("top")
            .frame(egui::Frame::default().fill(PANEL).inner_margin(egui::Margin::symmetric(16, 10)))
            .show(ctx, |ui| {
                ui.horizontal(|ui| {
                    ui.vertical(|ui| {
                        ui.label(egui::RichText::new("talkrypt").size(22.0).strong().color(FG));
                        ui.label(egui::RichText::new("🔒 ML-KEM-1024 · ML-DSA-87").small().color(ACCENT));
                    });
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        ui.label(egui::RichText::new(&self.status).small().color(MUTED));
                    });
                });
            });

        egui::CentralPanel::default()
            .frame(egui::Frame::default().fill(BG).inner_margin(egui::Margin::same(16)))
            .show(ctx, |ui| match self.screen {
                Screen::Home => {
                    ui.label(egui::RichText::new("New chat").size(26.0).strong().color(FG));
                    ui.add_space(16.0);
                    // CHANNEL
                    ui.label(egui::RichText::new("CHANNEL").size(12.0).strong().color(MUTED));
                    ui.add_space(6.0);
                    ui.add_sized(
                        [ui.available_width(), 40.0],
                        egui::TextEdit::singleline(&mut self.channel_input)
                            .font(egui::FontId::proportional(15.0)),
                    );
                    // POSTURE / ACCESS / PERSISTENCE dropdowns (match mobile).
                    combo_section(ui, "POSTURE", "posture", &mut self.posture,
                        &["pq-pure", "hybrid", "pq-pure-compact"]);
                    combo_section(ui, "ACCESS", "access", &mut self.access,
                        &["open", "contacts", "friends"]);
                    combo_section(ui, "PERSISTENCE", "persistence", &mut self.persistence,
                        &["Ephemeral", "Persistent", "Always-on"]);
                    ui.add_space(16.0);
                    ui.checkbox(
                        &mut self.use_tor,
                        egui::RichText::new("Route over Tor (.onion; needs the Tor build)").color(MUTED),
                    );
                    ui.add_space(20.0);
                    if pill(ui, "Host a chat", ACCENT, egui::Color32::WHITE).clicked() {
                        let ch = if self.channel_input.trim().is_empty() {
                            "#general".into()
                        } else {
                            self.channel_input.clone()
                        };
                        let _ = self.cmd_tx.send(Cmd::Host {
                            channel: ch,
                            posture: self.posture.clone(),
                            access: self.access.clone(),
                        });
                        self.screen = Screen::Hosting;
                    }
                    ui.add_space(20.0);
                    ui.label(egui::RichText::new("— or join —").color(MUTED));
                    ui.add_space(8.0);
                    ui.add(egui::TextEdit::multiline(&mut self.join_input).hint_text("talkrypt://…").desired_rows(2).desired_width(f32::INFINITY));
                    ui.add_space(8.0);
                    if pill(ui, "Join", PANEL, FG).clicked() {
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
                        ui.label(egui::RichText::new("Scan to join").size(22.0).strong().color(FG));
                        ui.label(egui::RichText::new("point a phone camera at this code").small().color(MUTED));
                        ui.add_space(12.0);
                        if let Some(tex) = &self.qr {
                            // White quiet-zone frame so the QR scans on the dark bg.
                            egui::Frame::default()
                                .fill(egui::Color32::WHITE)
                                .corner_radius(egui::CornerRadius::same(10))
                                .inner_margin(egui::Margin::same(10))
                                .show(ui, |ui| ui.image((tex.id(), tex.size_vec2())));
                        } else {
                            ui.spinner();
                            ui.label(egui::RichText::new("publishing invite…").color(MUTED));
                        }
                        ui.add_space(14.0);
                        if let Some(inv) = &self.invite {
                            ui.collapsing(egui::RichText::new("invite text").color(MUTED), |ui| {
                                ui.label(egui::RichText::new(inv).monospace().small().color(MUTED));
                            });
                        }
                        ui.add_space(6.0);
                        if pill(ui, "Open chat", PANEL, FG).clicked() {
                            self.screen = Screen::Chat;
                        }
                    });
                }
                Screen::Chat => {
                    egui::ScrollArea::vertical()
                        .auto_shrink([false, false])
                        .max_height(ui.available_height() - 56.0)
                        .stick_to_bottom(true)
                        .show(ui, |ui| {
                            for (mine, who, text) in &self.transcript {
                                ui.add_space(4.0);
                                if *mine {
                                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Min), |ui| {
                                        bubble(ui, ACCENT, None, text, egui::Color32::WHITE);
                                    });
                                } else if who == "•" {
                                    ui.vertical_centered(|ui| {
                                        ui.label(egui::RichText::new(text).small().italics().color(MUTED));
                                    });
                                } else {
                                    ui.with_layout(egui::Layout::left_to_right(egui::Align::Min), |ui| {
                                        bubble(ui, PEER_BUBBLE, Some(who), text, FG);
                                    });
                                }
                            }
                        });
                    ui.add_space(6.0);
                    ui.horizontal(|ui| {
                        let send_w = 72.0;
                        let resp = ui.add_sized(
                            [ui.available_width() - send_w, 38.0],
                            egui::TextEdit::singleline(&mut self.msg_input).hint_text("Message"),
                        );
                        let enter = resp.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
                        let clicked = pill(ui, "Send", ACCENT, egui::Color32::WHITE).clicked();
                        if (clicked || enter) && !self.msg_input.trim().is_empty() {
                            let _ = self.cmd_tx.send(Cmd::Send(self.msg_input.trim().to_string()));
                            self.msg_input.clear();
                            resp.request_focus();
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
