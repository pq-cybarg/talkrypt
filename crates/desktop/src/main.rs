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

use std::collections::HashMap;
use std::sync::Arc;

use eframe::egui;
use talkrypt_core::{ChatDescriptor, Core, Event, Persistence, TopologyKind};
use talkrypt_crypto::{dr_suite_id, IdentityKeyPair, KemProfile, SuiteRegistry, DEFAULT_SUITE_ID};
use talkrypt_transport::{TcpTransport, Transport};
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender};

mod headless;

/// Persistent Tor state dir (consensus/descriptor cache + onion keys). Reusing
/// it across launches lets warm starts skip the directory bootstrap and keeps a
/// stable `.onion`. Overridable via `TALKRYPT_TOR_STATE` — used to give two
/// instances on one host separate dirs (Arti locks its state dir).
#[cfg(feature = "tor")]
fn tor_state_dir() -> std::path::PathBuf {
    use std::path::PathBuf;
    if let Some(dir) = std::env::var_os("TALKRYPT_TOR_STATE") {
        return PathBuf::from(dir);
    }
    let base = if cfg!(target_os = "windows") {
        std::env::var_os("LOCALAPPDATA").map(PathBuf::from)
    } else if cfg!(target_os = "macos") {
        std::env::var_os("HOME").map(|h| PathBuf::from(h).join("Library/Application Support"))
    } else {
        std::env::var_os("XDG_DATA_HOME")
            .map(PathBuf::from)
            .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".local/share")))
    };
    base.unwrap_or_else(std::env::temp_dir).join("talkrypt").join("tor")
}

/// Bootstrap the shared Tor transport at most once and reuse it for every onion
/// session. A concurrent caller awaits the in-flight bootstrap instead of
/// starting a second one — so a 2nd/3rd chat reuses the already-warm client.
#[cfg(feature = "tor")]
async fn init_tor(
    cell: &tokio::sync::OnceCell<Arc<dyn Transport>>,
    ui_tx: &std::sync::mpsc::Sender<UiEvt>,
    id: u64,
) -> Result<Arc<dyn Transport>, String> {
    use talkrypt_transport::{ArtiTransport, OnionPersistence};
    if let Some(t) = cell.get() {
        return Ok(t.clone());
    }
    let _ = ui_tx.send(UiEvt::Status {
        id,
        text: "bootstrapping Tor (Arti) — one-time, ~a minute…".into(),
    });
    cell.get_or_try_init(|| async {
        let dir = tor_state_dir();
        let _ = std::fs::create_dir_all(&dir);
        ArtiTransport::bootstrap(OnionPersistence::Persistent { state_dir: dir }, "talkrypt")
            .await
            .map(|t| Arc::new(t) as Arc<dyn Transport>)
            .map_err(|e| format!("tor bootstrap failed: {e}"))
    })
    .await
    .map(|t| t.clone())
}

/// Build the network transport for a host/join action. With `use_tor` (the
/// default) it reuses the shared, pre-warmed Tor client (onion = NAT-free, both
/// peers dial out). Without it, a fresh TCP transport bound to `listen` is used
/// (the same-Wi-Fi fast path).
async fn make_transport(
    id: u64,
    use_tor: bool,
    listen: &str,
    ui_tx: &std::sync::mpsc::Sender<UiEvt>,
    tor_cell: &tokio::sync::OnceCell<Arc<dyn Transport>>,
) -> Result<Arc<dyn Transport>, String> {
    if use_tor {
        #[cfg(feature = "tor")]
        {
            return init_tor(tor_cell, ui_tx, id).await;
        }
        #[cfg(not(feature = "tor"))]
        {
            let _ = (id, ui_tx, tor_cell);
            return Err("this build has Tor disabled (rebuild with --features tor)".into());
        }
    }
    Ok(Arc::new(TcpTransport::new(listen)) as Arc<dyn Transport>)
}

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
        .width(ui.available_width()) // match the full-width text fields
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

/// Commands from the UI thread to the async worker that owns the `Core`s. Every
/// command carries the UI-allocated session `id` it applies to, so the worker
/// can hold many concurrent chats (one `Core` each) and route to the right one.
enum Cmd {
    Host {
        id: u64,
        channel: String,
        posture: String,
        access: String,
        use_tor: bool,
    },
    Join {
        id: u64,
        uri: String,
        use_tor: bool,
    },
    Send {
        id: u64,
        text: String,
    },
    /// Re-dial a joined session whose transport dropped (the host stays listening
    /// on its onion/port, so the joiner just re-runs the initiator handshake).
    Reconnect {
        id: u64,
    },
}

/// Map a posture label to a KEM profile (mirrors the CLI / mobile postures).
fn profile_from(posture: &str) -> KemProfile {
    match posture {
        "hybrid" => KemProfile::hybrid(),
        "pq-pure-compact" => KemProfile::pq_pure_compact(),
        _ => KemProfile::pq_pure(),
    }
}

/// Updates from the worker back to the UI, each tagged with the session `id`
/// it belongs to so the UI updates the right chat.
enum UiEvt {
    Invite { id: u64, uri: String },
    Status { id: u64, text: String },
    Connected { id: u64, who: String },
    Disconnected { id: u64, who: String },
    /// `mine = true` for our own echoed line; else an inbound peer message.
    Line { id: u64, mine: bool, who: String, text: String },
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

/// The async worker that owns the `Core`: it consumes [`Cmd`]s, drives the
/// transport (TCP or Tor), and reports back as [`UiEvt`]s. `on_event` is invoked
/// after every state change — the GUI uses it to request a repaint; the headless
/// driver uses a no-op. This is the single networking code path shared by the
/// egui app and the `--headless` harness, so they can never drift.
async fn worker_loop<F: Fn() + Clone + Send + 'static>(
    mut cmd_rx: UnboundedReceiver<Cmd>,
    ui_tx: std::sync::mpsc::Sender<UiEvt>,
    on_event: F,
) {
    // One Core per live session, keyed by the UI-allocated id. Each Core's event
    // stream is drained by its own forwarder task (spawn_forwarder) that tags
    // events with the id, so all sessions stay live concurrently.
    let mut cores: HashMap<u64, Core> = HashMap::new();
    // Joined sessions remember their dial endpoint so Reconnect can re-dial.
    let mut rejoin: HashMap<u64, String> = HashMap::new();
    let default_suite = SuiteRegistry::with_defaults()
        .get(DEFAULT_SUITE_ID)
        .expect("default suite");

    // One shared, pre-warmed Tor client for ALL onion sessions (bootstrapped at
    // most once). Pre-warm in the background so it's ready before the first
    // host/join, without blocking LAN-only use.
    let tor_cell: Arc<tokio::sync::OnceCell<Arc<dyn Transport>>> = Arc::new(tokio::sync::OnceCell::new());
    #[cfg(feature = "tor")]
    {
        let cell = tor_cell.clone();
        let ui = ui_tx.clone();
        let ev = on_event.clone();
        tokio::spawn(async move {
            let _ = init_tor(&cell, &ui, 0).await; // id 0 = no session; status is dropped
            ev();
        });
    }

    while let Some(cmd) = cmd_rx.recv().await {
        match cmd {
            Cmd::Host { id, channel, posture, access, use_tor } => {
                // Posture selects the suite; access sets who's heard.
                let suite_id = dr_suite_id(profile_from(&posture));
                let host_suite = match SuiteRegistry::with_defaults().get(&suite_id) {
                    Ok(s) => s,
                    Err(e) => { let _ = ui_tx.send(UiEvt::Status { id, text: format!("bad posture: {e}") }); on_event(); continue; }
                };
                // TCP binds 0.0.0.0:LAN_PORT; Tor ignores the bind addr (the onion
                // service picks its own virtual port).
                let listen = format!("0.0.0.0:{LAN_PORT}");
                let transport = match make_transport(id, use_tor, &listen, &ui_tx, &tor_cell).await {
                    Ok(t) => t,
                    Err(e) => { let _ = ui_tx.send(UiEvt::Status { id, text: format!("host failed: {e}") }); on_event(); continue; }
                };
                let desc = ChatDescriptor::new(
                    TopologyKind::P2P,
                    Persistence::Ephemeral,
                    &suite_id,
                    vec![listen.clone()],
                    channel,
                );
                let (c, rx) = Core::new(IdentityKeyPair::generate(), host_suite, transport, desc);
                match c.host().await {
                    // `host()` returns the listener endpoint: the dialable
                    // `.onion:port` over Tor, or the local bind over TCP.
                    Ok(bound) => {
                        match access.as_str() {
                            "contacts" => c.restrict_to_contacts(),
                            "friends" => c.restrict_to_friends(),
                            _ => c.open_access(),
                        }
                        // Over Tor advertise the onion endpoint as-is (globally
                        // dialable, no NAT); over TCP swap the wildcard bind for
                        // this machine's LAN IP.
                        let advertised = if use_tor { bound } else { format!("{}:{LAN_PORT}", lan_ip()) };
                        let mut d = c.descriptor().clone();
                        d.endpoints = vec![advertised];
                        let net = if use_tor { "tor" } else { "lan" };
                        let _ = ui_tx.send(UiEvt::Invite { id, uri: d.to_uri() });
                        let _ = ui_tx.send(UiEvt::Status { id, text: format!("hosting · {net} · {posture} · {access}") });
                        spawn_forwarder(id, rx, ui_tx.clone(), on_event.clone());
                        cores.insert(id, c);
                    }
                    Err(e) => { let _ = ui_tx.send(UiEvt::Status { id, text: format!("host failed: {e}") }); }
                }
            }
            Cmd::Join { id, uri, use_tor } => {
                match ChatDescriptor::from_uri(&uri) {
                    Ok(desc) => {
                        // Use the invite's own suite (posture), falling back to default.
                        let sid = desc.resolved_suite_id().to_string();
                        let join_suite = SuiteRegistry::with_defaults().get(&sid).unwrap_or_else(|_| default_suite.clone());
                        let endpoint = desc.endpoints.first().cloned().unwrap_or_default();
                        // Auto-route to Tor when the invite is an onion, regardless
                        // of the toggle (a `.onion` is only reachable through Tor).
                        let join_tor = use_tor || endpoint.contains(".onion");
                        let transport = match make_transport(id, join_tor, "0.0.0.0:0", &ui_tx, &tor_cell).await {
                            Ok(t) => t,
                            Err(e) => { let _ = ui_tx.send(UiEvt::Status { id, text: format!("join failed: {e}") }); on_event(); continue; }
                        };
                        let (c, rx) = Core::new(IdentityKeyPair::generate(), join_suite, transport, desc);
                        match c.connect(&endpoint).await {
                            Ok(_) => {
                                let _ = ui_tx.send(UiEvt::Status { id, text: format!("joined — connected to {endpoint}") });
                                rejoin.insert(id, endpoint);
                                spawn_forwarder(id, rx, ui_tx.clone(), on_event.clone());
                                cores.insert(id, c);
                            }
                            Err(e) => { let _ = ui_tx.send(UiEvt::Status { id, text: format!("join failed: {e}") }); }
                        }
                    }
                    Err(e) => { let _ = ui_tx.send(UiEvt::Status { id, text: format!("bad invite: {e}") }); }
                }
            }
            Cmd::Send { id, text } => {
                if let Some(c) = cores.get(&id) {
                    match c.send(&text).await {
                        Ok(_) => { let _ = ui_tx.send(UiEvt::Line { id, mine: true, who: "me".into(), text }); }
                        Err(e) => { let _ = ui_tx.send(UiEvt::Status { id, text: format!("send failed: {e}") }); }
                    }
                }
            }
            Cmd::Reconnect { id } => {
                // A joined session re-dials its host (which is still listening on
                // the same onion/port). A host has nothing to re-dial — it just
                // keeps listening for the peer to come back.
                if let Some(endpoint) = rejoin.get(&id).cloned() {
                    if let Some(c) = cores.get(&id) {
                        let _ = ui_tx.send(UiEvt::Status { id, text: "reconnecting…".into() });
                        match c.connect(&endpoint).await {
                            Ok(_) => { let _ = ui_tx.send(UiEvt::Status { id, text: "reconnected".into() }); }
                            Err(e) => { let _ = ui_tx.send(UiEvt::Status { id, text: format!("reconnect failed: {e}") }); }
                        }
                    }
                } else {
                    let _ = ui_tx.send(UiEvt::Status { id, text: "still hosting — waiting for peer to rejoin".into() });
                }
            }
        }
        on_event();
    }
}

/// Drain one session's event stream on its own task, tagging each event with the
/// session `id` so the UI updates the right chat and repaints.
fn spawn_forwarder<F: Fn() + Send + 'static>(
    id: u64,
    mut rx: UnboundedReceiver<Event>,
    ui_tx: std::sync::mpsc::Sender<UiEvt>,
    on_event: F,
) {
    tokio::spawn(async move {
        while let Some(ev) = rx.recv().await {
            match ev {
                Event::Message { from, text, .. } => { let _ = ui_tx.send(UiEvt::Line { id, mine: false, who: short(&from), text }); }
                Event::Connected { fingerprint } => { let _ = ui_tx.send(UiEvt::Connected { id, who: short(&fingerprint) }); }
                Event::Disconnected { fingerprint } => { let _ = ui_tx.send(UiEvt::Disconnected { id, who: short(&fingerprint) }); }
                Event::Identity { account_fingerprint, username, .. } => {
                    let who = username.unwrap_or_else(|| short(&account_fingerprint));
                    let _ = ui_tx.send(UiEvt::Status { id, text: format!("identity: {who}") });
                }
                Event::Error(m) => { let _ = ui_tx.send(UiEvt::Status { id, text: format!("! {m}") }); }
            }
            on_event();
        }
    });
}

/// Spawn the async worker on its own thread + Tokio runtime (the GUI path).
/// Returns the command sender and a std receiver the UI drains each frame; the
/// worker requests an egui repaint after every event.
fn spawn_worker(ctx: egui::Context) -> (UnboundedSender<Cmd>, std::sync::mpsc::Receiver<UiEvt>) {
    let (cmd_tx, cmd_rx) = tokio::sync::mpsc::unbounded_channel::<Cmd>();
    let (ui_tx, ui_rx) = std::sync::mpsc::channel::<UiEvt>();

    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("tokio runtime");
        rt.block_on(worker_loop(cmd_rx, ui_tx, move || ctx.request_repaint()));
    });

    (cmd_tx, ui_rx)
}

#[derive(PartialEq, Clone, Copy)]
enum Screen {
    /// The list of chats you're in (the home, like mobile).
    Home,
    /// The host/join form for starting a new chat.
    NewChat,
    /// One open chat's transcript.
    Chat,
}

#[derive(PartialEq, Clone, Copy)]
enum Kind {
    Host,
    Join,
}

/// One live chat the worker holds a `Core` for. The UI mirrors its state here.
struct Session {
    id: u64,
    kind: Kind,
    title: String,
    transcript: Vec<(bool, String, String)>, // (mine, who, text)
    peers: usize,
    connected: bool,
    invite: Option<String>,
    qr: Option<egui::TextureHandle>,
    status: String,
}

impl Session {
    fn new(id: u64, kind: Kind, title: String) -> Self {
        Self {
            id,
            kind,
            title,
            transcript: Vec::new(),
            peers: 0,
            connected: false,
            invite: None,
            qr: None,
            status: "starting…".into(),
        }
    }
}

struct App {
    cmd_tx: UnboundedSender<Cmd>,
    ui_rx: std::sync::mpsc::Receiver<UiEvt>,
    screen: Screen,
    sessions: Vec<Session>,
    active: Option<u64>, // id of the chat currently open on the Chat screen
    next_id: u64,
    // ----- new-chat form -----
    channel_input: String,
    posture: String,
    access: String,
    persistence: String,
    use_tor: bool,
    join_input: String,
    // ----- chat screen -----
    msg_input: String,
    show_invite: bool, // toggles the invite/QR panel inside a chat
    notice: String,    // transient form message on the new-chat screen
}

impl App {
    fn new(cc: &eframe::CreationContext<'_>) -> Self {
        apply_theme(&cc.egui_ctx);
        let (cmd_tx, ui_rx) = spawn_worker(cc.egui_ctx.clone());
        Self {
            cmd_tx,
            ui_rx,
            screen: Screen::Home,
            sessions: Vec::new(),
            active: None,
            next_id: 1,
            channel_input: "#general".into(),
            posture: "pq-pure".into(),
            access: "open".into(),
            persistence: "Persistent".into(), // default Persistent, matching mobile
            // Tor on by default whenever this build can do Tor; a LAN-only
            // (--no-default-features) build starts unchecked.
            use_tor: cfg!(feature = "tor"),
            join_input: String::new(),
            msg_input: String::new(),
            show_invite: false,
            notice: String::new(),
        }
    }

    fn alloc_id(&mut self) -> u64 {
        let id = self.next_id;
        self.next_id += 1;
        id
    }

    fn session_mut(&mut self, id: u64) -> Option<&mut Session> {
        self.sessions.iter_mut().find(|s| s.id == id)
    }

    fn active_session(&self) -> Option<&Session> {
        self.active.and_then(|id| self.sessions.iter().find(|s| s.id == id))
    }

    /// Open `id` on the Chat screen.
    fn open(&mut self, id: u64) {
        self.active = Some(id);
        self.show_invite = false;
        self.msg_input.clear();
        self.screen = Screen::Chat;
    }

    fn drain(&mut self, ctx: &egui::Context) {
        while let Ok(evt) = self.ui_rx.try_recv() {
            match evt {
                UiEvt::Invite { id, uri } => {
                    let tex = render_qr(ctx, id, &uri);
                    if let Some(s) = self.session_mut(id) {
                        s.qr = tex;
                        s.invite = Some(uri);
                    }
                }
                UiEvt::Status { id, text } => {
                    if let Some(s) = self.session_mut(id) {
                        s.status = text;
                    }
                }
                UiEvt::Connected { id, who } => {
                    if let Some(s) = self.session_mut(id) {
                        s.peers += 1;
                        s.connected = true;
                        s.transcript.push((false, "•".into(), format!("{who} connected")));
                    }
                }
                UiEvt::Disconnected { id, who } => {
                    if let Some(s) = self.session_mut(id) {
                        s.peers = s.peers.saturating_sub(1);
                        if s.peers == 0 {
                            s.connected = false;
                        }
                        s.transcript.push((false, "•".into(), format!("{who} left")));
                    }
                }
                UiEvt::Line { id, mine, who, text } => {
                    if let Some(s) = self.session_mut(id) {
                        s.transcript.push((mine, who, text));
                    }
                }
            }
        }
    }
}

/// Render an invite string as a QR texture (black/white module grid). Named per
/// session id so concurrent chats don't share/overwrite one texture.
fn render_qr(ctx: &egui::Context, id: u64, invite: &str) -> Option<egui::TextureHandle> {
    let code = qrcode::QrCode::new(invite.as_bytes()).ok()?;
    let modules = code.to_colors();
    let dim = (modules.len() as f64).sqrt() as usize;
    let quiet = 4usize;
    // Target ~240px total so the QR doesn't swallow the window; pick an integer
    // module scale (>=2) so modules stay crisp under NEAREST.
    let scale = (240 / (dim + quiet * 2)).max(2);
    let px = (dim + quiet * 2) * scale;
    let mut img = egui::ColorImage::new([px, px], egui::Color32::WHITE);
    for y in 0..dim {
        for x in 0..dim {
            if modules[y * dim + x] != qrcode::Color::Dark {
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
    Some(ctx.load_texture(format!("invite-qr-{id}"), img, egui::TextureOptions::NEAREST))
}

impl App {
    /// Home: the list of chats you're in, plus a "New chat" entry point.
    fn home_screen(&mut self, ui: &mut egui::Ui) {
        egui::ScrollArea::vertical().auto_shrink([false, false]).show(ui, |ui| {
            ui.label(egui::RichText::new("Chats").size(26.0).strong().color(FG));
            ui.add_space(12.0);
            if pill(ui, "+ New chat", ACCENT, egui::Color32::WHITE).clicked() {
                self.notice.clear();
                self.screen = Screen::NewChat;
            }
            ui.add_space(14.0);
            if self.sessions.is_empty() {
                ui.add_space(24.0);
                ui.vertical_centered(|ui| {
                    ui.label(egui::RichText::new("No chats yet").color(MUTED));
                    ui.label(egui::RichText::new("Host one, or join with an invite / QR.").small().color(MUTED));
                });
                return;
            }
            // Snapshot the rows so we don't hold a borrow across the click handler.
            let rows: Vec<(u64, String, String, bool, usize, bool)> = self
                .sessions
                .iter()
                .map(|s| (s.id, s.title.clone(), s.status.clone(), s.connected, s.peers, matches!(s.kind, Kind::Host)))
                .collect();
            let mut open_id: Option<u64> = None;
            for (id, title, status, connected, peers, is_host) in rows {
                let (badge, badge_col) = if connected { ("online", ACCENT) } else { ("offline", MUTED) };
                let inner = egui::Frame::default()
                    .fill(PANEL)
                    .corner_radius(egui::CornerRadius::same(12))
                    .inner_margin(egui::Margin::symmetric(14, 12))
                    .show(ui, |ui| {
                        ui.horizontal(|ui| {
                            ui.vertical(|ui| {
                                ui.label(egui::RichText::new(&title).strong().color(FG));
                                let sub = if connected {
                                    format!("{peers} connected · {}", if is_host { "hosting" } else { "joined" })
                                } else {
                                    status.clone()
                                };
                                ui.label(egui::RichText::new(sub).small().color(MUTED));
                            });
                            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                                ui.label(egui::RichText::new(badge).small().strong().color(badge_col));
                            });
                        });
                    });
                if inner.response.interact(egui::Sense::click()).clicked() {
                    open_id = Some(id);
                }
                ui.add_space(8.0);
            }
            if let Some(id) = open_id {
                self.open(id);
            }
        });
    }

    /// New chat: the host/join form. Both actions allocate a session and open it.
    fn new_chat_screen(&mut self, ui: &mut egui::Ui) {
        egui::ScrollArea::vertical().auto_shrink([false, false]).show(ui, |ui| {
            ui.horizontal(|ui| {
                if ui.add(egui::Button::new(egui::RichText::new("< Back").color(FG)).fill(PANEL)).clicked() {
                    self.screen = Screen::Home;
                }
                ui.add_space(6.0);
                ui.label(egui::RichText::new("New chat").size(22.0).strong().color(FG));
            });
            ui.add_space(14.0);
            ui.label(egui::RichText::new("CHANNEL").size(12.0).strong().color(MUTED));
            ui.add_space(6.0);
            ui.add_sized(
                [ui.available_width(), 40.0],
                egui::TextEdit::singleline(&mut self.channel_input)
                    .font(egui::FontId::proportional(15.0))
                    .vertical_align(egui::Align::Center)
                    .margin(egui::Margin::symmetric(14, 8)),
            );
            combo_section(ui, "POSTURE", "posture", &mut self.posture, &["pq-pure", "hybrid", "pq-pure-compact"]);
            combo_section(ui, "ACCESS", "access", &mut self.access, &["open", "contacts", "friends"]);
            combo_section(ui, "PERSISTENCE", "persistence", &mut self.persistence, &["Ephemeral", "Persistent", "Always-on"]);
            ui.add_space(16.0);
            ui.checkbox(
                &mut self.use_tor,
                egui::RichText::new("Route over Tor (.onion — works across any network, no NAT)").color(MUTED),
            );
            ui.add_space(20.0);
            if pill(ui, "Host a chat", ACCENT, egui::Color32::WHITE).clicked() {
                let ch = if self.channel_input.trim().is_empty() { "#general".into() } else { self.channel_input.clone() };
                let id = self.alloc_id();
                self.sessions.push(Session::new(id, Kind::Host, ch.clone()));
                let _ = self.cmd_tx.send(Cmd::Host {
                    id,
                    channel: ch,
                    posture: self.posture.clone(),
                    access: self.access.clone(),
                    use_tor: self.use_tor,
                });
                self.open(id);
                self.show_invite = true; // hosts land on the QR so they can share it
            }
            ui.add_space(20.0);
            ui.label(egui::RichText::new("— or join —").color(MUTED));
            ui.add_space(8.0);
            ui.add(
                egui::TextEdit::multiline(&mut self.join_input)
                    .hint_text("talkrypt://…")
                    .desired_rows(2)
                    .desired_width(f32::INFINITY)
                    .margin(egui::Margin::symmetric(14, 8)),
            );
            ui.add_space(8.0);
            if pill(ui, "Join", PANEL, FG).clicked() {
                let uri = self.join_input.trim().to_string();
                if uri.starts_with("talkrypt://") {
                    let title = ChatDescriptor::from_uri(&uri).map(|d| d.channel).unwrap_or_else(|_| "chat".into());
                    let id = self.alloc_id();
                    self.sessions.push(Session::new(id, Kind::Join, title));
                    let _ = self.cmd_tx.send(Cmd::Join { id, uri, use_tor: self.use_tor });
                    self.join_input.clear();
                    self.notice.clear();
                    self.open(id);
                } else {
                    self.notice = "paste a talkrypt:// invite".into();
                }
            }
            if !self.notice.is_empty() {
                ui.add_space(8.0);
                ui.label(egui::RichText::new(&self.notice).small().color(egui::Color32::from_rgb(0xFF, 0xD1, 0x66)));
            }
        });
    }

    /// One open chat: header (back / invite / online / reconnect), an optional
    /// invite-QR panel, the transcript, and the message composer.
    fn chat_screen(&mut self, ui: &mut egui::Ui) {
        let Some(id) = self.active else { self.screen = Screen::Home; return };
        let Some(idx) = self.sessions.iter().position(|s| s.id == id) else { self.screen = Screen::Home; return };
        let (title, connected, peers, invite, is_host) = {
            let s = &self.sessions[idx];
            (s.title.clone(), s.connected, s.peers, s.invite.clone(), matches!(s.kind, Kind::Host))
        };

        let mut go_home = false;
        let mut toggle_invite = false;
        let mut do_reconnect = false;
        ui.horizontal(|ui| {
            if ui.add(egui::Button::new(egui::RichText::new("< Back").color(FG)).fill(PANEL)).clicked() {
                go_home = true;
            }
            ui.label(egui::RichText::new(&title).strong().color(FG));
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if invite.is_some() && ui.add(egui::Button::new(egui::RichText::new("Invite").color(ACCENT)).fill(PANEL)).clicked() {
                    toggle_invite = true;
                }
                let (txt, col) = if connected {
                    (format!("{peers} online"), ACCENT)
                } else {
                    ("offline".to_string(), MUTED)
                };
                ui.label(egui::RichText::new(txt).small().color(col));
                // A joined session can re-dial a dropped host; a host just waits.
                if !connected && !is_host
                    && ui.add(egui::Button::new(egui::RichText::new("Reconnect").color(FG)).fill(PANEL)).clicked()
                {
                    do_reconnect = true;
                }
            });
        });
        if go_home {
            self.screen = Screen::Home;
            return;
        }
        if toggle_invite {
            self.show_invite = !self.show_invite;
        }
        if do_reconnect {
            let _ = self.cmd_tx.send(Cmd::Reconnect { id });
        }
        ui.add_space(6.0);
        ui.separator();

        // Invite/QR panel (toggle via the ⧉ button; auto-on for a fresh host).
        if self.show_invite {
            if let Some(inv) = invite.clone() {
                ui.add_space(6.0);
                ui.vertical_centered(|ui| {
                    if let Some(tex) = self.sessions[idx].qr.as_ref() {
                        egui::Frame::default()
                            .fill(egui::Color32::WHITE)
                            .corner_radius(egui::CornerRadius::same(10))
                            .inner_margin(egui::Margin::same(10))
                            .show(ui, |ui| ui.image((tex.id(), tex.size_vec2())));
                    } else {
                        ui.spinner();
                        ui.label(egui::RichText::new("publishing invite…").color(MUTED));
                    }
                });
                ui.add_space(8.0);
                if pill(ui, "Copy invite link", PANEL, FG).clicked() {
                    ui.ctx().copy_text(inv);
                }
                ui.add_space(6.0);
                ui.separator();
            }
        }

        // Transcript.
        let avail = ui.available_height();
        egui::ScrollArea::vertical()
            .id_salt("transcript")
            .auto_shrink([false, false])
            .max_height((avail - 52.0).max(80.0))
            .stick_to_bottom(true)
            .show(ui, |ui| {
                for (mine, who, text) in &self.sessions[idx].transcript {
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
        ui.add_space(8.0);
        // Message row: padded field + a Send button the SAME height.
        ui.horizontal(|ui| {
            let send_w = 64.0;
            let resp = ui.add_sized(
                [ui.available_width() - send_w - 8.0, 40.0],
                egui::TextEdit::singleline(&mut self.msg_input)
                    .hint_text("Message")
                    .vertical_align(egui::Align::Center)
                    .margin(egui::Margin::symmetric(14, 8)),
            );
            let enter = resp.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
            let clicked = ui
                .add_sized(
                    [send_w, 40.0],
                    egui::Button::new(egui::RichText::new("Send").color(egui::Color32::WHITE).strong())
                        .fill(ACCENT)
                        .corner_radius(egui::CornerRadius::same(12)),
                )
                .clicked();
            if (clicked || enter) && !self.msg_input.trim().is_empty() {
                let _ = self.cmd_tx.send(Cmd::Send { id, text: self.msg_input.trim().to_string() });
                self.msg_input.clear();
                resp.request_focus();
            }
        });
    }
}

impl eframe::App for App {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.drain(ctx);
        // Header: brand + crypto subtitle; right side shows the open chat's status.
        let header_status = self
            .active_session()
            .map(|s| s.status.clone())
            .unwrap_or_else(|| "ML-KEM-1024 · ML-DSA-87 · AES-256-GCM · NOT audited".into());
        egui::TopBottomPanel::top("top")
            .frame(egui::Frame::default().fill(PANEL).inner_margin(egui::Margin::symmetric(16, 10)))
            .show(ctx, |ui| {
                ui.horizontal(|ui| {
                    ui.vertical(|ui| {
                        ui.label(egui::RichText::new("talkrypt").size(22.0).strong().color(FG));
                        ui.label(egui::RichText::new("🔒 ML-KEM-1024 · ML-DSA-87").small().color(ACCENT));
                    });
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        ui.label(egui::RichText::new(header_status).small().color(MUTED));
                    });
                });
            });

        egui::CentralPanel::default()
            .frame(egui::Frame::default().fill(BG).inner_margin(egui::Margin::same(16)))
            .show(ctx, |ui| match self.screen {
                Screen::Home => self.home_screen(ui),
                Screen::NewChat => self.new_chat_screen(ui),
                Screen::Chat => self.chat_screen(ui),
            });
    }
}

fn main() -> eframe::Result<()> {
    // Headless driver path: no window, scriptable over argv + stdin/stdout.
    let argv: Vec<String> = std::env::args().collect();
    if argv.iter().any(|a| a == "--headless") {
        std::process::exit(headless::run(&argv));
    }

    let opts = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([420.0, 640.0])
            .with_title("talkrypt"),
        ..Default::default()
    };
    eframe::run_native("talkrypt", opts, Box::new(|cc| Ok(Box::new(App::new(cc)))))
}
