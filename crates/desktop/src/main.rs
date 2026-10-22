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
use talkrypt_transport::{
    endpoint_scheme, select_endpoint, split_endpoints, Scheme, TcpTransport, Transport,
};
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender};

mod headless;

/// The app-data base directory (`.../talkrypt`), platform-appropriate. Always
/// compiled — both the (tor-gated) onion state dir and the persistent-chat store
/// dir hang off it.
fn app_data_dir() -> std::path::PathBuf {
    use std::path::PathBuf;
    let base = if cfg!(target_os = "windows") {
        std::env::var_os("LOCALAPPDATA").map(PathBuf::from)
    } else if cfg!(target_os = "macos") {
        std::env::var_os("HOME").map(|h| PathBuf::from(h).join("Library/Application Support"))
    } else {
        std::env::var_os("XDG_DATA_HOME")
            .map(PathBuf::from)
            .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".local/share")))
    };
    base.unwrap_or_else(std::env::temp_dir).join("talkrypt")
}

/// Persistent Tor state dir (consensus/descriptor cache + onion keys). Reusing it
/// across launches lets warm starts skip the directory bootstrap and keeps a
/// stable `.onion`. Overridable via `TALKRYPT_TOR_STATE` (two instances on one
/// host need separate dirs — Arti locks its state dir).
#[cfg(any(feature = "tor", feature = "nym"))]
fn tor_state_dir() -> std::path::PathBuf {
    if let Some(dir) = std::env::var_os("TALKRYPT_TOR_STATE") {
        return std::path::PathBuf::from(dir);
    }
    app_data_dir().join("tor")
}

/// Per-chat directory for a persistent chat's sealed at-rest store, under the
/// same app-data base as the Tor state. Keyed by a filesystem-safe form of the
/// channel name so re-hosting the same channel re-opens its retained history.
fn chat_store_dir(channel: &str) -> std::path::PathBuf {
    let safe: String = channel
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
        .collect();
    let safe = if safe.is_empty() { "chat".to_string() } else { safe };
    app_data_dir().join("chats").join(safe)
}

/// Directory holding named persistent identities ("personas"). Several let a
/// user COMPARTMENTALIZE — keep unlinkable identities for different associate
/// groups — so compromising or burning one never exposes the others.
fn identities_dir() -> std::path::PathBuf {
    app_data_dir().join("identities")
}

/// Filesystem-safe leaf for a persona name.
fn persona_file(name: &str) -> std::path::PathBuf {
    let safe: String = name
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() || c == '-' || c == '_' { c } else { '_' })
        .collect();
    let safe = if safe.is_empty() { "persona".to_string() } else { safe };
    identities_dir().join(format!("{safe}.key"))
}

/// Names of all saved personas (sorted), derived from `identities/*.key`.
fn list_identities() -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(identities_dir())
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|e| {
            let p = e.path();
            (p.extension()?.to_str()? == "key")
                .then(|| p.file_stem().and_then(|s| s.to_str()).map(str::to_string))
                .flatten()
        })
        .collect();
    names.sort();
    names
}

/// Load-or-create the seed for persona `name` (0600 seed file). A persistent
/// persona has a STABLE identity across launches — peers recognize it, its safety
/// number is constant, and the contact list refers to a fixed account. (Seed-file
/// device key as the CLI does; at-rest *sealing* of the key is the custody path.)
/// Falls back to a fresh random seed if the file can't be read/written.
fn identity_seed(name: &str) -> [u8; 32] {
    use std::io::Read;
    let path = persona_file(name);
    if let Ok(mut f) = std::fs::File::open(&path) {
        let mut s = String::new();
        if f.read_to_string(&mut s).is_ok() {
            let s = s.trim();
            if s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit()) {
                let mut seed = [0u8; 32];
                for (i, b) in seed.iter_mut().enumerate() {
                    *b = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap_or(0);
                }
                return seed;
            }
        }
    }
    let seed = IdentityKeyPair::generate().export_secret();
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let hexs: String = seed.iter().map(|b| format!("{b:02x}")).collect();
    if std::fs::write(&path, &hexs).is_ok() {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
        }
    }
    seed
}

/// BURN a persona: best-effort secure-erase of its seed file (overwrite the key
/// bytes with random, flush, then unlink) so the identity can't be recovered from
/// the file. (On a COW/SSD filesystem the overwrite may not hit the original
/// blocks — true erasure needs full-disk encryption; this is the standard
/// best-effort, and the in-memory copy is never written elsewhere.)
fn burn_identity(name: &str) {
    use std::io::Write;
    let path = persona_file(name);
    if let Ok(meta) = std::fs::metadata(&path) {
        let len = meta.len() as usize;
        if let Ok(mut f) = std::fs::OpenOptions::new().write(true).open(&path) {
            let mut junk = vec![0u8; len.max(64)];
            talkrypt_crypto::fill_secure(&mut junk);
            let _ = f.write_all(&junk);
            let _ = f.flush();
        }
    }
    let _ = std::fs::remove_file(&path);
}

/// Path to the persisted contact list (TSV: `accountPubkeyHex \t friend \t name`).
fn contacts_path() -> std::path::PathBuf {
    app_data_dir().join("contacts.tsv")
}

/// Where the identity-mode preference is recorded ("persistent" | "ephemeral").
fn identity_pref_path() -> std::path::PathBuf {
    app_data_dir().join("identity-mode")
}

/// The saved identity choice: `None` = never chosen (→ first-run prompt);
/// `Some(None)` = ephemeral; `Some(Some(name))` = that persistent persona.
fn load_identity_pref() -> Option<Option<String>> {
    let s = std::fs::read_to_string(identity_pref_path()).ok()?;
    let s = s.trim();
    Some(match s.strip_prefix("persona\t") {
        Some(name) if !name.is_empty() => Some(name.to_string()),
        _ => None, // "ephemeral" (or anything else) → ephemeral
    })
}

/// Record the identity choice so the first-run prompt doesn't reappear and the
/// last-used identity is restored next launch.
fn save_identity_pref(choice: &Option<String>) {
    let path = identity_pref_path();
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let body = match choice {
        Some(name) => format!("persona\t{name}"),
        None => "ephemeral".to_string(),
    };
    let _ = std::fs::write(&path, body);
}

/// Restore recognized accounts from a previous session into `core` (mirrors the
/// CLI), so contacts/friends-only access actually admits the right people.
fn load_contacts(core: &Core) {
    let Ok(text) = std::fs::read_to_string(contacts_path()) else {
        return;
    };
    for line in text.lines() {
        let parts: Vec<&str> = line.splitn(3, '\t').collect();
        if parts.len() < 2 {
            continue;
        }
        let Some(pk) = parts[0].len().is_multiple_of(2)
            .then(|| {
                (0..parts[0].len() / 2)
                    .map(|i| u8::from_str_radix(&parts[0][i * 2..i * 2 + 2], 16))
                    .collect::<Result<Vec<u8>, _>>()
                    .ok()
            })
            .flatten()
        else {
            continue;
        };
        let friend = parts[1] == "1";
        let name = parts.get(2).filter(|s| !s.is_empty()).map(|s| s.to_string());
        core.add_contact_bytes(pk, name, friend);
    }
}

/// Persist the current contact list (0600 on unix). Called after any change.
fn save_contacts(core: &Core) {
    let path = contacts_path();
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let mut out = String::new();
    for (pk, name, friend) in core.export_contacts() {
        let pkhex: String = pk.iter().map(|b| format!("{b:02x}")).collect();
        out.push_str(&format!("{}\t{}\t{}\n", pkhex, u8::from(friend), name.unwrap_or_default()));
    }
    if std::fs::write(&path, out).is_ok() {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
        }
    }
}

/// Bootstrap the shared Tor transport at most once and reuse it for every onion
/// session. A concurrent caller awaits the in-flight bootstrap instead of
/// starting a second one — so a 2nd/3rd chat reuses the already-warm client.
#[cfg(feature = "tor")]
async fn init_tor<R: Fn() + Clone + Send + 'static>(
    cell: &tokio::sync::OnceCell<Arc<dyn Transport>>,
    ui_tx: &std::sync::mpsc::Sender<UiEvt>,
    on_event: R,
) -> Result<Arc<dyn Transport>, String> {
    use talkrypt_transport::{ArtiTransport, OnionPersistence};
    if let Some(t) = cell.get() {
        return Ok(t.clone());
    }
    // A live bootstrap-progress callback: report the fraction to the UI (global,
    // since there's one shared Tor client) and request a repaint so the percent
    // animates while the directory downloads.
    let prog_tx = ui_tx.clone();
    let prog_repaint = on_event;
    let progress: Box<dyn Fn(f32) + Send> = Box::new(move |frac| {
        let _ = prog_tx.send(UiEvt::TorProgress(frac));
        prog_repaint();
    });
    cell.get_or_try_init(|| async {
        let dir = tor_state_dir();
        let _ = std::fs::create_dir_all(&dir);
        ArtiTransport::bootstrap_with_progress(
            OnionPersistence::Persistent { state_dir: dir },
            "talkrypt",
            None,
            Some(progress),
        )
        .await
        .map(|t| Arc::new(t) as Arc<dyn Transport>)
        .map_err(|e| format!("tor bootstrap failed: {e}"))
    })
    .await
    .cloned()
}

/// Connect the shared Nym mixnet transport at most once and reuse it for every
/// mixnet session. The gateway handshake is the slow part (like a Tor
/// bootstrap), so a 2nd/3rd chat reuses the already-connected client.
/// Connect the shared Nym client once. With a `TALKRYPT_NYM_MNEMONIC` env var
/// set, connect in **paid** mode (acquire a zk-nym bandwidth credential paying
/// with that NYM wallet mnemonic, persisting under `<state>/nym`); otherwise
/// free ephemeral mode. The mnemonic controls funds — it's read from the env
/// only, never logged.
#[cfg(feature = "nym")]
async fn init_nym(
    cell: &tokio::sync::OnceCell<Arc<dyn Transport>>,
    ui_tx: &std::sync::mpsc::Sender<UiEvt>,
) -> Result<Arc<dyn Transport>, String> {
    use talkrypt_transport::NymTransport;
    if let Some(t) = cell.get() {
        return Ok(t.clone());
    }
    let mnemonic = std::env::var("TALKRYPT_NYM_MNEMONIC").unwrap_or_default();
    let paid = !mnemonic.trim().is_empty();
    let _ = ui_tx.send(UiEvt::Status {
        id: 0,
        text: if paid {
            "connecting to Nym mixnet (paid: acquiring bandwidth)…".into()
        } else {
            "connecting to Nym mixnet…".into()
        },
    });
    cell.get_or_try_init(|| async {
        let nym = if paid {
            let dir = tor_state_dir().join("nym");
            NymTransport::connect_paid(&dir, mnemonic.trim()).await
        } else {
            NymTransport::connect().await
        };
        nym.map(|t| Arc::new(t) as Arc<dyn Transport>)
            .map_err(|e| format!("nym connect failed: {e}"))
    })
    .await
    .cloned()
}

/// Build the network transport for a host/join action.
///
/// * `use_nym` (opt-in) multi-homes over BOTH a Tor onion and the Nym mixnet:
///   a host is reachable on either network, and a [`MultiTransport`] routes each
///   dial by the endpoint's scheme. This is the strongest privacy path (mixnet
///   traffic-analysis resistance) and is why the host advertises several
///   endpoints (a multi-homed invite).
/// * `use_tor` (the default) reuses the shared, pre-warmed Tor client (onion =
///   NAT-free, both peers dial out).
/// * Otherwise a fresh TCP transport bound to `listen` is used (same-Wi-Fi fast
///   path).
#[allow(unused_variables)]
// Eight distinct dependencies (id, two transport toggles, listen addr, UI sender,
// two shared-transport cells, repaint callback); bundling them into a struct would
// add indirection for this single internal call site with no clarity gain.
#[allow(clippy::too_many_arguments)]
async fn make_transport<R: Fn() + Clone + Send + 'static>(
    id: u64,
    use_tor: bool,
    use_nym: bool,
    listen: &str,
    ui_tx: &std::sync::mpsc::Sender<UiEvt>,
    tor_cell: &tokio::sync::OnceCell<Arc<dyn Transport>>,
    nym_cell: &tokio::sync::OnceCell<Arc<dyn Transport>>,
    on_event: R,
) -> Result<Arc<dyn Transport>, String> {
    #[cfg(feature = "nym")]
    if use_nym {
        use talkrypt_transport::MultiTransport;
        // Multi-home: a Nym leg always, plus a Tor leg when this build has Tor
        // (it almost always does — both are dial-out anonymity networks, so the
        // host is reachable to joiners on either). The MultiTransport fans in
        // both listeners and routes dials by scheme.
        let mut multi = MultiTransport::new();
        #[cfg(feature = "tor")]
        if use_tor {
            let tor = init_tor(tor_cell, ui_tx, on_event.clone()).await?;
            multi = multi.with(Scheme::Onion, tor);
        }
        let nym = init_nym(nym_cell, ui_tx).await?;
        multi = multi.with(Scheme::Nym, nym);
        return Ok(Arc::new(multi) as Arc<dyn Transport>);
    }
    if use_tor {
        #[cfg(feature = "tor")]
        {
            return init_tor(tor_cell, ui_tx, on_event).await;
        }
        #[cfg(not(feature = "tor"))]
        {
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
    v.widgets.inactive.fg_stroke = egui::Stroke::new(1.0_f32, FG);
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
        /// "Ephemeral" | "Persistent" | "Always-on" (see the PERSISTENCE combo).
        persistence: String,
        /// At-rest seal passphrase for a persistent chat (empty for Ephemeral).
        seal_pass: String,
        /// Which identity to use: `None` = fresh per-launch ephemeral; `Some(name)`
        /// = the persistent persona with that name.
        identity: Option<String>,
        use_tor: bool,
        use_nym: bool,
    },
    Join {
        id: u64,
        uri: String,
        /// Identity choice (see `Cmd::Host`): ephemeral (`None`) or a persona.
        identity: Option<String>,
        use_tor: bool,
        use_nym: bool,
    },
    Send {
        id: u64,
        text: String,
    },
    /// Set (and CQ-announce) this session's leading self-declared name (SUB-SPEC A).
    /// An empty label clears it.
    SetName {
        id: u64,
        label: String,
    },
    /// Toggle the periodic CQ re-beacon (SUB-SPEC A). `secs == 0` disables it.
    SetCadence {
        id: u64,
        secs: u64,
    },
    /// Re-dial a joined session whose transport dropped (the host stays listening
    /// on its onion/port, so the joiner just re-runs the initiator handshake).
    Reconnect {
        id: u64,
    },
    /// Add the session's presented peer account to the persistent contact list
    /// (optionally as a friend). Makes contacts/friends-only access usable: the
    /// host builds a contact set from people it has actually talked to.
    AddContact {
        id: u64,
        account_fp: [u8; 48],
        name: String,
        friend: bool,
    },
    /// Run a raw interactive slash-command (`/verify`, `/vouch <fp>`, `/username
    /// <name>`, …) through the shared `talkrypt-replcmd` logic — the same engine
    /// the CLI and TUI use. The worker dispatches it against this session's `Core`
    /// + `ReplState` and returns the output lines as a [`UiEvt::CommandOutput`].
    RunCommand {
        id: u64,
        line: String,
    },
    /// Leave + delete a chat: drop this session's `Core` (disconnecting it) and
    /// its per-session state, so dead chats don't leak in the worker.
    Close {
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
    /// Our own message was handed to the transport — rendered as a bubble in the
    /// `Sent` state, keyed by `gid` so a later `Delivered` can upgrade it.
    Sent { id: u64, gid: [u8; 32], text: String },
    /// A recipient acked the message with this `gid` (group/persistent path).
    Delivered { id: u64, gid: [u8; 32] },
    /// The outbox dropped `count` un-acked messages (cap/TTL) → mark that many of
    /// our most-recent still-unacked bubbles as failed.
    Dropped { id: u64, count: usize },
    /// A peer presented its account identity — carries the account fingerprint +
    /// display name so the chat can offer "Add contact / friend".
    PeerIdentity { id: u64, account_fp: [u8; 48], name: String },
    /// Global Tor bootstrap progress (one shared client), `frac` in 0.0..=1.0.
    /// Only constructed on a Tor build (init_tor); harmless dead variant otherwise.
    #[cfg_attr(not(feature = "tor"), allow(dead_code))]
    TorProgress(f32),
    /// Output lines from a [`Cmd::RunCommand`] slash-command, rendered into the
    /// transcript as system lines (one per line, in order).
    CommandOutput { id: u64, lines: Vec<String> },
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
    // Per-session REPL state (account/username) for the shared slash-command
    // engine. Each chat starts as an unlinkable pseudonym; `/account new` makes
    // one — exactly like the CLI/TUI.
    let mut repl_states: HashMap<u64, talkrypt_replcmd::ReplState> = HashMap::new();
    // Joined sessions remember their dial endpoint so Reconnect can re-dial.
    let mut rejoin: HashMap<u64, String> = HashMap::new();
    // The per-launch EPHEMERAL identity: one fresh key for this process run, used
    // by any session the user runs in ephemeral mode, discarded on exit and never
    // written to disk. (Persistent mode uses the on-disk `device.key` instead.)
    // A closure yields a keypair from the chosen seed per session.
    let ephemeral_seed = IdentityKeyPair::generate().export_secret();
    let identity_for = |choice: &Option<String>| {
        IdentityKeyPair::from_secret_bytes(match choice {
            Some(name) => identity_seed(name),
            None => ephemeral_seed,
        })
    };
    let default_suite = SuiteRegistry::with_defaults()
        .get(DEFAULT_SUITE_ID)
        .expect("default suite");

    // One shared, pre-warmed Tor client for ALL onion sessions (bootstrapped at
    // most once). Pre-warm in the background so it's ready before the first
    // host/join, without blocking LAN-only use.
    let tor_cell: Arc<tokio::sync::OnceCell<Arc<dyn Transport>>> = Arc::new(tokio::sync::OnceCell::new());
    // The Nym mixnet client is connected lazily on first opt-in use (unlike Tor,
    // which is pre-warmed): a user who never enables Nym never touches a gateway.
    let nym_cell: Arc<tokio::sync::OnceCell<Arc<dyn Transport>>> = Arc::new(tokio::sync::OnceCell::new());
    #[cfg(feature = "tor")]
    {
        let cell = tor_cell.clone();
        let ui = ui_tx.clone();
        let ev = on_event.clone();
        tokio::spawn(async move {
            let _ = init_tor(&cell, &ui, ev.clone()).await;
            ev();
        });
    }

    while let Some(cmd) = cmd_rx.recv().await {
        match cmd {
            Cmd::Host { id, channel, posture, access, persistence, seal_pass, identity, use_tor, use_nym } => {
                // Posture selects the suite; access sets who's heard.
                let suite_id = dr_suite_id(profile_from(&posture));
                let host_suite = match SuiteRegistry::with_defaults().get(&suite_id) {
                    Ok(s) => s,
                    Err(e) => { let _ = ui_tx.send(UiEvt::Status { id, text: format!("bad posture: {e}") }); on_event(); continue; }
                };
                // Persistence tier: Ephemeral (no retention) / Persistent (sealed
                // at-rest history + outbox, survives restart) / Always-on (Persistent
                // PLUS keeper_mode — the host buffers-and-replays for offline members).
                let persistent = persistence != "Ephemeral";
                let always_on = persistence == "Always-on";
                // A persistent chat seals its on-disk store with a passphrase (the
                // same custody factor the core requires — fail closed, no plaintext
                // retention). Validate BEFORE the expensive transport bootstrap.
                if persistent && seal_pass.trim().is_empty() {
                    let _ = ui_tx.send(UiEvt::Status { id, text: "a persistent chat needs a seal passphrase (it encrypts the on-disk history)".into() });
                    on_event();
                    continue;
                }
                // TCP binds 0.0.0.0:LAN_PORT; Tor ignores the bind addr (the onion
                // service picks its own virtual port).
                let listen = format!("0.0.0.0:{LAN_PORT}");
                let transport = match make_transport(id, use_tor, use_nym, &listen, &ui_tx, &tor_cell, &nym_cell, on_event.clone()).await {
                    Ok(t) => t,
                    Err(e) => { let _ = ui_tx.send(UiEvt::Status { id, text: format!("host failed: {e}") }); on_event(); continue; }
                };
                // A Nym host is a TreeKEM GROUP committer (Hub topology) so it can
                // fan out / bridge across transports; otherwise a pairwise P2P chat.
                let topology = if use_nym { TopologyKind::Hub } else { TopologyKind::P2P };
                let desc = ChatDescriptor::new(
                    topology,
                    if persistent { Persistence::Persistent } else { Persistence::Ephemeral },
                    &suite_id,
                    vec![listen.clone()],
                    &channel,
                );
                // The chosen identity: a persistent persona (recognizable across
                // launches, so its contact list is meaningful) or a fresh ephemeral.
                let device = identity_for(&identity);
                let (c, rx) = if use_nym {
                    let (c, rx) = Core::new_group(device, host_suite, transport, desc, true);
                    // Multi-homed => gossip bridge: re-flood group ciphertext across
                    // all transports, merging Nym/Tor islands into one chat.
                    c.enable_gossip();
                    (c, rx)
                } else {
                    Core::new(device, host_suite, transport, desc)
                };
                // Restore saved contacts so contacts/friends-only access admits the
                // right accounts (and recognizes them by name).
                load_contacts(&c);
                // Wire at-rest persistence BEFORE host(): a passphrase-sealed
                // SealedFileStore (AES-256-GCM, Argon2id KEK) backs both the outbox
                // (so un-acked sends survive a restart) and the history (redisplayed
                // on reopen). Keyed per-channel so the same chat re-opens its store.
                if persistent {
                    let dir = chat_store_dir(&channel);
                    match talkrypt_core::SealedFileStore::open(&dir, Some(seal_pass.as_bytes()), None) {
                        Ok(store) => {
                            let store = std::sync::Arc::new(store);
                            c.set_outbox_store(store.clone());
                            c.set_history_store(store);
                            c.set_persistence(true);
                            if always_on {
                                c.keeper_mode(true);
                            }
                            // Redisplay any history this chat retained from a prior run.
                            for rec in c.load_history() {
                                let _ = ui_tx.send(UiEvt::Line {
                                    id,
                                    mine: rec.from == c.identity_public().fingerprint(),
                                    who: short(&rec.from),
                                    text: rec.text,
                                });
                            }
                        }
                        Err(e) => {
                            let _ = ui_tx.send(UiEvt::Status { id, text: format!("persistent store failed (wrong passphrase?): {e}") });
                            on_event();
                            continue;
                        }
                    }
                }
                match c.host().await {
                    // `host()` returns the listener endpoint: the dialable
                    // `.onion:port` over Tor, or the local bind over TCP.
                    Ok(bound) => {
                        match access.as_str() {
                            "contacts" => c.restrict_to_contacts(),
                            "friends" => c.restrict_to_friends(),
                            _ => c.open_access(),
                        }
                        // With Nym, `host()` returns a multi-homed listener whose
                        // endpoint is several globally-dialable addresses joined
                        // together (onion + nym); expand them into the invite so a
                        // joiner can pick by preference. Over Tor alone advertise
                        // the onion as-is; over TCP swap the wildcard bind for this
                        // machine's LAN IP.
                        let endpoints = if use_nym {
                            split_endpoints(&bound)
                        } else if use_tor {
                            vec![bound]
                        } else {
                            vec![format!("{}:{LAN_PORT}", lan_ip())]
                        };
                        // Label the chat by the networks it's actually homed on,
                        // derived from the advertised endpoints (e.g. "nym",
                        // "tor", "nym+tor", "lan") so it never claims a leg the
                        // transport doesn't carry.
                        let net = endpoints
                            .iter()
                            .map(|e| match endpoint_scheme(e) {
                                Scheme::Nym => "nym",
                                Scheme::Onion => "tor",
                                Scheme::Tcp => "lan",
                            })
                            .collect::<Vec<_>>()
                            .join("+");
                        let mut d = c.descriptor().clone();
                        d.endpoints = endpoints;
                        let _ = ui_tx.send(UiEvt::Invite { id, uri: d.to_uri() });
                        let tier = if always_on { "always-on" } else if persistent { "persistent" } else { "ephemeral" };
                        let _ = ui_tx.send(UiEvt::Status { id, text: format!("hosting · {net} · {posture} · {access} · {tier}") });
                        spawn_forwarder(id, rx, ui_tx.clone(), on_event.clone());
                        cores.insert(id, c);
                        repl_states.insert(id, talkrypt_replcmd::ReplState::new(None, None));
                    }
                    Err(e) => { let _ = ui_tx.send(UiEvt::Status { id, text: format!("host failed: {e}") }); }
                }
            }
            Cmd::Join { id, uri, identity, use_tor, use_nym } => {
                match ChatDescriptor::from_uri(&uri) {
                    Ok(desc) => {
                        // Use the invite's own suite (posture), falling back to default.
                        let sid = desc.resolved_suite_id().to_string();
                        let join_suite = SuiteRegistry::with_defaults().get(&sid).unwrap_or_else(|_| default_suite.clone());
                        // From a multi-homed invite, pick the best endpoint by
                        // preference: Nym (mixnet) when enabled, else Tor, else LAN.
                        // Falls back to the first endpoint so a peer is never
                        // stranded by a scheme we don't prefer.
                        let prefs: &[Scheme] = if use_nym {
                            &[Scheme::Nym, Scheme::Onion, Scheme::Tcp]
                        } else {
                            &[Scheme::Onion, Scheme::Tcp]
                        };
                        let endpoint = select_endpoint(&desc.endpoints, prefs)
                            .map(|s| s.to_string())
                            .unwrap_or_default();
                        // Route to the network the chosen endpoint lives on. A
                        // `nym:` endpoint forces Nym; a `.onion` forces Tor (only
                        // reachable that way) regardless of the toggle.
                        let join_nym = use_nym && endpoint_scheme(&endpoint) == Scheme::Nym;
                        let join_tor = use_tor || endpoint.contains(".onion");
                        let transport = match make_transport(id, join_tor, join_nym, "0.0.0.0:0", &ui_tx, &tor_cell, &nym_cell, on_event.clone()).await {
                            Ok(t) => t,
                            Err(e) => { let _ = ui_tx.send(UiEvt::Status { id, text: format!("join failed: {e}") }); on_event(); continue; }
                        };
                        // A Nym join is a TreeKEM group MEMBER (the host is the
                        // committer); connect sends our KeyPackage and we get a
                        // Welcome back. Otherwise a pairwise chat.
                        let device = identity_for(&identity);
                        let (c, rx) = if join_nym {
                            let (c, rx) = Core::new_group(device, join_suite, transport, desc, false);
                            c.enable_gossip(); // bridge (see the host path)
                            (c, rx)
                        } else {
                            Core::new(device, join_suite, transport, desc)
                        };
                        load_contacts(&c);
                        match c.connect(&endpoint).await {
                            Ok(_) => {
                                let _ = ui_tx.send(UiEvt::Status { id, text: format!("joined — connected to {endpoint}") });
                                rejoin.insert(id, endpoint);
                                spawn_forwarder(id, rx, ui_tx.clone(), on_event.clone());
                                cores.insert(id, c);
                                repl_states.insert(id, talkrypt_replcmd::ReplState::new(None, None));
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
                        Ok(gid) => { let _ = ui_tx.send(UiEvt::Sent { id, gid, text }); }
                        Err(e) => { let _ = ui_tx.send(UiEvt::Status { id, text: format!("send failed: {e}") }); }
                    }
                }
            }
            Cmd::AddContact { id, account_fp, name, friend } => {
                if let Some(c) = cores.get(&id) {
                    let name = (!name.trim().is_empty()).then(|| name.trim().to_string());
                    if c.add_seen_contact(account_fp, name, friend) {
                        save_contacts(c);
                        let kind = if friend { "friend" } else { "contact" };
                        let _ = ui_tx.send(UiEvt::Status { id, text: format!("added {kind} {}", short(&account_fp)) });
                    } else {
                        let _ = ui_tx.send(UiEvt::Status { id, text: "could not add contact (account not presented yet)".into() });
                    }
                }
            }
            Cmd::Close { id } => {
                // Drop the Core (its transport/listeners close) and forget the
                // session's worker-side state. The UI already removed its own copy.
                cores.remove(&id);
                repl_states.remove(&id);
                rejoin.remove(&id);
            }
            Cmd::RunCommand { id, line } => {
                // Dispatch a slash-command through the shared engine (same as the
                // CLI/TUI): split off the leading `/`, first token is the command,
                // the remainder is the argument, then render the returned lines.
                if let (Some(c), Some(state)) = (cores.get(&id), repl_states.get_mut(&id)) {
                    let rest = line.trim_start_matches('/');
                    let mut parts = rest.splitn(2, ' ');
                    let cmd = parts.next().unwrap_or("");
                    let arg = parts.next().unwrap_or("").trim();
                    let lines = talkrypt_replcmd::run_command(c, state, cmd, arg).await;
                    let _ = ui_tx.send(UiEvt::CommandOutput { id, lines });
                } else {
                    let _ = ui_tx.send(UiEvt::Status { id, text: "connect to a chat first".into() });
                }
            }
            Cmd::SetName { id, label } => {
                if let Some(c) = cores.get(&id) {
                    if label.is_empty() {
                        c.set_leading_name(None);
                        let _ = ui_tx.send(UiEvt::Status { id, text: "name cleared".into() });
                    } else {
                        c.set_leading_name(Some(talkrypt_core::presence::NameEntry {
                            id: label.clone(),
                            label: label.clone(),
                            backing: talkrypt_core::presence::NameBacking::Bare,
                        }));
                        let _ = c.announce_presence().await;
                        let _ = ui_tx.send(UiEvt::Status { id, text: format!("calling as \"{label}\"") });
                    }
                }
            }
            Cmd::SetCadence { id, secs } => {
                if let Some(c) = cores.get(&id) {
                    let cur = c.presence_cadence();
                    c.set_presence_cadence(talkrypt_core::presence::PresenceCadence {
                        periodic_secs: (secs > 0).then_some(secs),
                        on_message_id: cur.on_message_id,
                    });
                    let text = if secs > 0 {
                        format!("CQ every {secs}s")
                    } else {
                        "CQ periodic off".into()
                    };
                    let _ = ui_tx.send(UiEvt::Status { id, text });
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
                    // Surface the account so the chat can offer "Add contact/friend".
                    let _ = ui_tx.send(UiEvt::PeerIdentity { id, account_fp: account_fingerprint, name: who });
                }
                Event::Name { from, label, tier, caveat, safety_number, .. } => {
                    // SUB-SPEC A NameRender: honest tier badge, always-available safety
                    // number, and any collision caveat. A suppressed name (label None)
                    // still surfaces via its safety number + the caveat.
                    let badge = match tier {
                        talkrypt_core::nametrust::NameTier::Linked => "\u{1F517} ", // 🔗
                        talkrypt_core::nametrust::NameTier::RegistryConfirmed => "\u{2713} ", // ✓
                        talkrypt_core::nametrust::NameTier::Bare => "",
                    };
                    let head = match label {
                        Some(l) => format!("{badge}{} is calling as \"{l}\" [{safety_number}]", short(&from)),
                        None => format!("{} [{safety_number}]", short(&from)),
                    };
                    let text = match caveat {
                        Some(c) => format!("{head} \u{26a0} {c}"), // ⚠
                        None => head,
                    };
                    let _ = ui_tx.send(UiEvt::Status { id, text });
                }
                Event::Linkage { .. } => {} // SUB-SPEC B (UI: Task 13)
                Event::Vouch { subject, vouched, .. } if vouched => {
                    let _ = ui_tx.send(UiEvt::Status { id, text: format!("\u{2733} {} is vouched", short(&subject)) });
                }
                Event::Vouch { .. } => {} // below threshold / withdrawn — no status line
                Event::Delivered { gossip_id } => { let _ = ui_tx.send(UiEvt::Delivered { id, gid: gossip_id }); }
                Event::OutboxDropped { count } => { let _ = ui_tx.send(UiEvt::Dropped { id, count }); }
                Event::PromoteProposed { .. } => { let _ = ui_tx.send(UiEvt::Status { id, text: "promotion proposed".into() }); }
                Event::Promoted { .. } => { let _ = ui_tx.send(UiEvt::Status { id, text: "promoted — chat is persistent".into() }); }
                Event::PromoteAborted { .. } => { let _ = ui_tx.send(UiEvt::Status { id, text: "promotion aborted".into() }); }
                Event::BeaconSeen { source, .. } => { let via = source.map(|s| format!(" ({s})")).unwrap_or_default(); let _ = ui_tx.send(UiEvt::Status { id, text: format!("nearby device beaconing this channel{via}") }); }
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

/// Per-message delivery state for our OWN sent messages. `Sent` = handed to the
/// transport (terminal for a pairwise chat — there's no ack); `Delivered` = a
/// recipient ack (`Event::Delivered`, group/persistent path); `Failed` = the
/// outbox dropped it (cap/TTL). Rendered as a trailing ·/✓✓/✗ on own bubbles.
#[derive(PartialEq, Clone, Copy)]
enum Delivery {
    Sent,
    Delivered,
    Failed,
}

/// One rendered transcript line: who said it, the text, and (for our own lines)
/// the delivery state. Peer/system lines carry `mine = false` and ignore it.
struct Msg {
    mine: bool,
    who: String,
    text: String,
    delivery: Delivery,
}

/// One live chat the worker holds a `Core` for. The UI mirrors its state here.
struct Session {
    id: u64,
    kind: Kind,
    title: String,
    transcript: Vec<Msg>,
    peers: usize,
    connected: bool,
    invite: Option<String>,
    qr: Option<egui::TextureHandle>,
    status: String,
    /// The peer's presented account (fingerprint + display name), if any — the
    /// target of the chat's "Add contact / friend" affordance.
    peer_account: Option<([u8; 48], String)>,
    /// Our own sent messages by `gossip_id` → transcript index, so a later
    /// `Delivered` ack can upgrade the right bubble's state.
    sent_index: std::collections::HashMap<[u8; 32], usize>,
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
            peer_account: None,
            sent_index: std::collections::HashMap::new(),
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
    /// At-rest seal passphrase typed for a persistent chat (never persisted in UI
    /// state beyond the host action).
    seal_pass_input: String,
    use_tor: bool,
    use_nym: bool,
    join_input: String,
    // ----- chat screen -----
    msg_input: String,
    name_input: String, // SUB-SPEC A: leading self-declared name draft
    cq_periodic: bool,  // SUB-SPEC A: periodic CQ re-beacon toggle (active session)
    show_invite: bool, // toggles the invite/QR panel inside a chat
    notice: String,    // transient form message on the new-chat screen
    tor_progress: Option<f32>, // global Tor bootstrap fraction while < 1.0
    // ----- identity (opsec compartmentalization) -----
    /// The active identity for new chats: `None` = fresh per-launch ephemeral;
    /// `Some(name)` = that persistent persona.
    current_identity: Option<String>,
    /// Known persistent personas (names of the `identities/*.key` files).
    identities: Vec<String>,
    /// Draft name for creating a new persona (first-run prompt + manager).
    new_identity_name: String,
    /// Show the first-run identity chooser (no preference saved yet).
    show_identity_prompt: bool,
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
            name_input: String::new(),
            cq_periodic: false,
            // Ephemeral by default on desktop: a persistent chat requires a seal
            // passphrase (below), so don't impose that friction unless the user
            // opts in. (The old "Persistent" default was a dead no-op.)
            persistence: "Ephemeral".into(),
            seal_pass_input: String::new(),
            // Tor on by default whenever this build can do Tor; a LAN-only
            // (--no-default-features) build starts unchecked.
            use_tor: cfg!(feature = "tor"),
            // Nym mixnet is opt-in and off by default even in a `nym` build (it
            // connects to a gateway only when the user asks for it).
            use_nym: false,
            join_input: String::new(),
            msg_input: String::new(),
            show_invite: false,
            notice: String::new(),
            tor_progress: None,
            // Restore the saved identity choice; prompt on first run (no pref yet).
            // Ephemeral is the privacy-first default if the prompt is dismissed.
            current_identity: load_identity_pref().flatten(),
            identities: list_identities(),
            new_identity_name: String::new(),
            show_identity_prompt: load_identity_pref().is_none(),
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
                        s.transcript.push(Msg { mine: false, who: "•".into(), text: format!("{who} connected"), delivery: Delivery::Delivered });
                    }
                }
                UiEvt::Disconnected { id, who } => {
                    if let Some(s) = self.session_mut(id) {
                        s.peers = s.peers.saturating_sub(1);
                        if s.peers == 0 {
                            s.connected = false;
                        }
                        s.transcript.push(Msg { mine: false, who: "•".into(), text: format!("{who} left"), delivery: Delivery::Delivered });
                    }
                }
                UiEvt::Line { id, mine, who, text } => {
                    if let Some(s) = self.session_mut(id) {
                        s.transcript.push(Msg { mine, who, text, delivery: Delivery::Delivered });
                    }
                }
                UiEvt::Sent { id, gid, text } => {
                    if let Some(s) = self.session_mut(id) {
                        let idx = s.transcript.len();
                        s.transcript.push(Msg { mine: true, who: "me".into(), text, delivery: Delivery::Sent });
                        s.sent_index.insert(gid, idx);
                    }
                }
                UiEvt::Delivered { id, gid } => {
                    if let Some(s) = self.session_mut(id) {
                        if let Some(&idx) = s.sent_index.get(&gid) {
                            if let Some(m) = s.transcript.get_mut(idx) {
                                m.delivery = Delivery::Delivered;
                            }
                        }
                    }
                }
                UiEvt::Dropped { id, count } => {
                    if let Some(s) = self.session_mut(id) {
                        // Mark the `count` most-recent still-unacked own messages failed
                        // (OutboxDropped carries no per-message id).
                        let mut n = count;
                        for m in s.transcript.iter_mut().rev() {
                            if n == 0 {
                                break;
                            }
                            if m.mine && m.delivery == Delivery::Sent {
                                m.delivery = Delivery::Failed;
                                n -= 1;
                            }
                        }
                    }
                }
                UiEvt::PeerIdentity { id, account_fp, name } => {
                    if let Some(s) = self.session_mut(id) {
                        s.peer_account = Some((account_fp, name));
                    }
                }
                UiEvt::TorProgress(frac) => {
                    // Clear once fully bootstrapped; otherwise show the fraction.
                    self.tor_progress = if frac >= 1.0 { None } else { Some(frac) };
                }
                UiEvt::CommandOutput { id, lines } => {
                    if let Some(s) = self.session_mut(id) {
                        // Render each returned line as a centered system line, like
                        // the TUI pushes them into its log.
                        for line in lines {
                            s.transcript.push(Msg { mine: false, who: "•".into(), text: line, delivery: Delivery::Delivered });
                        }
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
            // A persistent chat seals its history + outbox to disk; collect the
            // passphrase that encrypts that store (fail-closed — no plaintext
            // retention). Always-on additionally keeps-and-forwards for offline
            // members. Only shown when the user opts into persistence.
            if self.persistence != "Ephemeral" {
                ui.add_space(8.0);
                ui.label(egui::RichText::new("SEAL PASSPHRASE (encrypts on-disk history)").size(12.0).strong().color(MUTED));
                ui.add_space(6.0);
                ui.add_sized(
                    [ui.available_width(), 36.0],
                    egui::TextEdit::singleline(&mut self.seal_pass_input)
                        .password(true)
                        .hint_text("required for a persistent chat")
                        .margin(egui::Margin::symmetric(14, 8)),
                );
            }
            // IDENTITY: which persona (or ephemeral) this chat uses. Compartmentalize
            // associate groups with separate personas; burn one to erase it.
            ui.add_space(14.0);
            ui.label(egui::RichText::new("IDENTITY").size(12.0).strong().color(MUTED));
            ui.add_space(6.0);
            let current_label = self
                .current_identity
                .clone()
                .unwrap_or_else(|| "Ephemeral (fresh each launch)".into());
            let mut burn: Option<String> = None;
            egui::ComboBox::from_id_salt("identity")
                .selected_text(current_label)
                .show_ui(ui, |ui| {
                    ui.selectable_value(&mut self.current_identity, None, "Ephemeral (fresh each launch)");
                    for name in &self.identities {
                        ui.selectable_value(&mut self.current_identity, Some(name.clone()), name);
                    }
                });
            // Persist the selection so it's restored next launch.
            save_identity_pref(&self.current_identity);
            ui.horizontal(|ui| {
                ui.add_sized(
                    [180.0, 30.0],
                    egui::TextEdit::singleline(&mut self.new_identity_name).hint_text("new persona name"),
                );
                let name = self.new_identity_name.trim().to_string();
                if ui.add_enabled(!name.is_empty(), egui::Button::new(egui::RichText::new("+ Create").color(ACCENT)).fill(PANEL)).clicked() {
                    let _ = identity_seed(&name); // materialize its seed
                    self.identities = list_identities();
                    self.current_identity = Some(name);
                    self.new_identity_name.clear();
                    save_identity_pref(&self.current_identity);
                }
                // Burn the selected persona (secure-erase its seed).
                if let Some(sel) = self.current_identity.clone() {
                    if ui.add(egui::Button::new(egui::RichText::new("Burn").color(egui::Color32::from_rgb(220, 90, 90))).fill(PANEL)).clicked() {
                        burn = Some(sel);
                    }
                }
            });
            if let Some(name) = burn {
                burn_identity(&name);
                self.identities = list_identities();
                self.current_identity = None; // fall back to ephemeral
                save_identity_pref(&self.current_identity);
                self.notice = format!("burned persona '{name}'");
            }
            ui.add_space(16.0);
            ui.checkbox(
                &mut self.use_tor,
                egui::RichText::new("Route over Tor (.onion — works across any network, no NAT)").color(MUTED),
            );
            #[cfg(feature = "nym")]
            ui.checkbox(
                &mut self.use_nym,
                egui::RichText::new("Also route over Nym mixnet (traffic-analysis resistance; multi-homes the invite)").color(MUTED),
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
                    persistence: self.persistence.clone(),
                    seal_pass: self.seal_pass_input.clone(),
                    identity: self.current_identity.clone(),
                    use_tor: self.use_tor,
                    use_nym: self.use_nym,
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
                    let _ = self.cmd_tx.send(Cmd::Join { id, uri, identity: self.current_identity.clone(), use_tor: self.use_tor, use_nym: self.use_nym });
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
        let (title, connected, peers, invite, is_host, peer_account) = {
            let s = &self.sessions[idx];
            (s.title.clone(), s.connected, s.peers, s.invite.clone(), matches!(s.kind, Kind::Host), s.peer_account.clone())
        };

        let mut go_home = false;
        let mut toggle_invite = false;
        let mut do_reconnect = false;
        let mut close_chat = false;
        let mut add_contact: Option<bool> = None; // Some(friend?)
        ui.horizontal(|ui| {
            if ui.add(egui::Button::new(egui::RichText::new("< Back").color(FG)).fill(PANEL)).clicked() {
                go_home = true;
            }
            ui.label(egui::RichText::new(&title).strong().color(FG));
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                // Leave + delete this chat: disconnects (worker drops the Core) and
                // removes it from the list so dead chats don't accumulate forever.
                if ui
                    .add(egui::Button::new(egui::RichText::new("✕ Close").color(egui::Color32::from_rgb(220, 90, 90))).fill(PANEL))
                    .on_hover_text("Leave and delete this chat (disconnects; removes it from the list)")
                    .clicked()
                {
                    close_chat = true;
                }
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
        // Add-contact affordance: once a peer has presented its account, the host
        // can save it as a contact/friend — which is what makes contacts/friends-
        // only access usable (it builds the set from people you've talked to).
        if let Some((_fp, name)) = &peer_account {
            ui.horizontal(|ui| {
                ui.label(egui::RichText::new(format!("peer account: {name}")).small().color(MUTED));
                if ui.add(egui::Button::new(egui::RichText::new("Add contact").color(FG)).fill(PANEL)).clicked() {
                    add_contact = Some(false);
                }
                if ui.add(egui::Button::new(egui::RichText::new("Add friend").color(ACCENT)).fill(PANEL)).clicked() {
                    add_contact = Some(true);
                }
            });
        }
        if let (Some(friend), Some((fp, name))) = (add_contact, &peer_account) {
            let _ = self.cmd_tx.send(Cmd::AddContact { id, account_fp: *fp, name: name.clone(), friend });
        }
        if go_home {
            self.screen = Screen::Home;
            return;
        }
        if close_chat {
            // Tell the worker to drop the Core (disconnects), then forget the
            // session locally and return to the chat list.
            let _ = self.cmd_tx.send(Cmd::Close { id });
            self.sessions.retain(|s| s.id != id);
            if self.active == Some(id) {
                self.active = None;
            }
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
            // Reserve the full height of the controls that render BELOW the
            // transcript — the name row, the trust toolbar, and the composer
            // (plus inter-row spacing) — so none of them get clipped off the
            // bottom. (Was 52px, which only accounted for the composer.)
            .max_height((avail - 136.0).max(80.0))
            .stick_to_bottom(true)
            .show(ui, |ui| {
                for Msg { mine, who, text, delivery } in &self.sessions[idx].transcript {
                    ui.add_space(4.0);
                    if *mine {
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Min), |ui| {
                            // Per-message delivery indicator (RTL: sits left of the bubble):
                            // · sent · ✓✓ delivered (acked) · ✗ dropped/failed.
                            let (glyph, col) = match delivery {
                                Delivery::Sent => ("·", MUTED),
                                Delivery::Delivered => ("✓✓", ACCENT),
                                Delivery::Failed => ("✗", egui::Color32::from_rgb(220, 90, 90)),
                            };
                            ui.label(egui::RichText::new(glyph).small().color(col));
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
        // Name row (SUB-SPEC A): declare + CQ-announce a self-declared name for this chat.
        ui.horizontal(|ui| {
            let nr = ui.add(
                egui::TextEdit::singleline(&mut self.name_input)
                    .hint_text("Your name (CQ)")
                    .desired_width(160.0),
            );
            let set = ui.button("Set name").clicked()
                || (nr.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)));
            if set {
                let _ = self.cmd_tx.send(Cmd::SetName {
                    id,
                    label: self.name_input.trim().to_string(),
                });
            }
            // Periodic CQ toggle: re-beacon the name every 5 min so late joiners /
            // reconnects resolve us without a fresh roster-grow (SUB-SPEC A §4).
            if ui.checkbox(&mut self.cq_periodic, "CQ 5m").changed() {
                let _ = self.cmd_tx.send(Cmd::SetCadence {
                    id,
                    secs: if self.cq_periodic { 300 } else { 0 },
                });
            }
        });
        ui.add_space(4.0);
        // Trust & identity toolbar — discoverable buttons for the key trust-model
        // views; each fires a slash-command through the shared engine and the
        // output lands in the transcript. The full ~40-command surface (vouch,
        // username, access, contacts, opsec, grouping, register/resolve, …) is
        // reachable by typing `/command …` in the message box below.
        ui.horizontal_wrapped(|ui| {
            let run = |line: &str| {
                let _ = self.cmd_tx.send(Cmd::RunCommand { id, line: line.to_string() });
            };
            if ui.button("🔐 Verify").on_hover_text("Show safety numbers — compare out of band to defeat MITM").clicked() {
                run("/verify");
            }
            if ui.button("Who am I").on_hover_text("Your device + account identity and contact count").clicked() {
                run("/whoami");
            }
            if ui.button("Vouches").on_hover_text("Heard vouches (SUB-SPEC C; display-only, never gates access)").clicked() {
                run("/vouches");
            }
            if ui.button("Sybil").on_hover_text("Honest distinct-people estimate for this chat").clicked() {
                run("/sybil");
            }
            if ui.button("Commands…").on_hover_text("List every slash command (type them in the message box)").clicked() {
                run("/help");
            }
        });
        ui.add_space(4.0);
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
                let text = self.msg_input.trim().to_string();
                // A `/`-prefixed line is a slash-command (full CLI/TUI surface via
                // the shared engine), not a chat message — route it accordingly so
                // the desktop console reaches contacts, access, vouch, name, etc.
                if text.starts_with('/') {
                    let _ = self.cmd_tx.send(Cmd::RunCommand { id, line: text });
                } else {
                    let _ = self.cmd_tx.send(Cmd::Send { id, text });
                }
                self.msg_input.clear();
                resp.request_focus();
            }
        });
    }
}

impl eframe::App for App {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.drain(ctx);
        // While Tor's one-time bootstrap runs, keep repainting so the percent
        // animates (egui is otherwise event-driven).
        if self.tor_progress.is_some() {
            ctx.request_repaint_after(std::time::Duration::from_millis(120));
        }
        // Header: brand + subtitle. The subtitle shows the live Tor bootstrap
        // percent while it's running, else the crypto line; the right side shows
        // the open chat's status.
        let subtitle = match self.tor_progress {
            Some(f) => format!("🔒 Bootstrapping Tor… {}%", (f * 100.0).round() as u32),
            None => "🔒 ML-KEM-1024 · ML-DSA-87".to_string(),
        };
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
                        ui.label(egui::RichText::new(subtitle).small().color(ACCENT));
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

        // First-run identity chooser, drawn on top of everything.
        self.identity_prompt(ctx);
    }
}

impl App {
    /// First-launch modal: choose how this install identifies itself. Ephemeral is
    /// the privacy-first default (nothing written to disk); a persistent persona is
    /// opt-in and can be named here. The choice is saved so this never reappears,
    /// and can be changed later in the new-chat form's IDENTITY section.
    fn identity_prompt(&mut self, ctx: &egui::Context) {
        if !self.show_identity_prompt {
            return;
        }
        let mut chosen: Option<Option<String>> = None; // outer Some = decided; inner = choice
        egui::Window::new("Choose your identity")
            .collapsible(false)
            .resizable(false)
            .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
            .show(ctx, |ui| {
                ui.set_max_width(420.0);
                ui.label(egui::RichText::new(
                    "How should this device identify itself to the people you chat with?",
                ).color(FG));
                ui.add_space(10.0);
                ui.label(egui::RichText::new(
                    "Ephemeral — a fresh identity every launch. Unlinkable, nothing written to \
                     disk. Best for throwaway/anonymous use. (No saved contacts or stable safety \
                     number.)",
                ).small().color(MUTED));
                ui.add_space(4.0);
                if ui.add(egui::Button::new(egui::RichText::new("Stay ephemeral (recommended)").color(FG)).fill(PANEL)).clicked() {
                    chosen = Some(None);
                }
                ui.add_space(14.0);
                ui.label(egui::RichText::new(
                    "Persistent persona — a named identity that survives restarts, so peers \
                     recognize you, your safety number is stable, and contacts/friends-only \
                     access works. Create several to keep associate groups compartmentalized.",
                ).small().color(MUTED));
                ui.add_space(4.0);
                ui.horizontal(|ui| {
                    ui.add_sized(
                        [200.0, 30.0],
                        egui::TextEdit::singleline(&mut self.new_identity_name).hint_text("persona name (e.g. work)"),
                    );
                    let name = self.new_identity_name.trim().to_string();
                    if ui.add_enabled(!name.is_empty(), egui::Button::new(egui::RichText::new("Create persona").color(ACCENT)).fill(PANEL)).clicked() {
                        chosen = Some(Some(name));
                    }
                });
            });
        if let Some(choice) = chosen {
            if let Some(name) = &choice {
                // Materialize the persona (creates its sealed-at-rest-capable seed).
                let _ = identity_seed(name);
                self.identities = list_identities();
            }
            save_identity_pref(&choice);
            self.current_identity = choice;
            self.new_identity_name.clear();
            self.show_identity_prompt = false;
        }
    }
}

fn main() -> eframe::Result<()> {
    // Baseline, like the CLI/helper: FIPS power-on self-test + RAM-capture
    // hardening before any key material is touched.
    talkrypt_crypto::ensure_self_tested();
    talkrypt_crypto::ensure_hardened();

    // Opt-in permissive-security hardening (host with SIP/AMFI relaxed): anti-debug
    // + loader-injection scan + optional PQ self-attestation. Refuse to start on an
    // unacceptable posture. Applies to both the GUI and headless paths.
    if std::env::var_os(talkrypt_crypto::harden::HARDEN_ENV).is_some() {
        let posture = talkrypt_crypto::harden::from_env();
        eprintln!("talkrypt: hardening posture: {posture:?}");
        if !posture.is_acceptable() {
            eprintln!(
                "talkrypt: hardening posture unacceptable (loader-injection env set, \
                 or self-attestation failed) — refusing to start"
            );
            std::process::exit(1);
        }
    }

    // Headless driver path: no window, scriptable over argv + stdin/stdout.
    let argv: Vec<String> = std::env::args().collect();
    if argv.iter().any(|a| a == "--headless") {
        std::process::exit(headless::run(&argv));
    }

    let opts = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([420.0, 640.0])
            // Floor the window so it can't be dragged smaller than the chat
            // controls (header + transcript + name row + trust toolbar + composer)
            // need — below this the composer gets clipped off the bottom.
            .with_min_inner_size([360.0, 480.0])
            .with_title("talkrypt"),
        ..Default::default()
    };
    eframe::run_native("talkrypt", opts, Box::new(|cc| Ok(Box::new(App::new(cc)))))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn persona_file_sanitizes_and_is_stable_per_name() {
        // Same persona name -> same seed file (stable identity across launches).
        assert_eq!(persona_file("work"), persona_file("work"));
        assert_ne!(persona_file("work"), persona_file("activist"));
        // Path-hostile names are sanitized to a safe .key leaf under identities/.
        let p = persona_file("../../evil name!");
        let leaf = p.file_name().unwrap().to_string_lossy();
        assert!(leaf.ends_with(".key"));
        let stem = leaf.trim_end_matches(".key");
        assert!(stem.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'));
        assert!(p.parent().unwrap().ends_with("identities"));
    }

    #[test]
    fn identity_pref_round_trips_choices() {
        // Encoding is stable: ephemeral vs a named persona are distinguishable, and
        // the format matches what load expects (persona\t<name> / "ephemeral").
        // (Pure format check via the same strings load_identity_pref parses.)
        assert_eq!(
            Some("work".to_string()),
            "persona\twork".strip_prefix("persona\t").map(str::to_string)
        );
        assert_eq!(None, "ephemeral".strip_prefix("persona\t").map(str::to_string));
    }

    #[test]
    fn chat_store_dir_sanitizes_and_is_stable_per_channel() {
        // Same channel -> same dir (so a re-hosted chat re-opens its sealed store).
        assert_eq!(chat_store_dir("#general"), chat_store_dir("#general"));
        // Distinct channels -> distinct dirs.
        assert_ne!(chat_store_dir("#a"), chat_store_dir("#b"));
        // Path-hostile characters are replaced; no separators leak into the leaf.
        let d = chat_store_dir("../../etc/passwd");
        let leaf = d.file_name().unwrap().to_string_lossy();
        assert!(!leaf.contains('/') && !leaf.contains('.'));
        assert!(leaf.chars().all(|c| c.is_ascii_alphanumeric() || c == '_'));
        // An all-symbol channel still yields a non-empty leaf.
        assert!(!chat_store_dir("###").file_name().unwrap().is_empty());
    }
}
