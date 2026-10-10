//! talkrypt-tui — a minimalist ratatui front-end over the same `Core` engine.
//!
//!   talkrypt-tui host --listen 127.0.0.1:9000 --channel '#general'
//!   talkrypt-tui join talkrypt://...
//!
//! Uses the TCP transport today; swapping in `ArtiTransport` is a one-line
//! change once the `tor` feature is wired through the binary.

mod app;

use std::sync::Arc;
use std::time::Duration;

use clap::{Parser, Subcommand};
use ratatui::crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};

/// What the input thread forwards to the event loop: a key press, or a bare
/// redraw signal (e.g. a terminal resize) so the UI re-lays-out immediately
/// instead of staying garbled until the next keypress.
enum Input {
    Key(KeyEvent),
    Redraw,
}

use talkrypt_core::{ChatDescriptor, Core, Event as CoreEvent, Persistence, TopologyKind};
use talkrypt_crypto::{dr_suite_id, IdentityKeyPair, KemProfile, SuiteRegistry};
use talkrypt_topology::for_kind;
use talkrypt_transport::TcpTransport;

use app::{ui, App};

#[derive(Parser)]
#[command(name = "talkrypt-tui", about = "PQ E2E encrypted chat — terminal UI")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    Host {
        #[arg(long, default_value = "127.0.0.1:9000")]
        listen: String,
        #[arg(long, default_value = "p2p")]
        topology: String,
        #[arg(long, default_value = "#general")]
        channel: String,
        /// KEM posture: pq-pure (default) | hybrid | pq-pure-compact.
        #[arg(long, default_value = "pq-pure")]
        posture: String,
    },
    Join {
        uri: String,
    },
}

fn short_fp(fp: &[u8; 48]) -> String {
    fp[..6].iter().map(|b| format!("{b:02x}")).collect()
}

/// Parse a `--posture` value into a KEM profile (mirrors the CLI).
fn posture_from(s: &str) -> Option<KemProfile> {
    match s.to_ascii_lowercase().as_str() {
        "pq-pure" | "pqpure" | "pure" => Some(KemProfile::pq_pure()),
        "hybrid" => Some(KemProfile::hybrid()),
        "pq-pure-compact" | "compact" => Some(KemProfile::pq_pure_compact()),
        _ => None,
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    // ----- bootstrap the engine -----
    let reg = SuiteRegistry::with_defaults();
    let (core, mut core_rx, mut app) = match cli.cmd {
        Cmd::Host {
            listen,
            topology,
            channel,
            posture,
        } => {
            let kind = match topology.as_str() {
                "hub" => TopologyKind::Hub,
                "hybrid" => TopologyKind::Hybrid,
                _ => TopologyKind::P2P,
            };
            let profile = posture_from(&posture)
                .ok_or_else(|| format!("unknown posture {posture:?}"))?;
            let suite_id = dr_suite_id(profile);
            let suite = reg.get(&suite_id)?;
            let desc = ChatDescriptor::new(
                kind,
                Persistence::Ephemeral,
                &suite_id,
                vec![listen.clone()],
                &channel,
            );
            let transport = Arc::new(TcpTransport::new(&listen));
            let (core, rx) = Core::new(IdentityKeyPair::generate(), suite, transport, desc.clone());
            core.host().await?;
            let mut app = App::new(
                channel,
                format!("{topology} · hosting {listen} · {suite_id}"),
            );
            app.safety_number = core.identity_public().safety_number();
            app.peers = core.peer_count();
            app.push(format!("hosting on {listen} — share this invite:"));
            app.push(desc.to_uri());
            // Render the invite as a scannable QR so someone can join in person.
            app.push_qr(&desc.to_uri());
            (core, rx, app)
        }
        Cmd::Join { uri } => {
            let desc = ChatDescriptor::from_uri(&uri)?;
            // Resolve the chat's scheme by fingerprint (must be registered here).
            let suite = reg.get_by_scheme_hash(&desc.scheme_hash()).map_err(|_| {
                format!(
                    "this chat's scheme '{}' is not registered in this build",
                    desc.resolved_suite_id()
                )
            })?;
            let suite_id = desc.resolved_suite_id().to_string();
            let transport = Arc::new(TcpTransport::new("127.0.0.1:0"));
            let (core, rx) = Core::new(IdentityKeyPair::generate(), suite, transport, desc.clone());
            for_kind(desc.topology)
                .establish(&core, &desc.endpoints)
                .await?;
            let mut app = App::new(
                desc.channel.clone(),
                format!("joined · peers: {} · {suite_id}", core.peer_count()),
            );
            app.safety_number = core.identity_public().safety_number();
            app.peers = core.peer_count();
            app.push(format!(
                "joined chat {} ({} peers)",
                desc.channel,
                core.peer_count()
            ));
            (core, rx, app)
        }
    };
    app.push("type a message + Enter to send. /help for commands.".to_string());

    // ----- input reader on a blocking thread -----
    // Forwards full key events (so modifiers like Ctrl are visible) AND resize
    // events (as a redraw signal), instead of only key codes.
    let (key_tx, mut key_rx) = tokio::sync::mpsc::unbounded_channel::<Input>();
    std::thread::spawn(move || loop {
        if event::poll(Duration::from_millis(200)).unwrap_or(false) {
            match event::read() {
                Ok(Event::Key(k)) if k.kind == KeyEventKind::Press => {
                    if key_tx.send(Input::Key(k)).is_err() {
                        break;
                    }
                }
                Ok(Event::Resize(_, _)) => {
                    if key_tx.send(Input::Redraw).is_err() {
                        break;
                    }
                }
                Ok(_) => {}
                Err(_) => break,
            }
        }
    });

    // ----- terminal + event loop -----
    let mut terminal = ratatui::init();
    let result = run(&mut terminal, &core, &mut core_rx, &mut key_rx, &mut app).await;
    ratatui::restore();
    result
}

async fn run(
    terminal: &mut ratatui::DefaultTerminal,
    core: &Core,
    core_rx: &mut tokio::sync::mpsc::UnboundedReceiver<CoreEvent>,
    key_rx: &mut tokio::sync::mpsc::UnboundedReceiver<Input>,
    app: &mut App,
) -> Result<(), Box<dyn std::error::Error>> {
    terminal.draw(|f| ui(f, app))?;
    loop {
        tokio::select! {
            ev = core_rx.recv() => {
                match ev {
                    Some(CoreEvent::Message { from, channel, text, marking }) => {
                        let tag = marking
                            .map(|m| format!("[{}] ", m.banner()))
                            .unwrap_or_default();
                        app.push(format!("{tag}{channel} {}> {text}", short_fp(&from)));
                    }
                    Some(CoreEvent::Connected { fingerprint }) =>
                        app.push(format!("* peer connected: {}", short_fp(&fingerprint))),
                    Some(CoreEvent::Identity { from, account_fingerprint, username, contact, friend }) => {
                        let name = username.unwrap_or_else(|| "<no username>".into());
                        let tag = if friend { "friend" } else if contact { "contact" } else { "account" };
                        app.push(format!(
                            "* {tag} {name} (account {}) on device {}",
                            short_fp(&account_fingerprint),
                            short_fp(&from)
                        ));
                    }
                    Some(CoreEvent::Disconnected { fingerprint }) =>
                        app.push(format!("* peer disconnected: {}", short_fp(&fingerprint))),
                    Some(CoreEvent::Name { from, label: Some(label), .. }) =>
                        app.push(format!("* {} is calling as \"{label}\"", short_fp(&from))),
                    Some(CoreEvent::Name { .. }) => {}
                    Some(CoreEvent::Linkage { .. }) => {} // SUB-SPEC B (UI: Task 13)
                    Some(CoreEvent::Vouch { .. }) => {}   // SUB-SPEC C (UI: Task 11)
                    Some(CoreEvent::Delivered { .. }) => {}    // D1 delivery receipt (UI later)
                    Some(CoreEvent::OutboxDropped { .. }) => {} // D1 outbox cap/TTL drop
                    Some(CoreEvent::PromoteProposed { .. }) => app.push("* promotion proposed".to_string()),
                    Some(CoreEvent::Promoted { .. }) => app.push("* promoted - chat is persistent".to_string()),
                    Some(CoreEvent::PromoteAborted { .. }) => app.push("* promotion aborted".to_string()),
                    Some(CoreEvent::BeaconSeen { source, .. }) => app.push(format!(
                        "* nearby: a device on this channel is beaconing{}",
                        source.map(|s| format!(" ({s})")).unwrap_or_default()
                    )),
                    Some(CoreEvent::Error(e)) => app.push(format!("! {e}")),
                    None => {}
                }
                // Keep the stable status (topology · address · suite); only the
                // live peer count changes.
                app.peers = core.peer_count();
            }
            key = key_rx.recv() => {
                match key {
                    // Redraw-only signal (terminal resize): fall through to draw.
                    Some(Input::Redraw) => {}
                    Some(Input::Key(k)) => {
                        // Ctrl-C / Ctrl-D: the universal "quit" reflex. Under raw
                        // mode these arrive as a Char with the CONTROL modifier, not
                        // a signal — handle them explicitly so they don't type a
                        // literal 'c'/'d' into the message buffer.
                        let ctrl = k.modifiers.contains(KeyModifiers::CONTROL);
                        match k.code {
                            KeyCode::Char('c' | 'd') if ctrl => break,
                            KeyCode::Char(c) => app.input.push(c),
                            KeyCode::Backspace => { app.input.pop(); }
                            KeyCode::Esc => break,
                            KeyCode::PageUp => app.scroll_up(10),
                            KeyCode::PageDown => app.scroll_down(10),
                            KeyCode::Home => app.scroll_up(u16::MAX),
                            KeyCode::End => app.scroll_offset = 0,
                            KeyCode::Enter => {
                                let line = std::mem::take(&mut app.input);
                                let line = line.trim().to_string();
                                // Sending returns the user to the newest line.
                                app.scroll_offset = 0;
                                if line.is_empty() {
                                } else if let Some(cmd) = line.strip_prefix('/') {
                                    match cmd.split_whitespace().next().unwrap_or("") {
                                        "quit" | "q" => break,
                                        "help" => app.push(
                                            "commands: /help /invite /verify /peers /quit  |  keys: Enter send · Ctrl-C/Esc quit · PgUp/PgDn/Home/End scroll",
                                        ),
                                        "invite" => {
                                            let uri = core.descriptor().to_uri();
                                            app.push(uri.clone());
                                            app.push_qr(&uri);
                                        }
                                        "verify" => app.push(format!("safety number: {}", app.safety_number)),
                                        "peers" => app.push(format!("connected peers: {}", core.peer_count())),
                                        other => app.push(format!("unknown command: /{other}")),
                                    }
                                } else if let Err(e) = core.send(&line).await {
                                    app.push(format!("! send failed: {e}"));
                                } else {
                                    app.push(format!("me> {line}"));
                                }
                            }
                            _ => {}
                        }
                    }
                    None => break,
                }
            }
        }
        terminal.draw(|f| ui(f, app))?;
    }
    Ok(())
}
