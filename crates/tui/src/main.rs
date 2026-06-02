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
use ratatui::crossterm::event::{self, Event, KeyCode, KeyEventKind};

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
            app.push(format!("hosting on {listen} — share this invite:"));
            app.push(desc.to_uri());
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
            app.push(format!(
                "joined chat {} ({} peers)",
                desc.channel,
                core.peer_count()
            ));
            (core, rx, app)
        }
    };
    app.push("type a message + Enter to send. /help for commands.".to_string());

    // ----- key reader on a blocking thread -----
    let (key_tx, mut key_rx) = tokio::sync::mpsc::unbounded_channel::<KeyCode>();
    std::thread::spawn(move || loop {
        if event::poll(Duration::from_millis(200)).unwrap_or(false) {
            if let Ok(Event::Key(k)) = event::read() {
                if k.kind == KeyEventKind::Press && key_tx.send(k.code).is_err() {
                    break;
                }
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
    key_rx: &mut tokio::sync::mpsc::UnboundedReceiver<KeyCode>,
    app: &mut App,
) -> Result<(), Box<dyn std::error::Error>> {
    terminal.draw(|f| ui(f, app))?;
    loop {
        tokio::select! {
            ev = core_rx.recv() => {
                match ev {
                    Some(CoreEvent::Message { from, channel, text }) =>
                        app.push(format!("{channel} {}> {text}", short_fp(&from))),
                    Some(CoreEvent::Connected { fingerprint }) =>
                        app.push(format!("* peer connected: {}", short_fp(&fingerprint))),
                    Some(CoreEvent::Disconnected { fingerprint }) =>
                        app.push(format!("* peer disconnected: {}", short_fp(&fingerprint))),
                    Some(CoreEvent::Error(e)) => app.push(format!("! {e}")),
                    None => {}
                }
                app.status = format!("peers: {}", core.peer_count());
            }
            key = key_rx.recv() => {
                match key {
                    Some(KeyCode::Char(c)) => app.input.push(c),
                    Some(KeyCode::Backspace) => { app.input.pop(); }
                    Some(KeyCode::Esc) => break,
                    Some(KeyCode::Enter) => {
                        let line = std::mem::take(&mut app.input);
                        let line = line.trim().to_string();
                        if line.is_empty() {
                        } else if let Some(cmd) = line.strip_prefix('/') {
                            match cmd.split_whitespace().next().unwrap_or("") {
                                "quit" | "q" => break,
                                "help" => app.push("commands: /invite /verify /peers /quit"),
                                "invite" => app.push(core.descriptor().to_uri()),
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
                    Some(_) => {}
                    None => break,
                }
            }
        }
        terminal.draw(|f| ui(f, app))?;
    }
    Ok(())
}
