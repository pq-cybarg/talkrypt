//! talkrypt — minimalist, IRC-like, post-quantum end-to-end encrypted chat.
//!
//! Subcommands:
//!   * `demo`          — run a two-party PQ conversation in-process (proof).
//!   * `host`          — create a chat, print its talkrypt:// invite, and chat.
//!   * `join <uri>`    — join a chat from an invite URI and chat.
//!   * `version`       — print the build + honesty banner.
//!
//! `host`/`join` use a real TCP transport so two terminals (or machines) can
//! talk today; the Arti onion transport (same trait) is a drop-in swap.

use std::sync::Arc;

use clap::{Parser, Subcommand};
use tokio::io::{AsyncBufReadExt, BufReader};

use talkrypt_core::{ChatDescriptor, Core, Event, Persistence, TopologyKind};
use talkrypt_crypto::{IdentityKeyPair, SuiteRegistry, DEFAULT_SUITE_ID};
use talkrypt_topology::for_kind;
use talkrypt_transport::{LoopbackFabric, TcpTransport};

const BANNER: &str = "\
talkrypt 0.1.0 — PQ end-to-end encrypted chat over Tor (Arti)
Crypto: ML-KEM-1024 (PQ) + X25519 hybrid KEM, ML-DSA-87 auth, AES-256-GCM,
        SHA3-384/HKDF. Double Ratchet (forward secrecy + post-compromise).
        Identity & authentication are pure post-quantum (ML-DSA-87); X25519 is
        only the defense-in-depth half of the hybrid KEM — never load-bearing.

HONESTY: PQ algorithms aligned with CNSA 2.0 (hash defaults to SHA3/FIPS-202;
         build with `cnsa-sha2` for strict CNSA SHA-384). CSfC architecture-
         aligned. NOT FIPS-140-validated, NOT CSfC-accredited, NOT NSA-approved
         — those are external processes source code cannot self-certify.";

#[derive(Parser)]
#[command(
    name = "talkrypt",
    version,
    about = "PQ E2E encrypted IRC-like chat over Tor"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Run a two-party PQ conversation in-process (no network) and exit.
    Demo,
    /// Create a chat, print its invite URI, and start chatting.
    Host {
        /// Bind address for inbound connections (host:port).
        #[arg(long, default_value = "127.0.0.1:9000")]
        listen: String,
        /// Topology: p2p | hub | hybrid.
        #[arg(long, default_value = "p2p")]
        topology: String,
        /// Channel name.
        #[arg(long, default_value = "#general")]
        channel: String,
        /// Found a TreeKEM group chat (this node is the coordinator/relay).
        #[arg(long)]
        group: bool,
    },
    /// Join a chat from a talkrypt:// invite URI.
    Join {
        /// The invite URI (talkrypt://...).
        uri: String,
        /// Join as a TreeKEM group member (host must be a --group host).
        #[arg(long)]
        group: bool,
    },
    /// Print the build and honesty banner.
    Version,
    /// Print the CSfC architectural preflight checklist.
    Csfc {
        /// Model a single-layer (no outer onion) deployment.
        #[arg(long)]
        no_onion: bool,
    },
}

fn short_fp(fp: &[u8; 48]) -> String {
    fp[..6]
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>()
}

fn topology_from(s: &str) -> TopologyKind {
    match s.to_ascii_lowercase().as_str() {
        "hub" => TopologyKind::Hub,
        "hybrid" => TopologyKind::Hybrid,
        _ => TopologyKind::P2P,
    }
}

fn fmt_topology(t: TopologyKind) -> &'static str {
    match t {
        TopologyKind::P2P => "p2p",
        TopologyKind::Hub => "hub",
        TopologyKind::Hybrid => "hybrid",
    }
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    let result = match cli.cmd {
        Cmd::Version => {
            println!("{BANNER}");
            Ok(())
        }
        Cmd::Csfc { no_onion } => {
            print_csfc(no_onion);
            Ok(())
        }
        Cmd::Demo => {
            run_demo().await;
            Ok(())
        }
        Cmd::Host {
            listen,
            topology,
            channel,
            group,
        } => run_host(&listen, &topology, &channel, group).await,
        Cmd::Join { uri, group } => run_join(&uri, group).await,
    };
    if let Err(e) = result {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}

/// Print the CSfC architectural preflight (see docs/CSFC.md).
fn print_csfc(no_onion: bool) {
    use talkrypt_core::csfc;
    let fips = cfg!(feature = "fips");
    let mut cfg = csfc::recommended(fips);
    if no_onion {
        cfg.outer_onion = false;
    }
    let report = csfc::preflight(&cfg);

    println!("CSfC architectural preflight (NOT an accreditation)\n");
    println!("Checkable criteria:");
    for c in &report.criteria {
        let mark = if c.satisfied { "PASS" } else { "FAIL" };
        println!("  [{mark}] {:<26} {}", c.name, c.detail);
    }
    println!(
        "\nAll checkable criteria satisfied: {} (necessary, NOT sufficient){}",
        report.all_checkable_satisfied(),
        if fips {
            ""
        } else {
            "  — build with --features fips for the FIPS backend"
        }
    );
    println!("\nRequires an organization, not code:");
    for o in &report.organizational {
        println!("  - {o}");
    }
    println!("\nSee docs/CSFC.md for the full mapping.");
}

/// In-process end-to-end demonstration: two cores, real PQ crypto, no network.
async fn run_demo() {
    println!("{BANNER}\n");
    println!("== in-process PQ end-to-end demo ==\n");

    let fabric = LoopbackFabric::new();
    let suite = SuiteRegistry::with_defaults()
        .get(DEFAULT_SUITE_ID)
        .unwrap();
    let desc = ChatDescriptor::new(
        TopologyKind::P2P,
        Persistence::Ephemeral,
        DEFAULT_SUITE_ID,
        vec!["bob".into()],
        "#demo",
    );

    let (bob, mut bob_rx) = Core::new(
        IdentityKeyPair::generate(),
        suite.clone(),
        Arc::new(fabric.transport("bob")),
        desc.clone(),
    );
    let (alice, mut alice_rx) = Core::new(
        IdentityKeyPair::generate(),
        suite.clone(),
        Arc::new(fabric.transport("alice")),
        desc.clone(),
    );

    bob.host().await.unwrap();
    let bob_fp = alice.connect("bob").await.unwrap();
    println!("alice ↔ bob handshake complete (hybrid PQ X3DH + double ratchet)");
    println!("  alice fingerprint: {}", short_fp(&alice.fingerprint()));
    println!(
        "  bob   fingerprint: {}  (verified by alice: {})",
        short_fp(&bob.fingerprint()),
        short_fp(&bob_fp)
    );
    println!();

    for line in [
        "hey bob, this is post-quantum",
        "no server can read this",
        "each message ratchets forward",
    ] {
        alice.send(line).await.unwrap();
        if let Some(Event::Message { text, from, .. }) = recv_message(&mut bob_rx).await {
            println!("alice -> bob : {text:?}  (from {})", short_fp(&from));
        }
    }
    bob.send("acknowledged, fully encrypted end to end")
        .await
        .unwrap();
    if let Some(Event::Message { text, from, .. }) = recv_message(&mut alice_rx).await {
        println!("bob -> alice : {text:?}  (from {})", short_fp(&from));
    }

    println!("\nEvery message was sealed with AES-256-GCM under a fresh ratchet key.");
    println!("Invite URI for this descriptor:\n  {}", desc.to_uri());
}

async fn recv_message(rx: &mut tokio::sync::mpsc::UnboundedReceiver<Event>) -> Option<Event> {
    use std::time::Duration;
    loop {
        match tokio::time::timeout(Duration::from_secs(5), rx.recv()).await {
            Ok(Some(e @ Event::Message { .. })) => return Some(e),
            Ok(Some(_)) => continue,
            _ => return None,
        }
    }
}

async fn run_host(
    listen: &str,
    topology: &str,
    channel: &str,
    group: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("{BANNER}\n");
    let kind = topology_from(topology);
    let suite = SuiteRegistry::with_defaults().get(DEFAULT_SUITE_ID)?;
    let transport = Arc::new(TcpTransport::new(listen));

    // Advertise the configured bind address in the descriptor.
    let desc = ChatDescriptor::new(
        kind,
        Persistence::Ephemeral,
        DEFAULT_SUITE_ID,
        vec![listen.to_string()],
        channel,
    );
    let (core, rx) = if group {
        Core::new_group(
            IdentityKeyPair::generate(),
            suite,
            transport,
            desc.clone(),
            true,
        )
    } else {
        Core::new(IdentityKeyPair::generate(), suite, transport, desc.clone())
    };
    core.host().await?;

    println!(
        "hosting {} {topology} chat on {listen}",
        if group { "TreeKEM group" } else { "pairwise" }
    );
    println!(
        "your safety number: {}",
        core.identity_public().safety_number()
    );
    println!("\nShare this invite (carries the channel + one-time invite token):\n");
    println!("  {}\n", desc.to_uri());
    println!("waiting for peers — type a message + enter to send. /help for commands.\n");

    repl(core, rx).await
}

async fn run_join(uri: &str, group: bool) -> Result<(), Box<dyn std::error::Error>> {
    println!("{BANNER}\n");
    let desc = ChatDescriptor::from_uri(uri)?;
    if desc.suite_id != DEFAULT_SUITE_ID {
        return Err(format!(
            "this chat uses crypto suite '{}', which this build does not have enabled; \
             enable that suite to join",
            desc.suite_id
        )
        .into());
    }
    let suite = SuiteRegistry::with_defaults().get(&desc.suite_id)?;
    let transport = Arc::new(TcpTransport::new("127.0.0.1:0"));
    let (core, rx) = if group {
        Core::new_group(
            IdentityKeyPair::generate(),
            suite,
            transport,
            desc.clone(),
            false,
        )
    } else {
        Core::new(IdentityKeyPair::generate(), suite, transport, desc.clone())
    };

    println!(
        "joining {} {} chat on channel {}",
        if group { "TreeKEM group" } else { "pairwise" },
        fmt_topology(desc.topology),
        desc.channel
    );
    println!(
        "your safety number: {}",
        core.identity_public().safety_number()
    );

    let strategy = for_kind(desc.topology);
    strategy.establish(&core, &desc.endpoints).await?;
    println!(
        "connected to {} peer(s). /help for commands.\n",
        core.peer_count()
    );

    repl(core, rx).await
}

/// The interactive read-eval-print loop shared by host and join.
async fn repl(
    core: Core,
    mut rx: tokio::sync::mpsc::UnboundedReceiver<Event>,
) -> Result<(), Box<dyn std::error::Error>> {
    // Event printer task.
    tokio::spawn(async move {
        while let Some(ev) = rx.recv().await {
            match ev {
                Event::Connected { fingerprint } => {
                    println!("\r* peer connected: {}", short_fp(&fingerprint));
                }
                Event::Message {
                    from,
                    channel,
                    text,
                } => {
                    println!("\r{} {}> {}", channel, short_fp(&from), text);
                }
                Event::Disconnected { fingerprint } => {
                    println!("\r* peer disconnected: {}", short_fp(&fingerprint));
                }
                Event::Error(e) => eprintln!("\r! {e}"),
            }
        }
    });

    let mut lines = BufReader::new(tokio::io::stdin()).lines();
    while let Some(line) = lines.next_line().await? {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        if let Some(rest) = line.strip_prefix('/') {
            let mut parts = rest.splitn(2, ' ');
            let cmd = parts.next().unwrap_or("");
            match cmd {
                "quit" | "q" => break,
                "help" => println!("commands: /invite  /verify  /peers  /quit"),
                "invite" => println!("{}", core.descriptor().to_uri()),
                "verify" => {
                    println!(
                        "your safety number: {}",
                        core.identity_public().safety_number()
                    );
                    println!("(compare out-of-band with your peer to defeat MITM)");
                }
                "peers" => println!("connected peers: {}", core.peer_count()),
                other => println!("unknown command: /{other} (try /help)"),
            }
            continue;
        }
        if let Err(e) = core.send(line).await {
            eprintln!("! send failed: {e}");
        }
    }
    Ok(())
}
