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

use talkrypt_core::{
    build_advertisement, AdvertisePolicy, ChatDescriptor, Core, Event, Persistence, TopologyKind,
};
use talkrypt_crypto::{
    dr_suite_id, IdentityKeyPair, KemProfile, SuiteRegistry, DEFAULT_SUITE_ID,
};
use talkrypt_topology::for_kind;
use talkrypt_transport::{LoopbackFabric, TcpTransport};

const BANNER: &str = "\
talkrypt 0.1.0 — PQ end-to-end encrypted chat over Tor (Arti)
Crypto: ML-KEM-1024 (PQ) KEM, ML-DSA-87 auth, AES-256-GCM, KMAC256/SHA3.
        Double Ratchet (forward secrecy + post-compromise).
        Default posture is PQ-pure (zero elliptic curve), padded to be
        frame-indistinguishable from hybrid. `--posture hybrid` adds X25519
        defense-in-depth (non-load-bearing); identity/auth are pure PQ either
        way (ML-DSA-87). EC is never load-bearing.

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
        /// KEM posture: pq-pure (default, zero EC) | hybrid (ML-KEM+X25519
        /// defense-in-depth) | pq-pure-compact (pure, no wire padding, posture
        /// visible to a relay by frame size). Omit to use the PQ-pure default
        /// (unless --require-posture is set).
        #[arg(long)]
        posture: Option<String>,
        /// Require an explicit --posture (no silent default). The chat's
        /// "mandatory posture prompt" setting: refuse to create without a stated
        /// posture.
        #[arg(long)]
        require_posture: bool,
        /// Publish the chat's scheme at the server (opt-in; default off):
        /// off | fingerprint | full. Sealed (PQ + AES-256-GCM); a pure directory
        /// host stores it as opaque ciphertext.
        #[arg(long, default_value = "off")]
        advertise: String,
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

/// Parse a `--posture` value into a KEM profile. Unknown values fall back to the
/// PQ-pure default with a warning printed by the caller.
fn posture_from(s: &str) -> Option<KemProfile> {
    match s.to_ascii_lowercase().as_str() {
        "pq-pure" | "pqpure" | "pure" => Some(KemProfile::pq_pure()),
        "hybrid" => Some(KemProfile::hybrid()),
        "pq-pure-compact" | "compact" => Some(KemProfile::pq_pure_compact()),
        _ => None,
    }
}

/// Parse an `--advertise` value into a server-advertisement policy.
fn advertise_from(s: &str) -> Option<AdvertisePolicy> {
    match s.to_ascii_lowercase().as_str() {
        "off" | "none" | "never" => Some(AdvertisePolicy::Off),
        "fingerprint" | "hash" => Some(AdvertisePolicy::Fingerprint),
        "full" => Some(AdvertisePolicy::Full),
        _ => None,
    }
}

/// Lowercase hex of a byte slice (for printing opaque advertisement blobs).
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
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
            posture,
            require_posture,
            advertise,
        } => {
            run_host(
                &listen,
                &topology,
                &channel,
                group,
                posture.as_deref(),
                require_posture,
                &advertise,
            )
            .await
        }
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

#[allow(clippy::too_many_arguments)]
async fn run_host(
    listen: &str,
    topology: &str,
    channel: &str,
    group: bool,
    posture: Option<&str>,
    require_posture: bool,
    advertise: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("{BANNER}\n");
    let kind = topology_from(topology);
    // Mandatory-posture setting: refuse a silent default when required.
    let profile = match posture {
        Some(p) => posture_from(p)
            .ok_or_else(|| format!("unknown posture {p:?} (use pq-pure | hybrid | pq-pure-compact)"))?,
        None if require_posture => {
            return Err("this chat requires an explicit --posture \
                 (pq-pure | hybrid | pq-pure-compact); none given"
                .into());
        }
        None => KemProfile::pq_pure(),
    };
    let advertise_policy = advertise_from(advertise)
        .ok_or_else(|| format!("unknown --advertise {advertise:?} (use off | fingerprint | full)"))?;
    let suite_id = dr_suite_id(profile);
    let suite = SuiteRegistry::with_defaults().get(&suite_id)?;
    println!(
        "posture: {suite_id}\n  {}",
        if profile == KemProfile::hybrid() {
            "ML-KEM-1024 + X25519 (IETF defense-in-depth)"
        } else if profile == KemProfile::pq_pure_compact() {
            "ML-KEM-1024 only, no wire padding — posture visible to a relay by frame size"
        } else {
            "ML-KEM-1024 only, zero EC; padded to be frame-indistinguishable from hybrid"
        }
    );
    let transport = Arc::new(TcpTransport::new(listen));

    // Advertise the configured bind address in the descriptor, including
    // whether this is a group chat (so joiners auto-detect from the invite).
    let mut desc = ChatDescriptor::new(
        kind,
        Persistence::Ephemeral,
        &suite_id,
        vec![listen.to_string()],
        channel,
    );
    desc.group = group;
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

    // Optional server advertisement: a sealed (PQ + AES-256-GCM) beacon a
    // directory host can store as opaque ciphertext. Opt-in (default off).
    if let Some(blob) = build_advertisement(&desc, advertise_policy)? {
        println!(
            "server advertisement ({}): sealed, {} bytes — publish at a directory host \
             (opaque to anyone without the invite token):\n  {}\n",
            advertise.to_ascii_lowercase(),
            blob.len(),
            hex(&blob)
        );
    }
    println!("waiting for peers — type a message + enter to send. /help for commands.\n");

    repl(core, rx).await
}

async fn run_join(uri: &str, group: bool) -> Result<(), Box<dyn std::error::Error>> {
    println!("{BANNER}\n");
    let desc = ChatDescriptor::from_uri(uri)?;
    // Resolve the chat's scheme by its fingerprint — this is the "receiver must
    // have a matching registered scheme to participate" check. A blank posture
    // in the invite resolves to the PQ-pure default.
    let reg = SuiteRegistry::with_defaults();
    let suite = reg.get_by_scheme_hash(&desc.scheme_hash()).map_err(|_| {
        format!(
            "this chat's crypto scheme '{}' is not registered in this build; \
             add a matching scheme to join",
            desc.resolved_suite_id()
        )
    })?;
    println!("scheme: {}", desc.resolved_suite_id());
    let transport = Arc::new(TcpTransport::new("127.0.0.1:0"));
    // The invite descriptor declares group mode; --group can also force it.
    let want_group = group || desc.group;
    let (core, rx) = if want_group {
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
        if want_group {
            "TreeKEM group"
        } else {
            "pairwise"
        },
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
