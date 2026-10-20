//! talkrypt — minimalist, IRC-like, post-quantum end-to-end encrypted chat.
//!
//! Subcommands:
//!   * `demo`          — run a two-party PQ conversation in-process (proof).
//!   * `host`          — create a chat, print its talkrypt:// invite, and chat.
//!   * `join <uri>`    — join a chat from an invite URI and chat.
//!   * `registry`      — host a username→account directory (opt-in discovery).
//!   * `version`       — print the build + honesty banner.
//!
//! `host`/`join` are **interactive**: an in-session REPL (`/help`) drives chat
//! plus account identity (`/account`, `/username`, `/pseudonym`), friending
//! (`/friend trust` a just-seen account after an out-of-band safety-number
//! check, `/friends`), and registry use (`/register`, `/resolve` with
//! cross-compare). `--account <path>` links a session to a username account;
//! omitting it stays an unlinkable pseudonym.
//!
//! `host`/`join`/`registry` use a real TCP transport by default so two terminals
//! (or machines) can talk; pass `--tor` (on a `--features tor` build) to run over
//! real Tor instead — the host publishes an onion service and puts the `.onion`
//! in the invite, and joiners dial it.

use std::sync::Arc;

use clap::{Parser, Subcommand};
use tokio::io::{AsyncBufReadExt, BufReader};

use talkrypt_core::{
    build_advertisement, AdvertisePolicy, ChannelPassword, ChatDescriptor, Core, Event, LinkClient,
    LinkHost, Marking, Persistence, RegistryClient, RegistryServer, TopologyKind,
};
#[cfg(feature = "markings")]
use talkrypt_core::Classification;
use talkrypt_crypto::{
    dr_suite_id, IdentityChain, IdentityKeyPair, KemProfile, SuiteRegistry, DEFAULT_SUITE_ID,
};
use talkrypt_replcmd::{present, run_command, ReplState};
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
         aligned. NOT FIPS-140-validated, NOT CSfC-accredited, NOT NSA-approved,
         NOT authorized for any classification level, and NOT independently
         audited or cryptographically reviewed. Alignment means it uses these
         algorithms — not that it is certified or fit for real classified or
         high-stakes data. Experimental, pre-release software.";

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
        /// Channel classification (requires the `markings` build): unclassified
        /// | cui | confidential | secret | top-secret. Marks every message in
        /// the channel (advisory; carried authenticated in the payload).
        #[arg(long)]
        classification: Option<String>,
        /// Dissemination caveat, repeatable (e.g. NOFORN, ORCON, "REL TO USA").
        #[arg(long = "caveat")]
        caveats: Vec<String>,
        /// SCI compartment label, repeatable (e.g. SI, TK). Access is enforced
        /// by group membership; the label is advisory.
        #[arg(long = "compartment")]
        compartments: Vec<String>,
        /// Path to an account key (32-byte seed, hex). If it exists, link this
        /// session to that account; if it doesn't, a new account is generated
        /// and saved there. Omit to start as an unlinkable pseudonym.
        #[arg(long)]
        account: Option<String>,
        /// Self-asserted username advertised with the account (display only;
        /// the account key is the cryptographic identity). Needs --account.
        #[arg(long)]
        username: Option<String>,
        /// Persist this device's key at PATH (load if present, else create). A
        /// stable device key is what a linked account certificate (`--chain`)
        /// refers to. Omit for an ephemeral per-run device key.
        #[arg(long)]
        device: Option<String>,
        /// Present a linked account certificate chain from PATH (obtained via
        /// `link-accept`). Resolves you as that account using your `--device`
        /// key. Mutually exclusive with `--account`.
        #[arg(long)]
        chain: Option<String>,
        /// Password-gate this channel: the password is mixed into the session
        /// root via Argon2id and NEVER put in the invite, so a joiner needs both
        /// the invite AND this password. Share it out of band; joiners pass the
        /// same `--password`.
        #[arg(long)]
        password: Option<String>,
        /// Registry-restrict this channel: only accounts registered on the
        /// registry at this URI may participate (the URI is yours alone and
        /// never appears in the invite). The allowlist is pulled at startup.
        #[arg(long)]
        require_registry: Option<String>,
        /// Host over real Tor (Arti): publishes an onion service and puts the
        /// .onion in the invite. Requires a `--features tor` build.
        #[arg(long)]
        tor: bool,
        /// Advertise this address in the invite instead of the bound --listen
        /// address. Use when the address peers must dial differs from the one
        /// you bind (bind 0.0.0.0, advertise your LAN/public IP; on an Android
        /// emulator advertise the host alias 10.0.2.2). Ignored with --tor.
        #[arg(long)]
        endpoint: Option<String>,
        /// Self-declared leading callsign for this chat (SUB-SPEC A). Set before
        /// any peer connects so the on-join CQ auto-announce carries it — the
        /// non-interactive equivalent of `/name <callsign>`. Bare (not
        /// account-linked); use `/name link` in-session for a linked name.
        #[arg(long)]
        name: Option<String>,
        /// How joiners resolve self-declared name collisions (SUB-SPEC A). Travels
        /// in the invite so every joiner honors the host's choice: `signal`
        /// (default — never trust a name for identity; show it verbatim and rely
        /// on the safety number), `warn` (flag colliding names with a caveat), or
        /// `suppress` (hide a later collider's label, show its fingerprint).
        #[arg(long)]
        name_policy: Option<String>,
        #[command(flatten)]
        mesh: MeshArgs,
    },
    /// Join a chat from a talkrypt:// invite URI.
    Join {
        /// The invite URI (talkrypt://...).
        uri: String,
        /// Join as a TreeKEM group member (host must be a --group host).
        #[arg(long)]
        group: bool,
        /// Path to an account key (see `host --account`).
        #[arg(long)]
        account: Option<String>,
        /// Self-asserted username advertised with the account (needs --account).
        #[arg(long)]
        username: Option<String>,
        /// Persist this device's key at PATH (see `host --device`).
        #[arg(long)]
        device: Option<String>,
        /// Present a linked account chain from PATH (see `host --chain`).
        #[arg(long)]
        chain: Option<String>,
        /// Channel password (must match the host's `--password`); mixed into the
        /// session root via Argon2id, never sent on the wire.
        #[arg(long)]
        password: Option<String>,
        /// Dial over real Tor (Arti) — required when the invite is a .onion.
        /// Requires a `--features tor` build.
        #[arg(long)]
        tor: bool,
        /// Self-declared leading callsign for this chat (SUB-SPEC A). Set before
        /// dialing so the on-join CQ auto-announce carries it — the
        /// non-interactive equivalent of `/name <callsign>`. Bare (not
        /// account-linked); use `/name link` in-session for a linked name.
        #[arg(long)]
        name: Option<String>,
        #[command(flatten)]
        mesh: MeshArgs,
    },
    /// Offer to link a new device to your account (you hold the account key).
    /// Prints a one-time linking URI + QR; run `link-accept` on the new device.
    LinkOffer {
        /// Bind address for the new device to connect to (host:port).
        #[arg(long, default_value = "127.0.0.1:9200")]
        listen: String,
        /// Path to your account key (the one that will certify the new device).
        #[arg(long)]
        account: String,
        /// Username to convey to the new device (optional).
        #[arg(long)]
        username: Option<String>,
        /// Advertise this address in the linking URI instead of the bound
        /// --listen (e.g. bind 0.0.0.0, advertise your LAN IP; on an Android
        /// emulator advertise the host alias 10.0.2.2). Same idea as `host
        /// --endpoint`.
        #[arg(long)]
        endpoint: Option<String>,
    },
    /// Accept a link offer on a NEW device: connect to the offer's URI, get a
    /// certificate for this device's key, and save the chain for `host --chain`.
    LinkAccept {
        /// The linking URI printed by `link-offer`.
        uri: String,
        /// Persist this device's key at PATH (created if absent).
        #[arg(long, default_value = "~/.talkrypt/device.key")]
        device: String,
        /// Where to save the received account→device chain.
        #[arg(long, default_value = "~/.talkrypt/chain.bin")]
        chain_out: String,
        /// A label for this device (e.g. laptop, phone).
        #[arg(long, default_value = "device")]
        label: String,
    },
    /// Host a username registry (a directory mapping username → account key).
    /// Clients `/register` and `/resolve` against the printed registry URI.
    Registry {
        /// Bind address for inbound connections (host:port).
        #[arg(long, default_value = "127.0.0.1:9100")]
        listen: String,
        /// Registry channel label (part of its shared descriptor/handshake root).
        #[arg(long, default_value = "#registry")]
        channel: String,
        /// Host the registry as a Tor onion service (Arti). `--features tor`.
        #[arg(long)]
        tor: bool,
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

/// Build the channel marking from CLI flags. Gated by the `markings` feature:
/// builds without it refuse marking flags (consumer build), builds with it
/// (the intended audience) honor them.
#[cfg(feature = "markings")]
fn resolve_channel_marking(
    classification: Option<String>,
    caveats: Vec<String>,
    compartments: Vec<String>,
) -> Result<Option<Marking>, Box<dyn std::error::Error>> {
    match classification {
        Some(c) => {
            let level = classification_from(&c).ok_or_else(|| {
                format!("unknown classification {c:?} (unclassified|cui|confidential|secret|top-secret)")
            })?;
            Ok(Some(Marking {
                level,
                compartments,
                caveats,
            }))
        }
        None if !caveats.is_empty() || !compartments.is_empty() => {
            Err("--caveat/--compartment require --classification".into())
        }
        None => Ok(None),
    }
}

#[cfg(not(feature = "markings"))]
fn resolve_channel_marking(
    classification: Option<String>,
    caveats: Vec<String>,
    compartments: Vec<String>,
) -> Result<Option<Marking>, Box<dyn std::error::Error>> {
    if classification.is_some() || !caveats.is_empty() || !compartments.is_empty() {
        return Err("this build has classification markings disabled; \
             rebuild with `--features markings` to originate them"
            .into());
    }
    Ok(None)
}

#[cfg(feature = "markings")]
fn classification_from(s: &str) -> Option<Classification> {
    match s.to_ascii_lowercase().as_str() {
        "unclassified" | "u" => Some(Classification::Unclassified),
        "cui" => Some(Classification::Cui),
        "confidential" | "c" => Some(Classification::Confidential),
        "secret" | "s" => Some(Classification::Secret),
        "top-secret" | "topsecret" | "ts" => Some(Classification::TopSecret),
        _ => None,
    }
}

#[tokio::main]
async fn main() {
    // RAM-capture hardening (SECURITY-AUDIT R-8): disable core dumps and mark
    // the process non-dumpable before any secret exists, so a crash or a
    // same-uid attacker can't spill/scrape our memory.
    talkrypt_crypto::ensure_hardened();
    // Power-on self-test (FIPS POST / SECURITY-AUDIT R-5): verify every crypto
    // primitive at start-up and abort if any is broken, before doing anything.
    talkrypt_crypto::ensure_self_tested();
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
            classification,
            caveats,
            compartments,
            account,
            username,
            device,
            chain,
            password,
            require_registry,
            tor,
            endpoint,
            name,
            name_policy,
            mesh,
        } => {
            run_host(HostArgs {
                listen,
                topology,
                channel,
                group,
                posture,
                require_posture,
                advertise,
                classification,
                caveats,
                compartments,
                account,
                username,
                device,
                chain,
                password,
                require_registry,
                tor,
                endpoint,
                name,
                name_policy,
                mesh,
            })
            .await
        }
        Cmd::Join {
            uri,
            group,
            account,
            username,
            device,
            chain,
            password,
            tor,
            name,
            mesh,
        } => run_join(&uri, group, account, username, device, chain, password, tor, name, mesh).await,
        Cmd::Registry { listen, channel, tor } => run_registry(listen, channel, tor).await,
        Cmd::LinkOffer {
            listen,
            account,
            username,
            endpoint,
        } => run_link_offer(listen, account, username, endpoint).await,
        Cmd::LinkAccept {
            uri,
            device,
            chain_out,
            label,
        } => run_link_accept(&uri, device, chain_out, label).await,
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

/// Arguments for `host`, bundled to avoid a long positional signature.
struct HostArgs {
    listen: String,
    topology: String,
    channel: String,
    group: bool,
    posture: Option<String>,
    require_posture: bool,
    advertise: String,
    classification: Option<String>,
    caveats: Vec<String>,
    compartments: Vec<String>,
    account: Option<String>,
    username: Option<String>,
    device: Option<String>,
    chain: Option<String>,
    password: Option<String>,
    require_registry: Option<String>,
    tor: bool,
    endpoint: Option<String>,
    name: Option<String>,
    name_policy: Option<String>,
    mesh: MeshArgs,
}

/// Shared `--mesh-*` flags for `host` / `join`: optionally carry messages over a
/// LoRa mesh via a USB-serial Meshtastic / Meshcore node (feature `mesh-radio`).
#[derive(clap::Args, Clone)]
struct MeshArgs {
    /// Also carry this chat's messages over a LoRa mesh via a USB-serial node at
    /// this port (e.g. /dev/tty.usbserial-0001). Off unless set. Requires a build
    /// with `--features mesh-radio`.
    #[arg(long)]
    mesh_serial: Option<String>,
    /// Mesh firmware on the node: meshtastic (default) | meshcore.
    #[arg(long, default_value = "meshtastic")]
    mesh_kind: String,
    /// Serial baud for the mesh node (Meshtastic uses 115200).
    #[arg(long, default_value_t = 115200)]
    mesh_baud: u32,
    /// Mesh channel index to transmit talkrypt fragments on.
    #[arg(long, default_value_t = 0)]
    mesh_channel: u8,
    /// LoRa modem preset for airtime estimation (duty-cycle pacing): shortturbo |
    /// shortfast | shortslow | mediumfast | mediumslow | longfast (default) |
    /// longmoderate | longslow.
    #[arg(long, default_value = "longfast")]
    mesh_preset: String,
    /// Duty-cycle limit as a fraction of airtime (e.g. 0.01 for the EU868 1% cap).
    /// When set, transmissions are paced to respect it (plus `--mesh-min-gap`);
    /// omit for no duty-cycle pacing.
    #[arg(long)]
    mesh_duty_cycle: Option<f64>,
    /// Minimum gap between mesh transmissions, ms (protects the node's TX queue).
    #[arg(long, default_value_t = 250)]
    mesh_min_gap_ms: u64,
}

/// Parse a `--mesh-preset` name to a Meshtastic modem preset (default LongFast).
#[cfg(feature = "mesh-radio")]
fn parse_mesh_preset(s: &str) -> talkrypt_transport::mesh::MeshtasticPreset {
    use talkrypt_transport::mesh::MeshtasticPreset::*;
    match s.to_ascii_lowercase().as_str() {
        "shortturbo" => ShortTurbo,
        "shortfast" => ShortFast,
        "shortslow" => ShortSlow,
        "mediumfast" => MediumFast,
        "mediumslow" => MediumSlow,
        "longmoderate" => LongModerate,
        "longslow" => LongSlow,
        _ => LongFast,
    }
}

/// If `--mesh-serial` was given, open the serial mesh node and start carrying this
/// chat's messages over it (in addition to the primary transport). A no-op when
/// unset; errors clearly when set in a build without the `mesh-radio` feature.
async fn maybe_start_mesh(core: &Core, mesh: &MeshArgs) -> Result<(), Box<dyn std::error::Error>> {
    let Some(port) = mesh.mesh_serial.clone() else {
        return Ok(());
    };
    #[cfg(feature = "mesh-radio")]
    {
        use talkrypt_transport::mesh::{
            AirtimeBudget, MeshNode, MeshPolicy, MeshcoreSerial, MeshtasticSerial, PacedMeshNode,
        };
        let mut node: std::sync::Arc<dyn MeshNode> = match mesh.mesh_kind.as_str() {
            "meshcore" => MeshcoreSerial::open(&port, mesh.mesh_baud).await?,
            "meshtastic" => MeshtasticSerial::open(&port, mesh.mesh_baud).await?,
            other => {
                return Err(format!("unknown --mesh-kind '{other}' (meshtastic|meshcore)").into())
            }
        };
        // Optional duty-cycle pacing: wrap the node so transmissions respect the
        // configured airtime budget + min-gap for the chosen modem preset.
        let paced = if let Some(duty) = mesh.mesh_duty_cycle {
            let preset = parse_mesh_preset(&mesh.mesh_preset);
            let budget = AirtimeBudget::new(3_600_000, duty, mesh.mesh_min_gap_ms);
            node = std::sync::Arc::new(PacedMeshNode::new(node, preset, budget));
            format!(", paced {}% duty / {} ms gap", duty * 100.0, mesh.mesh_min_gap_ms)
        } else {
            String::new()
        };
        core.start_mesh_messaging(
            node,
            MeshPolicy {
                channel: mesh.mesh_channel,
                ..Default::default()
            },
        )
        .await;
        println!(
            "mesh: {} on {port} @ {} baud (channel {}{}) — messages also ride the LoRa mesh",
            mesh.mesh_kind, mesh.mesh_baud, mesh.mesh_channel, paced
        );
        Ok(())
    }
    #[cfg(not(feature = "mesh-radio"))]
    {
        let _ = core;
        Err(format!(
            "--mesh-serial {port} requires a build with `--features mesh-radio`"
        )
        .into())
    }
}

// ----- account identity helpers (username accounts over device keys) -----

/// Expand a leading `~/` to the user's home directory.
fn expand_tilde(path: &str) -> String {
    if let Some(rest) = path.strip_prefix("~/") {
        let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
        format!("{home}/{rest}")
    } else {
        path.to_string()
    }
}

/// Render a short string (an invite or linking URI) as a scannable QR in the
/// terminal so a phone can scan it in person. Long inputs that don't fit a QR
/// are silently skipped (the URI text is always printed alongside).
fn print_qr(data: &str) {
    if let Ok(code) = qrcode::QrCode::new(data.as_bytes()) {
        let rendered = code
            .render::<qrcode::render::unicode::Dense1x2>()
            .quiet_zone(true)
            .build();
        println!("{rendered}");
    }
}

/// Resolve the Core's device identity: load/create a persistent device seed at
/// `path`, or generate an ephemeral one when no path is given.
fn device_identity(path: &Option<String>) -> Result<IdentityKeyPair, Box<dyn std::error::Error>> {
    match path {
        Some(p) => {
            let p = expand_tilde(p);
            let (kp, fresh) = open_or_create_account(&p)?; // same 32-byte seed-file format
            println!(
                "device key: {} ({p})",
                if fresh { "new, saved" } else { "loaded" }
            );
            Ok(kp)
        }
        None => Ok(IdentityKeyPair::generate()),
    }
}

// ----- transport selection: plain TCP or real Tor (Arti) -----

/// The chosen network transport. Tor is feature-gated so a non-Tor build is
/// small; `--tor` on a non-Tor build is a clear error.
enum Net {
    Tcp(Arc<dyn talkrypt_transport::Transport>),
    #[cfg(feature = "tor")]
    Tor(Arc<talkrypt_transport::ArtiTransport>),
}

impl Net {
    fn transport(&self) -> Arc<dyn talkrypt_transport::Transport> {
        match self {
            Net::Tcp(t) => t.clone(),
            #[cfg(feature = "tor")]
            Net::Tor(t) => t.clone(),
        }
    }
    /// The dialable onion address (Tor only), available after `host()`.
    fn onion(&self) -> Option<String> {
        match self {
            Net::Tcp(_) => None,
            #[cfg(feature = "tor")]
            Net::Tor(t) => t.onion_address(),
        }
    }
}

/// Find a bindable TCP address starting at `listen` (`host:port`), trying the
/// next ports if the default is taken — so two hosts on one machine don't
/// collide. Returns the chosen address (the descriptor advertises this port).
/// Falls back to the original if nothing is free in the scanned range.
fn pick_listen(listen: &str) -> String {
    let Some((host, port_str)) = listen.rsplit_once(':') else {
        return listen.to_string();
    };
    let Ok(base) = port_str.parse::<u16>() else {
        return listen.to_string();
    };
    for offset in 0..100u16 {
        let port = base.saturating_add(offset);
        let addr = format!("{host}:{port}");
        // Bind then drop to release the port; TcpTransport rebinds it next.
        if std::net::TcpListener::bind(&addr).is_ok() {
            if offset > 0 {
                println!("port {base} busy; using {port}");
            }
            return addr;
        }
    }
    listen.to_string()
}

/// Build the transport: a bootstrapped Arti client for `--tor`, else TCP bound
/// to `tcp_listen`.
async fn make_net(tor: bool, tcp_listen: &str) -> Result<Net, Box<dyn std::error::Error>> {
    if tor {
        #[cfg(feature = "tor")]
        {
            use talkrypt_transport::{ArtiTransport, OnionPersistence};
            println!("bootstrapping Tor (Arti) — this can take a minute…");
            let t = ArtiTransport::bootstrap(OnionPersistence::Ephemeral, "talkrypt").await?;
            return Ok(Net::Tor(Arc::new(t)));
        }
        #[cfg(not(feature = "tor"))]
        {
            return Err("this build has Tor disabled; rebuild with `--features tor`".into());
        }
    }
    Ok(Net::Tcp(Arc::new(TcpTransport::new(tcp_listen))))
}

/// Save an encoded identity chain to a file.
fn save_chain(path: &str, chain: &IdentityChain) -> Result<(), Box<dyn std::error::Error>> {
    if let Some(parent) = std::path::Path::new(path).parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }
    std::fs::write(path, chain.encode())?;
    Ok(())
}

/// Load an encoded identity chain from a file.
fn load_chain(path: &str) -> Result<IdentityChain, Box<dyn std::error::Error>> {
    Ok(IdentityChain::decode(&std::fs::read(path)?)?)
}

// ----- contact persistence (so recognized accounts survive restarts) -----

/// Where the contact list is stored (TSV: `pubkey_hex \t 0|1 \t name`).
fn contacts_path() -> String {
    expand_tilde("~/.talkrypt/contacts.tsv")
}

/// Parse an even-length hex string into bytes.
fn parse_hex_bytes(s: &str) -> Option<Vec<u8>> {
    let s = s.trim();
    if s.is_empty() || s.len() % 2 != 0 || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).ok())
        .collect()
}

/// Re-add persisted contacts into a fresh `Core` (called on host/join startup).
fn load_contacts(core: &Core) {
    let Ok(text) = std::fs::read_to_string(contacts_path()) else {
        return;
    };
    for line in text.lines() {
        let parts: Vec<&str> = line.splitn(3, '\t').collect();
        if parts.len() < 2 {
            continue;
        }
        if let Some(pk) = parse_hex_bytes(parts[0]) {
            let friend = parts[1] == "1";
            let name = parts.get(2).filter(|s| !s.is_empty()).map(|s| s.to_string());
            core.add_contact_bytes(pk, name, friend);
        }
    }
}

/// Current Unix time in seconds (certificate validity stamps).
fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Full lowercase hex of a 48-byte fingerprint.
fn hex48(fp: &[u8; 48]) -> String {
    fp.iter().map(|b| format!("{b:02x}")).collect()
}

/// Parse 64 hex chars into a 32-byte account seed.
fn parse_seed_hex(s: &str) -> Result<[u8; 32], String> {
    let s = s.trim();
    if s.len() != 64 || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("account key must be 64 hex characters (32-byte seed)".into());
    }
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).map_err(|e| e.to_string())?;
    }
    Ok(out)
}

/// Load an account keypair from a seed file.
fn load_account(path: &str) -> Result<IdentityKeyPair, Box<dyn std::error::Error>> {
    let contents = std::fs::read_to_string(path)?;
    let seed = parse_seed_hex(&contents)?;
    Ok(IdentityKeyPair::from_secret_bytes(seed))
}

/// Save an account seed to a file with owner-only permissions (0600 on unix).
fn save_account(path: &str, kp: &IdentityKeyPair) -> Result<(), Box<dyn std::error::Error>> {
    if let Some(parent) = std::path::Path::new(path).parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }
    let seed = kp.export_secret();
    let hexs: String = seed.iter().map(|b| format!("{b:02x}")).collect();
    std::fs::write(path, hexs)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

/// Load the account at `path`, or generate + save a new one if it's absent.
/// Returns the keypair and whether it was freshly created.
fn open_or_create_account(
    path: &str,
) -> Result<(IdentityKeyPair, bool), Box<dyn std::error::Error>> {
    if std::path::Path::new(path).exists() {
        Ok((load_account(path)?, false))
    } else {
        let kp = IdentityKeyPair::generate();
        save_account(path, &kp)?;
        Ok((kp, true))
    }
}

/// At startup, if an account path was given, open/create it, present the
/// identity, and print the account's safety number. Returns the keypair (None =
/// pseudonym).
async fn setup_account(
    core: &Core,
    account_path: &Option<String>,
    username: &Option<String>,
) -> Result<Option<IdentityKeyPair>, Box<dyn std::error::Error>> {
    let Some(path) = account_path else {
        if username.is_some() {
            return Err("--username requires --account".into());
        }
        println!("identity: pseudonym (unlinkable — no account presented)");
        return Ok(None);
    };
    let expanded = expand_tilde(path);
    let (kp, fresh) = open_or_create_account(&expanded)?;
    present(core, &kp, username.clone()).await;
    println!(
        "identity: account {}{}",
        kp.public().safety_number(),
        if fresh {
            format!("  (new account saved to {expanded})")
        } else {
            format!("  (loaded from {expanded})")
        }
    );
    if let Some(u) = username {
        println!("username: {u}  (self-asserted; advertise via a registry to make it discoverable)");
    }
    Ok(Some(kp))
}

/// Resolve how this session presents itself. A linked `--chain` (a secondary
/// device certified by an account) takes precedence; otherwise fall back to
/// `--account` / pseudonym. Returns the account keypair if this device *holds*
/// one (so it can `/register`); a linked secondary device returns `None`.
async fn setup_identity(
    core: &Core,
    account: &Option<String>,
    chain: &Option<String>,
    username: &Option<String>,
) -> Result<Option<IdentityKeyPair>, Box<dyn std::error::Error>> {
    if let Some(chain_path) = chain {
        if account.is_some() {
            return Err("--chain and --account are mutually exclusive".into());
        }
        let ic = load_chain(&expand_tilde(chain_path))?;
        // The chain must certify THIS device's key (its leaf == our device key),
        // or peers will reject the binding.
        let binds = ic.leaf().map(|l| l.fingerprint()) == Some(core.identity_public().fingerprint());
        if !binds {
            return Err(
                "the --chain does not certify this --device key (leaf mismatch); \
                 use the same --device you linked with"
                    .into(),
            );
        }
        let account_sn = ic
            .links
            .first()
            .map(|l| l.issuer.safety_number())
            .unwrap_or_default();
        core.present_identity(ic, username.clone());
        core.announce_identity().await;
        println!("identity: linked device — presenting account chain");
        println!("account: {account_sn}");
        if let Some(u) = username {
            println!("username: {u}");
        }
        return Ok(None);
    }
    setup_account(core, account, username).await
}

/// Connect to a registry from its URI and return a client + the parsed
/// descriptor (so callers can label output).
async fn registry_connect(
    uri: &str,
) -> Result<(RegistryClient, ChatDescriptor), Box<dyn std::error::Error>> {
    let desc = ChatDescriptor::from_uri(uri)?;
    let reg = SuiteRegistry::with_defaults();
    let suite = reg
        .get_by_scheme_hash(&desc.scheme_hash())
        .map_err(|_| format!("registry scheme '{}' not in this build", desc.resolved_suite_id()))?;
    let endpoint = desc
        .endpoints
        .first()
        .ok_or("registry URI carries no endpoint address")?
        .clone();
    let transport = Arc::new(TcpTransport::new("127.0.0.1:0"));
    let id = IdentityKeyPair::generate(); // ephemeral; the registry auths the session, not us
    let client = RegistryClient::connect(&id, suite, transport, &desc, &endpoint).await?;
    Ok((client, desc))
}

async fn run_host(args: HostArgs) -> Result<(), Box<dyn std::error::Error>> {
    let HostArgs {
        listen,
        topology,
        channel,
        group,
        posture,
        require_posture,
        advertise,
        classification,
        caveats,
        compartments,
        account,
        username,
        device,
        chain,
        password,
        require_registry,
        tor,
        endpoint,
        name,
        name_policy,
        mesh,
    } = args;
    println!("{BANNER}\n");
    let kind = topology_from(&topology);
    // Mandatory-posture setting: refuse a silent default when required.
    let profile = match posture.as_deref() {
        Some(p) => posture_from(p)
            .ok_or_else(|| format!("unknown posture {p:?} (use pq-pure | hybrid | pq-pure-compact)"))?,
        None if require_posture => {
            return Err("this chat requires an explicit --posture \
                 (pq-pure | hybrid | pq-pure-compact); none given"
                .into());
        }
        None => KemProfile::pq_pure(),
    };
    let advertise_policy = advertise_from(&advertise)
        .ok_or_else(|| format!("unknown --advertise {advertise:?} (use off | fingerprint | full)"))?;
    let channel_marking = resolve_channel_marking(classification, caveats, compartments)?;
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
    if let Some(m) = &channel_marking {
        println!("classification: {}  (advisory; carried authenticated in every message)", m.banner());
    }
    // Auto-pick a free port if the default is busy (TCP only; Tor uses an onion).
    let listen = if tor { listen } else { pick_listen(&listen) };
    let net = make_net(tor, &listen).await?;

    // Advertise the configured bind address in the descriptor, including
    // whether this is a group chat (so joiners auto-detect from the invite).
    // For Tor the real endpoint is the .onion, known only after host(); patched
    // into the printed invite below.
    let mut desc = ChatDescriptor::new(
        kind,
        Persistence::Ephemeral,
        &suite_id,
        vec![listen.to_string()],
        &channel,
    );
    desc.group = group;
    desc.channel_marking = channel_marking;
    // F-25: a Tor-hosted chat requires an anonymizing transport — bind it into the
    // invite root so a joiner can't be downgraded to clearnet.
    desc.require_anon = tor;
    if let Some(p) = &name_policy {
        desc.name_trust_policy = parse_name_policy(p)?;
        println!("name-collision policy: {p}");
    }
    if let Some(pw) = &password {
        desc.password = Some(ChannelPassword::new(pw.clone()));
        println!("channel password: set (Argon2id-gated; not carried in the invite)");
    }
    let device_kp = device_identity(&device)?;
    let (core, rx) = if group {
        Core::new_group(device_kp, suite, net.transport(), desc.clone(), true)
    } else {
        Core::new(device_kp, suite, net.transport(), desc.clone())
    };
    core.host().await?;
    // For Tor, replace the invite's endpoint with the published .onion so peers
    // can dial it (the session root is unaffected — it derives from the token).
    if let Some(onion) = net.onion() {
        desc.endpoints = vec![onion.clone()];
        println!("onion: {onion}");
    } else if let Some(ep) = &endpoint {
        // Advertise a reachable address that differs from the bound one (we
        // still bind `listen`; only the invite's dial address changes). This
        // is what lets a host bind 0.0.0.0 but hand out its LAN/public IP, or
        // hand an Android emulator the host alias 10.0.2.2.
        desc.endpoints = vec![ep.clone()];
        println!("advertising endpoint: {ep} (bound on {listen})");
    }

    // Registry-restricted channel: pull the allowlist of account fingerprints
    // from a registry only the host knows; only those accounts will be heard.
    if let Some(reg_uri) = &require_registry {
        match registry_connect(reg_uri).await {
            Ok((mut client, _)) => match client.list().await {
                Ok(claims) => {
                    let allowed: std::collections::HashSet<[u8; 48]> = claims
                        .iter()
                        .map(|c| c.claim.account.fingerprint())
                        .collect();
                    let n = allowed.len();
                    core.restrict_to_accounts(allowed);
                    println!(
                        "access: registry-restricted to {n} account(s) from the configured registry"
                    );
                }
                Err(e) => return Err(format!("could not list the required registry: {e}").into()),
            },
            Err(e) => return Err(format!("could not reach the required registry: {e}").into()),
        }
    }

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

    // Optional: also carry messages over a LoRa mesh node (--mesh-serial).
    maybe_start_mesh(&core, &mesh).await?;
    // Show the invite as a scannable QR for in-person joining.
    println!("scan to join (or copy the URI above):\n");
    print_qr(&desc.to_uri());

    // Identity: linked chain (secondary device) / account / pseudonym.
    let account_kp = setup_identity(&core, &account, &chain, &username).await?;
    load_contacts(&core); // restore recognized accounts from previous sessions
    // SUB-SPEC A: arm the leading name before any peer connects, so the host's
    // on-join CQ auto-announce (fired in reader_loop when a joiner registers)
    // carries it hands-free.
    set_bare_leading_name(&core, &name);
    println!("\nwaiting for peers — type a message + enter to send. /help for commands.\n");

    repl(core, rx, ReplState::new(account_kp, username)).await
}

async fn run_join(
    uri: &str,
    group: bool,
    account: Option<String>,
    username: Option<String>,
    device: Option<String>,
    chain: Option<String>,
    password: Option<String>,
    tor: bool,
    name: Option<String>,
    mesh: MeshArgs,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("{BANNER}\n");
    let mut desc = ChatDescriptor::from_uri(uri)?;
    if let Some(pw) = &password {
        desc.password = Some(ChannelPassword::new(pw.clone()));
    }
    // SECURITY-AUDIT F-25: an invite marked anonymity-required must not be joined
    // over clearnet TCP. The flag is bound into the invite's root (tamper-evident),
    // so refuse unless the user is routing over Tor.
    if desc.require_anon && !tor {
        return Err("this invite requires an anonymizing transport; re-run with --tor".into());
    }
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
    let net = make_net(tor, "127.0.0.1:0").await?;
    let transport = net.transport();
    // The invite descriptor declares group mode; --group can also force it.
    let want_group = group || desc.group;
    let device_kp = device_identity(&device)?;
    let (core, rx) = if want_group {
        Core::new_group(device_kp, suite, transport, desc.clone(), false)
    } else {
        Core::new(device_kp, suite, transport, desc.clone())
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

    // SUB-SPEC A: arm the leading name BEFORE dialing, so the joiner's on-join
    // CQ auto-announce (fired inside establish/register) carries it hands-free.
    set_bare_leading_name(&core, &name);
    let strategy = for_kind(desc.topology);
    strategy.establish(&core, &desc.endpoints).await?;
    println!(
        "connected to {} peer(s). /help for commands.\n",
        core.peer_count()
    );

    // Optional: also carry messages over a LoRa mesh node (--mesh-serial).
    maybe_start_mesh(&core, &mesh).await?;

    // Identity: linked chain (secondary device) / account / pseudonym.
    let account_kp = setup_identity(&core, &account, &chain, &username).await?;
    load_contacts(&core); // restore recognized accounts from previous sessions
    repl(core, rx, ReplState::new(account_kp, username)).await
}

/// Host a username registry node (the `registry` subcommand).
async fn run_registry(
    listen: String,
    channel: String,
    tor: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("{BANNER}\n");
    // The registry uses the default PQ-pure suite; its descriptor (channel +
    // invite token) is the shared handshake root clients dial with.
    let suite = SuiteRegistry::with_defaults().get(DEFAULT_SUITE_ID)?;
    // Auto-pick a free port if the default is busy (TCP only).
    let listen = if tor { listen } else { pick_listen(&listen) };
    let mut desc = ChatDescriptor::new(
        TopologyKind::Hub,
        Persistence::Persistent,
        DEFAULT_SUITE_ID,
        vec![listen.clone()],
        &channel,
    );
    let net = make_net(tor, &listen).await?;
    let server = RegistryServer::new(IdentityKeyPair::generate(), suite, net.transport(), &desc);
    server.run().await?;
    // For Tor, advertise the published .onion in the registry URI.
    if let Some(onion) = net.onion() {
        desc.endpoints = vec![onion.clone()];
        println!("onion: {onion}");
    }

    println!("username registry hosting on {listen} (channel {channel})");
    println!("\nPublish this registry URI; scan the QR with the app or copy the URI:\n");
    println!("  {}\n", desc.to_uri());
    print_qr(&desc.to_uri());
    println!(
        "A registry only stores self-signed username→account claims (public by\n\
         nature). Register on several and clients cross-compare for unforgeability.\n\
         Ctrl-C to stop."
    );
    // Park forever; the accept loop runs in the background.
    loop {
        tokio::time::sleep(std::time::Duration::from_secs(3600)).await;
    }
}

/// `link-offer`: the account holder offers to certify a new device. Prints a
/// one-time linking URI + QR; the new device runs `link-accept`.
async fn run_link_offer(
    listen: String,
    account: String,
    username: Option<String>,
    endpoint: Option<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("{BANNER}\n");
    let suite = SuiteRegistry::with_defaults().get(DEFAULT_SUITE_ID)?;
    let account_path = expand_tilde(&account);
    let account_kp = load_account(&account_path)
        .map_err(|e| format!("could not load account {account_path}: {e}"))?;
    let account_sn = account_kp.public().safety_number();
    // The address advertised in the linking URI: the bound listen, unless the
    // caller advertises a different reachable one (bind 0.0.0.0, advertise LAN).
    let advertised = endpoint.clone().unwrap_or_else(|| listen.clone());
    // A one-time linking descriptor: its random invite token is the in-person
    // secret carried by the QR. The account key never crosses the wire.
    let desc = ChatDescriptor::new(
        TopologyKind::P2P,
        Persistence::Ephemeral,
        DEFAULT_SUITE_ID,
        vec![advertised.clone()],
        "#link",
    );
    if let Some(ep) = &endpoint {
        println!("advertising endpoint: {ep} (bound on {listen})");
    }
    let transport = Arc::new(TcpTransport::new(&listen));
    // The operator explicitly initiated this one-time, time-bounded offer by
    // running `link-offer` with their account, so the next device to present the
    // token inside the window is authorized (SECURITY-AUDIT L1: the human decision
    // is running this command; the cert is short-lived — 24h — and single-use).
    let host = LinkHost::new(
        account_kp,
        IdentityKeyPair::generate(),
        suite,
        transport,
        &desc,
        username.clone(),
        now_secs(),
    )
    .auto_approve();
    host.run().await?;

    println!("linking offer for account {account_sn}");
    println!("hosting on {listen}\n");
    println!("On the NEW device, run:\n  talkrypt link-accept '{}'\n", desc.to_uri());
    print_qr(&desc.to_uri());
    println!(
        "\nThe account key never leaves this device — only a signed device cert is\n\
         sent. After linking, compare the account safety number out of band.\n\
         Ctrl-C to stop."
    );
    loop {
        tokio::time::sleep(std::time::Duration::from_secs(3600)).await;
    }
}

/// `link-accept`: on a new device, connect to a link offer, get a certificate
/// for this device's key, and save the chain for `host --chain`.
async fn run_link_accept(
    uri: &str,
    device: String,
    chain_out: String,
    label: String,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("{BANNER}\n");
    let desc = ChatDescriptor::from_uri(uri)?;
    let suite = SuiteRegistry::with_defaults()
        .get_by_scheme_hash(&desc.scheme_hash())
        .map_err(|_| "this link offer's scheme is not registered in this build")?;
    let endpoint = desc
        .endpoints
        .first()
        .ok_or("link URI carries no endpoint address")?
        .clone();
    let device_path = expand_tilde(&device);
    let (device_kp, fresh) = open_or_create_account(&device_path)?;
    println!(
        "device key: {} ({device_path})",
        if fresh { "new, saved" } else { "loaded" }
    );
    let transport = Arc::new(TcpTransport::new("127.0.0.1:0"));
    let linked = LinkClient::request(
        &device_kp,
        suite,
        transport,
        &desc,
        &endpoint,
        label,
        now_secs(),
    )
    .await?;

    let chain_path = expand_tilde(&chain_out);
    save_chain(&chain_path, &linked.chain)?;
    println!("\nlinked to account: {}", linked.account.safety_number());
    if let Some(u) = &linked.username {
        println!("account username: {u}");
    }
    println!("saved account→device chain to {chain_path}");
    println!(
        "this device fingerprint (give to the account holder to revoke later if lost):\n  {}",
        hex48(&device_kp.public().fingerprint())
    );
    let uname_flag = linked
        .username
        .as_deref()
        .map(|u| format!(" --username {u}"))
        .unwrap_or_default();
    println!(
        "\nNow chat AS this account on this device:\n  \
         talkrypt host --device {device_path} --chain {chain_path}{uname_flag}\n"
    );
    println!("Verify the account safety number above matches the offering device out of band.");
    Ok(())
}

/// The interactive read-eval-print loop shared by host and join.
async fn repl(
    core: Core,
    mut rx: tokio::sync::mpsc::UnboundedReceiver<Event>,
    mut state: ReplState,
) -> Result<(), Box<dyn std::error::Error>> {
    // Event printer task. It holds a clone of the core so it can look up the
    // safety number of a just-presented account (for the trust prompt).
    let printer_core = core.clone();
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
                    marking,
                } => {
                    let tag = marking
                        .map(|m| format!("[{}] ", m.banner()))
                        .unwrap_or_default();
                    println!("\r{tag}{} {}> {}", channel, short_fp(&from), text);
                }
                Event::Identity {
                    from,
                    account_fingerprint,
                    username,
                    contact,
                    friend,
                } => {
                    let name = username.unwrap_or_else(|| "<no username>".into());
                    if contact {
                        let label = if friend { "friend" } else { "contact" };
                        println!(
                            "\r* {label} {name} (account {}) on device {}",
                            short_fp(&account_fingerprint),
                            short_fp(&from)
                        );
                    } else {
                        // Unknown account: show the safety number and how to add
                        // it as a contact after an out-of-band comparison.
                        let sn = printer_core
                            .seen_account(account_fingerprint)
                            .map(|a| a.safety_number())
                            .unwrap_or_default();
                        println!(
                            "\r* account {name} (fp {}) on device {} — not a contact",
                            short_fp(&account_fingerprint),
                            short_fp(&from)
                        );
                        println!("    account safety number: {sn}");
                        println!(
                            "    verify out of band, then: /contact add {} [name]   (or /friend {} to label a friend)",
                            short_fp(&account_fingerprint),
                            short_fp(&account_fingerprint)
                        );
                    }
                }
                Event::Disconnected { fingerprint } => {
                    println!("\r* peer disconnected: {}", short_fp(&fingerprint));
                }
                Event::Delivered { gossip_id } => {
                    let id: String = gossip_id.iter().take(4).map(|b| format!("{b:02x}")).collect();
                    println!("\r* delivered {id}");
                }
                Event::OutboxDropped { count } => {
                    eprintln!("\r! outbox: {count} un-acked message(s) dropped (cap/TTL)");
                }
                Event::PromoteProposed { by, promote_id, target_tier, retention_mode, picked } => {
                    let id: String = promote_id.iter().take(4).map(|b| format!("{b:02x}")).collect();
                    println!(
                        "\r* promotion proposed by {} (tier {target_tier}, retention {retention_mode}, {} members) — /consent {id} yes|no",
                        short_fp(&by),
                        picked.len()
                    );
                }
                Event::Promoted { promote_id } => {
                    let id: String = promote_id.iter().take(4).map(|b| format!("{b:02x}")).collect();
                    println!("\r* promoted {id} — chat is now persistent");
                }
                Event::PromoteAborted { promote_id } => {
                    let id: String = promote_id.iter().take(4).map(|b| format!("{b:02x}")).collect();
                    println!("\r* promotion {id} aborted — chat stays ephemeral");
                }
                Event::BeaconSeen { channel, source } => {
                    let via = source.map(|s| format!(" ({s})")).unwrap_or_default();
                    println!("\r* nearby: a device on {channel} is beaconing{via}");
                }
                Event::Name { from, label, tier, caveat, .. } => {
                    if let Some(label) = label {
                        // Badge the trust tier so a verified (account-linked /
                        // registry-confirmed) name is visually distinct from a bare
                        // one; the caveat carries any collision warning (SUB-SPEC A).
                        let badge = match tier {
                            talkrypt_core::nametrust::NameTier::Linked => "🔗 ",
                            talkrypt_core::nametrust::NameTier::RegistryConfirmed => "✓ ",
                            talkrypt_core::nametrust::NameTier::Bare => "",
                        };
                        let cav = caveat.map(|c| format!(" ({c})")).unwrap_or_default();
                        println!("\r* {} is calling as {badge}\"{label}\"{cav}", short_fp(&from));
                    }
                }
                Event::Linkage { subject, verdict, .. } => {
                    // SUB-SPEC B: a peer disclosed grouping linkage (account-hidden).
                    if verdict {
                        println!("\r* {} disclosed grouping linkage", short_fp(&subject));
                    }
                }
                Event::Vouch { subject, weighted_score, vouched, inflation_rejected } => {
                    // SUB-SPEC C: a subject's vouch standing changed (display-only).
                    if inflation_rejected {
                        println!("\r* {} vouch inflation rejected (sybil) — neutral", short_fp(&subject));
                    } else if vouched {
                        println!("\r\u{2733} {} vouched (score {weighted_score})", short_fp(&subject));
                    }
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
            let arg = parts.next().unwrap_or("").trim();
            if matches!(cmd, "quit" | "q") {
                break;
            }
            for line in run_command(&core, &mut state, cmd, arg).await {
                println!("{line}");
            }
            continue;
        }
        if let Err(e) = core.send(line).await {
            eprintln!("! send failed: {e}");
        }
    }
    Ok(())
}

/// Set a bare (non-account-linked) leading name from a `--name` flag, BEFORE the
/// session connects, so the on-join CQ auto-announce (SUB-SPEC A) carries it. No
/// explicit announce here — `register()`/`establish` emit the presence frame as
/// part of the join handshake.
fn set_bare_leading_name(core: &Core, name: &Option<String>) {
    use talkrypt_core::presence::{NameBacking, NameEntry};
    if let Some(label) = name {
        let label = label.trim();
        if label.is_empty() {
            return;
        }
        core.set_leading_name(Some(NameEntry {
            id: label.to_string(),
            label: label.to_string(),
            backing: NameBacking::Bare,
        }));
        println!("leading name \"{label}\" (bare) — will auto-announce on join");
    }
}

/// Map a `--name-policy` string to a [`NameTrustPolicy`] (SUB-SPEC A). The policy
/// is baked into the invite descriptor so every joiner resolves name collisions
/// the same way the host chose.
fn parse_name_policy(s: &str) -> Result<talkrypt_core::nametrust::NameTrustPolicy, String> {
    use talkrypt_core::nametrust::NameTrustPolicy;
    match s.trim().to_ascii_lowercase().as_str() {
        "signal" | "signal-style" | "signalstyle" => Ok(NameTrustPolicy::SignalStyle),
        "warn" | "warn-on-collision" => Ok(NameTrustPolicy::WarnOnCollision),
        "suppress" | "suppress-colliding" => Ok(NameTrustPolicy::SuppressColliding),
        other => Err(format!(
            "unknown --name-policy {other:?} (use signal | warn | suppress)"
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use talkrypt_core::nametrust::NameTrustPolicy;

    #[test]
    fn name_policy_parses_all_forms() {
        assert_eq!(parse_name_policy("signal").unwrap(), NameTrustPolicy::SignalStyle);
        assert_eq!(parse_name_policy("SignalStyle").unwrap(), NameTrustPolicy::SignalStyle);
        assert_eq!(parse_name_policy(" WARN ").unwrap(), NameTrustPolicy::WarnOnCollision);
        assert_eq!(parse_name_policy("warn-on-collision").unwrap(), NameTrustPolicy::WarnOnCollision);
        assert_eq!(parse_name_policy("suppress").unwrap(), NameTrustPolicy::SuppressColliding);
        assert_eq!(parse_name_policy("suppress-colliding").unwrap(), NameTrustPolicy::SuppressColliding);
    }

    #[test]
    fn name_policy_rejects_unknown() {
        let e = parse_name_policy("trustme").unwrap_err();
        assert!(e.contains("signal | warn | suppress"), "message guides the user: {e}");
    }
}
