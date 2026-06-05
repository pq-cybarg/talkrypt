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
//! `host`/`join`/`registry` use a real TCP transport so two terminals (or
//! machines) can talk today; the Arti onion transport (same trait) is a drop-in
//! swap.

use std::sync::Arc;

use clap::{Parser, Subcommand};
use tokio::io::{AsyncBufReadExt, BufReader};

use talkrypt_core::{
    build_advertisement, resolve_across, AdvertisePolicy, ChannelPassword, ChatDescriptor, Core,
    Event, LinkClient, LinkHost, Marking, Persistence, RegistryClient, RegistryServer, TopologyKind,
};
#[cfg(feature = "markings")]
use talkrypt_core::Classification;
use talkrypt_crypto::{
    dr_suite_id, IdentityChain, IdentityKeyPair, KemProfile, SignedClaim, SuiteRegistry,
    DEFAULT_SUITE_ID,
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
        } => run_join(&uri, group, account, username, device, chain, password).await,
        Cmd::Registry { listen, channel } => run_registry(listen, channel).await,
        Cmd::LinkOffer {
            listen,
            account,
            username,
        } => run_link_offer(listen, account, username).await,
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

/// Default account-key path: `~/.talkrypt/account.key`.
fn default_account_path() -> String {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
    format!("{home}/.talkrypt/account.key")
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

/// Build and present an account→device chain so peers resolve this session to
/// the account. Pushes it to any already-connected peers too.
async fn present(core: &Core, account: &IdentityKeyPair, username: Option<String>) {
    let chain = IdentityChain::device(
        account,
        core.identity_public(),
        "device:cli",
        now_secs(),
        0,
    );
    core.present_identity(chain, username);
    core.announce_identity().await;
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
    let transport = Arc::new(TcpTransport::new(&listen));

    // Advertise the configured bind address in the descriptor, including
    // whether this is a group chat (so joiners auto-detect from the invite).
    let mut desc = ChatDescriptor::new(
        kind,
        Persistence::Ephemeral,
        &suite_id,
        vec![listen.to_string()],
        &channel,
    );
    desc.group = group;
    desc.channel_marking = channel_marking;
    if let Some(pw) = &password {
        desc.password = Some(ChannelPassword::new(pw.clone()));
        println!("channel password: set (Argon2id-gated; not carried in the invite)");
    }
    let device_kp = device_identity(&device)?;
    let (core, rx) = if group {
        Core::new_group(device_kp, suite, transport, desc.clone(), true)
    } else {
        Core::new(device_kp, suite, transport, desc.clone())
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
    // Show the invite as a scannable QR for in-person joining.
    println!("scan to join (or copy the URI above):\n");
    print_qr(&desc.to_uri());

    // Identity: linked chain (secondary device) / account / pseudonym.
    let account_kp = setup_identity(&core, &account, &chain, &username).await?;
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
) -> Result<(), Box<dyn std::error::Error>> {
    println!("{BANNER}\n");
    let mut desc = ChatDescriptor::from_uri(uri)?;
    if let Some(pw) = &password {
        desc.password = Some(ChannelPassword::new(pw.clone()));
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
    let transport = Arc::new(TcpTransport::new("127.0.0.1:0"));
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

    let strategy = for_kind(desc.topology);
    strategy.establish(&core, &desc.endpoints).await?;
    println!(
        "connected to {} peer(s). /help for commands.\n",
        core.peer_count()
    );

    // Identity: linked chain (secondary device) / account / pseudonym.
    let account_kp = setup_identity(&core, &account, &chain, &username).await?;
    repl(core, rx, ReplState::new(account_kp, username)).await
}

/// Host a username registry node (the `registry` subcommand).
async fn run_registry(listen: String, channel: String) -> Result<(), Box<dyn std::error::Error>> {
    println!("{BANNER}\n");
    // The registry uses the default PQ-pure suite; its descriptor (channel +
    // invite token) is the shared handshake root clients dial with.
    let suite = SuiteRegistry::with_defaults().get(DEFAULT_SUITE_ID)?;
    let desc = ChatDescriptor::new(
        TopologyKind::Hub,
        Persistence::Persistent,
        DEFAULT_SUITE_ID,
        vec![listen.clone()],
        &channel,
    );
    let transport = Arc::new(TcpTransport::new(&listen));
    let server = RegistryServer::new(IdentityKeyPair::generate(), suite, transport, &desc);
    server.run().await?;

    println!("username registry hosting on {listen} (channel {channel})");
    println!("\nPublish this registry URI; clients use it with /register and /resolve:\n");
    println!("  {}\n", desc.to_uri());
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
) -> Result<(), Box<dyn std::error::Error>> {
    println!("{BANNER}\n");
    let suite = SuiteRegistry::with_defaults().get(DEFAULT_SUITE_ID)?;
    let account_path = expand_tilde(&account);
    let account_kp = load_account(&account_path)
        .map_err(|e| format!("could not load account {account_path}: {e}"))?;
    let account_sn = account_kp.public().safety_number();
    // A one-time linking descriptor: its random invite token is the in-person
    // secret carried by the QR. The account key never crosses the wire.
    let desc = ChatDescriptor::new(
        TopologyKind::P2P,
        Persistence::Ephemeral,
        DEFAULT_SUITE_ID,
        vec![listen.clone()],
        "#link",
    );
    let transport = Arc::new(TcpTransport::new(&listen));
    let host = LinkHost::new(
        account_kp,
        IdentityKeyPair::generate(),
        suite,
        transport,
        &desc,
        username.clone(),
        now_secs(),
    );
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

/// Mutable interactive state: the linked account (or pseudonym) + its username.
struct ReplState {
    account: Option<IdentityKeyPair>,
    username: Option<String>,
}

impl ReplState {
    fn new(account: Option<IdentityKeyPair>, username: Option<String>) -> Self {
        Self { account, username }
    }
}

const HELP: &str = "\
commands:
  /help                          show this help
  /whoami                        show your device + account identity
  /verify                        show safety numbers (compare out of band)
  /invite                        print this chat's invite URI
  /peers                         connected peer count
  account & friends:
  /account new [path]            generate an account, link this session, save seed
  /account load <path>           load an account seed and link this session
  /account save [path]           save the current account seed
  /username <name>               set the advertised username (re-presents)
  /pseudonym                     drop the account (become unlinkable)
  /friend trust <fp> [name]      pin a just-seen account by fingerprint prefix
  /friends                       list pinned friends
  registry (username discovery):
  /register <registry-uri>       publish username->account to a registry
  /resolve <name> <uri>[ <uri>…] [pin]
                                 cross-compare a name across registries
  /quit                          leave";

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
                    friend,
                } => {
                    let name = username.unwrap_or_else(|| "<no username>".into());
                    if friend {
                        println!(
                            "\r* friend {name} (account {}) on device {}",
                            short_fp(&account_fingerprint),
                            short_fp(&from)
                        );
                    } else {
                        // Not yet a friend: show the account safety number and how
                        // to pin it after an out-of-band comparison.
                        let sn = printer_core
                            .seen_account(account_fingerprint)
                            .map(|a| a.safety_number())
                            .unwrap_or_default();
                        println!(
                            "\r* account {name} (fp {}) on device {} — not a friend",
                            short_fp(&account_fingerprint),
                            short_fp(&from)
                        );
                        println!("    account safety number: {sn}");
                        println!(
                            "    verify out of band, then: /friend trust {}",
                            short_fp(&account_fingerprint)
                        );
                    }
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
            let arg = parts.next().unwrap_or("").trim();
            if matches!(cmd, "quit" | "q") {
                break;
            }
            run_command(&core, &mut state, cmd, arg).await;
            continue;
        }
        if let Err(e) = core.send(line).await {
            eprintln!("! send failed: {e}");
        }
    }
    Ok(())
}

/// Handle one slash command (everything except /quit, handled by the caller).
async fn run_command(core: &Core, state: &mut ReplState, cmd: &str, arg: &str) {
    match cmd {
        "help" => println!("{HELP}"),
        "invite" => println!("{}", core.descriptor().to_uri()),
        "peers" => println!("connected peers: {}", core.peer_count()),
        "verify" => {
            println!("device safety number:  {}", core.identity_public().safety_number());
            match &state.account {
                Some(a) => println!("account safety number: {}", a.public().safety_number()),
                None => println!("(pseudonym — no account)"),
            }
            println!("(compare out-of-band with your peer to defeat MITM)");
        }
        "whoami" => {
            println!("device: {}", core.identity_public().safety_number());
            match (&state.account, &state.username) {
                (Some(a), u) => println!(
                    "account: {}\nusername: {}",
                    a.public().safety_number(),
                    u.as_deref().unwrap_or("<none>")
                ),
                (None, _) => println!("identity: pseudonym (unlinkable)"),
            }
            println!("friends pinned: {}", core.friend_count());
        }
        "account" => cmd_account(core, state, arg).await,
        "username" => {
            if arg.is_empty() {
                println!("usage: /username <name>");
            } else {
                state.username = Some(arg.to_string());
                if let Some(a) = &state.account {
                    present(core, a, state.username.clone()).await;
                    println!("username set to {arg} (re-presented to peers)");
                } else {
                    println!("username set to {arg} (will apply once you /account new|load)");
                }
            }
        }
        "pseudonym" => {
            state.account = None;
            state.username = None;
            core.clear_identity();
            println!("now a pseudonym for future connections (existing sessions keep what they saw)");
        }
        "friend" => cmd_friend(core, arg),
        "friends" => cmd_friend(core, "list"),
        "register" => cmd_register(core, state, arg).await,
        "resolve" => cmd_resolve(core, arg).await,
        other => println!("unknown command: /{other} (try /help)"),
    }
}

/// `/account new|load|save`.
async fn cmd_account(core: &Core, state: &mut ReplState, arg: &str) {
    let mut it = arg.splitn(2, ' ');
    let sub = it.next().unwrap_or("");
    let rest = it.next().unwrap_or("").trim();
    match sub {
        "new" => {
            let path = if rest.is_empty() { default_account_path() } else { rest.to_string() };
            let kp = IdentityKeyPair::generate();
            if let Err(e) = save_account(&path, &kp) {
                println!("! could not save account to {path}: {e}");
                return;
            }
            present(core, &kp, state.username.clone()).await;
            println!("new account: {}", kp.public().safety_number());
            println!("saved seed to {path} (protect this file — it is your account key)");
            state.account = Some(kp);
        }
        "load" => {
            if rest.is_empty() {
                println!("usage: /account load <path>");
                return;
            }
            match load_account(rest) {
                Ok(kp) => {
                    present(core, &kp, state.username.clone()).await;
                    println!("loaded account: {}", kp.public().safety_number());
                    state.account = Some(kp);
                }
                Err(e) => println!("! could not load account: {e}"),
            }
        }
        "save" => match &state.account {
            Some(kp) => {
                let path = if rest.is_empty() { default_account_path() } else { rest.to_string() };
                match save_account(&path, kp) {
                    Ok(()) => println!("saved account seed to {path}"),
                    Err(e) => println!("! save failed: {e}"),
                }
            }
            None => println!("no account to save (try /account new)"),
        },
        _ => println!("usage: /account new [path] | load <path> | save [path]"),
    }
}

/// `/friend trust <fp-prefix> [name]` and `/friend list`.
fn cmd_friend(core: &Core, arg: &str) {
    let mut it = arg.splitn(2, ' ');
    let sub = it.next().unwrap_or("");
    let rest = it.next().unwrap_or("").trim();
    match sub {
        "list" | "" => {
            let friends = core.friends();
            if friends.is_empty() {
                println!("no friends pinned yet");
            } else {
                println!("pinned friends ({}):", friends.len());
                for (fp, name) in friends {
                    println!("  {}  {}", short_fp(&fp), name.as_deref().unwrap_or("<no username>"));
                }
            }
        }
        "trust" => {
            let mut p = rest.splitn(2, ' ');
            let prefix = p.next().unwrap_or("").to_lowercase();
            let name = p.next().map(|s| s.trim().to_string()).filter(|s| !s.is_empty());
            if prefix.is_empty() {
                println!("usage: /friend trust <account-fp-prefix> [username]");
                return;
            }
            let matches: Vec<[u8; 48]> = core
                .seen_account_fingerprints()
                .into_iter()
                .filter(|fp| hex48(fp).starts_with(&prefix))
                .collect();
            match matches.as_slice() {
                [] => println!("no account seen this session matches '{prefix}' (wait for them to present, then retry)"),
                [fp] => {
                    if core.pin_seen_account(*fp, name.clone()) {
                        println!(
                            "pinned friend {} {}",
                            short_fp(fp),
                            name.as_deref().unwrap_or("")
                        );
                    } else {
                        println!("! could not pin (account no longer known)");
                    }
                }
                _ => println!("'{prefix}' is ambiguous ({} matches) — use more characters", matches.len()),
            }
        }
        _ => println!("usage: /friend trust <fp> [name] | /friend list"),
    }
}

/// `/register <registry-uri>` — publish a self-signed username→account claim.
async fn cmd_register(core: &Core, state: &ReplState, arg: &str) {
    let _ = core; // (registry uses the account key, not the chat core)
    let Some(account) = &state.account else {
        println!("link an account first (/account new) before registering a name");
        return;
    };
    let Some(username) = &state.username else {
        println!("set a username first (/username <name>) before registering");
        return;
    };
    if arg.is_empty() {
        println!("usage: /register <registry-uri>");
        return;
    }
    let claim = SignedClaim::issue(account, username.clone(), now_secs());
    match registry_connect(arg).await {
        Ok((mut client, _desc)) => match client.register(&claim).await {
            Ok(()) => println!("registered '{username}' -> account {} at the registry", account.public().safety_number()),
            Err(e) => println!("! registry rejected: {e}"),
        },
        Err(e) => println!("! could not reach registry: {e}"),
    }
}

/// `/resolve <name> <uri>[ <uri> …] [pin]` — cross-compare a username across
/// one or more registries; optionally pin the agreed account as a friend.
async fn cmd_resolve(core: &Core, arg: &str) {
    let mut tokens: Vec<&str> = arg.split_whitespace().collect();
    if tokens.len() < 2 {
        println!("usage: /resolve <name> <registry-uri> [more-uris…] [pin]");
        return;
    }
    let name = tokens.remove(0).to_string();
    let do_pin = tokens.last() == Some(&"pin");
    if do_pin {
        tokens.pop();
    }
    if tokens.is_empty() {
        println!("give at least one registry URI to resolve against");
        return;
    }
    let mut all_claims: Vec<SignedClaim> = Vec::new();
    let mut answered = 0usize;
    for uri in &tokens {
        match registry_connect(uri).await {
            Ok((mut client, _)) => match client.resolve(&name).await {
                Ok(claims) => {
                    if claims.is_empty() {
                        println!("  {uri}: no binding for '{name}'");
                    } else {
                        answered += 1;
                        all_claims.extend(claims);
                    }
                }
                Err(e) => println!("  {uri}: error {e}"),
            },
            Err(e) => println!("  {uri}: unreachable ({e})"),
        }
    }
    match resolve_across(&name, &all_claims) {
        Some(account) => {
            println!(
                "'{name}' resolves to account {} ({} registr{} agreed)",
                account.safety_number(),
                answered,
                if answered == 1 { "y" } else { "ies" }
            );
            if do_pin {
                core.pin_friend(account, Some(name.clone()));
                println!("pinned '{name}' as a friend");
            } else {
                println!("verify the safety number out of band, then add `pin` to friend them");
            }
        }
        None => println!(
            "'{name}' did NOT resolve consistently — registries disagreed or none answered \
             (do not trust this name)"
        ),
    }
}
