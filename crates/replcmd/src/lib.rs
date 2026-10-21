//! talkrypt-replcmd — the interactive slash-command logic shared by every
//! talkrypt front-end (the CLI REPL, the TUI, and later the desktop app).
//!
//! The command handlers RETURN their output as `Vec<String>` (one `String` per
//! logical line) instead of printing it, so each UI renders them its own way —
//! the CLI `println!`s each line, the TUI pushes each into its scrollback. The
//! semantics (Core calls, argument parsing, error/usage strings) are identical
//! to the original in-CLI implementation.

use std::sync::Arc;

use talkrypt_core::{resolve_across, ChatDescriptor, Core, RegistryClient};
use talkrypt_crypto::{
    IdentityChain, IdentityKeyPair, Revocation, SignedClaim, SuiteRegistry,
};
use talkrypt_transport::TcpTransport;

/// Mutable interactive state: the linked account (or pseudonym) + its username.
pub struct ReplState {
    pub account: Option<IdentityKeyPair>,
    pub username: Option<String>,
}

impl ReplState {
    pub fn new(account: Option<IdentityKeyPair>, username: Option<String>) -> Self {
        Self { account, username }
    }
}

pub const HELP: &str = "\
commands:
  /help                          show this help
  /whoami                        show your device + account identity
  /verify                        show safety numbers (compare out of band)
  /invite                        print this chat's invite URI
  /peers                         connected peer count
  account:
  /account new [path]            generate an account, link this session, save seed
  /account load <path>           load an account seed and link this session
  /account save [path]           save the current account seed
  /username <name>               set the advertised username (re-presents)
  /pseudonym                     drop the account (become unlinkable)
  contacts (recognition — unilateral, NOT access):
  /contact add <fp> [name]       recognize a just-seen account (by fp prefix)
  /contacts                      list contacts
  /friend <fp>                   label a contact a friend  (/unfriend to clear)
  /revoke <device-fp>            (account holder) revoke + broadcast a lost device
  access (a SEPARATE grant — no contact/friend/mutual needed):
  /access open|contacts|friends  set who may join this channel
  /allow <fp>                    admit one specific account
  /deny <fp>                     revoke an account's access
  names + CQ beacon (self-declared display names):
  /name <callsign>               set a bare self-declared name and announce it
  /name link <callsign>          set an account-linked (verified) name (needs /account)
  /name new <callsign>           save a name to your book without switching to it
  /name list                     list saved names (* = active)
  /name use <id>                 switch your leading name to a saved one and announce
  /name off                      clear your leading name
  /opsec clean|selective|transparent [hide]   linkage-disclosure policy (SUB-SPEC B)
  /grouping new <name-id...>      define + disclose a grouping of your names (account-hidden)
  /showall on|off                disclose your grouping automatically on join
  /sybil                         show the honest distinct-people estimate
  /vouch <fp> | /unvouch <fp>    vouch / withdraw for an account fp (SUB-SPEC C; display-only)
  /vouchpolicy count <n>         your own vouch-tint threshold (stricter-only)
  /vouches                       list heard vouches (subject, score, standing)
  /cq                            re-announce your name to the chat now
  /cq periodic <mins>|off        auto re-beacon your name on a timer
  /cq onmsg on|off               stamp a name-id on each message (rename detection)
  registry (username discovery):
  /register <registry-uri>       publish username->account to a registry
  /resolve <name> <uri>[ <uri>…] [add]
                                 cross-compare a name; `add` saves it as a contact
  /quit                          leave";

/// Handle one slash command (everything except /quit, handled by the caller).
/// Returns the output lines for the UI to render (one `String` per line).
pub async fn run_command(core: &Core, state: &mut ReplState, cmd: &str, arg: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    match cmd {
        "help" => out.extend(HELP.lines().map(|l| l.to_string())),
        "invite" => out.push(core.descriptor().to_uri()),
        "peers" => out.push(format!("connected peers: {}", core.peer_count())),
        "verify" => {
            out.push(format!(
                "device safety number:  {}",
                core.identity_public().safety_number()
            ));
            match &state.account {
                Some(a) => out.push(format!(
                    "account safety number: {}",
                    a.public().safety_number()
                )),
                None => out.push("(pseudonym — no account)".to_string()),
            }
            out.push("(compare out-of-band with your peer to defeat MITM)".to_string());
        }
        "whoami" => {
            out.push(format!("device: {}", core.identity_public().safety_number()));
            match (&state.account, &state.username) {
                (Some(a), u) => {
                    out.push(format!("account: {}", a.public().safety_number()));
                    out.push(format!("username: {}", u.as_deref().unwrap_or("<none>")));
                }
                (None, _) => out.push("identity: pseudonym (unlinkable)".to_string()),
            }
            out.push(format!("contacts: {}", core.contact_count()));
        }
        "account" => out.extend(cmd_account(core, state, arg).await),
        "username" => {
            if arg.is_empty() {
                out.push("usage: /username <name>".to_string());
            } else {
                state.username = Some(arg.to_string());
                if let Some(a) = &state.account {
                    out.extend(present(core, a, state.username.clone()).await);
                    out.push(format!("username set to {arg} (re-presented to peers)"));
                } else {
                    out.push(format!(
                        "username set to {arg} (will apply once you /account new|load)"
                    ));
                }
            }
        }
        "pseudonym" => {
            state.account = None;
            state.username = None;
            core.clear_identity();
            out.push(
                "now a pseudonym for future connections (existing sessions keep what they saw)"
                    .to_string(),
            );
        }
        "contact" => out.extend(cmd_contact(core, arg)),
        "contacts" => out.extend(cmd_contact(core, "list")),
        "friend" => out.extend(cmd_contact(core, &format!("friend {arg}"))),
        "unfriend" => out.extend(cmd_contact(core, &format!("unfriend {arg}"))),
        "allow" => out.extend(cmd_access(core, arg, true)),
        "deny" => out.extend(cmd_access(core, arg, false)),
        "access" => match arg.trim() {
            "open" => {
                core.open_access();
                out.push("access: open (anyone with the invite)".to_string());
            }
            "contacts" => {
                core.restrict_to_contacts();
                out.push("access: contacts only (recognized contacts admitted)".to_string());
            }
            "friends" => {
                core.restrict_to_friends();
                out.push("access: friends only (contacts labeled friend admitted)".to_string());
            }
            _ => out.push(
                "usage: /access open | contacts | friends   (also: /allow <fp>, host --require-registry)"
                    .to_string(),
            ),
        },
        "register" => out.extend(cmd_register(core, state, arg).await),
        "revoke" => out.extend(cmd_revoke(core, state, arg).await),
        "resolve" => out.extend(cmd_resolve(core, arg).await),
        "name" => out.extend(cmd_name(core, state, arg).await),
        "cq" => {
            let a = arg.trim();
            if a.is_empty() {
                core.announce_presence().await.ok();
                out.push("CQ — announced your name to the chat".to_string());
            } else if let Some(rest) = a.strip_prefix("periodic") {
                let rest = rest.trim();
                let secs = if rest == "off" || rest.is_empty() {
                    None
                } else {
                    rest.parse::<u64>().ok().map(|m| m * 60)
                };
                let cur = core.presence_cadence();
                core.set_presence_cadence(talkrypt_core::presence::PresenceCadence {
                    periodic_secs: secs,
                    on_message_id: cur.on_message_id,
                });
                match secs {
                    Some(s) => out.push(format!("CQ cadence: every {} min", s / 60)),
                    None => out.push("CQ cadence: off (manual /cq only)".to_string()),
                }
            } else if let Some(rest) = a.strip_prefix("onmsg") {
                // Stamp a name-id on every outgoing message so peers detect a rename
                // they missed and drop the stale name (SUB-SPEC A §4 mode 3).
                let on = matches!(rest.trim(), "on" | "" | "true");
                let cur = core.presence_cadence();
                core.set_presence_cadence(talkrypt_core::presence::PresenceCadence {
                    periodic_secs: cur.periodic_secs,
                    on_message_id: on,
                });
                out.push(format!(
                    "CQ on-message name-id: {}",
                    if on { "on" } else { "off" }
                ));
            } else {
                out.push(
                    "usage: /cq   |   /cq periodic <minutes>|off   |   /cq onmsg on|off".to_string(),
                );
            }
        }
        "opsec" => out.extend(cmd_opsec(core, arg)),
        "grouping" => out.extend(cmd_grouping(core, arg).await),
        "showall" => match arg.trim() {
            "on" => {
                core.show_all_identities(true);
                out.push("show-all: on — your grouping is disclosed on join".to_string());
            }
            "off" => {
                core.show_all_identities(false);
                out.push("show-all: off".to_string());
            }
            _ => out.push("usage: /showall on|off".to_string()),
        },
        "sybil" => {
            let s = core.sybil_estimate();
            out.push(format!(
                "sybil estimate: >= {} distinct people ({} accounts, {} groupings, {} isolated)",
                s.min_distinct_people, s.distinct_accounts, s.distinct_groupings, s.isolated
            ));
        }
        // SUB-SPEC C: vouching (display-only; never gates access).
        "vouch" => out.extend(cmd_vouch(core, arg, true).await),
        "unvouch" => out.extend(cmd_vouch(core, arg, false).await),
        "vouches" => {
            let sum = core.vouch_summary();
            if sum.is_empty() {
                out.push("no vouches heard yet".to_string());
            } else {
                for (subject, score, vouched) in sum {
                    let fp: String =
                        subject.iter().take(4).map(|b| format!("{b:02x}")).collect();
                    let tag = if vouched {
                        "✳ vouched"
                    } else if score < 0 {
                        "inflation-rejected (neutral)"
                    } else {
                        "below threshold"
                    };
                    out.push(format!("  {fp}  score {score}  {tag}"));
                }
            }
        }
        "vouchpolicy" => match arg.split_whitespace().collect::<Vec<_>>().as_slice() {
            ["count", n] => match n.parse::<u32>() {
                Ok(c) => {
                    core.set_vouch_threshold(talkrypt_core::vouch::Threshold::Count(c));
                    out.push(format!("vouch threshold (yours): weighted score >= {c}"));
                }
                Err(_) => out.push("usage: /vouchpolicy count <n>".to_string()),
            },
            _ => out.push("usage: /vouchpolicy count <n>".to_string()),
        },
        other => out.push(format!("unknown command: /{other} (try /help)")),
    }
    out
}

/// `/vouch <fp>` / `/unvouch <fp>` — cast or withdraw a vouch for a 96-char hex
/// account fp (SUB-SPEC C). Additive-only, display-only; never gates access.
async fn cmd_vouch(core: &Core, arg: &str, on: bool) -> Vec<String> {
    let mut out = Vec::new();
    let fp_hex = arg.trim();
    let mut fp = [0u8; 48];
    if fp_hex.len() != 96
        || (0..48).any(
            |i| match u8::from_str_radix(&fp_hex[i * 2..i * 2 + 2], 16) {
                Ok(b) => {
                    fp[i] = b;
                    false
                }
                Err(_) => true,
            },
        )
    {
        out.push(format!(
            "usage: /{} <96-char-hex-account-fp>",
            if on { "vouch" } else { "unvouch" }
        ));
        return out;
    }
    let target = talkrypt_core::vouch::VouchTarget::Account(fp);
    if on {
        core.vouch_for(target).await;
        out.push(format!("vouched for {}", &fp_hex[..8]));
    } else {
        core.revoke_vouch(target).await;
        out.push(format!("withdrew vouch for {}", &fp_hex[..8]));
    }
    out
}

/// Map an `/opsec` argument to an [`OpsecMode`] (SUB-SPEC B linkage disclosure).
fn parse_opsec(s: &str) -> Result<talkrypt_core::linkage::OpsecMode, String> {
    use talkrypt_core::linkage::OpsecMode;
    let mut it = s.split_whitespace();
    match it.next().unwrap_or("").to_ascii_lowercase().as_str() {
        "clean" => Ok(OpsecMode::Clean),
        "selective" => Ok(OpsecMode::Selective),
        "transparent" => Ok(OpsecMode::Transparent {
            hide: it.next() == Some("hide"),
        }),
        other => Err(format!(
            "unknown opsec mode {other:?} (use clean | selective | transparent [hide])"
        )),
    }
}

/// `/opsec clean|selective|transparent [hide]` — set the linkage-disclosure policy.
fn cmd_opsec(core: &Core, arg: &str) -> Vec<String> {
    let mut out = Vec::new();
    match parse_opsec(arg) {
        Ok(m) => {
            core.set_opsec_mode(m);
            out.push(format!("opsec mode: {m:?}"));
        }
        Err(e) => out.push(e),
    }
    out
}

/// `/grouping new <name-id...>` — define a grouping of your names and disclose it
/// (account-hidden); `/grouping <id>` re-discloses an existing one.
async fn cmd_grouping(core: &Core, arg: &str) -> Vec<String> {
    let mut out = Vec::new();
    let arg = arg.trim();
    if let Some(rest) = arg.strip_prefix("new ") {
        let ids: Vec<String> = rest.split_whitespace().map(|s| s.to_string()).collect();
        if ids.is_empty() {
            out.push("usage: /grouping new <name-id> [<name-id>...]".to_string());
            return out;
        }
        let id = core.define_grouping(&ids);
        out.push(format!("grouping {id} defined ({} members)", ids.len()));
        core.present_grouping(&id).await;
        out.push("grouping disclosed to the chat (account-hidden)".to_string());
    } else if arg.is_empty() || arg == "show" {
        out.push("usage: /grouping new <name-id...>   (define + disclose a grouping)".to_string());
    } else {
        core.present_grouping(&arg.to_string()).await;
        out.push("grouping disclosed".to_string());
    }
    out
}

/// `/name <callsign>` (bare) | `/name link <callsign>` (account-linked) |
/// `/name new <callsign>` (save without switching) | `/name list` |
/// `/name use <id>` (switch to a saved name) | `/name off`.
/// Manages the self-declared name book and the leading name for this chat (SUB-SPEC A).
async fn cmd_name(core: &Core, state: &ReplState, arg: &str) -> Vec<String> {
    use talkrypt_core::presence::{NameBacking, NameEntry};
    let mut out = Vec::new();
    let arg = arg.trim();
    if arg.is_empty() {
        out.push(
            "usage: /name <callsign> | /name link <callsign> | /name new <callsign> | /name list | /name use <id> | /name off"
                .to_string(),
        );
        return out;
    }
    if arg == "off" {
        core.set_leading_name(None);
        out.push("leading name cleared".to_string());
        return out;
    }
    if arg == "list" {
        let book = core.name_book();
        if book.entries.is_empty() {
            out.push("(name book empty — /name <callsign> to add one)".to_string());
            return out;
        }
        let active = core.leading_name_id();
        for e in &book.entries {
            let tier = match e.backing {
                NameBacking::Account { .. } => "account-linked",
                NameBacking::Bare => "bare",
            };
            let mark = if active.as_deref() == Some(e.id.as_str()) {
                "* "
            } else {
                "  "
            };
            out.push(format!("{mark}{}  \"{}\"  ({tier})", e.id, e.label));
        }
        return out;
    }
    if let Some(id) = arg.strip_prefix("use ") {
        let id = id.trim();
        match core.use_name(id).await {
            Ok(()) => out.push(format!("switched leading name to \"{id}\" and announced")),
            Err(e) => out.push(format!("! {e}")),
        }
        return out;
    }
    // The remaining forms all define a name. `new` saves it to the book WITHOUT
    // switching; `link` makes it account-backed; a bare callsign sets + announces.
    let (save_only, rest) = match arg.strip_prefix("new ") {
        Some(rest) => (true, rest.trim()),
        None => (false, arg),
    };
    let (label, backing) = if let Some(label) = rest.strip_prefix("link ") {
        let label = label.trim().to_string();
        match &state.account {
            Some(acct) => {
                let chain = IdentityChain::device(
                    acct,
                    core.identity_public(),
                    "device:cli",
                    now_secs(),
                    0,
                );
                (label, NameBacking::Account { chain })
            }
            None => {
                out.push(
                    "! /name link needs an account (/account new|load) — using a bare name"
                        .to_string(),
                );
                (label, NameBacking::Bare)
            }
        }
    } else {
        (rest.to_string(), NameBacking::Bare)
    };
    if label.is_empty() {
        out.push(
            "usage: /name <callsign> | /name new <callsign> | /name [new] link <callsign>"
                .to_string(),
        );
        return out;
    }
    let linked = matches!(backing, NameBacking::Account { .. });
    let entry = NameEntry {
        id: label.clone(),
        label: label.clone(),
        backing,
    };
    // Always save to the book so it shows in `/name list` and can be re-selected.
    core.add_name(entry.clone());
    if save_only {
        out.push(format!(
            "saved \"{label}\" to the name book ({}); /name use {label} to switch",
            if linked { "account-linked" } else { "bare" }
        ));
    } else {
        core.set_leading_name(Some(entry));
        core.announce_presence().await.ok();
        out.push(format!(
            "name set to \"{label}\" ({}) and announced",
            if linked { "account-linked" } else { "bare" }
        ));
    }
    out
}

/// `/account new|load|save`.
async fn cmd_account(core: &Core, state: &mut ReplState, arg: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut it = arg.splitn(2, ' ');
    let sub = it.next().unwrap_or("");
    let rest = it.next().unwrap_or("").trim();
    match sub {
        "new" => {
            let path = if rest.is_empty() {
                default_account_path()
            } else {
                rest.to_string()
            };
            let kp = IdentityKeyPair::generate();
            if let Err(e) = save_account(&path, &kp) {
                out.push(format!("! could not save account to {path}: {e}"));
                return out;
            }
            out.extend(present(core, &kp, state.username.clone()).await);
            out.push(format!("new account: {}", kp.public().safety_number()));
            out.push(format!(
                "saved seed to {path} (protect this file — it is your account key)"
            ));
            state.account = Some(kp);
        }
        "load" => {
            if rest.is_empty() {
                out.push("usage: /account load <path>".to_string());
                return out;
            }
            match load_account(rest) {
                Ok(kp) => {
                    out.extend(present(core, &kp, state.username.clone()).await);
                    out.push(format!("loaded account: {}", kp.public().safety_number()));
                    state.account = Some(kp);
                }
                Err(e) => out.push(format!("! could not load account: {e}")),
            }
        }
        "save" => match &state.account {
            Some(kp) => {
                let path = if rest.is_empty() {
                    default_account_path()
                } else {
                    rest.to_string()
                };
                match save_account(&path, kp) {
                    Ok(()) => out.push(format!("saved account seed to {path}")),
                    Err(e) => out.push(format!("! save failed: {e}")),
                }
            }
            None => out.push("no account to save (try /account new)".to_string()),
        },
        _ => out.push("usage: /account new [path] | load <path> | save [path]".to_string()),
    }
    out
}

/// Resolve a seen account by fp-prefix: returns the unique match, else pushes a
/// diagnostic line onto `out` and returns `None`.
fn resolve_seen(core: &Core, prefix: &str, out: &mut Vec<String>) -> Option<[u8; 48]> {
    let prefix = prefix.to_lowercase();
    if prefix.is_empty() {
        out.push("give an account fingerprint prefix".to_string());
        return None;
    }
    let matches: Vec<[u8; 48]> = core
        .seen_account_fingerprints()
        .into_iter()
        .filter(|fp| hex48(fp).starts_with(&prefix))
        .collect();
    match matches.as_slice() {
        [] => {
            out.push(format!(
                "no account seen this session matches '{prefix}' (wait for them to present, then retry)"
            ));
            None
        }
        [fp] => Some(*fp),
        _ => {
            out.push(format!(
                "'{prefix}' is ambiguous ({} matches) — use more characters",
                matches.len()
            ));
            None
        }
    }
}

/// `/contact add <fp> [name]` | `/contact list` | `/contact friend|unfriend <fp>`.
/// A contact is recognition only (unilateral) — never an access grant.
fn cmd_contact(core: &Core, arg: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut it = arg.splitn(2, ' ');
    let sub = it.next().unwrap_or("");
    let rest = it.next().unwrap_or("").trim();
    match sub {
        "list" | "" => {
            let contacts = core.contacts();
            if contacts.is_empty() {
                out.push("no contacts yet".to_string());
            } else {
                out.push(format!("contacts ({}):", contacts.len()));
                for (fp, name, friend) in contacts {
                    let tag = if friend { " [friend]" } else { "" };
                    out.push(format!(
                        "  {}  {}{tag}",
                        short_fp(&fp),
                        name.as_deref().unwrap_or("<no name>")
                    ));
                }
            }
        }
        "add" | "trust" => {
            let mut p = rest.splitn(2, ' ');
            let prefix = p.next().unwrap_or("");
            let name = p
                .next()
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty());
            if let Some(fp) = resolve_seen(core, prefix, &mut out) {
                // Add as a contact (recognition); not a friend, not access.
                if core.add_seen_contact(fp, name.clone(), false) {
                    save_contacts(core);
                    out.push(format!(
                        "added contact {} {}",
                        short_fp(&fp),
                        name.as_deref().unwrap_or("")
                    ));
                } else {
                    out.push("! could not add (account no longer known)".to_string());
                }
            }
        }
        "friend" | "unfriend" => {
            let prefix = rest.split(' ').next().unwrap_or("");
            let make_friend = sub == "friend";
            if let Some(fp) = resolve_seen(core, prefix, &mut out) {
                if let Some(acct) = core.seen_account(fp) {
                    // Ensure they're a contact, then set the friend label.
                    if !core.is_contact(&acct) {
                        core.add_seen_contact(fp, None, make_friend);
                    } else {
                        core.set_friend(&acct, make_friend);
                    }
                    save_contacts(core);
                    out.push(format!(
                        "{} {}",
                        if make_friend {
                            "labeled friend"
                        } else {
                            "unlabeled friend"
                        },
                        short_fp(&fp)
                    ));
                } else {
                    out.push("! account no longer known".to_string());
                }
            }
        }
        _ => out.push("usage: /contact add <fp> [name] | list | friend <fp> | unfriend <fp>".to_string()),
    }
    out
}

/// `/allow <fp>` / `/deny <fp>` — grant or revoke channel access for an account
/// by fingerprint prefix. A UNILATERAL access grant — the account need not be a
/// contact, a friend, or a mutual. Switches an open channel into allowlist mode.
fn cmd_access(core: &Core, arg: &str, allow: bool) -> Vec<String> {
    let mut out = Vec::new();
    let prefix = arg.split(' ').next().unwrap_or("");
    if let Some(fp) = resolve_seen(core, prefix, &mut out) {
        if allow {
            core.allow_account(fp);
            out.push(format!(
                "granted access to {} (this channel is now restricted to allowed accounts)",
                short_fp(&fp)
            ));
        } else {
            core.deny_account(fp);
            out.push(format!("revoked access for {}", short_fp(&fp)));
        }
    }
    out
}

/// `/revoke <device-fp>` — the account holder revokes one of its device keys
/// (by 96-hex fingerprint, as printed by `link-accept`) and broadcasts the
/// account-signed revocation to connected peers so they lock the device out.
async fn cmd_revoke(core: &Core, state: &ReplState, arg: &str) -> Vec<String> {
    let mut out = Vec::new();
    let Some(account) = &state.account else {
        out.push(
            "link an account first (/account new|load) — only the account can revoke its devices"
                .to_string(),
        );
        return out;
    };
    let Some(fp) = parse_fp96(arg.trim()) else {
        out.push("usage: /revoke <96-hex device fingerprint>  (shown by `link-accept`)".to_string());
        return out;
    };
    let rev = Revocation::issue(account, fp, now_secs());
    if core.broadcast_revocation(rev).await {
        out.push(format!(
            "revoked device {} and broadcast to {} peer(s) — they'll refuse it",
            short_fp(&fp),
            core.peer_count()
        ));
    } else {
        out.push("! could not issue the revocation".to_string());
    }
    out
}

/// Parse a 96-char hex string into a 48-byte fingerprint.
fn parse_fp96(s: &str) -> Option<[u8; 48]> {
    let s = s.trim();
    if s.len() != 96 || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let mut out = [0u8; 48];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(out)
}

/// `/register <registry-uri>` — publish a self-signed username→account claim.
async fn cmd_register(core: &Core, state: &ReplState, arg: &str) -> Vec<String> {
    let mut out = Vec::new();
    let _ = core; // (registry uses the account key, not the chat core)
    let Some(account) = &state.account else {
        out.push("link an account first (/account new) before registering a name".to_string());
        return out;
    };
    let Some(username) = &state.username else {
        out.push("set a username first (/username <name>) before registering".to_string());
        return out;
    };
    if arg.is_empty() {
        out.push("usage: /register <registry-uri>".to_string());
        return out;
    }
    let claim = SignedClaim::issue(account, username.clone(), now_secs());
    match registry_connect(arg).await {
        Ok((mut client, _desc)) => match client.register(&claim).await {
            Ok(()) => out.push(format!(
                "registered '{username}' -> account {} at the registry",
                account.public().safety_number()
            )),
            Err(e) => out.push(format!("! registry rejected: {e}")),
        },
        Err(e) => out.push(format!("! could not reach registry: {e}")),
    }
    out
}

/// `/resolve <name> <uri>[ <uri> …] [pin]` — cross-compare a username across
/// one or more registries; optionally pin the agreed account as a friend.
async fn cmd_resolve(core: &Core, arg: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut tokens: Vec<&str> = arg.split_whitespace().collect();
    if tokens.len() < 2 {
        out.push("usage: /resolve <name> <registry-uri> [more-uris…] [pin]".to_string());
        return out;
    }
    let name = tokens.remove(0).to_string();
    let do_pin = matches!(tokens.last(), Some(&"add") | Some(&"pin"));
    if do_pin {
        tokens.pop();
    }
    if tokens.is_empty() {
        out.push("give at least one registry URI to resolve against".to_string());
        return out;
    }
    let mut all_claims: Vec<SignedClaim> = Vec::new();
    let mut answered = 0usize;
    for uri in &tokens {
        match registry_connect(uri).await {
            Ok((mut client, _)) => match client.resolve(&name).await {
                Ok(claims) => {
                    if claims.is_empty() {
                        out.push(format!("  {uri}: no binding for '{name}'"));
                    } else {
                        answered += 1;
                        all_claims.extend(claims);
                    }
                }
                Err(e) => out.push(format!("  {uri}: error {e}")),
            },
            Err(e) => out.push(format!("  {uri}: unreachable ({e})")),
        }
    }
    match resolve_across(&name, &all_claims) {
        Some(account) => {
            out.push(format!(
                "'{name}' resolves to account {} ({} registr{} agreed)",
                account.safety_number(),
                answered,
                if answered == 1 { "y" } else { "ies" }
            ));
            if do_pin {
                core.add_contact(account, Some(name.clone()), false);
                save_contacts(core);
                out.push(format!(
                    "added '{name}' as a contact (use /friend to label, /allow to grant access)"
                ));
            } else {
                out.push(format!(
                    "verify the safety number out of band, then add `add` to save '{name}' as a contact"
                ));
            }
        }
        None => out.push(format!(
            "'{name}' did NOT resolve consistently — registries disagreed or none answered \
             (do not trust this name)"
        )),
    }
    out
}

/// Build and present an account→device chain so peers resolve this session to
/// the account. Pushes it to any already-connected peers too. Produces no output
/// lines of its own (returns an empty `Vec`); kept returning `Vec<String>` so
/// callers can `out.extend(...)` uniformly.
pub async fn present(core: &Core, account: &IdentityKeyPair, username: Option<String>) -> Vec<String> {
    let chain = IdentityChain::device(account, core.identity_public(), "device:cli", now_secs(), 0);
    core.present_identity(chain, username);
    core.announce_identity().await;
    Vec::new()
}

/// Connect to a registry from its URI and return a client + the parsed
/// descriptor (so callers can label output).
async fn registry_connect(
    uri: &str,
) -> Result<(RegistryClient, ChatDescriptor), Box<dyn std::error::Error + Send + Sync>> {
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

// ----- small shared helpers (duplicated from the CLI; kept private here) -----

fn short_fp(fp: &[u8; 48]) -> String {
    fp[..6].iter().map(|b| format!("{b:02x}")).collect::<String>()
}

/// Full lowercase hex of a 48-byte fingerprint.
fn hex48(fp: &[u8; 48]) -> String {
    fp.iter().map(|b| format!("{b:02x}")).collect()
}

/// Current Unix time in seconds (certificate validity stamps).
fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Expand a leading `~/` to the user's home directory.
fn expand_tilde(path: &str) -> String {
    if let Some(rest) = path.strip_prefix("~/") {
        let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
        format!("{home}/{rest}")
    } else {
        path.to_string()
    }
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
fn load_account(path: &str) -> Result<IdentityKeyPair, Box<dyn std::error::Error + Send + Sync>> {
    let contents = std::fs::read_to_string(path)?;
    let seed = parse_seed_hex(&contents)?;
    Ok(IdentityKeyPair::from_secret_bytes(seed))
}

/// Save an account seed to a file with owner-only permissions (0600 on unix).
fn save_account(path: &str, kp: &IdentityKeyPair) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
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

/// Where the contact list is stored (TSV: `pubkey_hex \t 0|1 \t name`).
fn contacts_path() -> String {
    expand_tilde("~/.talkrypt/contacts.tsv")
}

/// Persist the current contact list (called after any contact change).
fn save_contacts(core: &Core) {
    let path = contacts_path();
    if let Some(parent) = std::path::Path::new(&path).parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let mut out = String::new();
    for (pk, name, friend) in core.export_contacts() {
        let pkhex: String = pk.iter().map(|b| format!("{b:02x}")).collect();
        out.push_str(&format!(
            "{}\t{}\t{}\n",
            pkhex,
            if friend { 1 } else { 0 },
            name.unwrap_or_default()
        ));
    }
    let _ = std::fs::write(&path, out);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn opsec_parses_all_forms() {
        use talkrypt_core::linkage::OpsecMode;
        assert_eq!(parse_opsec("clean").unwrap(), OpsecMode::Clean);
        assert_eq!(parse_opsec("selective").unwrap(), OpsecMode::Selective);
        assert_eq!(
            parse_opsec("transparent").unwrap(),
            OpsecMode::Transparent { hide: false }
        );
        assert_eq!(
            parse_opsec("transparent hide").unwrap(),
            OpsecMode::Transparent { hide: true }
        );
        assert!(parse_opsec("sneaky").is_err());
    }

    #[test]
    fn fp96_round_trips_and_rejects_bad_input() {
        let hex: String = (0..48).map(|_| "ab").collect();
        let fp = parse_fp96(&hex).expect("96 hex chars parse");
        assert_eq!(fp, [0xabu8; 48]);
        assert!(parse_fp96("tooshort").is_none());
        assert!(parse_fp96(&"zz".repeat(48)).is_none());
    }

    #[test]
    fn help_splits_into_renderable_lines() {
        let lines: Vec<&str> = HELP.lines().collect();
        assert!(lines.len() > 10, "HELP should be many lines");
        assert_eq!(lines[0], "commands:");
    }
}
