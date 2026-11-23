//! `talkrypt-keyvault` — the agent-isolated signing microapp (TUI front-end).
//!
//! Owns the WHOLE secret lifecycle in one hardened process; only PUBLIC data crosses
//! its boundary. The passphrase is read from the controlling terminal (`/dev/tty`),
//! never a stdin an automation agent can pipe — so an agent that launches this binary
//! (no controlling terminal) literally cannot supply the passphrase or read the seed.
//! See `docs/plans/0004-keyvault.md` (threat model) and `docs/FORMAL-SEAL.md`.
//!
//! Hardening: no core dumps + non-dumpable (anti-`ptrace`) via `crypto::mem`, plus
//! `deny_debugger` (a later debugger attach terminates the process). Secrets live in
//! `Zeroizing` buffers (wiped on every path).
//!
//! NOT FIPS-validated / audited. This process-level hardening defends against the
//! agent and other non-root local processes; it does NOT defend against root, a
//! kernel implant, or a hardware keylogger (out of scope — see the threat model).
//!
//! Usage (run in YOUR OWN terminal, not through the agent):
//!   talkrypt-keyvault [--algo ml-dsa|slh-dsa] keygen --out <file.seed.enc>
//!                     [--kdf desktop|mobile|embedded|fips]
//!   talkrypt-keyvault [--algo ml-dsa|slh-dsa] sign <manifest> <file.seed.enc>

use std::process::exit;

use talkrypt_relsign::{hex, seal, seed, sign, Algo};
use zeroize::Zeroizing;

mod tty;
#[cfg(feature = "gui")]
mod gui;

fn die(msg: &str) -> ! {
    eprintln!("talkrypt-keyvault: {msg}");
    exit(2);
}

/// Apply process hardening at every entry: no core dump + non-dumpable (blocks
/// same-uid ptrace / `/proc/pid/mem`), and refuse debugger attach.
fn harden() {
    talkrypt_crypto::ensure_hardened();
    let _ = talkrypt_crypto::deny_debugger();
}

fn take_algo(args: &mut Vec<String>) -> Algo {
    if let Some(i) = args.iter().position(|a| a == "--algo") {
        let val = args.get(i + 1).cloned();
        args.remove(i);
        if i < args.len() {
            args.remove(i);
        }
        match val.as_deref().and_then(Algo::parse) {
            Some(a) => a,
            None => die("unknown --algo (expected ml-dsa | slh-dsa)"),
        }
    } else {
        Algo::MlDsa
    }
}

fn take_opt(args: &mut Vec<String>, flag: &str) -> Option<String> {
    let i = args.iter().position(|a| a == flag)?;
    let val = args.get(i + 1).cloned();
    args.remove(i);
    if i < args.len() {
        args.remove(i);
    }
    val
}

fn parse_kdf(name: &str) -> seal::Kdf {
    match name {
        "desktop" => seal::Kdf::desktop(),
        "mobile" => seal::Kdf::mobile(),
        "embedded" => seal::Kdf::embedded(),
        "fips" => seal::Kdf::fips(),
        _ => die("unknown --kdf (expected desktop | mobile | embedded | fips)"),
    }
}

fn main() {
    harden();
    let mut args: Vec<String> = std::env::args().skip(1).collect();
    let algo = take_algo(&mut args);

    match args.first().map(String::as_str) {
        Some("keygen") => {
            let out = take_opt(&mut args, "--out")
                .unwrap_or_else(|| die("usage: keygen --out <file.seed.enc> [--kdf ...]"));
            let kdf = take_opt(&mut args, "--kdf").map(|k| parse_kdf(&k)).unwrap_or_else(seal::Kdf::desktop);
            if std::path::Path::new(&out).exists() {
                die("refusing to overwrite an existing key file (choose a new --out path)");
            }

            // Passphrase from the controlling terminal only (never the agent's stdin).
            let pw = tty::read_new_passphrase().unwrap_or_else(|e| {
                die(&format!(
                    "no controlling terminal for passphrase entry ({e}) — run this in your \
                     OWN terminal, not through an automation tool"
                ))
            });

            // Generate + seal entirely in-process. The seed never leaves this function
            // except as the sealed blob and the terminal-only recordable backup.
            let gen_seed = Zeroizing::new(talkrypt_crypto::IdentityKeyPair::generate().export_secret());
            let pubkey = talkrypt_relsign::pubkey_of(algo, *gen_seed);
            let desc = seed::Descriptor::for_algo(algo);
            let address = seed::address(desc, &pubkey);
            let blob = seal::seal_with_kdf(pw.as_bytes(), algo, &gen_seed, &pubkey, kdf)
                .unwrap_or_else(|e| die(&e.to_string()));

            // Write ONLY the sealed blob to disk (owner-only).
            std::fs::write(&out, blob.as_bytes()).unwrap_or_else(|e| die(&format!("write {out}: {e}")));
            set_owner_only(&out);

            // Non-secret confirmation to stdout (safe for any caller to see).
            println!("sealed {} key -> {out}", algo.label());
            println!("address {address}");
            println!("pubkey  {}", hex::encode(&pubkey));

            // Recordable SECRET backup to the terminal ONLY — never stdout.
            let mnemonic = Zeroizing::new(seed::mnemonic(desc, &gen_seed));
            let hexseed = Zeroizing::new(seed::hexseed(desc, &gen_seed));
            tty::eprintln_tty("");
            tty::eprintln_tty(">>> WRITE THIS DOWN OFFLINE (shown only on this screen) <<<");
            tty::eprintln_tty(&format!("mnemonic: {}", mnemonic.as_str()));
            tty::eprintln_tty(&format!("hexseed:  {}", hexseed.as_str()));
            tty::eprintln_tty("Keep the .seed.enc + this passphrase to sign; the mnemonic is an offline recovery backup.");
        }

        Some("sign") => {
            let (manifest, keyfile) = match (args.get(1), args.get(2)) {
                (Some(m), Some(k)) => (m.clone(), k.clone()),
                _ => die("usage: sign <manifest> <file.seed.enc>"),
            };
            let blob = std::fs::read_to_string(&keyfile)
                .unwrap_or_else(|e| die(&format!("read {keyfile}: {e}")));
            if !seal::is_sealed(&blob) {
                die("that key file is not a sealed .seed.enc (keyvault only opens sealed keys)");
            }
            let data = std::fs::read(&manifest).unwrap_or_else(|e| die(&format!("read {manifest}: {e}")));

            let pw = tty::read_passphrase("Passphrase (not echoed): ").unwrap_or_else(|e| {
                die(&format!(
                    "no controlling terminal for passphrase entry ({e}) — run this in your OWN terminal"
                ))
            });
            let recovered = seal::unseal(pw.as_bytes(), &blob).unwrap_or_else(|e| die(&e.to_string()));
            let sealed_algo = seal::read_public(&blob).map(|(a, _)| a).unwrap_or(algo);

            let sig = sign(sealed_algo, *recovered, &data);
            let sig_path = format!("{manifest}.{}", sealed_algo.sig_suffix());
            std::fs::write(&sig_path, hex::encode(&sig))
                .unwrap_or_else(|e| die(&format!("write {sig_path}: {e}")));
            // Only the PUBLIC signature path crosses the boundary.
            println!("signed {manifest} -> {sig_path} ({})", sealed_algo.label());
        }

        Some("gui") => {
            // Launch the window popup. The passphrase is typed into the window (not
            // stdin), so the isolation boundary is the window the agent can't observe.
            #[cfg(feature = "gui")]
            gui::run().unwrap_or_else(|e| die(&e));
            #[cfg(not(feature = "gui"))]
            die("this keyvault was built without the GUI — rebuild with --features gui, or use the TUI (keygen/sign)");
        }

        _ => die(
            "usage: [--algo ml-dsa|slh-dsa] keygen --out <file.seed.enc> [--kdf desktop|mobile|embedded|fips] | \
             sign <manifest> <file.seed.enc> | gui",
        ),
    }
}

/// Best-effort owner-only perms on the sealed key file (Unix 0600).
fn set_owner_only(path: &str) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
    }
}
