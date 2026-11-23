//! `talkrypt-relsign` — post-quantum signing for release manifests & your own copies
//! (SECURITY-AUDIT F-8). The reusable crypto lives in the crate library
//! ([`talkrypt_relsign`]); this is the thin CLI over it.
//!
//! talkrypt's packages ship dual checksums but a mirror could serve a tampered
//! artifact **and** a matching checksum file. This tool signs a manifest (or any
//! file) with **ML-DSA-87** and/or **SLH-DSA** so integrity chains artifact →
//! checksum → signed manifest → a public key you trust.
//!
//! **Anyone can sign — not just the project.** Generate your OWN keypair with
//! `keygen`, sign your own copies, and hand your public key to the people you
//! distribute to. The git repo holds **no key material of any kind**.
//!
//! Seeds can be stored **sealed** (passphrase-encrypted, Argon2id + AES-256-GCM):
//! `keygen --encrypt` writes a `.seed.enc`; `sign`/`pubkey` auto-detect a sealed
//! seed and read the passphrase from `$TALKRYPT_KEY_PASSWORD` (for CI). For an
//! interactive, agent-isolated passphrase prompt that never transits a shared
//! terminal, use `talkrypt-keyvault` instead (see `docs/plans/0004-keyvault.md`).
//!
//! Usage:
//!   talkrypt-relsign [--algo A] keygen [--encrypt]      # SEED/PUBKEY, or a sealed blob
//!   talkrypt-relsign [--algo A] sign   <file> <seed>    # writes <file>.sig / .slh.sig
//!   talkrypt-relsign [--algo A] pubkey <seed>           # derive the public key
//!   talkrypt-relsign [--algo A] verify <file> <sig> <pubkey>
//!   talkrypt-relsign [--algo A] seal   <plaintext-seed> # migrate a plaintext seed → sealed
//!
//! `<seed>` may be: raw hex, a path to a hex file, or a path to a `.seed.enc`
//! sealed blob (needs `$TALKRYPT_KEY_PASSWORD`). `<pubkey>` may be hex or a file.

use std::io::IsTerminal;
use std::process::exit;

use talkrypt_relsign::{hex, seal, seed, sign, verify, Algo};
use zeroize::Zeroizing;

/// Refuse to emit SECRET material (a raw seed, a mnemonic) unless stdout is a real
/// terminal — i.e. a human's screen. A captured/piped stdout (an automation agent, a
/// `script(1)` log, a redirect) would expose the secret, so we fail closed there and
/// point at the sealed path / the isolated keyvault. Override only for a deliberate,
/// understood pipe: `TALKRYPT_ALLOW_SECRET_STDOUT=1`.
fn require_terminal_for_secret() {
    if std::env::var_os("TALKRYPT_ALLOW_SECRET_STDOUT").is_some() {
        return;
    }
    if !std::io::stdout().is_terminal() {
        die(
            "refusing to print secret key material to a non-terminal (it would be \
             captured). Run this in a real terminal to record it, use `keygen --encrypt` \
             (writes a sealed .seed.enc, safe to pipe), or use talkrypt-keyvault. To \
             override deliberately: TALKRYPT_ALLOW_SECRET_STDOUT=1",
        );
    }
}

/// Extract an optional `--algo <name>` flag (default ML-DSA), removing it so the
/// positional args that follow are unaffected.
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

/// Remove a boolean `--flag`, returning whether it was present.
fn take_flag(args: &mut Vec<String>, flag: &str) -> bool {
    if let Some(i) = args.iter().position(|a| a == flag) {
        args.remove(i);
        true
    } else {
        false
    }
}

fn die(msg: &str) -> ! {
    eprintln!("talkrypt-relsign: {msg}");
    exit(2);
}

/// Resolve a hex argument that may be the hex itself OR a path to a file holding it.
fn load_hex(arg: &str) -> Result<Vec<u8>, String> {
    let raw = if std::path::Path::new(arg).is_file() {
        std::fs::read_to_string(arg)
            .map_err(|e| format!("read {arg}: {e}"))?
            .lines()
            .filter(|l| !l.trim_start().starts_with('#'))
            .collect::<Vec<_>>()
            .join("")
    } else {
        arg.to_string()
    };
    hex::decode(raw.trim())
}

/// The passphrase for a sealed seed: from `$TALKRYPT_KEY_PASSWORD` (CI / scripts).
/// This CLI does NOT prompt — an interactive prompt belongs in `talkrypt-keyvault`,
/// whose window/TTY is isolated from a shared terminal.
fn sealed_passphrase() -> Zeroizing<String> {
    match std::env::var("TALKRYPT_KEY_PASSWORD") {
        Ok(p) => Zeroizing::new(p),
        Err(_) => die(
            "sealed seed needs a passphrase — set TALKRYPT_KEY_PASSWORD, or use \
             talkrypt-keyvault for an interactive isolated prompt",
        ),
    }
}

/// Load a 32-byte signing seed. Accepts, in order: a sealed `.seed.enc` file
/// (decrypted with `$TALKRYPT_KEY_PASSWORD`), a QRL 24-word mnemonic, a 35-byte
/// hexseed (descriptor+entropy), or a bare 32-byte hex seed — as a literal arg or a
/// file holding one (comment `#` lines ignored).
fn load_signing_seed(arg: &str) -> Zeroizing<[u8; 32]> {
    if std::path::Path::new(arg).is_file() {
        if let Ok(text) = std::fs::read_to_string(arg) {
            if seal::is_sealed(&text) {
                let pw = sealed_passphrase();
                return seal::unseal(pw.as_bytes(), &text).unwrap_or_else(|e| die(&e.to_string()));
            }
            return parse_seed_text(&strip_comments(&text));
        }
    }
    parse_seed_text(arg)
}

/// Drop `#` comment lines; join the rest (so a mnemonic/hexseed backup file works).
fn strip_comments(text: &str) -> String {
    text.lines()
        .filter(|l| !l.trim_start().starts_with('#'))
        .collect::<Vec<_>>()
        .join(" ")
}

/// Parse a seed from an unsealed string: mnemonic (≥2 words), hexseed (35 B), or raw
/// seed (32 B). The entropy is extracted (any descriptor is validated but dropped —
/// the signing seed is the 32-byte entropy).
fn parse_seed_text(s: &str) -> Zeroizing<[u8; 32]> {
    let t = s.trim();
    if t.split_whitespace().count() >= 2 {
        let (_d, e) = seed::parse_mnemonic(t).unwrap_or_else(|e| die(&e.to_string()));
        return Zeroizing::new(e);
    }
    let bytes = hex::decode(t).unwrap_or_else(|e| die(&e));
    match bytes.len() {
        35 => {
            let (_d, e) = seed::parse_hexseed(t).unwrap_or_else(|e| die(&e.to_string()));
            Zeroizing::new(e)
        }
        32 => {
            let mut a = [0u8; 32];
            a.copy_from_slice(&bytes);
            Zeroizing::new(a)
        }
        _ => die("seed must be a 24-word mnemonic, a 70-hex hexseed, or a 64-hex raw seed"),
    }
}

/// Load a 32-byte seed for KEY DERIVATION where a sealed file's cleartext pubkey is
/// enough — returns the pubkey directly if sealed (no passphrase), else derives it.
fn pubkey_for(algo: Algo, arg: &str) -> Vec<u8> {
    if std::path::Path::new(arg).is_file() {
        if let Ok(text) = std::fs::read_to_string(arg) {
            if seal::is_sealed(&text) {
                let (sealed_algo, pk) = seal::read_public(&text).unwrap_or_else(|e| die(&e.to_string()));
                if sealed_algo != algo {
                    die("--algo does not match the sealed seed's algorithm");
                }
                return pk;
            }
        }
    }
    let seed = load_signing_seed(arg);
    talkrypt_relsign::pubkey_of(algo, *seed)
}

fn main() {
    let mut args: Vec<String> = std::env::args().skip(1).collect();
    let algo = take_algo(&mut args);
    match args.first().map(String::as_str) {
        Some("keygen") => {
            let encrypt = take_flag(&mut args, "--encrypt");
            // The seed is the SECRET; the pubkey + address are PUBLIC. 32 bytes both schemes.
            let seed = Zeroizing::new(talkrypt_crypto::IdentityKeyPair::generate().export_secret());
            let pubkey = talkrypt_relsign::pubkey_of(algo, *seed);
            let desc = seed::Descriptor::for_algo(algo);
            let address = seed::address(desc, &pubkey);
            if encrypt {
                // Sealed: the .seed.enc blob and the pubkey/address are all PUBLIC, so
                // this path is safe to pipe. No secret reaches stdout.
                let pw = sealed_passphrase();
                let blob = seal::seal(pw.as_bytes(), algo, &seed, &pubkey)
                    .unwrap_or_else(|e| die(&e.to_string()));
                // STDOUT carries ONLY the sealed blob, so it can be redirected straight
                // to a .seed.enc. Everything else (public) goes to stderr.
                print!("{blob}");
                eprintln!(
                    "\nSealed {} seed (passphrase from $TALKRYPT_KEY_PASSWORD). Redirect \n\
                     stdout to a .seed.enc. PUBLIC key id (pin out of band): {address}\n\
                     PUBKEY {}",
                    algo.label(),
                    hex::encode(&pubkey),
                );
            } else {
                // Unsealed: the mnemonic + hexseed ARE the secret — show them ONLY to a
                // human terminal so an operator can transcribe them for offline backup.
                require_terminal_for_secret();
                let mnemonic = Zeroizing::new(seed::mnemonic(desc, &seed));
                let hexseed = Zeroizing::new(seed::hexseed(desc, &seed));
                println!("# talkrypt {} signing key — WRITE THE MNEMONIC DOWN, OFFLINE.", algo.label());
                println!("address:  {address}   (public — pin this out of band)");
                println!("pubkey:   {}", hex::encode(&pubkey));
                println!("mnemonic: {}", &*mnemonic);
                println!("hexseed:  {}", &*hexseed);
                eprintln!(
                    "\nThe mnemonic/hexseed are SECRET. Prefer `keygen --encrypt` (sealed at \n\
                     rest) or talkrypt-keyvault. Restore with `sign <file> <mnemonic-or-hexseed>`."
                );
            }
        }
        Some("pubkey") => {
            let seed_arg = args
                .get(1)
                .unwrap_or_else(|| die("usage: [--algo A] pubkey <seed-hex-or-path>"));
            println!("{}", hex::encode(&pubkey_for(algo, seed_arg)));
        }
        Some("sign") => {
            let (file, seed_arg) = match (args.get(1), args.get(2)) {
                (Some(f), Some(s)) => (f.clone(), s.clone()),
                _ => die("usage: [--algo A] sign <file> <seed-hex-or-path>"),
            };
            let seed = load_signing_seed(&seed_arg);
            let data = std::fs::read(&file).unwrap_or_else(|e| die(&format!("read {file}: {e}")));
            let sig = sign(algo, *seed, &data);
            let sig_path = format!("{file}.{}", algo.sig_suffix());
            std::fs::write(&sig_path, hex::encode(&sig))
                .unwrap_or_else(|e| die(&format!("write {sig_path}: {e}")));
            println!("signed {file} -> {sig_path} ({})", algo.label());
        }
        Some("verify") => {
            let (file, sig_file, pk) = match (args.get(1), args.get(2), args.get(3)) {
                (Some(f), Some(s), Some(p)) => (f, s, p),
                _ => die("usage: [--algo A] verify <file> <sig-file> <pubkey-hex>"),
            };
            let data = std::fs::read(file).unwrap_or_else(|e| die(&format!("read {file}: {e}")));
            let sig_hex = std::fs::read_to_string(sig_file)
                .unwrap_or_else(|e| die(&format!("read {sig_file}: {e}")));
            let sig = hex::decode(sig_hex.trim()).unwrap_or_else(|e| die(&e));
            let pk_bytes = load_hex(pk).unwrap_or_else(|e| die(&e));
            if verify(algo, &pk_bytes, &data, &sig) {
                println!("OK: {file} signature verifies under the given key ({})", algo.label());
            } else {
                eprintln!("FAIL: {file} signature does NOT verify (tampered or wrong key)");
                exit(1);
            }
        }
        Some("seal") => {
            // Migrate a plaintext seed (hex or file) to a sealed `.seed.enc` on stdout.
            let seed_arg = args
                .get(1)
                .unwrap_or_else(|| die("usage: [--algo A] seal <plaintext-seed-hex-or-path>"));
            let seed = load_signing_seed(seed_arg);
            let pubkey = talkrypt_relsign::pubkey_of(algo, *seed);
            let pw = sealed_passphrase();
            let blob =
                seal::seal(pw.as_bytes(), algo, &seed, &pubkey).unwrap_or_else(|e| die(&e.to_string()));
            print!("{blob}");
            eprintln!("\nsealed {} seed (store as .seed.enc; delete the plaintext).", algo.label());
        }
        Some("selftest-kdf") => {
            // Seal + unseal a fixed seed with a platform KDF preset at its REAL work
            // factor, and exit 0 on round-trip. Used to validate that a seal with a
            // given KDF actually RUNS (and fits in memory) on a target / emulator — e.g.
            // the mobile preset succeeds under a tight RAM cap where `desktop` (256 MiB
            // Argon2id) is OOM-killed. See docs/FORMAL-SEAL.md / the mobile-KDF test.
            let preset = args.get(1).map(String::as_str).unwrap_or("mobile");
            let kdf = match preset {
                "desktop" => seal::Kdf::desktop(),
                "mobile" => seal::Kdf::mobile(),
                "embedded" => seal::Kdf::embedded(),
                "fips" => seal::Kdf::fips(),
                _ => die("usage: selftest-kdf desktop|mobile|embedded|fips"),
            };
            let seed = [7u8; 32];
            let pubkey = talkrypt_relsign::pubkey_of(algo, seed);
            let blob = seal::seal_with_kdf(b"selftest", algo, &seed, &pubkey, kdf)
                .unwrap_or_else(|e| die(&e.to_string()));
            let got = seal::unseal(b"selftest", &blob).unwrap_or_else(|e| die(&e.to_string()));
            if *got == seed {
                println!("OK selftest-kdf {preset} ({})", algo.label());
            } else {
                die("selftest-kdf: round-trip mismatch");
            }
        }
        _ => die(
            "usage: [--algo ml-dsa|slh-dsa] keygen [--encrypt] | pubkey <seed> | \
             sign <file> <seed> | verify <file> <sig> <pubkey> | seal <seed> | \
             selftest-kdf <preset>",
        ),
    }
}
