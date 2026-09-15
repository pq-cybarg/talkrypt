//! `talkrypt-relsign` — post-quantum signing for release manifests & your own copies
//! (SECURITY-AUDIT F-8).
//!
//! talkrypt's packages ship dual checksums (`SHA256SUMS` + `SHA3-256SUMS`) but a
//! mirror could serve a tampered artifact **and** a matching checksum file. This
//! tool signs a manifest (or any file) with an **ML-DSA-87** key so integrity chains
//! artifact -> SHA-256 -> signed manifest -> a public key you trust.
//!
//! **Anyone can sign — not just the project.** There is no central signing authority:
//! generate your OWN keypair with `keygen`, sign your own copies/rebuilds/mirrors,
//! and hand your public key to the people you distribute to; they verify against it.
//! The project signs its releases the same way with its release key (published as
//! the repo's `docs/RELEASE_PUBKEY.hex`). Deliberately PQ and CA-free: no dependency
//! on Apple notarization or a Debian archive key. Keep your seed (secret) offline or
//! in a CI secret; publish only the public key.
//!
//! Usage:
//!   talkrypt-relsign keygen                      # -> SEED (secret) + PUBKEY (hex) on stdout
//!   talkrypt-relsign sign   <file> <seed>        # writes <file>.sig (hex ML-DSA-87 sig)
//!   talkrypt-relsign verify <file> <sig-file> <pubkey>       # exit 0 iff valid
//!
//! `<seed>` / `<pubkey>` may be the hex itself OR a path to a file holding it; files
//! may carry `#` comment lines (only the hex is read).

use std::process::exit;
use talkrypt_crypto::{IdentityKeyPair, IdentityPublic};

fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

fn hex_decode(s: &str) -> Result<Vec<u8>, String> {
    let s = s.trim();
    if s.len() % 2 != 0 {
        return Err("hex string has odd length".into());
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|_| "invalid hex digit".to_string()))
        .collect()
}

/// Resolve a hex argument that may be the hex itself OR a path to a file holding it.
/// Comment lines (`#...`) and all whitespace are stripped, so an annotated key file
/// (e.g. `docs/RELEASE_PUBKEY.hex`) works directly.
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
    hex_decode(raw.trim())
}

/// Load a 32-byte signing seed (hex or file, comment-aware).
fn load_seed(arg: &str) -> Result<[u8; 32], String> {
    load_hex(arg)?
        .try_into()
        .map_err(|_| "seed must be exactly 32 bytes (64 hex chars)".to_string())
}

fn die(msg: &str) -> ! {
    eprintln!("talkrypt-relsign: {msg}");
    exit(2);
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("keygen") => {
            let kp = IdentityKeyPair::generate();
            // The seed is the SECRET (keep offline); sig_vk is the PUBLIC verify key.
            println!("SEED   {}", hex_encode(&kp.export_secret()));
            println!("PUBKEY {}", hex_encode(&kp.public().sig_vk));
            eprintln!(
                "\nThis is YOUR signing keypair. Keep SEED secret (offline / CI secret); give\n\
                 PUBKEY to whoever verifies your copies. `sign <file> <seed>` then\n\
                 `verify <file> <file>.sig <pubkey>`."
            );
        }
        Some("sign") => {
            let (file, seed_arg) = match (args.get(1), args.get(2)) {
                (Some(f), Some(s)) => (f, s),
                _ => die("usage: sign <file> <seed-hex-or-path>"),
            };
            let seed = load_seed(seed_arg).unwrap_or_else(|e| die(&e));
            let data = std::fs::read(file).unwrap_or_else(|e| die(&format!("read {file}: {e}")));
            let kp = IdentityKeyPair::from_secret_bytes(seed);
            let sig = kp.sign(&data);
            let sig_path = format!("{file}.sig");
            std::fs::write(&sig_path, hex_encode(&sig))
                .unwrap_or_else(|e| die(&format!("write {sig_path}: {e}")));
            println!("signed {file} -> {sig_path} (ML-DSA-87)");
            println!("verify key: {}", hex_encode(&kp.public().sig_vk));
        }
        Some("verify") => {
            let (file, sig_file, pk) = match (args.get(1), args.get(2), args.get(3)) {
                (Some(f), Some(s), Some(p)) => (f, s, p),
                _ => die("usage: verify <file> <sig-file> <pubkey-hex>"),
            };
            let data = std::fs::read(file).unwrap_or_else(|e| die(&format!("read {file}: {e}")));
            let sig_hex =
                std::fs::read_to_string(sig_file).unwrap_or_else(|e| die(&format!("read {sig_file}: {e}")));
            let sig = hex_decode(sig_hex.trim()).unwrap_or_else(|e| die(&e));
            let sig_vk = load_hex(pk).unwrap_or_else(|e| die(&e));
            let public = IdentityPublic { sig_vk };
            match public.verify(&data, &sig) {
                Ok(()) => {
                    println!("OK: {file} signature verifies under the given key");
                }
                Err(_) => {
                    eprintln!("FAIL: {file} signature does NOT verify (tampered or wrong key)");
                    exit(1);
                }
            }
        }
        _ => die("usage: keygen | sign <file> <seed> | verify <file> <sig> <pubkey>"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_roundtrips_and_rejects_bad_input() {
        let bytes = [0x00u8, 0x5a, 0xff, 0x10];
        assert_eq!(hex_encode(&bytes), "005aff10");
        assert_eq!(hex_decode("005aff10").unwrap(), bytes);
        assert!(hex_decode("abc").is_err(), "odd length rejected");
        assert!(hex_decode("zz").is_err(), "non-hex rejected");
    }

    #[test]
    fn sign_then_verify_roundtrips_under_the_release_key() {
        let kp = IdentityKeyPair::generate();
        let seed = hex_encode(&kp.export_secret());
        let pubkey = hex_encode(&kp.public().sig_vk);
        let manifest = b"deadbeef  talkrypt-desktop.tar.gz\ncafebabe  talkrypt.apk\n";

        // Sign with the loaded seed (as the `sign` subcommand does).
        let signer = IdentityKeyPair::from_secret_bytes(load_seed(&seed).unwrap());
        let sig = signer.sign(manifest);

        // Verify with the published pubkey (as the `verify` subcommand does).
        let public = IdentityPublic { sig_vk: hex_decode(&pubkey).unwrap() };
        assert!(public.verify(manifest, &sig).is_ok(), "valid signature verifies");
    }

    #[test]
    fn a_tampered_manifest_fails_verification() {
        let kp = IdentityKeyPair::generate();
        let sig = kp.sign(b"original manifest bytes");
        let public = IdentityPublic { sig_vk: kp.public().sig_vk.clone() };
        assert!(
            public.verify(b"TAMPERED manifest bytes", &sig).is_err(),
            "a modified manifest must fail the release-key signature"
        );
    }

    #[test]
    fn a_wrong_release_key_fails_verification() {
        let signer = IdentityKeyPair::generate();
        let attacker = IdentityKeyPair::generate();
        let msg = b"manifest";
        let sig = signer.sign(msg);
        let wrong = IdentityPublic { sig_vk: attacker.public().sig_vk.clone() };
        assert!(
            wrong.verify(msg, &sig).is_err(),
            "a signature must not verify under a different release key"
        );
    }

    #[test]
    fn load_seed_accepts_64_hex_and_rejects_wrong_length() {
        let kp = IdentityKeyPair::generate();
        let seed_hex = hex_encode(&kp.export_secret());
        assert_eq!(load_seed(&seed_hex).unwrap(), kp.export_secret());
        assert!(load_seed("00").is_err(), "too-short seed rejected");
    }
}
