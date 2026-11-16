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
//! The project signs its releases the same way with its release key, whose PUBLIC
//! half is **published with each release** (written into `dist/` next to the
//! artifacts, and injected into the binaries at build time) — the git repo holds
//! **no key material of any kind**. Deliberately PQ and CA-free: no dependency on
//! Apple notarization or a Debian archive key. Keep your seed (secret) offline or in
//! a CI secret; publish only the public key, and pin the copy you got out of band.
//!
//! Usage:
//!   talkrypt-relsign keygen                      # -> SEED (secret) + PUBKEY (hex) on stdout
//!   talkrypt-relsign sign   <file> <seed>        # writes <file>.sig (hex ML-DSA-87 sig)
//!   talkrypt-relsign verify <file> <sig-file> <pubkey>       # exit 0 iff valid
//!
//! `<seed>` / `<pubkey>` may be the hex itself OR a path to a file holding it; files
//! may carry `#` comment lines (only the hex is read).

use std::process::exit;

use rand::{rngs::StdRng, SeedableRng};
use talkrypt_crypto::{IdentityKeyPair, IdentityPublic};

/// Release-signing algorithm. ML-DSA-87 (FIPS 204) is the general/default signer;
/// SLH-DSA (FIPS 205, stateless hash-based) is the NIST stateless software-signing
/// scheme added for release co-signing. (LMS / SP 800-208 — the CNSA-designated
/// stateful scheme — is the next addition; see `docs/plans/0003-release-cosigning.md`.)
#[derive(Clone, Copy, PartialEq, Eq)]
enum Algo {
    MlDsa,
    SlhDsa,
}

impl Algo {
    /// Extract an optional `--algo <name>` flag from the args (default ML-DSA),
    /// removing it so the positional args that follow are unaffected.
    fn take_from(args: &mut Vec<String>) -> Algo {
        if let Some(i) = args.iter().position(|a| a == "--algo") {
            let val = args.get(i + 1).cloned();
            args.remove(i); // drop the flag
            if i < args.len() {
                args.remove(i); // drop its value (now shifted into position i)
            }
            match val.as_deref() {
                Some("ml-dsa") | Some("mldsa") => Algo::MlDsa,
                Some("slh-dsa") | Some("slhdsa") | Some("slh") => Algo::SlhDsa,
                other => die(&format!(
                    "unknown --algo {:?} (expected ml-dsa | slh-dsa)",
                    other.unwrap_or("")
                )),
            }
        } else {
            Algo::MlDsa
        }
    }

    /// Detached-signature filename suffix. ML-DSA keeps the historic `<file>.sig`
    /// (back-compat); other schemes get `<file>.<algo>.sig` so one manifest can carry
    /// multiple co-signatures side by side.
    fn sig_suffix(self) -> &'static str {
        match self {
            Algo::MlDsa => "sig",
            Algo::SlhDsa => "slh.sig",
        }
    }

    fn label(self) -> &'static str {
        match self {
            Algo::MlDsa => "ML-DSA-87",
            Algo::SlhDsa => "SLH-DSA-SHA2-256s",
        }
    }
}

/// SLH-DSA (FIPS 205) release-signing, parameter set **SLH-DSA-SHA2-256s** (SHA-2
/// family for CNSA-hash consistency; the small-signature "s" variant). Keys derive
/// deterministically from a 32-byte seed via a seeded CSPRNG, so the offline secret
/// is a single 32-byte value exactly like the ML-DSA path, and signing is
/// deterministic (hedged = false) so re-signing a manifest is reproducible.
mod slhdsa {
    use super::StdRng;
    use fips205::slh_dsa_sha2_256s as p;
    use fips205::traits::{SerDes, Signer, Verifier};
    use rand::SeedableRng;

    fn keypair(seed: [u8; 32]) -> (p::PublicKey, p::PrivateKey) {
        let mut rng = StdRng::from_seed(seed);
        p::try_keygen_with_rng(&mut rng).expect("SLH-DSA key generation")
    }

    /// Public verify key bytes derived from the 32-byte seed.
    pub fn public_key(seed: [u8; 32]) -> Vec<u8> {
        keypair(seed).0.into_bytes().to_vec()
    }

    /// Deterministically sign `msg` (hedged = false → reproducible).
    pub fn sign(seed: [u8; 32], msg: &[u8]) -> Vec<u8> {
        let (_pk, sk) = keypair(seed);
        sk.try_sign(msg, &[], false)
            .expect("SLH-DSA signing")
            .to_vec()
    }

    /// Verify `sig` over `msg` under `pk_bytes`. Any malformed input (wrong length,
    /// bad key) is a clean `false`, never a panic.
    pub fn verify(pk_bytes: &[u8], msg: &[u8], sig: &[u8]) -> bool {
        let pk_arr: [u8; p::PK_LEN] = match pk_bytes.try_into() {
            Ok(a) => a,
            Err(_) => return false,
        };
        let sig_arr: [u8; p::SIG_LEN] = match sig.try_into() {
            Ok(a) => a,
            Err(_) => return false,
        };
        match p::PublicKey::try_from_bytes(pk_arr) {
            Ok(pk) => pk.verify(msg, &sig_arr, &[]),
            Err(_) => false,
        }
    }
}

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
    let mut args: Vec<String> = std::env::args().skip(1).collect();
    let algo = Algo::take_from(&mut args);
    match args.first().map(String::as_str) {
        Some("keygen") => {
            // The seed is the SECRET (keep offline); the pubkey is PUBLIC. For both
            // schemes the secret is a single 32-byte seed.
            let seed = IdentityKeyPair::generate().export_secret();
            let pubkey = match algo {
                Algo::MlDsa => hex_encode(&IdentityKeyPair::from_secret_bytes(seed).public().sig_vk),
                Algo::SlhDsa => hex_encode(&slhdsa::public_key(seed)),
            };
            println!("SEED   {}", hex_encode(&seed));
            println!("PUBKEY {pubkey}");
            eprintln!(
                "\nThis is YOUR {} signing keypair. Keep SEED secret (offline / CI secret);\n\
                 give PUBKEY to whoever verifies your copies. `sign <file> <seed>` then\n\
                 `verify <file> <file>.{} <pubkey>`.",
                algo.label(),
                algo.sig_suffix()
            );
        }
        Some("pubkey") => {
            // Derive the PUBLIC verify key from a signing seed, so a release can
            // PUBLISH the pubkey (into dist/, next to the artifacts) without any key
            // ever living in the git repo. Trust anchor is still obtained out of band.
            let seed_arg = args
                .get(1)
                .unwrap_or_else(|| die("usage: [--algo A] pubkey <seed-hex-or-path>"));
            let seed = load_seed(seed_arg).unwrap_or_else(|e| die(&e));
            let pubkey = match algo {
                Algo::MlDsa => hex_encode(&IdentityKeyPair::from_secret_bytes(seed).public().sig_vk),
                Algo::SlhDsa => hex_encode(&slhdsa::public_key(seed)),
            };
            println!("{pubkey}");
        }
        Some("sign") => {
            let (file, seed_arg) = match (args.get(1), args.get(2)) {
                (Some(f), Some(s)) => (f, s),
                _ => die("usage: [--algo A] sign <file> <seed-hex-or-path>"),
            };
            let seed = load_seed(seed_arg).unwrap_or_else(|e| die(&e));
            let data = std::fs::read(file).unwrap_or_else(|e| die(&format!("read {file}: {e}")));
            let sig = match algo {
                Algo::MlDsa => IdentityKeyPair::from_secret_bytes(seed).sign(&data),
                Algo::SlhDsa => slhdsa::sign(seed, &data),
            };
            let sig_path = format!("{file}.{}", algo.sig_suffix());
            std::fs::write(&sig_path, hex_encode(&sig))
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
            let sig = hex_decode(sig_hex.trim()).unwrap_or_else(|e| die(&e));
            let pk_bytes = load_hex(pk).unwrap_or_else(|e| die(&e));
            let ok = match algo {
                Algo::MlDsa => IdentityPublic { sig_vk: pk_bytes }.verify(&data, &sig).is_ok(),
                Algo::SlhDsa => slhdsa::verify(&pk_bytes, &data, &sig),
            };
            if ok {
                println!("OK: {file} signature verifies under the given key ({})", algo.label());
            } else {
                eprintln!("FAIL: {file} signature does NOT verify (tampered or wrong key)");
                exit(1);
            }
        }
        _ => die(
            "usage: [--algo ml-dsa|slh-dsa] keygen | pubkey <seed> | \
             sign <file> <seed> | verify <file> <sig> <pubkey>",
        ),
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
    fn pubkey_subcommand_derives_the_published_verify_key_from_the_seed() {
        // The `pubkey <seed>` subcommand must reproduce exactly the verify key that
        // `keygen` prints, so a release can PUBLISH the pubkey derived from the
        // offline secret — with no key file ever committed to the repo.
        let kp = IdentityKeyPair::generate();
        let derived = IdentityKeyPair::from_secret_bytes(kp.export_secret());
        assert_eq!(
            derived.public().sig_vk,
            kp.public().sig_vk,
            "pubkey derived from the seed equals the keygen-published verify key"
        );
    }

    #[test]
    fn load_seed_accepts_64_hex_and_rejects_wrong_length() {
        let kp = IdentityKeyPair::generate();
        let seed_hex = hex_encode(&kp.export_secret());
        assert_eq!(load_seed(&seed_hex).unwrap(), kp.export_secret());
        assert!(load_seed("00").is_err(), "too-short seed rejected");
    }

    #[test]
    fn slhdsa_pubkey_is_deterministic_from_the_seed() {
        let seed = [7u8; 32];
        assert_eq!(
            slhdsa::public_key(seed),
            slhdsa::public_key(seed),
            "same seed -> same SLH-DSA public key (so a release can republish it)"
        );
    }

    #[test]
    fn slhdsa_sign_then_verify_roundtrips_and_rejects_tampering() {
        let seed = [42u8; 32];
        let pk = slhdsa::public_key(seed);
        let manifest = b"deadbeef  talkrypt-desktop.tar.gz\n";
        let sig = slhdsa::sign(seed, manifest);
        assert!(slhdsa::verify(&pk, manifest, &sig), "valid SLH-DSA signature verifies");
        assert!(
            !slhdsa::verify(&pk, b"TAMPERED manifest", &sig),
            "a modified manifest must fail the SLH-DSA signature"
        );
    }

    #[test]
    fn slhdsa_wrong_key_and_malformed_inputs_fail_cleanly() {
        let sig = slhdsa::sign([1u8; 32], b"manifest");
        let wrong_pk = slhdsa::public_key([2u8; 32]);
        assert!(!slhdsa::verify(&wrong_pk, b"manifest", &sig), "wrong key rejected");
        // Malformed inputs must be a clean `false`, never a panic.
        assert!(!slhdsa::verify(b"short-pk", b"manifest", &sig));
        assert!(!slhdsa::verify(&wrong_pk, b"manifest", b"short-sig"));
    }
}
