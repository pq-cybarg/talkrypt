//! `talkrypt-relsign` — the reusable release-signing crypto (SECURITY-AUDIT F-8),
//! shared by the `talkrypt-relsign` CLI (CI / env-secret signing) and the isolated
//! `talkrypt-keyvault` microapp (interactive, hardened, agent-isolated custody —
//! see `docs/plans/0004-keyvault.md`).
//!
//! Two signature schemes co-sign a release manifest (every signature present must
//! verify): **ML-DSA-87** (FIPS 204, general) and **SLH-DSA-SHA2-256s** (FIPS 205,
//! stateless hash-based). Seeds are a single 32-byte value for both, so one
//! offline secret per scheme. The [`seal`] module seals that secret at rest with
//! Argon2id + AES-256-GCM so it never sits in plaintext.
//!
//! NOT FIPS-validated · NOT CSfC-accredited · NOT NSA-approved · NOT audited.

use rand::rngs::StdRng;
use talkrypt_crypto::{IdentityKeyPair, IdentityPublic};

pub mod seal;
pub mod seed;

/// Release-signing algorithm. ML-DSA-87 (FIPS 204) is the general/default signer;
/// SLH-DSA (FIPS 205, stateless hash-based) is the NIST stateless software-signing
/// scheme. (LMS / SP 800-208 — the CNSA-designated stateful scheme — is the next
/// addition; see `docs/plans/0003-release-cosigning.md`.)
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Algo {
    MlDsa,
    SlhDsa,
}

impl Algo {
    /// Parse the `--algo <name>` value (`ml-dsa` | `slh-dsa`, with aliases).
    pub fn parse(name: &str) -> Option<Algo> {
        match name {
            "ml-dsa" | "mldsa" => Some(Algo::MlDsa),
            "slh-dsa" | "slhdsa" | "slh" => Some(Algo::SlhDsa),
            _ => None,
        }
    }

    /// Detached-signature filename suffix. ML-DSA keeps the historic `<file>.sig`
    /// (back-compat); other schemes get `<file>.<algo>.sig` so one manifest can
    /// carry multiple co-signatures side by side.
    pub fn sig_suffix(self) -> &'static str {
        match self {
            Algo::MlDsa => "sig",
            Algo::SlhDsa => "slh.sig",
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Algo::MlDsa => "ML-DSA-87",
            Algo::SlhDsa => "SLH-DSA-SHA2-256s",
        }
    }

    /// Short wire tag stored in a sealed-seed header so `unseal` knows the scheme.
    pub fn tag(self) -> &'static str {
        match self {
            Algo::MlDsa => "ml-dsa",
            Algo::SlhDsa => "slh-dsa",
        }
    }
}

/// Derive the PUBLIC verify key for `algo` from a 32-byte signing `seed`.
pub fn pubkey_of(algo: Algo, seed: [u8; 32]) -> Vec<u8> {
    match algo {
        Algo::MlDsa => IdentityKeyPair::from_secret_bytes(seed).public().sig_vk.clone(),
        Algo::SlhDsa => slhdsa::public_key(seed),
    }
}

/// Sign `msg` under `algo` with the 32-byte `seed`. Deterministic for both schemes
/// so re-signing a manifest is reproducible.
pub fn sign(algo: Algo, seed: [u8; 32], msg: &[u8]) -> Vec<u8> {
    match algo {
        Algo::MlDsa => IdentityKeyPair::from_secret_bytes(seed).sign(msg),
        Algo::SlhDsa => slhdsa::sign(seed, msg),
    }
}

/// Verify `sig` over `msg` under `pk` for `algo`. Any malformed input is a clean
/// `false`, never a panic.
pub fn verify(algo: Algo, pk: &[u8], msg: &[u8], sig: &[u8]) -> bool {
    match algo {
        Algo::MlDsa => IdentityPublic { sig_vk: pk.to_vec() }.verify(msg, sig).is_ok(),
        Algo::SlhDsa => slhdsa::verify(pk, msg, sig),
    }
}

/// SLH-DSA (FIPS 205), parameter set **SLH-DSA-SHA2-256s** (SHA-2 for CNSA-hash
/// consistency; the small-signature "s" variant). Keys derive deterministically
/// from a 32-byte seed via a seeded CSPRNG, and signing is deterministic.
pub mod slhdsa {
    use super::StdRng;
    use fips205::slh_dsa_sha2_256s as p;
    use fips205::traits::{SerDes, Signer, Verifier};
    use rand::SeedableRng;

    fn keypair(seed: [u8; 32]) -> (p::PublicKey, p::PrivateKey) {
        let mut rng = StdRng::from_seed(seed);
        p::try_keygen_with_rng(&mut rng).expect("SLH-DSA key generation")
    }

    pub fn public_key(seed: [u8; 32]) -> Vec<u8> {
        keypair(seed).0.into_bytes().to_vec()
    }

    pub fn sign(seed: [u8; 32], msg: &[u8]) -> Vec<u8> {
        let (_pk, sk) = keypair(seed);
        sk.try_sign(msg, &[], false).expect("SLH-DSA signing").to_vec()
    }

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

/// Lowercase-hex helpers (no external dep; used for keys, sigs, seal fields).
pub mod hex {
    pub fn encode(bytes: &[u8]) -> String {
        let mut s = String::with_capacity(bytes.len() * 2);
        for b in bytes {
            s.push_str(&format!("{b:02x}"));
        }
        s
    }

    pub fn decode(s: &str) -> Result<Vec<u8>, String> {
        let s = s.trim();
        if s.len() % 2 != 0 {
            return Err("hex string has odd length".into());
        }
        (0..s.len())
            .step_by(2)
            .map(|i| {
                u8::from_str_radix(&s[i..i + 2], 16).map_err(|_| "invalid hex digit".to_string())
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_roundtrips_and_rejects_bad_input() {
        assert_eq!(hex::encode(&[0x00, 0x5a, 0xff, 0x10]), "005aff10");
        assert_eq!(hex::decode("005aff10").unwrap(), [0x00, 0x5a, 0xff, 0x10]);
        assert!(hex::decode("abc").is_err());
        assert!(hex::decode("zz").is_err());
    }

    #[test]
    fn ml_dsa_sign_verify_roundtrips_and_rejects_tamper() {
        let seed = IdentityKeyPair::generate().export_secret();
        let pk = pubkey_of(Algo::MlDsa, seed);
        let msg = b"deadbeef  talkrypt.tar.gz\n";
        let sig = sign(Algo::MlDsa, seed, msg);
        assert!(verify(Algo::MlDsa, &pk, msg, &sig));
        assert!(!verify(Algo::MlDsa, &pk, b"TAMPERED", &sig));
    }

    #[test]
    fn slh_dsa_sign_verify_roundtrips_and_rejects_tamper() {
        let seed = [42u8; 32];
        let pk = pubkey_of(Algo::SlhDsa, seed);
        let msg = b"cafebabe  talkrypt.apk\n";
        let sig = sign(Algo::SlhDsa, seed, msg);
        assert!(verify(Algo::SlhDsa, &pk, msg, &sig));
        assert!(!verify(Algo::SlhDsa, &pk, b"TAMPERED", &sig));
    }

    #[test]
    fn pubkey_is_deterministic_from_seed_both_schemes() {
        let seed = [7u8; 32];
        assert_eq!(pubkey_of(Algo::MlDsa, seed), pubkey_of(Algo::MlDsa, seed));
        assert_eq!(pubkey_of(Algo::SlhDsa, seed), pubkey_of(Algo::SlhDsa, seed));
    }
}
