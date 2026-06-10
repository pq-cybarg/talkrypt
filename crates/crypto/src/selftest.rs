//! Power-on self-tests (POST) for the cryptographic primitives — SECURITY-AUDIT
//! R-5, and a prerequisite for any FIPS 140-3 posture (the module must verify
//! its primitives at start-up and **fail closed** if any is broken or
//! corrupted).
//!
//! [`self_test`] runs:
//!   * **AES-256-GCM** — a fixed known-answer test (NIST empty-message vector)
//!     plus a round-trip and a tamper-rejection check.
//!   * **Hash** — a known-answer test for the active hash (SHA3-384 by default,
//!     SHA-384 under `cnsa-sha2`) on the empty input.
//!   * **KDF** — determinism and domain-separation of `kdf_rk`/`kdf_ck`.
//!   * **ML-KEM-1024** — encapsulate/decapsulate agreement (the FIPS conditional
//!     keygen self-test) plus rejection of a tampered ciphertext.
//!   * **ML-DSA-87** — sign/verify round-trip plus rejection of a tampered
//!     message (pairwise consistency).
//!
//! [`ensure_self_tested`] runs it exactly once and **aborts the process** on
//! failure — call it at start-up before any crypto is used.

use sha3::Digest as _; // brings the Digest trait into scope (works for sha2 too)

use crate::aead;
use crate::error::{CryptoError, Result};
use crate::hash::Hash;
use crate::hybrid::{KemProfile, RatchetSecret};
use crate::identity::IdentityKeyPair;
use crate::kdf::{kdf_ck, kdf_rk};

fn check(ok: bool, what: &'static str) -> Result<()> {
    if ok {
        Ok(())
    } else {
        Err(CryptoError::SelfTest(what))
    }
}

/// AES-256-GCM known-answer + round-trip + tamper test.
fn aead_kat() -> Result<()> {
    // NIST AES-256-GCM vector: key=0^256, nonce=0^96, no plaintext, no AAD →
    // ciphertext is empty and the tag is the value below. Our `seal` returns
    // `ciphertext || tag`, so for empty plaintext that is just the 16-byte tag.
    let key = [0u8; 32];
    let nonce = [0u8; 12];
    let expect_tag: [u8; 16] = [
        0x53, 0x0f, 0x8a, 0xfb, 0xc7, 0x45, 0x36, 0xb9, 0xa9, 0x63, 0xb4, 0xf1, 0xc4, 0xcb, 0x73,
        0x8b,
    ];
    let kat = aead::seal(&key, &nonce, b"", b"")?;
    check(kat == expect_tag, "aes-256-gcm KAT")?;

    // Round-trip + tamper rejection with a non-trivial message.
    let k = [0x11u8; 32];
    let n = [0x22u8; 12];
    let pt = b"talkrypt power-on self-test";
    let aad = b"aad";
    let mut ct = aead::seal(&k, &n, pt, aad)?;
    check(aead::open(&k, &n, &ct, aad)? == *pt, "aes-256-gcm round-trip")?;
    ct[0] ^= 0x01; // flip a bit
    check(aead::open(&k, &n, &ct, aad).is_err(), "aes-256-gcm tamper rejection")?;
    Ok(())
}

/// Known-answer test for the active hash on the empty input.
fn hash_kat() -> Result<()> {
    #[cfg(not(feature = "cnsa-sha2"))]
    // SHA3-384("")
    let expect: [u8; 48] = [
        0x0c, 0x63, 0xa7, 0x5b, 0x84, 0x5e, 0x4f, 0x7d, 0x01, 0x10, 0x7d, 0x85, 0x2e, 0x4c, 0x24,
        0x85, 0xc5, 0x1a, 0x50, 0xaa, 0xaa, 0x94, 0xfc, 0x61, 0x99, 0x5e, 0x71, 0xbb, 0xee, 0x98,
        0x3a, 0x2a, 0xc3, 0x71, 0x38, 0x31, 0x26, 0x4a, 0xdb, 0x47, 0xfb, 0x6b, 0xd1, 0xe0, 0x58,
        0xd5, 0xf0, 0x04,
    ];
    #[cfg(feature = "cnsa-sha2")]
    // SHA-384("")
    let expect: [u8; 48] = [
        0x38, 0xb0, 0x60, 0xa7, 0x51, 0xac, 0x96, 0x38, 0x4c, 0xd9, 0x32, 0x7e, 0xb1, 0xb1, 0xe3,
        0x6a, 0x21, 0xfd, 0xb7, 0x11, 0x14, 0xbe, 0x07, 0x43, 0x4c, 0x0c, 0xc7, 0xbf, 0x63, 0xf6,
        0xe1, 0xda, 0x27, 0x4e, 0xde, 0xbf, 0xe7, 0x6f, 0x65, 0xfb, 0xd5, 0x1a, 0xd2, 0xf1, 0x48,
        0x98, 0xb9, 0x5b,
    ];
    let got = Hash::digest(b"");
    check(got.as_slice() == &expect[..], "hash KAT")?;
    Ok(())
}

/// KDF determinism + domain separation (a corrupted KDF fails these).
fn kdf_kat() -> Result<()> {
    let root = [0x42u8; 32];
    let (r1, c1) = kdf_rk(&root, b"ikm");
    let (r2, c2) = kdf_rk(&root, b"ikm");
    check(*r1 == *r2 && *c1 == *c2, "kdf_rk determinism")?;
    check(*r1 != *c1, "kdf_rk domain separation (root != chain)")?;
    let (r3, _) = kdf_rk(&root, b"other-ikm");
    check(*r1 != *r3, "kdf_rk input sensitivity")?;
    let (next, mk_seed) = kdf_ck(&c1);
    check(*next != *c1 && *next != *mk_seed, "kdf_ck advance + separation")?;
    Ok(())
}

/// ML-KEM-1024 encapsulate/decapsulate agreement + tamper rejection.
fn kem_consistency() -> Result<()> {
    let (sk, pk) = RatchetSecret::generate(KemProfile::pq_pure());
    let (ct, ss_enc) = pk.encapsulate()?;
    let ss_dec = sk.decapsulate(&ct)?;
    check(ss_enc == ss_dec, "ml-kem-1024 encaps/decaps agreement")?;
    // ML-KEM uses implicit rejection: a tampered ciphertext decapsulates to a
    // *different* secret rather than erroring, so the secrets must differ.
    let mut bad = ct.clone();
    bad[0] ^= 0x01;
    let ss_bad = sk.decapsulate(&bad)?;
    check(ss_bad != ss_enc, "ml-kem-1024 tampered-ct rejection")?;
    Ok(())
}

/// ML-DSA-87 sign/verify round-trip + tamper rejection (deterministic keypair).
fn dsa_consistency() -> Result<()> {
    let kp = IdentityKeyPair::from_secret_bytes([0x37u8; 32]);
    let msg = b"talkrypt ml-dsa-87 self-test";
    let sig = kp.sign(msg);
    check(kp.public().verify(msg, &sig).is_ok(), "ml-dsa-87 sign/verify")?;
    check(
        kp.public().verify(b"different message", &sig).is_err(),
        "ml-dsa-87 wrong-message rejection",
    )?;
    let other = IdentityKeyPair::from_secret_bytes([0x99u8; 32]);
    check(
        other.public().verify(msg, &sig).is_err(),
        "ml-dsa-87 wrong-key rejection",
    )?;
    Ok(())
}

/// Run every primitive self-test. Returns the first failure, if any.
pub fn self_test() -> Result<()> {
    aead_kat()?;
    hash_kat()?;
    kdf_kat()?;
    kem_consistency()?;
    dsa_consistency()?;
    Ok(())
}

/// Run [`self_test`] exactly once, **aborting the process** if it fails. Call at
/// start-up before any cryptographic operation. Subsequent calls are no-ops.
/// Aborting (not unwinding) is deliberate: a broken primitive must not be
/// catchable or recoverable.
pub fn ensure_self_tested() {
    use std::sync::Once;
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        if let Err(e) = self_test() {
            eprintln!("FATAL: talkrypt cryptographic self-test failed: {e}");
            std::process::abort();
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The full POST passes — this also validates every pinned KAT vector in
    /// this file, so a mistyped constant fails here (in CI), never in production.
    #[test]
    fn self_test_passes() {
        self_test().expect("power-on self-test must pass");
    }

    /// `ensure_self_tested` is idempotent and does not abort on a good build.
    #[test]
    fn ensure_is_idempotent() {
        ensure_self_tested();
        ensure_self_tested();
    }
}
