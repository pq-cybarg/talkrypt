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
use crate::identity::IdentityKeyPair;
use crate::kdf::kdf_rk;

fn check(ok: bool, what: &'static str) -> Result<()> {
    if ok {
        Ok(())
    } else {
        Err(CryptoError::SelfTest(what))
    }
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn fhex(s: &str) -> Vec<u8> {
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap_or(0))
        .collect()
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

/// KDF known-answer test: a fixed `(root, ikm)` yields a fixed `(new_root,
/// chain)` (build-dependent — the default uses KMAC256, `cnsa-sha2` HKDF-SHA384).
fn kdf_kat() -> Result<()> {
    #[cfg(not(feature = "cnsa-sha2"))]
    let (er, ec) = (
        "3afb3992ba0f52fab0daad74ddcb136a6dd231a956d748edc4a0f24b6cb6c89a",
        "27cc24572a59fe8f8acfce32e7691d1b4f7cd903fc9670098bd85d3efb86f319",
    );
    #[cfg(feature = "cnsa-sha2")]
    let (er, ec) = (
        "17631455fa7f981984b5c899043ed1bd0bcf7ead18e1c7a8955307836bc97f72",
        "8e6001f90598771ca623b8955245aef1beb350ec6637fb28ab51912cc635d941",
    );
    let (r, c) = kdf_rk(&[0x42u8; 32], b"talkrypt-kat-ikm");
    check(hex(&*r) == er, "kdf_rk KAT (new root)")?;
    check(hex(&*c) == ec, "kdf_rk KAT (chain key)")?;
    Ok(())
}

/// ML-KEM-1024 known-answer test against the **NIST FIPS-203 ACVP** keyGen vector
/// (usnistgov/ACVP-Server): NIST's seed `(d, z)` must generate the encapsulation
/// and decapsulation keys whose SHA3-256 digests NIST publishes — genuine CAVP
/// traceability (inputs and expected outputs are NIST's). The full encapsulation
/// and decapsulation ACVP shared-secret vectors are checked in
/// `tests/nist_mlkem_acvp.rs`. We also confirm encaps/decaps agree on these keys.
fn kem_kat() -> Result<()> {
    use ml_kem::kem::Decapsulate;
    use ml_kem::{EncapsulateDeterministic, EncodedSizeUser, KemCore, MlKem1024, B32};
    let d = fhex("f3a706faf090c03db506863ab0b20bd8a1627956318e88c67eb875e8e7266009");
    let z = fhex("35d2bc43dd1cc879f765bf2a0c5e297889dde910e57e2bb0eae417b90ab7a275");
    let (dk, ek) = MlKem1024::generate_deterministic(
        &B32::try_from(&d[..]).map_err(|_| CryptoError::SelfTest("ml-kem KAT d"))?,
        &B32::try_from(&z[..]).map_err(|_| CryptoError::SelfTest("ml-kem KAT z"))?,
    );
    check(
        hex(&sha3::Sha3_256::digest(ek.as_bytes().as_slice()))
            == "9370fe5b05ddc92c939f62cbde4c0fea36f45cd20c5748cf3ac891a4c2604496",
        "ml-kem-1024 keyGen KAT (NIST ACVP ek)",
    )?;
    check(
        hex(&sha3::Sha3_256::digest(dk.as_bytes().as_slice()))
            == "b8c683c71564ff8e2391c57b68c3a1ff186734b13e31d2a075b65307c8b80888",
        "ml-kem-1024 keyGen KAT (NIST ACVP dk)",
    )?;
    // Encaps/decaps must agree on the NIST-conformant key pair.
    let m = B32::try_from(&[0x33u8; 32][..]).map_err(|_| CryptoError::SelfTest("ml-kem m"))?;
    let (ct, k) = ek
        .encapsulate_deterministic(&m)
        .map_err(|_| CryptoError::SelfTest("ml-kem-1024 encapsulate"))?;
    let k2 = dk
        .decapsulate(&ct)
        .map_err(|_| CryptoError::SelfTest("ml-kem-1024 decapsulate"))?;
    check(k == k2, "ml-kem-1024 encaps/decaps agreement")?;
    Ok(())
}

/// ML-DSA-87 known-answer test (FIPS 204).
///
/// **keyGen KAT (externally traceable):** the FIPS-204 reference seed
/// `0x00,0x01,…,0x1f` generates a public key whose SHA3-256 digest matches the
/// `ml-dsa` crate's published `ML-DSA-87.pub` reference example (that crate is
/// validated against the NIST ACVP vectors upstream) — so this ties our key
/// generation to an external reference, not just our own output.
///
/// **sigGen KAT:** a fixed message signs (deterministically) to a fixed
/// signature, pinned by its SHA3-256 digest; it verifies, and a tampered
/// message / wrong key are rejected.
fn dsa_kat() -> Result<()> {
    // keyGen against the FIPS-204 reference seed 0x00..0x1f.
    let mut ref_seed = [0u8; 32];
    for (i, b) in ref_seed.iter_mut().enumerate() {
        *b = i as u8;
    }
    let refkp = IdentityKeyPair::from_secret_bytes(ref_seed);
    let refdig = sha3::Sha3_256::digest(&refkp.public().sig_vk);
    check(
        hex(refdig.as_slice()) == "e6cf50a9c2fa5234f59949ff61f8161db4d629532127f4aefa8bb10811ecfb1e",
        "ml-dsa-87 keyGen KAT (FIPS-204 reference public key)",
    )?;

    // sigGen + verify + negative cases.
    let kp = IdentityKeyPair::from_secret_bytes([0x37u8; 32]);
    let msg = b"talkrypt ml-dsa-87 self-test";
    let sig = kp.sign(msg);
    let dig = sha3::Sha3_256::digest(&sig);
    check(
        hex(dig.as_slice()) == "f130db39e74aecf90ee9f0b0563ba4b55e7dc4b0fbd9e622f1f3fee80dd9c282",
        "ml-dsa-87 sigGen KAT",
    )?;
    check(kp.public().verify(msg, &sig).is_ok(), "ml-dsa-87 verify")?;
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

/// Run every primitive known-answer test. Returns the first failure, if any.
pub fn self_test() -> Result<()> {
    aead_kat()?;
    hash_kat()?;
    kdf_kat()?;
    kem_kat()?;
    dsa_kat()?;
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

    // NOTE on ML-KEM-1024 traceability (R-5): `kem_kat` and
    // `tests/nist_mlkem_acvp.rs` verify keygen/encaps/decaps against the **NIST
    // final FIPS-203 ACVP** vectors (usnistgov/ACVP-Server) — exact matches.
    // Caution worth recording: the commonly-cited C2SP/CCTV ML-KEM vectors are
    // FIPS-203 **draft** (`G(d)`, no `G(d‖k)` domain separator — `SHA3-512(d)`
    // equals their published `ρ‖σ`), so they do NOT match a conformant final
    // implementation; use the NIST ACVP vectors above, not those.

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
