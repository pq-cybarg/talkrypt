//! Fuzz the at-rest sealed-envelope decoder (`TKS1`, SECURITY-AUDIT R-8/F-15).
//!
//! A sealed blob lives on disk (the device seed, NYM mnemonic, segment keys); an
//! attacker with file access can corrupt or forge arbitrary bytes there, and the
//! decode path runs before any key material is recovered. `tier_of` and the
//! header parse inside `unseal` must be **total** — a malformed/hostile blob must
//! resolve to a clean `Err`, never a panic / OOM / out-of-range slice (the class
//! of remote-DoS bug the ratchet-header fuzzer surfaced as F-14).
//!
//! Driving `unseal` with no passphrase and no wrapper exercises every
//! length-prefixed field decode (magic, version, tier, flags, salt, wrapped-KEK,
//! nonce, ciphertext) and all the length guards + `finish()`, then bails before
//! any Argon2id / AEAD work — so the parser is fuzzed cheaply (no per-input KDF
//! cost dominating throughput).
//!
//! Run: `cargo +nightly fuzz run seal_envelope`
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Peek the custody tier: pure parse of magic+version+tier. Total function.
    let _ = talkrypt_core::seal::tier_of(data);

    // Full envelope header decode. With `None, None`, every field is parsed and
    // length-checked, then it returns a declared-factor error before running any
    // crypto — so this fuzzes the decoder, not Argon2/AEAD. Must never panic.
    let _ = talkrypt_core::seal::unseal(data, None, None);
});
