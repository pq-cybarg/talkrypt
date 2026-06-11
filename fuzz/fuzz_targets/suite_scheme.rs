//! Fuzz the crypto-scheme parsing/matching path. A "scheme" is an arbitrary
//! suite id (a string) plus opaque params; a receiver derives its
//! `scheme_hash` fingerprint and matches it against its local registry. None of
//! `scheme_hash`, `meets_cnsa_floor`, or `get_by_scheme_hash` may panic on any
//! input — a peer can advertise a hostile id/params, and a non-matching scheme
//! must resolve to a clean "unknown scheme" error (the "receiver lacks this
//! scheme, cannot participate" case), never a crash.
//!
//! Run: `cargo +nightly fuzz run suite_scheme`
#![no_main]

use libfuzzer_sys::fuzz_target;
use std::sync::OnceLock;
use talkrypt_crypto::suite::meets_cnsa_floor;
use talkrypt_crypto::{scheme_hash, SuiteRegistry};

fn registry() -> &'static SuiteRegistry {
    static REG: OnceLock<SuiteRegistry> = OnceLock::new();
    REG.get_or_init(SuiteRegistry::with_defaults)
}

fuzz_target!(|data: &[u8]| {
    // Split the input into a (possibly invalid-UTF-8) suite id and params at the
    // first NUL, mirroring how an attacker-chosen id/params pair would arrive.
    let (id_bytes, params) = match data.iter().position(|&b| b == 0) {
        Some(i) => (&data[..i], &data[i + 1..]),
        None => (data, &[][..]),
    };
    let id = String::from_utf8_lossy(id_bytes);

    // Deriving the fingerprint and the floor check must be total functions.
    let fp = scheme_hash(&id, params);
    let _ = meets_cnsa_floor(&id);

    // Looking the fingerprint up in a real default registry must never panic;
    // a non-match must be a clean error, not a crash.
    let _ = registry().get_by_scheme_hash(&fp);
});
