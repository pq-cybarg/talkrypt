#![no_main]
//! Fuzz the Double-Ratchet message-header decoder across all three KEM
//! profiles (hybrid / pq-pure / pq-pure-compact). The header is attacker-
//! controlled wire data parsed on every inbound message, so it must never
//! panic or over-read. A successful decode must round-trip through the
//! serializer. Exercised via the crate's `fuzzing`-gated hook since `Header`
//! is crate-private.
//!
//! Run: `cargo +nightly fuzz run ratchet_header`

use libfuzzer_sys::fuzz_target;
use talkrypt_crypto::ratchet::fuzz_header_roundtrip;
use talkrypt_crypto::KemProfile;

fuzz_target!(|data: &[u8]| {
    // The first byte selects which profile to parse against; the rest is the
    // header body. Covering all profiles keeps the per-profile public-key
    // length decoding in scope.
    let (profile, body) = match data.split_first() {
        Some((sel, rest)) => {
            let profile = match sel % 3 {
                0 => KemProfile::hybrid(),
                1 => KemProfile::pq_pure(),
                _ => KemProfile::pq_pure_compact(),
            };
            (profile, rest)
        }
        None => (KemProfile::hybrid(), data),
    };
    fuzz_header_roundtrip(profile, body);
});
