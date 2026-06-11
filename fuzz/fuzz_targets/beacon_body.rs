//! Fuzz the scheme-beacon body decoder (the always-encrypted advertisement of
//! a chat's crypto scheme: either a bare fingerprint or a full suite-id+params
//! definition). Arbitrary bytes must never panic; a successful decode must
//! round-trip. Exercised via the crate's `fuzzing`-gated hook since
//! `BeaconBody`'s codec is crate-private.
//!
//! Run: `cargo +nightly fuzz run beacon_body`
#![no_main]

use libfuzzer_sys::fuzz_target;
use talkrypt_crypto::beacon::fuzz_beacon_roundtrip;

fuzz_target!(|data: &[u8]| {
    fuzz_beacon_roundtrip(data);
});
