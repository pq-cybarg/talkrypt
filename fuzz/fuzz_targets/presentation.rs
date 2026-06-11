#![no_main]
//! Fuzz the contact-presentation decoder (the self-introduction a peer sends:
//! identity + chain + claims). Arbitrary bytes must never panic; this is the
//! first thing received from an unauthenticated peer, so it must be robust to
//! fully adversarial input. Successful decodes must re-encode and re-decode.
//!
//! Run: `cargo +nightly fuzz run presentation`

use libfuzzer_sys::fuzz_target;
use talkrypt_core::Presentation;

fuzz_target!(|data: &[u8]| {
    if let Ok(p) = Presentation::decode(data) {
        let re = p.encode();
        Presentation::decode(&re).expect("re-decode of re-encoded presentation");
    }
});
