#![no_main]
//! Fuzz the SUB-SPEC C vouch decoders — `Vouch`, `VouchTarget`, and `VouchPolicy`
//! all parse untrusted, adversarial bytes (a vouch arrives inside the encrypted
//! channel but is attacker-chosen). Arbitrary input must never panic; decode
//! either fails cleanly or, on success, re-encodes and re-decodes to an equal
//! value (the wire-format round-trip invariant). Decode runs BEFORE signature
//! verification, so it must tolerate anything.
//!
//! Run: `cargo +nightly fuzz run vouch_parser`

use libfuzzer_sys::fuzz_target;
use talkrypt_core::vouch::{Vouch, VouchPolicy, VouchTarget};

fuzz_target!(|data: &[u8]| {
    if let Some(t) = VouchTarget::decode(data) {
        assert_eq!(VouchTarget::decode(&t.encode()).as_ref(), Some(&t));
    }
    if let Some(v) = Vouch::decode(data) {
        assert_eq!(Vouch::decode(&v.encode()).as_ref(), Some(&v));
    }
    if let Some(p) = VouchPolicy::decode(data) {
        assert_eq!(VouchPolicy::decode(&p.encode()).as_ref(), Some(&p));
    }
});
