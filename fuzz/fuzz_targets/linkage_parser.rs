#![no_main]
//! Fuzz the SUB-SPEC B linkage decoders — `Predicate`, `LinkageProof`, and
//! `LinkagePayload` all parse untrusted, adversarial bytes (a linkage disclosure
//! arrives inside the encrypted channel but is attacker-chosen). Arbitrary input
//! must never panic; decode either fails cleanly or, on success, re-encodes and
//! re-decodes to an equal value. Decode runs BEFORE any cryptographic
//! verification (`MlDsaCertBackend::verify`), so it must tolerate anything.
//!
//! Run: `cargo +nightly fuzz run linkage_parser`

use libfuzzer_sys::fuzz_target;
use talkrypt_core::linkage::{LinkagePayload, LinkageProof, Predicate};

fuzz_target!(|data: &[u8]| {
    if let Some(p) = Predicate::decode(data) {
        assert_eq!(Predicate::decode(&p.encode()).as_ref(), Some(&p));
    }
    if let Some(lp) = LinkageProof::decode(data) {
        assert_eq!(LinkageProof::decode(&lp.encode()).as_ref(), Some(&lp));
    }
    if let Some(pl) = LinkagePayload::decode(data) {
        assert_eq!(LinkagePayload::decode(&pl.encode()).as_ref(), Some(&pl));
    }
});
