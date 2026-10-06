#![no_main]
//! Fuzz the TreeKEM group-layer decoders — `KeyPackage`, `Commit`, and `Welcome`
//! — across all three KEM profiles (hybrid / pq-pure / pq-pure-compact).
//!
//! These are attacker-reachable: a malicious or MITM group peer sends a
//! KeyPackage (join request), a Commit (membership/epoch change), or a Welcome
//! (new-member bootstrap), all parsed from untrusted wire bytes BEFORE the
//! sender's signature/membership is authenticated. A panic or over-read here is a
//! remote DoS on every group member (and the historically-flagged G3/G4 commit
//! path). Decode must tolerate anything: arbitrary input never panics, and any
//! successful decode must round-trip through the serializer.
//!
//! This closes the fuzz-coverage gap for the group decoders (the pairwise ratchet
//! header already has `ratchet_header`; the group tier had none). CLAUDE.md:
//! every attacker-reachable decoder gets a fuzz target.
//!
//! Run: `cargo +nightly fuzz run treekem_parser`

use libfuzzer_sys::fuzz_target;
use talkrypt_crypto::{Commit, KemProfile, KeyPackage, Welcome};

fuzz_target!(|data: &[u8]| {
    // First byte selects the KEM profile to parse against (so the per-profile
    // public-key length decoding stays in scope); the rest is the message body.
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

    // Assert byte-stable round-trip (re-encode -> re-decode -> re-encode yields
    // identical bytes). This exercises the re-decode path without requiring the
    // group types to implement `Debug`/`PartialEq` (KeyPackage implements
    // neither), and is a strictly stronger structural check than Ok-ness alone.
    if let Ok(kp) = KeyPackage::decode(profile.clone(), body) {
        let re = kp.encode();
        let kp2 = KeyPackage::decode(profile.clone(), &re).expect("KeyPackage re-decode");
        assert_eq!(re, kp2.encode(), "KeyPackage round-trip not byte-stable");
    }
    if let Ok(c) = Commit::decode(profile.clone(), body) {
        let re = c.encode();
        let c2 = Commit::decode(profile.clone(), &re).expect("Commit re-decode");
        assert_eq!(re, c2.encode(), "Commit round-trip not byte-stable");
    }
    if let Ok(w) = Welcome::decode(profile.clone(), body) {
        let re = w.encode();
        let w2 = Welcome::decode(profile.clone(), &re).expect("Welcome re-decode");
        assert_eq!(re, w2.encode(), "Welcome round-trip not byte-stable");
    }
});
