#![no_main]
//! Fuzz the signed-claim decoder (e.g. a username claim bound to an account).
//! Arbitrary bytes must never panic; the decode runs before signature
//! verification, so it must tolerate adversarial input. Successful decodes
//! must re-encode and re-decode.
//!
//! Run: `cargo +nightly fuzz run signed_claim`

use libfuzzer_sys::fuzz_target;
use talkrypt_crypto::SignedClaim;

fuzz_target!(|data: &[u8]| {
    if let Ok(claim) = SignedClaim::decode(data) {
        let re = claim.encode();
        SignedClaim::decode(&re).expect("re-decode of re-encoded signed claim");
    }
});
