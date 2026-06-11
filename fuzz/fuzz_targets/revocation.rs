#![no_main]
//! Fuzz the revocation decoder (an account-signed statement that refuses a
//! leaked device key). Arbitrary bytes must never panic; the decode runs before
//! signature verification, so it must tolerate adversarial input. Successful
//! decodes must re-encode and re-decode.
//!
//! Run: `cargo +nightly fuzz run revocation`

use libfuzzer_sys::fuzz_target;
use talkrypt_crypto::Revocation;

fuzz_target!(|data: &[u8]| {
    if let Ok(rev) = Revocation::decode(data) {
        let re = rev.encode();
        Revocation::decode(&re).expect("re-decode of re-encoded revocation");
    }
});
