#![no_main]
//! Fuzz the identity-chain decoder: arbitrary bytes must never panic or
//! over-read — only ever yield `Ok` or a `CryptoError`. This is the
//! account→device→segment certificate chain an attacker can hand us; the
//! decoder runs *before* any signature is verified, so it must be robust to
//! fully adversarial input.
//!
//! A successful decode must re-encode and re-decode (structural round-trip),
//! proving the parser and serializer agree on the wire format.
//!
//! Run: `cargo +nightly fuzz run identity_chain`

use libfuzzer_sys::fuzz_target;
use talkrypt_crypto::IdentityChain;

fuzz_target!(|data: &[u8]| {
    if let Ok(chain) = IdentityChain::decode(data) {
        let re = chain.encode();
        IdentityChain::decode(&re).expect("re-decode of re-encoded identity chain");
    }
});
