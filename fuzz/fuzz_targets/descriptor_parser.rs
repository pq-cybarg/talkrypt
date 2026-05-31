#![no_main]
//! Fuzz the chat-descriptor parser: arbitrary URI strings must never panic;
//! parse either succeeds or returns an error, and any successful parse must
//! round-trip back to an equal URI.
//!
//! Run: `cargo +nightly fuzz run descriptor_parser`

use libfuzzer_sys::fuzz_target;
use talkrypt_core::ChatDescriptor;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        if let Ok(desc) = ChatDescriptor::from_uri(s) {
            // Successful parses must re-encode and re-parse to an equal value.
            let uri = desc.to_uri();
            let reparsed = ChatDescriptor::from_uri(&uri).expect("round-trip parse");
            assert_eq!(desc, reparsed);
        }
    }
});
