#![no_main]
//! Fuzz the wire decoder: arbitrary bytes must never panic or over-read — only
//! ever yield `Ok` or a `WireError`.
//!
//! Run: `cargo +nightly fuzz run wire_reader`

use libfuzzer_sys::fuzz_target;
use talkrypt_wire::Reader;

fuzz_target!(|data: &[u8]| {
    let mut r = Reader::new(data);
    // Drain a bounded number of length-prefixed fields; must never panic.
    for _ in 0..64 {
        match r.get_bytes() {
            Ok(b) => {
                // The returned slice must lie within the input.
                assert!(b.len() <= data.len());
            }
            Err(_) => break,
        }
    }
});
