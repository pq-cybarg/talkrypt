#![no_main]
//! Fuzz the SUB-SPEC A presence decoders — `NamePresence` (the self-declared name
//! beacon, whose `Linked` variant carries an embedded identity chain), `NameBook`,
//! and the `Marking` classification codec. All parse untrusted, adversarial bytes
//! (a presence beacon arrives inside the encrypted channel but is attacker-chosen)
//! BEFORE any signature/chain verification, so decode must tolerate anything:
//! arbitrary input never panics, and any success re-encodes/re-decodes equal.
//!
//! Run: `cargo +nightly fuzz run presence_parser`

use libfuzzer_sys::fuzz_target;
use talkrypt_core::marking::Marking;
use talkrypt_core::presence::{NameBook, NamePresence};

fuzz_target!(|data: &[u8]| {
    if let Ok(np) = NamePresence::decode(data) {
        let re = np.encode();
        assert_eq!(NamePresence::decode(&re).ok().as_ref(), Some(&np));
    }
    if let Ok(nb) = NameBook::decode(data) {
        let re = nb.encode();
        assert_eq!(NameBook::decode(&re).ok().as_ref(), Some(&nb));
    }
    if let Ok(m) = Marking::decode(data) {
        let re = m.encode();
        assert_eq!(Marking::decode(&re).ok().as_ref(), Some(&m));
    }
});
