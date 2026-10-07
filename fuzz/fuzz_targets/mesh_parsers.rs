#![no_main]
//! Fuzz the foreign-protocol MESH ingest decoders (round-2 pentest, F-20). These
//! parse untrusted Meshtastic / MQTT / Meshcore bytes straight off a LoRa radio or
//! a public MQTT broker — BEFORE any talkrypt seal/AEAD check — so a malformed
//! packet must return `None`, never panic or over-read. A pre-auth panic here is a
//! remote process abort on every subscribed node (the F-14/G3/G4 class).
//!
//! This closes the coverage gap round 2 found: the `fuzz` crate did not even
//! depend on `talkrypt-transport`, so none of these were fuzzed — which is how the
//! `meshtastic::each_field` `pos + len` overflow (fixed alongside this target)
//! shipped. `frag::parse_fragment` is separately Kani-proven.
//!
//! Run: `cargo +nightly fuzz run mesh_parsers`

use libfuzzer_sys::fuzz_target;
use talkrypt_transport::mesh::{meshcore, meshtastic, mqtt};

fuzz_target!(|data: &[u8]| {
    // Meshtastic FromRadio / MeshPacket protobuf (reaches `each_field`, the
    // overflow site). Both must tolerate arbitrary bytes.
    let _ = meshtastic::parse_fromradio(data);
    let _ = meshtastic::parse_meshpacket(data);
    // Meshtastic MQTT ServiceEnvelope wrapper (the internet-reachable path).
    let _ = mqtt::parse_service_envelope(data);
    // Meshcore channel-recv (base64 + fixed-offset reads).
    let _ = meshcore::parse_channel_recv_b64(data);
});
