//! Real-radio [`MeshNode`] adapters — Meshtastic and Meshcore.
//!
//! The USB-serial adapters are **built** behind `feature = "mesh-radio"`:
//! [`super::meshtastic::MeshtasticSerial`] and [`super::meshcore::MeshcoreSerial`].
//! Their pure codecs (Meshtastic protobuf + Stream API framing; Meshcore companion
//! frames + base64 text wrapping) are unit-tested with golden vectors; the serial
//! I/O is validated on hardware. They plug straight into the [`MeshNode`] seam, so
//! the rest of talkrypt — beacon, messaging, fragmentation, classification — works
//! unchanged over them, exactly as over [`super::MockMeshNode`].
//!
//! ```ignore
//! # #[cfg(feature = "mesh-radio")]
//! use talkrypt_transport::mesh::MeshtasticSerial;
//! let node = MeshtasticSerial::open("/dev/tty.usbserial-0001", 115200).await?;
//! core.start_mesh_messaging(node, policy).await; // messages ride the mesh
//! // or: MultiBeacon::new().with(Arc::new(MeshBeacon::new(node, policy)))
//! ```
//!
//! # Meshtastic ([`super::meshtastic`])
//! USB serial (also BLE / TCP on a real firmware — this adapter is serial). The
//! `ToRadio` / `FromRadio` protobuf stream over the Stream API framing
//! (`0x94 0xC3 <len16> <pb>`). Sends `ToRadio { packet: MeshPacket { to:
//! BROADCAST, channel, decoded: Data { portnum: PRIVATE_APP, payload } } }`;
//! receives `FromRadio { packet }` and surfaces the `PRIVATE_APP` payload. Verified
//! field numbers; `PRIVATE_APP = 256` carries arbitrary binary, so no wrapping is
//! needed. Conservative MTU 200. This is the primary, fully-verified adapter.
//!
//! # Meshcore ([`super::meshcore`])
//! USB serial companion protocol. Channel messages carry a UTF-8 *text* field, so
//! talkrypt fragments are **base64-wrapped** for text-safety. Command/response
//! payload layouts (`CMD_SEND_CHANNEL_TXT_MSG` 0x03, `PACKET_CHANNEL_MSG_RECV`
//! 0x08 / `_V3` 0x11) are verified against the companion protocol doc; the serial
//! OUTER framing (`[type][len16 LE][payload]`) is firmware-dependent — see the
//! module docs. MTU 120 (so `base64(fragment) ≤ 160` text chars). Baseline AES-128
//! channel key is an untrusted outer wrapper. **Validate on your firmware.**
//!
//! # BLE (host-language) alternative
//! A phone talking to a node over BLE implements the seam in Kotlin/Swift via the
//! FFI callback (`MeshNodeBackend` + `FfiMeshNode.deliverPacket`) rather than these
//! native serial adapters. See the FFI surface and `docs/mesh-lora-backend.md`.
