//! Real-radio [`MeshNode`] adapters — Meshtastic and Meshcore.
//!
//! LEAVE-BEHIND / DEVICE-GATED. There is no LoRa node in the dev loop, so these
//! adapters are documented, correct-by-construction ports that plug into the
//! [`MeshNode`] seam; they are validated on hardware later. The testable core —
//! fragmentation ([`super::frag`]), classification ([`super::MeshIngest`]), and
//! the beacon ([`super::MeshBeacon`]) — runs fully over [`super::MockMeshNode`]
//! today and does not depend on these.
//!
//! Both stacks expose, from the phone/desktop side, the same shape the seam needs:
//! a BLE / serial link to a node, a "send this payload on this channel" call, and
//! an inbound packet stream. The node firmware has already handled the LoRa PHY,
//! routing, and (if configured) its own channel crypto — we deal only in
//! application payloads, and talkrypt's own seal is the real security envelope
//! (see the module docs on the mesh security posture).
//!
//! # Meshtastic
//! Transport: BLE (Nordic-UART-style service), USB serial, or TCP. Protocol: the
//! `ToRadio` / `FromRadio` protobuf stream (meshtastic `mesh.proto`). To send, wrap
//! bytes in a `MeshPacket { decoded: Data { portnum: PRIVATE_APP, payload } }` on
//! the configured channel index and write a `ToRadio { packet }`. To receive, read
//! `FromRadio { packet }` and surface `packet.decoded.payload`. Usable MTU for the
//! `Data.payload` is ~233 bytes. Implementation needs a protobuf codec
//! (e.g. `prost`) and a BLE/serial handle — pulled in behind the `mesh-radio`
//! feature so the default build stays lean.
//!
//! # Meshcore
//! Transport: BLE / USB serial companion link. Protocol: Meshcore's framed
//! companion protocol (send/receive channel messages; baseline AES-128 shared
//! key at the network layer, which we treat as an untrusted outer wrapper). Usable
//! MTU ~184-230 depending on build. Same seam: send bytes on a channel, receive an
//! inbound stream.
//!
//! ## Sketch (behind `feature = "mesh-radio"`)
//! ```ignore
//! use crate::mesh::{MeshNode, MeshInbox, MeshPacket};
//! use async_trait::async_trait;
//!
//! pub struct MeshtasticNode { /* BLE/serial handle, channel map, prost codec */ }
//!
//! #[async_trait]
//! impl MeshNode for MeshtasticNode {
//!     fn mtu(&self) -> usize { 233 } // Data.payload budget
//!     async fn send(&self, channel: u8, payload: &[u8]) -> crate::Result<()> {
//!         // build ToRadio{ packet: MeshPacket{ channel, decoded: Data{
//!         //   portnum: PRIVATE_APP, payload } } }, write to the BLE/serial stream
//!         todo!("prost-encode ToRadio and write to the link")
//!     }
//!     async fn subscribe(&self) -> crate::Result<MeshInbox> {
//!         let (inbox, tx) = MeshInbox::channel();
//!         // spawn a reader: decode FromRadio frames, push MeshPacket{ channel,
//!         // payload: decoded.payload, from: Some(node_id) } into `tx`.
//!         todo!("spawn FromRadio reader feeding tx")
//!     }
//! }
//! ```
//! The Meshcore adapter mirrors this against its companion framing. Once either is
//! implemented, the rest of talkrypt (beacon, fragmentation, classification) works
//! unchanged — that is the whole point of the seam.

// No compiled code yet: the adapters land behind `feature = "mesh-radio"` with
// their protobuf / serial dependencies when a device is in the loop. The seam,
// mock, fragmentation, classification, and beacon are fully built and tested in
// the sibling modules.
