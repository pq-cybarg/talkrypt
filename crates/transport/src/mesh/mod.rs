//! Mesh (LoRa) backend — Meshtastic / Meshcore.
//!
//! Lets talkrypt ride a LoRa mesh as another *local bearer* (like BLE / Wi-Fi),
//! carrying talkrypt's own PQ + AES-sealed ciphertext end-to-end
//! ("encapsulation"), while also reading everything else on the mesh: it
//! recognises other talkrypt nodes' fragments and hands their opaque blob to core
//! to open (if we hold the keys), and surfaces foreign / plaintext traffic
//! CLEARLY LABELLED as **not** talkrypt-secured.
//!
//! # One seam, two stacks
//! [`MeshNode`] is the common denominator of Meshtastic and Meshcore as seen from
//! the phone/desktop: connect to a node over BLE / serial, send one packet's worth
//! of application bytes on a channel, subscribe to inbound packets. Meshtastic and
//! Meshcore adapters (see [`adapters`], feature `mesh-radio`, device-gated) plug
//! in behind it; [`MockMeshNode`] drives tests and offline use.
//!
//! # Security posture
//! LoRa mesh crypto does not meet talkrypt's bar: Meshtastic is AES-256-CTR per
//! channel with a cleartext header, the well-known default key `AQ==`, **no PFS,
//! no channel-message integrity, no channel authentication** (forgeable sender
//! id), and non-PQ DMs; Meshcore's baseline is a shared AES-128 key. So talkrypt's
//! own seal is ALWAYS the real security envelope (encapsulation, the default), and
//! the mesh's own crypto — if any — is an untrusted outer wrapper. A native /
//! plaintext "downgrade" send under *their* crypto is possible but gated behind
//! explicit consent ([`NativeSend`]); it is, by construction, below our standard.
//!
//! The [`crate::LocalBeacon`] implementation lives in [`beacon`]; it slots into
//! [`crate::MultiBeacon`] next to BLE / Wi-Fi with no core change. The
//! fragmentation / reassembly substrate is in [`frag`].

pub mod adapters;
pub mod beacon;
pub mod frag;
pub mod mock;

#[cfg(feature = "mesh-radio")]
pub mod meshcore;
#[cfg(feature = "mesh-radio")]
pub mod meshtastic;

use async_trait::async_trait;
use tokio::sync::mpsc;

use crate::Result;

pub use beacon::MeshBeacon;
pub use mock::{MockMeshFabric, MockMeshNode};

#[cfg(feature = "mesh-radio")]
pub use meshcore::MeshcoreSerial;
#[cfg(feature = "mesh-radio")]
pub use meshtastic::MeshtasticSerial;

/// One packet received from the mesh (already de-radioed by the node firmware —
/// this is an application payload, never raw LoRa symbols).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MeshPacket {
    /// Channel index / hash the packet arrived on.
    pub channel: u8,
    /// The application payload (up to the node's MTU). May be a talkrypt fragment,
    /// or foreign plaintext, depending on the sender.
    pub payload: Vec<u8>,
    /// Sender node id — INDICATIVE ONLY (Meshtastic warns it is a forgeable
    /// hardware MAC). Used for reassembly grouping / coarse signal, never identity.
    pub from: Option<u32>,
}

impl MeshPacket {
    /// A coarse, non-identity source handle for reassembly keying / dedup.
    fn source_key(&self) -> String {
        match self.from {
            Some(id) => format!("{id:08x}"),
            None => "unknown".to_string(),
        }
    }
}

/// A subscription to inbound mesh packets. Dropping it ends the subscription.
pub struct MeshInbox {
    rx: mpsc::UnboundedReceiver<MeshPacket>,
}

impl MeshInbox {
    /// A push-fed inbox: returns the inbox and a sender a backend feeds packets
    /// into (mirrors [`crate::BeaconScan::channel`] for PUSH-style radios / FFI).
    pub fn channel() -> (MeshInbox, mpsc::UnboundedSender<MeshPacket>) {
        let (tx, rx) = mpsc::unbounded_channel();
        (MeshInbox { rx }, tx)
    }

    /// The next inbound packet, or `None` when the node closes.
    pub async fn next(&mut self) -> Option<MeshPacket> {
        self.rx.recv().await
    }
}

/// A connection to a LoRa mesh node (Meshtastic / Meshcore) over BLE or serial.
///
/// Implementors move application payloads only; they never see talkrypt keys or
/// plaintext (the same opaque-bytes invariant as every talkrypt radio backend).
#[async_trait]
pub trait MeshNode: Send + Sync {
    /// Usable application-payload bytes per packet on this node / region. talkrypt
    /// fragments are sized to fit this.
    fn mtu(&self) -> usize;
    /// Transmit one packet's worth of bytes on `channel`. `payload` MUST already
    /// fit [`MeshNode::mtu`] (the caller fragments).
    async fn send(&self, channel: u8, payload: &[u8]) -> Result<()>;
    /// Subscribe to inbound packets.
    async fn subscribe(&self) -> Result<MeshInbox>;
}

/// Whether talkrypt may send NATIVE mesh messages under the network's own crypto
/// (Meshcore AES-128 / Meshtastic AES-256-CTR). This is BELOW talkrypt's PQ
/// standard, so it is gated.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum NativeSend {
    /// Never send native / plaintext (default). Only encapsulated talkrypt
    /// ciphertext leaves the device.
    #[default]
    Off,
    /// Allowed, but the host must confirm each native send (per-message prompt).
    AskEachTime,
    /// Allowed without prompting (a deliberate settings opt-in).
    Allowed,
}

/// Mesh carriage policy: where we transmit, whether we surface foreign traffic,
/// and whether native / downgrade send is permitted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MeshPolicy {
    /// Channel index our encapsulated talkrypt fragments are transmitted on.
    pub channel: u8,
    /// Surface foreign (non-talkrypt) mesh traffic to the host (clearly labelled
    /// as NOT talkrypt-secured). Off by default — a talkrypt user is not
    /// automatically a mesh chat client.
    pub read_foreign: bool,
    /// Whether native / downgrade send is permitted (default [`NativeSend::Off`]).
    pub native_send: NativeSend,
}

impl Default for MeshPolicy {
    fn default() -> Self {
        Self {
            channel: 0,
            read_foreign: false,
            native_send: NativeSend::Off,
        }
    }
}

impl MeshPolicy {
    /// Whether a native / plaintext send is currently permitted WITHOUT a prompt.
    /// [`NativeSend::AskEachTime`] returns `false` here — the host must call the
    /// confirming path, not this convenience check.
    pub fn native_send_allowed(&self) -> bool {
        matches!(self.native_send, NativeSend::Allowed)
    }
}

/// A classified inbound mesh observation. Talkrypt fragments are reassembled into
/// an opaque blob for core to open; everything else is foreign and only surfaced
/// when the policy opts in.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MeshHeard {
    /// A fully reassembled talkrypt-over-mesh sealed blob. OPAQUE — hand to core
    /// (`open_advertisement` for a beacon; the message path for data). If we lack
    /// the keys, core simply cannot open it and we learn only "a talkrypt node is
    /// here".
    Talkrypt {
        blob: Vec<u8>,
        /// Coarse, non-identity source handle (for dedup / signal only).
        source: Option<String>,
    },
    /// Foreign / plaintext mesh traffic — NOT talkrypt-secured. Surfaced only when
    /// [`MeshPolicy::read_foreign`] is set, always labelled downgraded by the host.
    Foreign {
        channel: u8,
        payload: Vec<u8>,
        source: Option<String>,
    },
}

/// Classify + reassemble inbound mesh packets against a policy.
///
/// Holds the bounded [`frag::Reassembler`]. Feed every inbound [`MeshPacket`];
/// get back `Some(MeshHeard)` when a packet either completes a talkrypt message or
/// is foreign traffic the policy wants surfaced. Talkrypt fragments that only
/// partially complete a message return `None`.
pub struct MeshIngest {
    reasm: frag::Reassembler,
    read_foreign: bool,
}

impl MeshIngest {
    pub fn new(policy: &MeshPolicy) -> Self {
        Self {
            reasm: frag::Reassembler::default(),
            read_foreign: policy.read_foreign,
        }
    }

    /// Classify one inbound packet. Talkrypt fragments feed the reassembler and
    /// only yield `Talkrypt` once complete; foreign packets yield `Foreign` iff
    /// `read_foreign`. Malformed / partial input yields `None`.
    pub fn accept(&mut self, packet: &MeshPacket) -> Option<MeshHeard> {
        let source = packet.source_key();
        if frag::parse_fragment(&packet.payload).is_some() {
            // A talkrypt fragment — reassemble; surface only when complete.
            let blob = self.reasm.accept(&source, &packet.payload)?;
            Some(MeshHeard::Talkrypt {
                blob,
                source: Some(source),
            })
        } else if self.read_foreign {
            Some(MeshHeard::Foreign {
                channel: packet.channel,
                payload: packet.payload.clone(),
                source: Some(source),
            })
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pkt(payload: Vec<u8>) -> MeshPacket {
        MeshPacket {
            channel: 0,
            payload,
            from: Some(0xdead_beef),
        }
    }

    #[test]
    fn talkrypt_fragments_reassemble_into_talkrypt_heard() {
        let sealed: Vec<u8> = (0..600u32).map(|i| i as u8).collect();
        let frags = frag::fragment(frag::KIND_FRAME, 1, &sealed, 64).unwrap();
        let mut ingest = MeshIngest::new(&MeshPolicy::default());
        let mut heard = None;
        for f in &frags {
            if let Some(h) = ingest.accept(&pkt(f.clone())) {
                heard = Some(h);
            }
        }
        match heard.expect("a Talkrypt heard once complete") {
            MeshHeard::Talkrypt { blob, .. } => assert_eq!(blob, sealed),
            other => panic!("expected Talkrypt, got {other:?}"),
        }
    }

    #[test]
    fn foreign_traffic_suppressed_by_default() {
        let mut ingest = MeshIngest::new(&MeshPolicy::default());
        assert!(ingest.accept(&pkt(b"hello mesh".to_vec())).is_none());
    }

    #[test]
    fn foreign_traffic_surfaced_when_opted_in() {
        let policy = MeshPolicy {
            read_foreign: true,
            ..Default::default()
        };
        let mut ingest = MeshIngest::new(&policy);
        match ingest.accept(&pkt(b"hello mesh".to_vec())) {
            Some(MeshHeard::Foreign { payload, .. }) => assert_eq!(payload, b"hello mesh"),
            other => panic!("expected Foreign, got {other:?}"),
        }
    }

    #[test]
    fn native_send_gated_off_by_default() {
        assert_eq!(MeshPolicy::default().native_send, NativeSend::Off);
        assert!(!MeshPolicy::default().native_send_allowed());
        let ask = MeshPolicy {
            native_send: NativeSend::AskEachTime,
            ..Default::default()
        };
        assert!(
            !ask.native_send_allowed(),
            "AskEachTime is not silently allowed"
        );
        let allowed = MeshPolicy {
            native_send: NativeSend::Allowed,
            ..Default::default()
        };
        assert!(allowed.native_send_allowed());
    }

    #[test]
    fn partial_talkrypt_message_yields_nothing() {
        let sealed: Vec<u8> = (0..600u32).map(|i| i as u8).collect();
        let frags = frag::fragment(frag::KIND_FRAME, 1, &sealed, 64).unwrap();
        let mut ingest = MeshIngest::new(&MeshPolicy::default());
        // Feed all but the last fragment → never completes.
        for f in &frags[..frags.len() - 1] {
            assert!(ingest.accept(&pkt(f.clone())).is_none());
        }
    }
}
