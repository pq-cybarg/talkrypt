//! [`LocalBeacon`] over a LoRa mesh node.
//!
//! `MeshBeacon` carries talkrypt's opaque, already-sealed CQ beacon over a
//! [`MeshNode`] (Meshtastic / Meshcore) by fragmenting it across mesh packets and
//! reassembling nearby peers' fragments back into whole beacons. It implements the
//! existing [`LocalBeacon`] seam unchanged, so it slots straight into
//! [`crate::MultiBeacon`] alongside BLE / Wi-Fi — a build packages the mesh radio
//! like any other beacon plugin, no core change. The beacon layer only ever moves
//! opaque sealed bytes (the non-negotiable backend invariant).
//!
//! Encapsulation is the ONLY beacon mode: a CQ is always talkrypt-sealed and
//! fragmented under our magic, so peers with the invite recover it and everyone
//! else sees mere fragments. Foreign / native mesh traffic is a chat-layer concern
//! ([`super::MeshIngest`] / [`super::MeshHeard::Foreign`]), not a beacon.

use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use tokio::sync::mpsc;

use super::frag::{self, Reassembler};
use super::{MeshNode, MeshPolicy};
use crate::beacon::{BeaconScan, LocalBeacon, Seen};
use crate::Result;

/// A [`LocalBeacon`] that advertises + scans talkrypt CQ beacons over a mesh node.
pub struct MeshBeacon {
    node: Arc<dyn MeshNode>,
    channel: u8,
    /// Rolling per-message id so each `advertise` groups its own fragments.
    msg_id: AtomicU16,
    /// The most recently advertised opaque blob (re-fragmented on each scanner's
    /// join is unnecessary; the mesh is broadcast). Kept for parity / diagnostics.
    last: Mutex<Option<Vec<u8>>>,
}

impl MeshBeacon {
    /// Build a mesh beacon over `node`, transmitting on `policy.channel`.
    pub fn new(node: Arc<dyn MeshNode>, policy: MeshPolicy) -> Self {
        Self {
            node,
            channel: policy.channel,
            msg_id: AtomicU16::new(0),
            last: Mutex::new(None),
        }
    }
}

#[async_trait]
impl LocalBeacon for MeshBeacon {
    async fn advertise(&self, blob: Vec<u8>) -> Result<()> {
        let mtu = self.node.mtu();
        let id = self.msg_id.fetch_add(1, Ordering::Relaxed);
        // Fragment the opaque sealed CQ; if it is too large for the mesh (over
        // MAX_FRAGMENTS at this MTU), we simply cannot beacon it here — a beacon
        // that big does not belong on LoRa. Best-effort, like the other radios.
        if let Some(frags) = frag::fragment(frag::KIND_ADVERT, id, &blob, mtu) {
            for f in frags {
                let _ = self.node.send(self.channel, &f).await;
            }
        }
        *self.last.lock().unwrap() = Some(blob);
        Ok(())
    }

    async fn stop(&self) -> Result<()> {
        // A mesh has no persistent advertisement to tear down (each send is a
        // one-shot broadcast); simply forget the last blob so we go quiet.
        *self.last.lock().unwrap() = None;
        Ok(())
    }

    async fn scan(&self) -> Result<BeaconScan> {
        let mut inbox = self.node.subscribe().await?;
        let (scan, tx) = BeaconScan::channel();
        let want_channel = self.channel;
        // Reassemble talkrypt fragments off the mesh; emit each completed beacon
        // once. Foreign packets are ignored at the beacon layer.
        tokio::spawn(async move {
            // Only reassemble beacon adverts; ignore message-frame fragments that
            // share this mesh channel (they are handled by mesh messaging).
            let mut reasm = Reassembler::for_kind(frag::KIND_ADVERT);
            while let Some(pkt) = inbox.next().await {
                if pkt.channel != want_channel {
                    continue;
                }
                let source = pkt.from.map(|id| format!("{id:08x}"));
                let key = source.clone().unwrap_or_else(|| "unknown".to_string());
                if let Some(blob) = reasm.accept(&key, &pkt.payload) {
                    let seen = Seen { blob, source };
                    if tx.send(seen).is_err() {
                        break; // scan dropped by the caller
                    }
                }
            }
        });
        Ok(scan)
    }
}

// Keep the mpsc import used even if BeaconScan::channel's type changes upstream.
#[allow(unused_imports)]
use mpsc as _mpsc_marker;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mesh::MockMeshFabric;

    async fn recv_blob(scan: &mut BeaconScan) -> Vec<u8> {
        tokio::time::timeout(std::time::Duration::from_secs(2), scan.next())
            .await
            .expect("a beacon before timeout")
            .expect("channel open")
            .blob
    }

    #[tokio::test]
    async fn large_sealed_cq_survives_fragmentation_over_mesh() {
        // A realistic multi-hundred-byte sealed CQ, MTU forced small → many frags.
        let fabric = MockMeshFabric::new(64);
        let advertiser = MeshBeacon::new(Arc::new(fabric.node(1)), MeshPolicy::default());
        let scanner = MeshBeacon::new(Arc::new(fabric.node(2)), MeshPolicy::default());

        let mut scan = scanner.scan().await.unwrap();
        let sealed: Vec<u8> = (0..777u32).map(|i| (i % 251) as u8).collect();
        advertiser.advertise(sealed.clone()).await.unwrap();

        assert_eq!(recv_blob(&mut scan).await, sealed);
    }

    #[tokio::test]
    async fn a_mesh_beacon_does_not_hear_itself() {
        let fabric = MockMeshFabric::new(64);
        let me = MeshBeacon::new(Arc::new(fabric.node(1)), MeshPolicy::default());
        let mut scan = me.scan().await.unwrap();
        me.advertise(b"my own cq beacon padded out a bit".to_vec())
            .await
            .unwrap();
        let got = tokio::time::timeout(std::time::Duration::from_millis(300), scan.next()).await;
        assert!(got.is_err(), "a node must not scan its own mesh beacon");
    }

    #[tokio::test]
    async fn foreign_mesh_traffic_is_not_a_beacon() {
        // A non-talkrypt sender on the same channel must not surface as a beacon.
        let fabric = MockMeshFabric::new(64);
        let scanner = MeshBeacon::new(Arc::new(fabric.node(2)), MeshPolicy::default());
        let foreigner = fabric.node(3);
        let mut scan = scanner.scan().await.unwrap();
        foreigner
            .send(0, b"hello from a plain meshtastic node")
            .await
            .unwrap();
        let got = tokio::time::timeout(std::time::Duration::from_millis(300), scan.next()).await;
        assert!(got.is_err(), "foreign traffic must not be a beacon");
    }

    #[tokio::test]
    async fn composes_into_multibeacon() {
        // MeshBeacon is a drop-in LocalBeacon plugin: a peer with BLE + mesh finds
        // a mesh-only advertiser through the merged MultiBeacon scan.
        use crate::MultiBeacon;
        let mesh = MockMeshFabric::new(64);
        let ble = crate::LoopbackBeaconFabric::new();

        let peer = MultiBeacon::new()
            .with(Arc::new(crate::mesh::MeshBeacon::new(
                Arc::new(mesh.node(2)),
                MeshPolicy::default(),
            )))
            .with(Arc::new(ble.node("peer")));
        let mut scan = peer.scan().await.unwrap();

        let advertiser = MeshBeacon::new(Arc::new(mesh.node(1)), MeshPolicy::default());
        let sealed: Vec<u8> = (0..300u32).map(|i| i as u8).collect();
        advertiser.advertise(sealed.clone()).await.unwrap();

        assert_eq!(recv_blob(&mut scan).await, sealed);
    }
}
