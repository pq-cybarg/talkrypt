//! SUB-SPEC A / #68 — pre-session over-the-air presence beacon seam.
//!
//! A [`LocalBeacon`] broadcasts an OPAQUE beacon blob to nearby devices over a local radio
//! (BLE advertisement / GATT, Wi-Fi Direct / Aware, mDNS on a LAN, ...) and scans for
//! others' — BEFORE any session exists, so people can discover each other in the field
//! ("CQ CQ, anyone on this channel?"). This layer moves only ciphertext: the blob is
//! already PQ + AES-256-GCM sealed by `talkrypt_core::advert::build_advertisement` (which
//! calls `talkrypt_crypto::beacon`), so a scanner that lacks the chat key learns nothing
//! but "some device is beaconing" — never a name, channel, or scheme.
//!
//! MULTIPLATFORM-FIRST: the seam lives here once; each host plugs its radio backend in by
//! implementing [`LocalBeacon`] (Android BLE, Apple CoreBluetooth, Linux BlueZ, Wi-Fi
//! Aware). The in-memory [`LoopbackBeaconFabric`] drives tests and offline use — exactly as
//! [`crate::LoopbackFabric`] does for [`crate::Transport`]. Beaconing is opt-in / default
//! OFF at the policy layer (see `talkrypt_core::advert::AdvertisePolicy`); this transport
//! only acts when a host calls `advertise`.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use tokio::sync::mpsc;

use crate::Result;

/// One beacon observed from a nearby device: the opaque (sealed) blob plus an optional
/// coarse backend-supplied source handle (a BLE MAC / advertisement id, for dedup or
/// relative-signal only — never an identity; the identity, if any, is inside the ciphertext).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Seen {
    pub blob: Vec<u8>,
    pub source: Option<String>,
}

/// A local-radio presence transport: advertise an opaque beacon, scan for nearby ones.
#[async_trait]
pub trait LocalBeacon: Send + Sync {
    /// Start (or replace) the advertised beacon payload. Idempotent. The blob MUST already
    /// be sealed by the caller — this layer treats it as opaque bytes.
    async fn advertise(&self, blob: Vec<u8>) -> Result<()>;
    /// Stop advertising (go dark).
    async fn stop(&self) -> Result<()>;
    /// Open a scan subscription; each `next()` yields a nearby beacon. Dropping the returned
    /// [`BeaconScan`] ends the subscription.
    async fn scan(&self) -> Result<BeaconScan>;
}

/// A scan subscription: await nearby beacons until dropped or the backend closes.
pub struct BeaconScan {
    rx: mpsc::UnboundedReceiver<Seen>,
}

impl BeaconScan {
    /// The next nearby beacon, or `None` when the backend is closed.
    pub async fn next(&mut self) -> Option<Seen> {
        self.rx.recv().await
    }
}

// ---------------------------------------------------------------------------
// In-memory loopback backend (tests / offline). A shared fabric relays each node's
// advertised blob to every OTHER node currently scanning — modelling co-located radios.
// ---------------------------------------------------------------------------

#[derive(Default)]
struct FabricInner {
    /// node id -> its current advertised blob (None once stopped).
    advertised: HashMap<String, Vec<u8>>,
    /// node id -> live scan subscribers.
    scanners: HashMap<String, Vec<mpsc::UnboundedSender<Seen>>>,
}

/// A shared in-memory radio neighbourhood. Hand each node a [`LoopbackBeacon`] via
/// [`LoopbackBeaconFabric::node`]; advertisers are seen by every other node scanning.
#[derive(Clone, Default)]
pub struct LoopbackBeaconFabric {
    inner: Arc<Mutex<FabricInner>>,
}

impl LoopbackBeaconFabric {
    pub fn new() -> Self {
        Self { inner: Arc::new(Mutex::new(FabricInner::default())) }
    }

    /// A beacon endpoint for node `id` on this fabric.
    pub fn node(&self, id: &str) -> LoopbackBeacon {
        LoopbackBeacon { id: id.to_string(), fabric: self.inner.clone() }
    }
}

/// One node's handle onto a [`LoopbackBeaconFabric`].
pub struct LoopbackBeacon {
    id: String,
    fabric: Arc<Mutex<FabricInner>>,
}

impl LoopbackBeacon {
    /// Deliver `seen` to every scanner except our own node (a radio doesn't hear itself).
    fn fanout(inner: &mut FabricInner, from: &str, blob: &[u8]) {
        let seen = Seen { blob: blob.to_vec(), source: Some(from.to_string()) };
        for (node, subs) in inner.scanners.iter_mut() {
            if node == from {
                continue;
            }
            subs.retain(|tx| tx.send(seen.clone()).is_ok());
        }
    }
}

#[async_trait]
impl LocalBeacon for LoopbackBeacon {
    async fn advertise(&self, blob: Vec<u8>) -> Result<()> {
        let mut inner = self.fabric.lock().unwrap();
        inner.advertised.insert(self.id.clone(), blob.clone());
        Self::fanout(&mut inner, &self.id, &blob);
        Ok(())
    }

    async fn stop(&self) -> Result<()> {
        self.fabric.lock().unwrap().advertised.remove(&self.id);
        Ok(())
    }

    async fn scan(&self) -> Result<BeaconScan> {
        let (tx, rx) = mpsc::unbounded_channel();
        let mut inner = self.fabric.lock().unwrap();
        // Replay every OTHER node's currently-advertised beacon so a fresh scanner sees the
        // devices already beaconing, not only ones that (re)advertise after we start.
        let existing: Vec<Seen> = inner
            .advertised
            .iter()
            .filter(|(node, _)| node.as_str() != self.id)
            .map(|(node, blob)| Seen { blob: blob.clone(), source: Some(node.clone()) })
            .collect();
        for seen in existing {
            let _ = tx.send(seen);
        }
        inner.scanners.entry(self.id.clone()).or_default().push(tx);
        Ok(BeaconScan { rx })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn recv_blob(scan: &mut BeaconScan) -> Vec<u8> {
        tokio::time::timeout(std::time::Duration::from_secs(2), scan.next())
            .await
            .expect("a beacon before timeout")
            .expect("channel open")
            .blob
    }

    #[tokio::test]
    async fn advertiser_is_seen_by_a_scanner() {
        let fabric = LoopbackBeaconFabric::new();
        let a = fabric.node("a");
        let b = fabric.node("b");
        let mut scan_b = b.scan().await.unwrap();
        a.advertise(b"opaque-beacon".to_vec()).await.unwrap();
        let seen = recv_blob(&mut scan_b).await;
        assert_eq!(seen, b"opaque-beacon");
    }

    #[tokio::test]
    async fn scanner_replays_existing_advertisers() {
        let fabric = LoopbackBeaconFabric::new();
        let a = fabric.node("a");
        // a is already beaconing BEFORE b starts scanning.
        a.advertise(b"already-here".to_vec()).await.unwrap();
        let b = fabric.node("b");
        let mut scan_b = b.scan().await.unwrap();
        assert_eq!(recv_blob(&mut scan_b).await, b"already-here");
    }

    #[tokio::test]
    async fn a_radio_does_not_hear_itself() {
        let fabric = LoopbackBeaconFabric::new();
        let a = fabric.node("a");
        let mut scan_a = a.scan().await.unwrap();
        a.advertise(b"mine".to_vec()).await.unwrap();
        // Give any (incorrect) self-delivery a chance to arrive.
        let got = tokio::time::timeout(std::time::Duration::from_millis(200), scan_a.next()).await;
        assert!(got.is_err(), "a node must not scan its own beacon");
    }

    #[tokio::test]
    async fn stop_then_new_scanner_sees_nothing() {
        let fabric = LoopbackBeaconFabric::new();
        let a = fabric.node("a");
        a.advertise(b"transient".to_vec()).await.unwrap();
        a.stop().await.unwrap();
        let b = fabric.node("b");
        let mut scan_b = b.scan().await.unwrap();
        let got = tokio::time::timeout(std::time::Duration::from_millis(200), scan_b.next()).await;
        assert!(got.is_err(), "a stopped advertiser is not replayed");
    }
}
