//! In-memory mock mesh node + fabric for tests and offline use.
//!
//! Models a shared LoRa neighbourhood the way [`crate::LoopbackBeaconFabric`]
//! models co-located radios: every [`MockMeshNode`] on a [`MockMeshFabric`] hears
//! every OTHER node's sends on the same channel, with a configurable MTU so a test
//! can force many-fragment reassembly. No real radio, no hardware — the full
//! fragment / classify / reassemble path runs over it.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use tokio::sync::mpsc;

use super::{MeshInbox, MeshNode, MeshPacket};
use crate::Result;

#[derive(Default)]
struct FabricInner {
    /// node id -> its live inbound subscribers.
    subscribers: HashMap<u32, Vec<mpsc::UnboundedSender<MeshPacket>>>,
}

/// A shared in-memory mesh neighbourhood. Hand each node a [`MockMeshNode`] via
/// [`MockMeshFabric::node`]; a send on one node is delivered to every OTHER node
/// currently subscribed (a radio does not hear itself).
#[derive(Clone)]
pub struct MockMeshFabric {
    inner: Arc<Mutex<FabricInner>>,
    mtu: usize,
}

impl MockMeshFabric {
    /// A fabric whose nodes report `mtu` usable payload bytes per packet. Use a
    /// small value (e.g. 64) to force multi-fragment reassembly in tests.
    pub fn new(mtu: usize) -> Self {
        Self {
            inner: Arc::new(Mutex::new(FabricInner::default())),
            mtu,
        }
    }

    /// A node endpoint on this fabric with the given (indicative) node id.
    pub fn node(&self, node_id: u32) -> MockMeshNode {
        MockMeshNode {
            node_id,
            mtu: self.mtu,
            fabric: self.inner.clone(),
        }
    }
}

/// One node's handle onto a [`MockMeshFabric`].
pub struct MockMeshNode {
    node_id: u32,
    mtu: usize,
    fabric: Arc<Mutex<FabricInner>>,
}

#[async_trait]
impl MeshNode for MockMeshNode {
    fn mtu(&self) -> usize {
        self.mtu
    }

    async fn send(&self, channel: u8, payload: &[u8]) -> Result<()> {
        let packet = MeshPacket {
            channel,
            payload: payload.to_vec(),
            from: Some(self.node_id),
        };
        let mut inner = self.fabric.lock().unwrap();
        for (node, subs) in inner.subscribers.iter_mut() {
            if *node == self.node_id {
                continue; // a radio does not hear itself
            }
            subs.retain(|tx| tx.send(packet.clone()).is_ok());
        }
        Ok(())
    }

    async fn subscribe(&self) -> Result<MeshInbox> {
        let (inbox, tx) = MeshInbox::channel();
        self.fabric
            .lock()
            .unwrap()
            .subscribers
            .entry(self.node_id)
            .or_default()
            .push(tx);
        Ok(inbox)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn send_reaches_other_nodes_not_self() {
        let fabric = MockMeshFabric::new(64);
        let a = fabric.node(1);
        let b = fabric.node(2);
        let mut inbox_b = b.subscribe().await.unwrap();
        let mut inbox_a = a.subscribe().await.unwrap();
        a.send(0, b"hi").await.unwrap();

        let got = tokio::time::timeout(std::time::Duration::from_secs(1), inbox_b.next())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(got.payload, b"hi");
        assert_eq!(got.from, Some(1));

        // The sender does not receive its own packet.
        let self_heard =
            tokio::time::timeout(std::time::Duration::from_millis(200), inbox_a.next()).await;
        assert!(self_heard.is_err(), "a node must not hear its own send");
    }

    #[tokio::test]
    async fn mtu_is_reported() {
        let fabric = MockMeshFabric::new(233);
        assert_eq!(fabric.node(1).mtu(), 233);
    }
}
