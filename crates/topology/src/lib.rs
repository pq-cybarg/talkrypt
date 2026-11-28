//! Topology strategies: how a node wires up connectivity for a chat.
//!
//! All three reuse the same [`Core`] engine; they differ only in *who hosts*
//! and *who dials whom*:
//!
//!   * [`P2PMesh`] — host an onion AND dial every listed peer (full mesh).
//!   * [`HubClient`] — dial the hub onion(s) only; the hub relays ciphertext
//!     (the relay itself is `talkrypt-server`).
//!   * [`HybridClient`] — host an onion for peer-to-peer delivery AND dial the
//!     hub for rendezvous/discovery.
//!
//! Selecting a strategy from a [`ChatDescriptor`]'s [`TopologyKind`] is done by
//! [`for_kind`].

use async_trait::async_trait;

use talkrypt_core::{Core, Result, TopologyKind};

/// A connectivity strategy for one node in a chat.
#[async_trait]
pub trait Topology: Send + Sync {
    /// Bring this node online: host and/or dial peers as the topology dictates.
    async fn establish(&self, core: &Core, peers: &[String]) -> Result<()>;
    /// Which topology this implements.
    fn kind(&self) -> TopologyKind;
}

/// Full peer-to-peer mesh: host, then dial every peer.
pub struct P2PMesh;

#[async_trait]
impl Topology for P2PMesh {
    async fn establish(&self, core: &Core, peers: &[String]) -> Result<()> {
        core.host().await?;
        for p in peers {
            core.connect(p).await?;
        }
        Ok(())
    }
    fn kind(&self) -> TopologyKind {
        TopologyKind::P2P
    }
}

/// IRC-like hub client: dial the hub onion(s); the hub fans out ciphertext.
pub struct HubClient;

#[async_trait]
impl Topology for HubClient {
    async fn establish(&self, core: &Core, peers: &[String]) -> Result<()> {
        for hub in peers {
            core.connect(hub).await?;
        }
        Ok(())
    }
    fn kind(&self) -> TopologyKind {
        TopologyKind::Hub
    }
}

/// Hybrid: host for P2P message delivery, and dial the hub for rendezvous.
pub struct HybridClient;

#[async_trait]
impl Topology for HybridClient {
    async fn establish(&self, core: &Core, peers: &[String]) -> Result<()> {
        core.host().await?;
        for hub in peers {
            core.connect(hub).await?;
        }
        Ok(())
    }
    fn kind(&self) -> TopologyKind {
        TopologyKind::Hybrid
    }
}

/// Relay-chain client (plan 0005, hub-peer-peer-peer): dial the given upstream(s) —
/// a hub or a prior peer in the chain — AND host for a downstream peer, then enable
/// gossip so received content and host-signed Commit/Roster are re-flooded along the
/// chain. A line of these forms `hub — peer — peer — …`; each link may be any bearer.
/// Content delivery never waits on the hub once a peer can shuttle.
pub struct RelayChain;

#[async_trait]
impl Topology for RelayChain {
    async fn establish(&self, core: &Core, peers: &[String]) -> Result<()> {
        core.enable_gossip(); // relay = re-flood to other peers (loop-free via dedup)
        core.host().await?; // accept a downstream peer
        for upstream in peers {
            core.connect(upstream).await?;
        }
        Ok(())
    }
    fn kind(&self) -> TopologyKind {
        TopologyKind::Hybrid
    }
}

/// Resilient-hybrid client (plan 0005, hub-dropout + multi-hub): host for direct
/// peer-to-peer delivery, dial every given hub (multi-hub active-active — redundant
/// delivery of the one committer's frames, deduplicated), and enable gossip. Members
/// also interconnecting this way keep delivering content to each other after any/all
/// hubs drop; membership changes pause until a committer returns (invariant I1).
pub struct ResilientHybrid;

#[async_trait]
impl Topology for ResilientHybrid {
    async fn establish(&self, core: &Core, peers: &[String]) -> Result<()> {
        core.enable_gossip();
        core.host().await?; // reachable for direct peer links (survives hub loss)
        for hub in peers {
            core.connect(hub).await?; // connect to EVERY hub (multi-hub redundancy)
        }
        Ok(())
    }
    fn kind(&self) -> TopologyKind {
        TopologyKind::Hybrid
    }
}

/// Select a topology strategy for a descriptor's [`TopologyKind`].
pub fn for_kind(kind: TopologyKind) -> Box<dyn Topology> {
    match kind {
        TopologyKind::P2P => Box::new(P2PMesh),
        TopologyKind::Hub => Box::new(HubClient),
        TopologyKind::Hybrid => Box::new(HybridClient),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::time::Duration;
    use talkrypt_core::{ChatDescriptor, Core, Event, Persistence};
    use talkrypt_crypto::{IdentityKeyPair, SuiteRegistry, DEFAULT_SUITE_ID};
    use talkrypt_transport::LoopbackFabric;
    use tokio::time::timeout;

    fn node(
        fabric: &LoopbackFabric,
        ep: &str,
        desc: &ChatDescriptor,
    ) -> (Core, tokio::sync::mpsc::UnboundedReceiver<Event>) {
        let suite = SuiteRegistry::with_defaults()
            .get(DEFAULT_SUITE_ID)
            .unwrap();
        Core::new(
            IdentityKeyPair::generate(),
            suite,
            Arc::new(fabric.transport(ep)),
            desc.clone(),
        )
    }

    async fn wait_message(rx: &mut tokio::sync::mpsc::UnboundedReceiver<Event>) -> String {
        loop {
            match timeout(Duration::from_secs(5), rx.recv())
                .await
                .unwrap()
                .unwrap()
            {
                Event::Message { text, .. } => return text,
                _ => continue,
            }
        }
    }

    #[tokio::test]
    async fn p2p_message_reaches_all_peers() {
        let fabric = LoopbackFabric::new();
        let desc = ChatDescriptor::new(
            TopologyKind::P2P,
            Persistence::Ephemeral,
            DEFAULT_SUITE_ID,
            vec![],
            "#mesh",
        );

        // Bob and Carol host; Alice meshes out to both.
        let (bob, mut bob_rx) = node(&fabric, "bob", &desc);
        let (carol, mut carol_rx) = node(&fabric, "carol", &desc);
        let (alice, _alice_rx) = node(&fabric, "alice", &desc);

        bob.host().await.unwrap();
        carol.host().await.unwrap();

        P2PMesh
            .establish(&alice, &["bob".to_string(), "carol".to_string()])
            .await
            .unwrap();
        assert_eq!(alice.peer_count(), 2);

        alice.send("mesh hello").await.unwrap();
        assert_eq!(wait_message(&mut bob_rx).await, "mesh hello");
        assert_eq!(wait_message(&mut carol_rx).await, "mesh hello");
    }

    #[tokio::test]
    async fn for_kind_selects_right_strategy() {
        assert_eq!(for_kind(TopologyKind::P2P).kind(), TopologyKind::P2P);
        assert_eq!(for_kind(TopologyKind::Hub).kind(), TopologyKind::Hub);
        assert_eq!(for_kind(TopologyKind::Hybrid).kind(), TopologyKind::Hybrid);
    }
}
