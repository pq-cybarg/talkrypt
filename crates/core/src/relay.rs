//! A non-member relay (an MLS-style "delivery service") for group chat.
//!
//! The relay terminates the **pairwise** channel with each participant (so it
//! can authenticate and route), but it is **not** a group member: it holds no
//! TreeKEM group state and no group key, so it cannot read group-message
//! plaintext — it only forwards the still-encrypted inner frames per their
//! [`Route`]. The first participant to connect is treated as the committer.
//!
//! Confidentiality vs. the relay: group messages and Welcome secrets are
//! encrypted to group/leaf keys the relay never has. The relay learns routing
//! metadata and ciphertext only — exactly the CSfC "untrusted delivery"
//! posture.

use std::sync::{Arc, Mutex};

use tokio::sync::Mutex as AsyncMutex;

use talkrypt_crypto::suite::SessionHandle;
use talkrypt_crypto::{CryptoSuite, IdentityKeyPair};
use talkrypt_transport::{Endpoint, FrameWriter, Transport};

use crate::descriptor::ChatDescriptor;
use crate::engine::{Route, Routed};
use crate::error::Result;
use crate::handshake;

type Sess = Arc<AsyncMutex<Box<dyn SessionHandle>>>;
type Wr = Arc<AsyncMutex<Box<dyn FrameWriter>>>;

struct RelayPeer {
    fp: [u8; 48],
    writer: Wr,
    session: Sess,
}

struct Switch {
    peers: Mutex<Vec<RelayPeer>>,
    committer: Mutex<Option<[u8; 48]>>,
}

/// A standalone relay node. Hosts a listener and forwards routed frames between
/// connected participants without ever joining the group.
pub struct RelayHub {
    identity: IdentityKeyPair,
    suite: Arc<dyn CryptoSuite>,
    transport: Arc<dyn Transport>,
    root0: [u8; 32],
    switch: Arc<Switch>,
}

impl RelayHub {
    pub fn new(
        identity: IdentityKeyPair,
        suite: Arc<dyn CryptoSuite>,
        transport: Arc<dyn Transport>,
        descriptor: &ChatDescriptor,
    ) -> RelayHub {
        RelayHub {
            identity,
            suite,
            transport,
            root0: descriptor.derive_root(),
            switch: Arc::new(Switch {
                peers: Mutex::new(Vec::new()),
                committer: Mutex::new(None),
            }),
        }
    }

    /// Number of currently-connected participants.
    pub fn participant_count(&self) -> usize {
        self.switch.peers.lock().unwrap().len()
    }

    /// Start listening and forwarding (spawns a background accept loop).
    pub async fn run(&self) -> Result<Endpoint> {
        let listener = self.transport.listen().await?;
        let endpoint = listener.endpoint();
        let mut listener = listener;
        let switch = self.switch.clone();
        // Clone what the accept loop needs (handshake inputs).
        let suite = self.suite.clone();
        let root0 = self.root0;
        // The relay needs its own long-term identity for the pairwise handshake.
        let id_seed = self.identity.export_secret();

        tokio::spawn(async move {
            while let Ok(mut stream) = listener.accept().await {
                let identity = IdentityKeyPair::from_secret_bytes(id_seed);
                let hs =
                    handshake::respond(stream.as_mut(), &identity, suite.as_ref(), root0).await;
                let Ok(hs) = hs else { continue };
                let fp = hs.peer_identity.fingerprint();
                let (writer, reader) = stream.into_split();
                let writer = Arc::new(AsyncMutex::new(writer));
                let session = Arc::new(AsyncMutex::new(hs.session));
                {
                    let mut peers = switch.peers.lock().unwrap();
                    peers.push(RelayPeer {
                        fp,
                        writer: writer.clone(),
                        session: session.clone(),
                    });
                    let mut committer = switch.committer.lock().unwrap();
                    if committer.is_none() {
                        *committer = Some(fp); // first participant = committer
                    }
                }
                tokio::spawn(forward_loop(switch.clone(), reader, session, fp));
            }
        });
        Ok(endpoint)
    }
}

async fn forward_loop(
    switch: Arc<Switch>,
    mut reader: Box<dyn talkrypt_transport::FrameReader>,
    session: Sess,
    sender_fp: [u8; 48],
) {
    loop {
        let frame = match reader.recv_frame().await {
            Ok(f) => f,
            Err(_) => break,
        };
        let pt = {
            let mut s = session.lock().await;
            match s.decrypt(&frame) {
                Ok(pt) => pt,
                Err(_) => continue,
            }
        };
        let Some(routed) = Routed::decode(&pt) else {
            continue;
        };

        // Decide destinations, then forward the (still-encrypted) inner frame,
        // stamping the authoritative sender fingerprint.
        let committer = *switch.committer.lock().unwrap();
        let targets: Vec<(Sess, Wr)> = {
            let peers = switch.peers.lock().unwrap();
            peers
                .iter()
                .filter(|p| match routed.to {
                    Route::Broadcast => p.fp != sender_fp,
                    Route::Peer(dst) => p.fp == dst,
                    Route::Committer => Some(p.fp) == committer && p.fp != sender_fp,
                })
                .map(|p| (p.session.clone(), p.writer.clone()))
                .collect()
        };

        let fwd = Routed {
            to: routed.to,
            from: sender_fp,
            inner: routed.inner,
        }
        .encode();

        for (s, w) in targets {
            let ct = {
                let mut sl = s.lock().await;
                match sl.encrypt(&fwd) {
                    Ok(ct) => ct,
                    Err(_) => continue,
                }
            };
            let mut wl = w.lock().await;
            let _ = wl.send_frame(&ct).await;
        }
    }
    // Drop the disconnected peer.
    switch.peers.lock().unwrap().retain(|p| p.fp != sender_fp);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::descriptor::{Persistence, TopologyKind};
    use crate::{Core, Event};
    use std::time::Duration;
    use talkrypt_crypto::{SuiteRegistry, DEFAULT_SUITE_ID};
    use talkrypt_transport::LoopbackFabric;
    use tokio::time::timeout;

    fn suite() -> Arc<dyn CryptoSuite> {
        SuiteRegistry::with_defaults()
            .get(DEFAULT_SUITE_ID)
            .unwrap()
    }

    async fn next_message(rx: &mut tokio::sync::mpsc::UnboundedReceiver<Event>) -> String {
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

    /// Group chat over a NON-member relay: the committer and a member talk
    /// through a relay that holds no group key and only forwards ciphertext.
    #[tokio::test]
    async fn group_chat_through_non_member_relay() {
        let fabric = LoopbackFabric::new();
        let desc = crate::ChatDescriptor::new(
            TopologyKind::Hub,
            Persistence::Ephemeral,
            DEFAULT_SUITE_ID,
            vec!["relay".into()],
            "#relayed",
        );

        // The relay hosts; it is not a group member.
        let relay = RelayHub::new(
            talkrypt_crypto::IdentityKeyPair::generate(),
            suite(),
            Arc::new(fabric.transport("relay")),
            &desc,
        );
        relay.run().await.unwrap();

        // Committer connects FIRST (the relay marks it committer), then a member.
        let (committer, mut c_rx) = Core::new_relayed_group(
            talkrypt_crypto::IdentityKeyPair::generate(),
            suite(),
            Arc::new(fabric.transport("committer")),
            desc.clone(),
            true,
        );
        committer.connect("relay").await.unwrap();
        tokio::time::sleep(Duration::from_millis(150)).await;

        let (member, mut m_rx) = Core::new_relayed_group(
            talkrypt_crypto::IdentityKeyPair::generate(),
            suite(),
            Arc::new(fabric.transport("member")),
            desc.clone(),
            false,
        );
        member.connect("relay").await.unwrap();
        tokio::time::sleep(Duration::from_millis(400)).await;

        // Committer sends; member receives via the relay (which cannot read it).
        committer.send("through the blind relay").await.unwrap();
        assert_eq!(next_message(&mut m_rx).await, "through the blind relay");

        // Member sends; committer receives (relay forwards the ciphertext).
        member.send("reply via relay").await.unwrap();
        assert_eq!(next_message(&mut c_rx).await, "reply via relay");

        // The relay has two participants and — by construction — no group state.
        assert_eq!(relay.participant_count(), 2);
    }
}
