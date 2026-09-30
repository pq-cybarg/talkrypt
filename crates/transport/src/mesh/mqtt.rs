//! Meshtastic **MQTT-gateway** ingest as a [`MeshNode`].
//!
//! A Meshtastic gateway node uplinks/downlinks packets to an MQTT broker, wrapping
//! each `MeshPacket` in a `ServiceEnvelope` protobuf on the topic
//! `msh/REGION/2/e/CHANNELNAME/NODEID`. `MqttMeshNode` speaks that: it publishes
//! talkrypt fragments as `PRIVATE_APP` packets and ingests inbound ones — bridging
//! talkrypt-over-mesh across the internet (wide-area) or to a private broker.
//!
//! **Security / channel config:** talkrypt's payload is already PQ+AES sealed, so it
//! rides an **unencrypted** Meshtastic channel (the well-known key) — the gateway
//! then publishes it as a `decoded` `Data { PRIVATE_APP }` we can read. Our seal is
//! the real envelope; the broker (and anyone on it) sees only opaque ciphertext. If
//! the channel is Meshtastic-encrypted the gateway publishes `encrypted` bytes we
//! can't open without the channel key, so use an unencrypted channel for talkrypt.
//!
//! Verified: `ServiceEnvelope.packet = 1` (MeshPacket), `.channel_id = 2` (string),
//! `.gateway_id = 3` (string); topic `msh/<region>/2/e/<channel>/<nodeid>` carries a
//! `ServiceEnvelope` protobuf (meshtastic/protobufs `mqtt.proto` + the MQTT docs).
//!
//! The `ServiceEnvelope` codec + the [`MqttMeshNode`] logic are always compiled and
//! unit-tested over an in-memory [`LoopbackBroker`]; the real `rumqttc` client is
//! behind `feature = "mesh-mqtt"`.

use std::sync::Arc;

use async_trait::async_trait;
use tokio::sync::mpsc;

use super::meshtastic::{encode_meshpacket, parse_meshpacket};
use super::{MeshInbox, MeshNode, MeshPacket};
use crate::Result;

// ---------------------------------------------------------------------------
// ServiceEnvelope codec (reuses the Meshtastic MeshPacket codec) + topic.
// ---------------------------------------------------------------------------

fn put_varint(out: &mut Vec<u8>, mut v: u64) {
    loop {
        let mut byte = (v & 0x7f) as u8;
        v >>= 7;
        if v != 0 {
            byte |= 0x80;
        }
        out.push(byte);
        if v == 0 {
            break;
        }
    }
}

fn put_len_delim(out: &mut Vec<u8>, field: u32, bytes: &[u8]) {
    put_varint(out, ((field << 3) | 2) as u64);
    put_varint(out, bytes.len() as u64);
    out.extend_from_slice(bytes);
}

/// Encode a `ServiceEnvelope { packet: MeshPacket, channel_id, gateway_id }`.
pub fn encode_service_envelope(channel_id: &str, gateway_id: &str, meshpacket: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    put_len_delim(&mut out, 1, meshpacket); // packet = 1 (MeshPacket)
    put_len_delim(&mut out, 2, channel_id.as_bytes()); // channel_id = 2
    put_len_delim(&mut out, 3, gateway_id.as_bytes()); // gateway_id = 3
    out
}

/// Extract the inner `MeshPacket` (field 1) bytes from a `ServiceEnvelope`; `None`
/// if absent/truncated. Flat, bounded, never panics on malformed input.
pub fn parse_service_envelope(buf: &[u8]) -> Option<Vec<u8>> {
    let mut pos = 0;
    while pos < buf.len() {
        // tag varint
        let tag = read_varint(buf, &mut pos)?;
        let field = tag >> 3;
        let wire = tag & 7;
        match wire {
            0 => {
                read_varint(buf, &mut pos)?;
            }
            5 => {
                pos = pos.checked_add(4)?;
                if pos > buf.len() {
                    return None;
                }
            }
            1 => {
                pos = pos.checked_add(8)?;
                if pos > buf.len() {
                    return None;
                }
            }
            2 => {
                let len = read_varint(buf, &mut pos)? as usize;
                let end = pos.checked_add(len)?;
                if end > buf.len() {
                    return None;
                }
                if field == 1 {
                    return Some(buf[pos..end].to_vec()); // MeshPacket
                }
                pos = end;
            }
            _ => return None,
        }
    }
    None
}

fn read_varint(buf: &[u8], pos: &mut usize) -> Option<u64> {
    let mut result = 0u64;
    let mut shift = 0;
    for _ in 0..10 {
        let b = *buf.get(*pos)?;
        *pos += 1;
        result |= u64::from(b & 0x7f) << shift;
        if b & 0x80 == 0 {
            return Some(result);
        }
        shift += 7;
    }
    None
}

/// The Meshtastic publish/subscribe topic for a channel: `<root>/2/e/<channel>/<node>`
/// (e.g. `msh/US/2/e/talkrypt/!abcd`). `root` is the deployment prefix (`msh/REGION`).
pub fn mqtt_topic(root: &str, channel: &str, node: &str) -> String {
    let root = root.trim_end_matches('/');
    format!("{root}/2/e/{channel}/{node}")
}

// ---------------------------------------------------------------------------
// Pluggable MQTT client seam (so the node logic is testable without a broker).
// ---------------------------------------------------------------------------

/// The minimal MQTT surface [`MqttMeshNode`] needs. Implement over `rumqttc`
/// (see [`connect`]) or any client; the in-memory [`LoopbackBroker`] backs tests.
#[async_trait]
pub trait MqttClient: Send + Sync + 'static {
    /// Publish `payload` to `topic`.
    async fn publish(&self, topic: String, payload: Vec<u8>) -> Result<()>;
    /// Take the inbound `(topic, payload)` stream. Called once by `subscribe`.
    fn inbound(&self) -> mpsc::UnboundedReceiver<(String, Vec<u8>)>;
}

/// Configuration for an [`MqttMeshNode`].
#[derive(Clone, Debug)]
pub struct MqttConfig {
    /// Topic root / deployment prefix, e.g. `msh/US`.
    pub root: String,
    /// Meshtastic channel name (unencrypted, for talkrypt — see module docs).
    pub channel_name: String,
    /// Our gateway/node id in the topic (e.g. `!aabbccdd`).
    pub gateway_id: String,
    /// Fragment byte budget per packet (sized for an RF hop if the gateway relays).
    pub mtu: usize,
}

impl Default for MqttConfig {
    fn default() -> Self {
        Self {
            root: "msh/US".into(),
            channel_name: "talkrypt".into(),
            gateway_id: "!talkrypt".into(),
            mtu: 200,
        }
    }
}

/// A [`MeshNode`] that carries talkrypt fragments over a Meshtastic MQTT gateway.
pub struct MqttMeshNode<C: MqttClient> {
    client: Arc<C>,
    cfg: MqttConfig,
}

impl<C: MqttClient> MqttMeshNode<C> {
    pub fn new(client: Arc<C>, cfg: MqttConfig) -> Arc<Self> {
        Arc::new(Self { client, cfg })
    }
}

#[async_trait]
impl<C: MqttClient> MeshNode for MqttMeshNode<C> {
    fn mtu(&self) -> usize {
        self.cfg.mtu
    }

    async fn send(&self, channel: u8, payload: &[u8]) -> Result<()> {
        let mp = encode_meshpacket(channel, payload);
        let env = encode_service_envelope(&self.cfg.channel_name, &self.cfg.gateway_id, &mp);
        let topic = mqtt_topic(&self.cfg.root, &self.cfg.channel_name, &self.cfg.gateway_id);
        self.client.publish(topic, env).await
    }

    async fn subscribe(&self) -> Result<MeshInbox> {
        let mut rx = self.client.inbound();
        let (inbox, tx) = MeshInbox::channel();
        tokio::spawn(async move {
            while let Some((_topic, payload)) = rx.recv().await {
                // ServiceEnvelope → inner MeshPacket → PRIVATE_APP talkrypt fragment.
                if let Some(mp) = parse_service_envelope(&payload) {
                    if let Some(rx) = parse_meshpacket(&mp) {
                        if tx
                            .send(MeshPacket {
                                channel: rx.channel,
                                payload: rx.payload,
                                from: rx.from,
                            })
                            .is_err()
                        {
                            return;
                        }
                    }
                }
            }
        });
        Ok(inbox)
    }
}

// ---------------------------------------------------------------------------
// Real MQTT client (feature `mesh-mqtt`) — rumqttc.
// ---------------------------------------------------------------------------

#[cfg(feature = "mesh-mqtt")]
mod rumqtt {
    use super::*;
    use crate::TransportError;
    use rumqttc::{AsyncClient, Event, MqttOptions, Packet, QoS};

    /// A `rumqttc`-backed [`MqttClient`]. Subscribes to `<root>/2/e/<channel>/#` and
    /// pumps inbound publishes to the node.
    pub struct RumqttClient {
        client: AsyncClient,
        inbound: std::sync::Mutex<Option<mpsc::UnboundedReceiver<(String, Vec<u8>)>>>,
    }

    #[async_trait]
    impl MqttClient for RumqttClient {
        async fn publish(&self, topic: String, payload: Vec<u8>) -> Result<()> {
            self.client
                .publish(topic, QoS::AtLeastOnce, false, payload)
                .await
                .map_err(|e| TransportError::Io(e.to_string()))
        }
        fn inbound(&self) -> mpsc::UnboundedReceiver<(String, Vec<u8>)> {
            self.inbound
                .lock()
                .unwrap()
                .take()
                .expect("inbound() called more than once")
        }
    }

    /// Connect to an MQTT broker and build an [`MqttMeshNode`] over it, subscribing
    /// to the channel's topic. `client_id` identifies this MQTT session.
    pub async fn connect(
        broker_host: &str,
        broker_port: u16,
        client_id: &str,
        cfg: MqttConfig,
    ) -> Result<Arc<MqttMeshNode<RumqttClient>>> {
        let mut opts = MqttOptions::new(client_id, broker_host, broker_port);
        opts.set_keep_alive(std::time::Duration::from_secs(30));
        let (client, mut eventloop) = AsyncClient::new(opts, 32);
        let sub = format!("{}/2/e/{}/#", cfg.root.trim_end_matches('/'), cfg.channel_name);
        client
            .subscribe(sub, QoS::AtLeastOnce)
            .await
            .map_err(|e| TransportError::Io(e.to_string()))?;
        let (tx, rx) = mpsc::unbounded_channel();
        tokio::spawn(async move {
            loop {
                match eventloop.poll().await {
                    Ok(Event::Incoming(Packet::Publish(p))) => {
                        if tx.send((p.topic, p.payload.to_vec())).is_err() {
                            break;
                        }
                    }
                    Ok(_) => {}
                    Err(_) => {
                        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                    }
                }
            }
        });
        Ok(MqttMeshNode::new(
            Arc::new(RumqttClient {
                client,
                inbound: std::sync::Mutex::new(Some(rx)),
            }),
            cfg,
        ))
    }
}

#[cfg(feature = "mesh-mqtt")]
pub use rumqtt::{connect, RumqttClient};

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// An in-memory MQTT broker: fans each publish to every OTHER client's inbound
    /// (a client does not receive its own publish — mirrors the mesh loopback).
    #[derive(Default)]
    struct LoopbackBroker {
        subs: Mutex<Vec<(usize, mpsc::UnboundedSender<(String, Vec<u8>)>)>>,
        next_id: std::sync::atomic::AtomicUsize,
    }

    impl LoopbackBroker {
        fn client(self: &Arc<Self>) -> Arc<LoopbackClient> {
            let id = self.next_id.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let (tx, rx) = mpsc::unbounded_channel();
            self.subs.lock().unwrap().push((id, tx));
            Arc::new(LoopbackClient {
                broker: self.clone(),
                id,
                inbound: Mutex::new(Some(rx)),
            })
        }
        fn fan(&self, from: usize, topic: &str, payload: &[u8]) {
            for (id, tx) in self.subs.lock().unwrap().iter() {
                if *id != from {
                    let _ = tx.send((topic.to_string(), payload.to_vec()));
                }
            }
        }
    }

    struct LoopbackClient {
        broker: Arc<LoopbackBroker>,
        id: usize,
        inbound: Mutex<Option<mpsc::UnboundedReceiver<(String, Vec<u8>)>>>,
    }

    #[async_trait]
    impl MqttClient for LoopbackClient {
        async fn publish(&self, topic: String, payload: Vec<u8>) -> Result<()> {
            self.broker.fan(self.id, &topic, &payload);
            Ok(())
        }
        fn inbound(&self) -> mpsc::UnboundedReceiver<(String, Vec<u8>)> {
            self.inbound.lock().unwrap().take().unwrap()
        }
    }

    #[test]
    fn service_envelope_roundtrips_and_carries_private_app() {
        let frag = b"talkrypt-over-mqtt-fragment";
        let mp = encode_meshpacket(7, frag);
        let env = encode_service_envelope("talkrypt", "!gw", &mp);
        // Extract the inner MeshPacket and confirm it is our PRIVATE_APP payload.
        let inner = parse_service_envelope(&env).unwrap();
        let rx = parse_meshpacket(&inner).unwrap();
        assert_eq!(rx.channel, 7);
        assert_eq!(rx.payload, frag);
    }

    #[test]
    fn parse_service_envelope_tolerates_junk() {
        assert!(parse_service_envelope(b"").is_none());
        assert!(parse_service_envelope(b"\x10\x05").is_none()); // a varint field, no packet
        assert!(parse_service_envelope(&[0x0a, 0x40, 0x01]).is_none()); // len-delim past end
    }

    #[test]
    fn topic_has_the_meshtastic_shape() {
        assert_eq!(mqtt_topic("msh/US", "talkrypt", "!ab"), "msh/US/2/e/talkrypt/!ab");
        assert_eq!(mqtt_topic("msh/EU/", "c", "!x"), "msh/EU/2/e/c/!x");
    }

    #[tokio::test]
    async fn fragment_travels_over_the_mqtt_gateway() {
        let broker = Arc::new(LoopbackBroker::default());
        let sender = MqttMeshNode::new(broker.client(), MqttConfig::default());
        let receiver = MqttMeshNode::new(broker.client(), MqttConfig::default());

        let mut inbox = receiver.subscribe().await.unwrap();
        // Give the subscribe task a tick to start draining before we publish.
        tokio::task::yield_now().await;
        sender.send(3, b"opaque sealed fragment").await.unwrap();

        let got = tokio::time::timeout(std::time::Duration::from_secs(2), inbox.next())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(got.channel, 3);
        assert_eq!(got.payload, b"opaque sealed fragment");
    }
}
