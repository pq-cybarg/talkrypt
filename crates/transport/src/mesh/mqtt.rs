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

/// The inbound stream an [`MqttClient`] hands to `subscribe`: `(topic, payload)`
/// pairs as they arrive from the broker.
type InboundRx = mpsc::UnboundedReceiver<(String, Vec<u8>)>;
/// The sender half of [`InboundRx`] — a broker-side handle used to deliver
/// `(topic, payload)` pairs to a subscribed client. Only the in-memory test broker
/// holds these (the real `rumqttc` client owns its own event loop).
#[cfg(test)]
type InboundTx = mpsc::UnboundedSender<(String, Vec<u8>)>;

/// The minimal MQTT surface [`MqttMeshNode`] needs. Implement over `rumqttc`
/// (see [`connect`]) or any client; the in-memory [`LoopbackBroker`] backs tests.
#[async_trait]
pub trait MqttClient: Send + Sync + 'static {
    /// Publish `payload` to `topic`.
    async fn publish(&self, topic: String, payload: Vec<u8>) -> Result<()>;
    /// Take the inbound `(topic, payload)` stream. Called once by `subscribe`.
    fn inbound(&self) -> InboundRx;
}

/// How talkrypt frames are CARRIED over MQTT. talkrypt's PQ seal is the real
/// envelope either way; this selects only the OUTER MQTT carriage. Two methods are
/// intended (only the first is implemented today):
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum MqttMethod {
    /// **Encapsulated Meshtastic** (default, implemented): each talkrypt fragment
    /// rides inside a Meshtastic `ServiceEnvelope` on `PRIVATE_APP`, using the same
    /// topics/format as a real Meshtastic MQTT gateway — so it **interoperates with
    /// the Meshtastic mesh ecosystem** and an RF-hop-sized MTU (~200 B). This is the
    /// "encapsulated / adjusted" route, matching how the LoRa radio meshnets carry
    /// talkrypt. Latency is stop-and-wait-ARQ × fragment-count × broker RTT.
    #[default]
    EncapsulatedMeshtastic,
    /// **PQ-MQTT (RESERVED — not implemented).** A direct, internet-tuned, PQ-secured
    /// MQTT transport (Robobus-style "PQ-MQTT"): native MQTT carriage with no
    /// Meshtastic framing, a large MTU, and a windowed/batched send path, for much
    /// lower latency when Meshtastic interop is not needed. The seam is reserved here
    /// so it can slot in without reworking the node; selecting it today is an explicit
    /// error. See `docs/mesh-lora-backend.md`.
    PqMqttReserved,
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
    /// Which MQTT carriage method to use. Only [`MqttMethod::EncapsulatedMeshtastic`]
    /// is implemented; [`MqttMethod::PqMqttReserved`] is a reserved future slot.
    pub method: MqttMethod,
}

impl Default for MqttConfig {
    fn default() -> Self {
        Self {
            root: "msh/US".into(),
            channel_name: "talkrypt".into(),
            gateway_id: "!talkrypt".into(),
            mtu: 200,
            method: MqttMethod::EncapsulatedMeshtastic,
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
        inbound: std::sync::Mutex<Option<InboundRx>>,
    }

    #[async_trait]
    impl MqttClient for RumqttClient {
        async fn publish(&self, topic: String, payload: Vec<u8>) -> Result<()> {
            self.client
                .publish(topic, QoS::AtLeastOnce, false, payload)
                .await
                .map_err(|e| TransportError::Io(e.to_string()))
        }
        fn inbound(&self) -> InboundRx {
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
        if cfg.method == super::MqttMethod::PqMqttReserved {
            return Err(TransportError::Io(
                "MqttMethod::PqMqttReserved is a reserved future slot (Robobus-style PQ-MQTT), \
                 not yet implemented — use EncapsulatedMeshtastic"
                    .into(),
            ));
        }
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
        subs: Mutex<Vec<(usize, InboundTx)>>,
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
        inbound: Mutex<Option<InboundRx>>,
    }

    #[async_trait]
    impl MqttClient for LoopbackClient {
        async fn publish(&self, topic: String, payload: Vec<u8>) -> Result<()> {
            self.broker.fan(self.id, &topic, &payload);
            Ok(())
        }
        fn inbound(&self) -> InboundRx {
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

    #[test]
    fn default_method_is_encapsulated_meshtastic() {
        assert_eq!(MqttConfig::default().method, MqttMethod::EncapsulatedMeshtastic);
        assert_eq!(MqttMethod::default(), MqttMethod::EncapsulatedMeshtastic);
    }

    /// The reserved PQ-MQTT slot must refuse to connect (it is not implemented) and
    /// must do so BEFORE touching the network, so no broker is required for this test.
    #[cfg(feature = "mesh-mqtt")]
    #[tokio::test]
    async fn pq_mqtt_reserved_method_is_rejected() {
        use crate::TransportError;
        let cfg = MqttConfig { method: MqttMethod::PqMqttReserved, ..Default::default() };
        // 203.0.113.0/24 is TEST-NET-3 (RFC 5737): unroutable, so if the guard were
        // missing this would hang/fail on connect instead of returning promptly.
        // (Ok carries an Arc<MqttMeshNode<_>> which isn't Debug, so match rather than
        // unwrap_err.)
        match connect("203.0.113.1", 1883, "talkrypt-test", cfg).await {
            Err(TransportError::Io(m)) => assert!(m.contains("reserved"), "unexpected: {m}"),
            other => panic!("expected the reserved-slot error, got Ok/other variant: {}", other.is_ok()),
        }
    }

    /// Measure end-to-end fragment round-trip latency over a REAL MQTT broker (the
    /// encapsulated-Meshtastic carriage). Ignored by default — it needs a running
    /// broker. Point it at one with `TALKRYPT_MQTT_BROKER=host:port` (default
    /// `127.0.0.1:1883`) and run:
    ///   `cargo test -p talkrypt-transport --features mesh-mqtt -- --ignored --nocapture mqtt_latency`
    /// The printed per-fragment median is the broker round-trip; a whole chat message
    /// is 1-2 fragments, a handshake ~25 (each a stop-and-wait ARQ segment).
    #[cfg(feature = "mesh-mqtt")]
    #[tokio::test]
    #[ignore = "needs a live MQTT broker; set TALKRYPT_MQTT_BROKER"]
    async fn mqtt_latency_over_a_real_broker() {
        let (host, port) = match std::env::var("TALKRYPT_MQTT_BROKER") {
            Ok(s) => {
                let (h, p) = s.rsplit_once(':').expect("TALKRYPT_MQTT_BROKER must be host:port");
                (h.to_string(), p.parse().expect("port"))
            }
            Err(_) => ("127.0.0.1".to_string(), 1883u16),
        };
        let cfg = MqttConfig::default();
        let rx_node = connect(&host, port, "talkrypt-rx", cfg.clone()).await.expect("rx connect");
        let tx_node = connect(&host, port, "talkrypt-tx", cfg).await.expect("tx connect");
        let mut inbox = rx_node.subscribe().await.expect("subscribe");
        // Let both subscriptions settle on the broker before timing.
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;

        let frag = vec![0xABu8; 200]; // one full MTU-sized sealed fragment
        let iters = 30u32;
        let mut samples = Vec::with_capacity(iters as usize);
        for _ in 0..iters {
            let t0 = tokio::time::Instant::now();
            tx_node.send(3, &frag).await.expect("send");
            let got = tokio::time::timeout(std::time::Duration::from_secs(5), inbox.next())
                .await
                .expect("round-trip timed out")
                .expect("inbox closed");
            samples.push(t0.elapsed());
            assert_eq!(got.payload, frag);
        }
        samples.sort();
        let median = samples[samples.len() / 2];
        let min = samples[0];
        let max = samples[samples.len() - 1];
        println!(
            "mqtt encapsulated-Meshtastic fragment round-trip over {host}:{port} \
             (n={iters}, 200B): min={min:?} median={median:?} max={max:?}"
        );
    }
}
