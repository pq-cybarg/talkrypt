//! Reliable [`Transport`] over a broadcast LoRa [`MeshNode`].
//!
//! `Transport` is connection-oriented + reliable; a `MeshNode` is broadcast,
//! connectionless, lossy, and small-MTU. `MeshTransport` bridges the two with a
//! pseudo-connection + **stop-and-wait ARQ** layer, so the unchanged talkrypt
//! engine (handshake, group commits, messaging) can run entirely over LoRa.
//!
//! - **Connections** are identified by a dialer-chosen 64-bit `conn_id`; setup
//!   (`SYN`) also carries short endpoint labels so a listener knows a `SYN` is for
//!   it. Packets for an unknown `conn_id` / other endpoint are ignored.
//! - **Coexistence:** transport packets use a distinct 2-byte magic (`0xA7 0x74`)
//!   from the fragmentation codec's (`0xA7 0x6D`), so beacon/messaging fragments
//!   and transport segments share one mesh channel without cross-parsing.
//! - **Reliability:** each `send_frame` fragments the frame into MTU-sized segments
//!   and sends them one at a time, awaiting a per-segment ACK with timeout +
//!   bounded retransmit — the pragmatic correct choice for LoRa (a window buys
//!   little and risks airtime storms; compose [`super::PacedMeshNode`] for duty).
//!
//! Security: `Transport` already carries opaque end-to-end ciphertext; this layer
//! moves only those frames + its own routing/ARQ headers, never keys or plaintext.
//! A forged transport packet fails `parse_packet`, targets an unknown `conn_id`, or
//! delivers ciphertext the engine's crypto rejects — the ARQ is not a trust boundary.
//!
//! See `docs/superpowers/specs/2026-09-27-mesh-transport-design.md`.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use tokio::sync::mpsc;

use super::MeshNode;
use crate::{
    Endpoint, FrameReader, FrameWriter, Listener, Result, Stream, Transport, TransportError,
    TransportStatus,
};

// ---------------------------------------------------------------------------
// Packet codec (flat, bounded, Kani-provable decode).
// ---------------------------------------------------------------------------

const MAGIC0: u8 = 0xA7;
const MAGIC1: u8 = 0x74; // 't' — distinct from the fragmentation codec's 0x6D ('m')
const VERSION: u8 = 1;
/// Fixed header length before any payload.
const HEADER_LEN: usize = 18;

const T_SYN: u8 = 0;
const T_SYN_ACK: u8 = 1;
const T_DATA: u8 = 2;
const T_DATA_ACK: u8 = 3;
#[allow(dead_code)]
const T_FIN: u8 = 4;

/// A message that needs more than this many segments does not belong on LoRa
/// (bounds reassembly memory against a forged `frag_cnt`).
const MAX_SEGMENTS: u16 = 4096;

/// A parsed transport packet header + payload slice. Flat (scalars + a slice) so
/// [`parse_packet`] is a bounded, panic-free decode.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Packet<'a> {
    typ: u8,
    conn_id: u64,
    msg_seq: u16,
    frag_idx: u16,
    frag_cnt: u16,
    payload: &'a [u8],
}

fn parse_packet(b: &[u8]) -> Option<Packet<'_>> {
    if b.len() < HEADER_LEN {
        return None;
    }
    if b[0] != MAGIC0 || b[1] != MAGIC1 || b[2] != VERSION {
        return None;
    }
    let typ = b[3];
    let conn_id = u64::from_be_bytes([b[4], b[5], b[6], b[7], b[8], b[9], b[10], b[11]]);
    let msg_seq = u16::from_be_bytes([b[12], b[13]]);
    let frag_idx = u16::from_be_bytes([b[14], b[15]]);
    let frag_cnt = u16::from_be_bytes([b[16], b[17]]);
    Some(Packet {
        typ,
        conn_id,
        msg_seq,
        frag_idx,
        frag_cnt,
        payload: &b[HEADER_LEN..],
    })
}

fn put_header(out: &mut Vec<u8>, typ: u8, conn_id: u64, msg_seq: u16, frag_idx: u16, frag_cnt: u16) {
    out.push(MAGIC0);
    out.push(MAGIC1);
    out.push(VERSION);
    out.push(typ);
    out.extend_from_slice(&conn_id.to_be_bytes());
    out.extend_from_slice(&msg_seq.to_be_bytes());
    out.extend_from_slice(&frag_idx.to_be_bytes());
    out.extend_from_slice(&frag_cnt.to_be_bytes());
}

fn encode_syn(conn_id: u64, src_ep: &str, dst_ep: &str) -> Vec<u8> {
    let mut out = Vec::new();
    put_header(&mut out, T_SYN, conn_id, 0, 0, 0);
    // src_ep (len u8 ‖ bytes) ‖ dst_ep (len u8 ‖ bytes) — endpoints are short labels.
    out.push(src_ep.len().min(255) as u8);
    out.extend_from_slice(&src_ep.as_bytes()[..src_ep.len().min(255)]);
    out.push(dst_ep.len().min(255) as u8);
    out.extend_from_slice(&dst_ep.as_bytes()[..dst_ep.len().min(255)]);
    out
}

/// Parse the `(src_ep, dst_ep)` from a `SYN` payload; `None` if truncated.
fn parse_syn_eps(p: &[u8]) -> Option<(String, String)> {
    let mut pos = 0;
    let src_len = *p.get(pos)? as usize;
    pos += 1;
    let src = p.get(pos..pos + src_len)?;
    pos += src_len;
    let dst_len = *p.get(pos)? as usize;
    pos += 1;
    let dst = p.get(pos..pos + dst_len)?;
    Some((
        String::from_utf8_lossy(src).into_owned(),
        String::from_utf8_lossy(dst).into_owned(),
    ))
}

fn encode_ctrl(typ: u8, conn_id: u64, msg_seq: u16, frag_idx: u16) -> Vec<u8> {
    let mut out = Vec::new();
    put_header(&mut out, typ, conn_id, msg_seq, frag_idx, 0);
    out
}

fn encode_data(conn_id: u64, msg_seq: u16, frag_idx: u16, frag_cnt: u16, seg: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(HEADER_LEN + seg.len());
    put_header(&mut out, T_DATA, conn_id, msg_seq, frag_idx, frag_cnt);
    out.extend_from_slice(seg);
    out
}

// ---------------------------------------------------------------------------
// Owned inbound packet (what the demux routes to a connection's channels).
// ---------------------------------------------------------------------------

#[derive(Clone, Debug)]
struct InPkt {
    typ: u8,
    msg_seq: u16,
    frag_idx: u16,
    frag_cnt: u16,
    payload: Vec<u8>,
}

/// Per-connection inbound routing: control/acks to `ack_tx`, DATA to `data_tx`.
struct ConnChannels {
    ack_tx: mpsc::UnboundedSender<InPkt>,
    data_tx: mpsc::UnboundedSender<InPkt>,
}

// ---------------------------------------------------------------------------
// Shared transport state + the single inbound reader/demux task.
// ---------------------------------------------------------------------------

struct TxInner {
    node: Arc<dyn MeshNode>,
    channel: u8,
    local_ep: String,
    timeout: Duration,
    retries: usize,
    conns: Mutex<HashMap<u64, ConnChannels>>,
    incoming_tx: Mutex<Option<mpsc::UnboundedSender<MeshStream>>>,
    started: AtomicBool,
    conn_ctr: AtomicU64,
}

fn fnv1a(s: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in s {
        h ^= *b as u64;
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    h
}

impl TxInner {
    /// Start the inbound reader/demux task once.
    fn ensure_started(self: &Arc<Self>) {
        if self.started.swap(true, Ordering::SeqCst) {
            return;
        }
        let inner = self.clone();
        tokio::spawn(async move {
            let Ok(mut inbox) = inner.node.subscribe().await else {
                return;
            };
            while let Some(pkt) = inbox.next().await {
                if pkt.channel != inner.channel {
                    continue;
                }
                let Some(p) = parse_packet(&pkt.payload) else {
                    continue;
                };
                if p.typ == T_SYN {
                    inner.handle_syn(&p).await;
                    continue;
                }
                // Route to the owning connection: acks/control to ack_tx, DATA to data_tx.
                let in_pkt = InPkt {
                    typ: p.typ,
                    msg_seq: p.msg_seq,
                    frag_idx: p.frag_idx,
                    frag_cnt: p.frag_cnt,
                    payload: p.payload.to_vec(),
                };
                // Does this connection exist? (release the lock before any await.)
                let known = inner.conns.lock().unwrap().contains_key(&p.conn_id);
                if !known {
                    continue;
                }
                if p.typ == T_DATA {
                    // ACK every received DATA here — decoupled from the app's recv pace,
                    // so the sender's stop-and-wait advances even if recv_frame is slow.
                    let _ = inner
                        .node
                        .send(
                            inner.channel,
                            &encode_ctrl(T_DATA_ACK, p.conn_id, p.msg_seq, p.frag_idx),
                        )
                        .await;
                    if let Some(ch) = inner.conns.lock().unwrap().get(&p.conn_id) {
                        let _ = ch.data_tx.send(in_pkt);
                    }
                } else if let Some(ch) = inner.conns.lock().unwrap().get(&p.conn_id) {
                    let _ = ch.ack_tx.send(in_pkt);
                }
            }
        });
    }

    /// Handle an inbound `SYN`: if it targets our endpoint and is new, create the
    /// connection, reply `SYN_ACK`, and hand a `MeshStream` to the listener (if
    /// any). A duplicate `SYN` just re-acks (idempotent).
    async fn handle_syn(self: &Arc<Self>, p: &Packet<'_>) {
        let Some((_src, dst)) = parse_syn_eps(p.payload) else {
            return;
        };
        if dst != self.local_ep {
            return; // not for us
        }
        // Always (re-)ack so a dropped SYN_ACK is recovered by the dialer's SYN retransmit.
        let _ = self
            .node
            .send(self.channel, &encode_ctrl(T_SYN_ACK, p.conn_id, 0, 0))
            .await;
        {
            let conns = self.conns.lock().unwrap();
            if conns.contains_key(&p.conn_id) {
                return; // already established — the re-ack above suffices
            }
        }
        let stream = self.register_conn(p.conn_id);
        if let Some(tx) = self.incoming_tx.lock().unwrap().as_ref() {
            let _ = tx.send(stream);
        }
    }

    /// Create the per-connection channels, register them, and build a `MeshStream`.
    fn register_conn(self: &Arc<Self>, conn_id: u64) -> MeshStream {
        let (ack_tx, ack_rx) = mpsc::unbounded_channel();
        let (data_tx, data_rx) = mpsc::unbounded_channel();
        self.conns
            .lock()
            .unwrap()
            .insert(conn_id, ConnChannels { ack_tx, data_tx });
        MeshStream {
            writer: MeshWriter {
                inner: self.clone(),
                conn_id,
                next_msg_seq: 0,
                ack_rx,
            },
            reader: MeshReader {
                data_rx,
                reasm: HashMap::new(),
            },
        }
    }
}

// ---------------------------------------------------------------------------
// Transport / Listener.
// ---------------------------------------------------------------------------

/// A reliable [`Transport`] over a broadcast LoRa [`MeshNode`].
pub struct MeshTransport {
    inner: Arc<TxInner>,
}

impl MeshTransport {
    /// Build a mesh transport on `channel` with our endpoint label `local_ep`
    /// (a short, ideally-unique id peers dial — e.g. a fingerprint prefix).
    pub fn new(node: Arc<dyn MeshNode>, channel: u8, local_ep: impl Into<String>) -> Arc<Self> {
        Self::with_timeout(node, channel, local_ep, Duration::from_secs(3), 8)
    }

    /// As [`new`](Self::new) with an explicit per-segment retransmit `timeout` and
    /// max `retries` (tests use a short timeout; LoRa wants seconds).
    pub fn with_timeout(
        node: Arc<dyn MeshNode>,
        channel: u8,
        local_ep: impl Into<String>,
        timeout: Duration,
        retries: usize,
    ) -> Arc<Self> {
        Arc::new(Self {
            inner: Arc::new(TxInner {
                node,
                channel,
                local_ep: local_ep.into(),
                timeout,
                retries: retries.max(1),
                conns: Mutex::new(HashMap::new()),
                incoming_tx: Mutex::new(None),
                started: AtomicBool::new(false),
                conn_ctr: AtomicU64::new(0),
            }),
        })
    }
}

#[async_trait]
impl Transport for MeshTransport {
    async fn listen(&self) -> Result<Box<dyn Listener>> {
        self.inner.ensure_started();
        let (tx, rx) = mpsc::unbounded_channel();
        *self.inner.incoming_tx.lock().unwrap() = Some(tx);
        Ok(Box::new(MeshListener {
            endpoint: self.inner.local_ep.clone(),
            incoming: rx,
        }))
    }

    async fn dial(&self, endpoint: &Endpoint) -> Result<Box<dyn Stream>> {
        self.inner.ensure_started();
        // Choose a conn_id (no RNG dep): mix our endpoint hash with a counter.
        let ctr = self.inner.conn_ctr.fetch_add(1, Ordering::Relaxed);
        let conn_id = fnv1a(self.inner.local_ep.as_bytes())
            ^ ctr.wrapping_mul(0x9E37_79B9_7F4A_7C15).wrapping_add(1);
        let stream = self.inner.register_conn(conn_id);
        // Send SYN, await SYN_ACK on the connection's ack channel, retransmit on timeout.
        let syn = encode_syn(conn_id, &self.inner.local_ep, endpoint);
        let mut ack_rx = {
            // Temporarily borrow the writer's ack_rx via the stream: the SYN_ACK is
            // routed to ack_tx. We poll it here before handing the stream to the caller.
            // (send_frame has not run yet, so nothing else consumes ack_rx.)
            None
        };
        // Move the ack_rx out of the writer for the handshake, then restore.
        let MeshStream { mut writer, reader } = stream;
        for _ in 0..self.inner.retries {
            let _ = self.inner.node.send(self.inner.channel, &syn).await;
            match tokio::time::timeout(self.inner.timeout, writer.ack_rx.recv()).await {
                Ok(Some(p)) if p.typ == T_SYN_ACK => {
                    ack_rx = Some(());
                    break;
                }
                Ok(Some(_)) => continue,
                Ok(None) => break,
                Err(_) => continue, // timeout → retransmit SYN
            }
        }
        if ack_rx.is_none() {
            self.inner.conns.lock().unwrap().remove(&conn_id);
            return Err(TransportError::Io("mesh dial: no SYN-ACK".into()));
        }
        Ok(Box::new(MeshStream { writer, reader }))
    }

    fn status(&self) -> TransportStatus {
        TransportStatus::Online {
            endpoint: self.inner.local_ep.clone(),
        }
    }

    fn local_endpoint(&self) -> Endpoint {
        self.inner.local_ep.clone()
    }
}

/// Accepts inbound mesh pseudo-connections.
struct MeshListener {
    endpoint: Endpoint,
    incoming: mpsc::UnboundedReceiver<MeshStream>,
}

#[async_trait]
impl Listener for MeshListener {
    async fn accept(&mut self) -> Result<Box<dyn Stream>> {
        match self.incoming.recv().await {
            Some(s) => Ok(Box::new(s)),
            None => Err(TransportError::Closed),
        }
    }

    fn endpoint(&self) -> Endpoint {
        self.endpoint.clone()
    }
}

// ---------------------------------------------------------------------------
// Stream (writer + reader halves) with stop-and-wait ARQ.
// ---------------------------------------------------------------------------

/// One reliable pseudo-connection over the mesh.
struct MeshStream {
    writer: MeshWriter,
    reader: MeshReader,
}

#[async_trait]
impl Stream for MeshStream {
    async fn send_frame(&mut self, frame: &[u8]) -> Result<()> {
        self.writer.send_frame(frame).await
    }
    async fn recv_frame(&mut self) -> Result<Vec<u8>> {
        self.reader.recv_frame().await
    }
    fn into_split(self: Box<Self>) -> (Box<dyn FrameWriter>, Box<dyn FrameReader>) {
        (Box::new(self.writer), Box::new(self.reader))
    }
}

struct MeshWriter {
    inner: Arc<TxInner>,
    conn_id: u64,
    next_msg_seq: u16,
    ack_rx: mpsc::UnboundedReceiver<InPkt>,
}

impl MeshWriter {
    /// Fragment `frame` and send each segment with stop-and-wait ARQ.
    async fn send_one(&mut self, frame: &[u8]) -> Result<()> {
        let msg_seq = self.next_msg_seq;
        self.next_msg_seq = self.next_msg_seq.wrapping_add(1);
        let mtu = self.inner.node.mtu();
        let chunk = mtu.saturating_sub(HEADER_LEN).max(1);
        // An empty frame still transmits one empty segment.
        let segs: Vec<&[u8]> = if frame.is_empty() {
            vec![&[][..]]
        } else {
            frame.chunks(chunk).collect()
        };
        let cnt = segs.len() as u16;
        for (i, seg) in segs.iter().enumerate() {
            let idx = i as u16;
            let pkt = encode_data(self.conn_id, msg_seq, idx, cnt, seg);
            let mut acked = false;
            for _ in 0..self.inner.retries {
                let _ = self.inner.node.send(self.inner.channel, &pkt).await;
                loop {
                    match tokio::time::timeout(self.inner.timeout, self.ack_rx.recv()).await {
                        Ok(Some(p))
                            if p.typ == T_DATA_ACK
                                && p.msg_seq == msg_seq
                                && p.frag_idx == idx =>
                        {
                            acked = true;
                            break;
                        }
                        Ok(Some(_)) => continue, // stale/mismatched ack — keep waiting
                        Ok(None) => return Err(TransportError::Closed),
                        Err(_) => break, // timeout → retransmit this segment
                    }
                }
                if acked {
                    break;
                }
            }
            if !acked {
                return Err(TransportError::Closed);
            }
        }
        Ok(())
    }
}

#[async_trait]
impl FrameWriter for MeshWriter {
    async fn send_frame(&mut self, frame: &[u8]) -> Result<()> {
        self.send_one(frame).await
    }
}

struct MeshReader {
    data_rx: mpsc::UnboundedReceiver<InPkt>,
    /// Partial reassembly per message: msg_seq -> (segments, have_count).
    reasm: HashMap<u16, (Vec<Option<Vec<u8>>>, usize)>,
}

impl MeshReader {
    /// Receive DATA segments (deduping), reassemble, and return the first message
    /// that completes. Segments are ACKed at the demux (see `ensure_started`), so
    /// the sender advances regardless of this method's call pace. Stop-and-wait
    /// keeps messages in order.
    async fn recv_one(&mut self) -> Result<Vec<u8>> {
        loop {
            let p = self.data_rx.recv().await.ok_or(TransportError::Closed)?;
            if p.typ != T_DATA || p.frag_cnt == 0 || p.frag_cnt > MAX_SEGMENTS {
                continue;
            }
            let cnt = p.frag_cnt as usize;
            let idx = p.frag_idx as usize;
            if idx >= cnt {
                continue;
            }
            let entry = self
                .reasm
                .entry(p.msg_seq)
                .or_insert_with(|| (vec![None; cnt], 0));
            if entry.0.len() != cnt {
                continue; // inconsistent frag_cnt for this msg — ignore
            }
            if entry.0[idx].is_none() {
                entry.0[idx] = Some(p.payload);
                entry.1 += 1;
            }
            if entry.1 == cnt {
                let (segs, _) = self.reasm.remove(&p.msg_seq).unwrap();
                let mut out = Vec::new();
                for s in segs.into_iter() {
                    out.extend_from_slice(&s.unwrap_or_default());
                }
                return Ok(out);
            }
        }
    }
}

#[async_trait]
impl FrameReader for MeshReader {
    async fn recv_frame(&mut self) -> Result<Vec<u8>> {
        self.recv_one().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mesh::{MeshInbox, MeshPacket, MockMeshFabric};

    // ---- deterministic lossy decorator: drop the FIRST send of each distinct
    // payload, pass retransmissions. Forces exactly one retransmit per packet and
    // always converges. ----
    struct DropOnceMeshNode {
        inner: Arc<dyn MeshNode>,
        seen: Mutex<std::collections::HashSet<Vec<u8>>>,
    }
    impl DropOnceMeshNode {
        fn new(inner: Arc<dyn MeshNode>) -> Arc<Self> {
            Arc::new(Self {
                inner,
                seen: Mutex::new(std::collections::HashSet::new()),
            })
        }
    }
    #[async_trait]
    impl MeshNode for DropOnceMeshNode {
        fn mtu(&self) -> usize {
            self.inner.mtu()
        }
        async fn send(&self, channel: u8, payload: &[u8]) -> Result<()> {
            let first = self.seen.lock().unwrap().insert(payload.to_vec());
            if first {
                return Ok(()); // drop the first transmission of this exact packet
            }
            self.inner.send(channel, payload).await
        }
        async fn subscribe(&self) -> Result<MeshInbox> {
            self.inner.subscribe().await
        }
    }

    fn short_to() -> Duration {
        Duration::from_millis(120)
    }

    #[tokio::test]
    async fn handshake_and_multi_segment_frame_over_reliable_mesh() {
        let fabric = MockMeshFabric::new(40); // tiny MTU → many segments
        let host = MeshTransport::with_timeout(
            Arc::new(fabric.node(1)),
            0,
            "host",
            short_to(),
            10,
        );
        let dialer = MeshTransport::with_timeout(
            Arc::new(fabric.node(2)),
            0,
            "dialer",
            short_to(),
            10,
        );
        let mut listener = host.listen().await.unwrap();
        let accept = tokio::spawn(async move { listener.accept().await });

        let mut client = dialer.dial(&"host".to_string()).await.unwrap();
        let mut server = accept.await.unwrap().unwrap();

        // Frame far larger than the MTU → fragmented into many segments.
        let frame: Vec<u8> = (0..500u32).map(|i| (i % 251) as u8).collect();
        client.send_frame(&frame).await.unwrap();
        let got = tokio::time::timeout(Duration::from_secs(5), server.recv_frame())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(got, frame);

        // Reverse direction reuses the connection.
        let reply = b"ack from server".to_vec();
        server.send_frame(&reply).await.unwrap();
        let back = tokio::time::timeout(Duration::from_secs(5), client.recv_frame())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(back, reply);
    }

    #[tokio::test]
    async fn delivers_despite_deterministic_loss() {
        // Every distinct packet's first transmission is dropped → the ARQ must
        // retransmit and still deliver a multi-segment frame + handshake.
        let fabric = MockMeshFabric::new(48);
        let host = MeshTransport::with_timeout(
            DropOnceMeshNode::new(Arc::new(fabric.node(1))),
            0,
            "h",
            short_to(),
            12,
        );
        let dialer = MeshTransport::with_timeout(
            DropOnceMeshNode::new(Arc::new(fabric.node(2))),
            0,
            "d",
            short_to(),
            12,
        );
        let mut listener = host.listen().await.unwrap();
        let accept = tokio::spawn(async move { listener.accept().await });
        let mut client = dialer.dial(&"h".to_string()).await.unwrap();
        let mut server = accept.await.unwrap().unwrap();

        let frame: Vec<u8> = (0..300u32).map(|i| i as u8).collect();
        client.send_frame(&frame).await.unwrap();
        let got = tokio::time::timeout(Duration::from_secs(10), server.recv_frame())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(got, frame);
    }

    #[tokio::test]
    async fn split_halves_send_and_receive_concurrently() {
        let fabric = MockMeshFabric::new(64);
        let host = MeshTransport::with_timeout(Arc::new(fabric.node(1)), 0, "h", short_to(), 10);
        let dialer = MeshTransport::with_timeout(Arc::new(fabric.node(2)), 0, "d", short_to(), 10);
        let mut listener = host.listen().await.unwrap();
        let accept = tokio::spawn(async move { listener.accept().await });
        let client = dialer.dial(&"h".to_string()).await.unwrap();
        let server = accept.await.unwrap().unwrap();

        let (mut cw, _cr) = client.into_split();
        let (_sw, mut sr) = server.into_split();
        cw.send_frame(b"hello over split halves").await.unwrap();
        let got = tokio::time::timeout(Duration::from_secs(5), sr.recv_frame())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(got, b"hello over split halves");
    }

    #[test]
    fn packet_codec_roundtrips_and_rejects_junk() {
        let syn = encode_syn(0x0102_0304_0506_0708, "alice", "bob");
        let p = parse_packet(&syn).unwrap();
        assert_eq!(p.typ, T_SYN);
        assert_eq!(p.conn_id, 0x0102_0304_0506_0708);
        assert_eq!(parse_syn_eps(p.payload).unwrap(), ("alice".into(), "bob".into()));

        let d = encode_data(9, 3, 1, 5, b"seg");
        let pd = parse_packet(&d).unwrap();
        assert_eq!((pd.typ, pd.conn_id, pd.msg_seq, pd.frag_idx, pd.frag_cnt), (T_DATA, 9, 3, 1, 5));
        assert_eq!(pd.payload, b"seg");

        assert!(parse_packet(b"").is_none());
        assert!(parse_packet(b"\xff\xff junk padding tail").is_none());
        assert!(parse_packet(&[MAGIC0, MAGIC1]).is_none()); // too short
        // wrong magic byte 1
        let mut bad = encode_ctrl(T_DATA_ACK, 1, 2, 3);
        bad[1] = 0x6D;
        assert!(parse_packet(&bad).is_none());
    }

    #[tokio::test]
    async fn dial_without_a_listener_errors() {
        let fabric = MockMeshFabric::new(64);
        let dialer = MeshTransport::with_timeout(
            Arc::new(fabric.node(1)),
            0,
            "d",
            Duration::from_millis(30),
            2,
        );
        // No one is listening on "ghost" → no SYN-ACK → dial fails (does not hang).
        let r = dialer.dial(&"ghost".to_string()).await;
        assert!(r.is_err());
    }

    // Keep MeshPacket referenced (used indirectly via the fabric) for clarity.
    #[allow(dead_code)]
    fn _mp(_p: MeshPacket) {}
}

// ---------------------------------------------------------------------------
// Formal verification: the packet decoder is proven TOTAL (never panics) and
// in-bounds for all short inputs — like `frag::parse_fragment` and the wire
// decoders. The stateful ARQ (nested heap) is covered by the tests above.
// ---------------------------------------------------------------------------
#[cfg(kani)]
mod proofs {
    use super::*;

    #[kani::proof]
    #[kani::unwind(24)]
    fn parse_packet_never_panics_and_is_bounded() {
        let len: usize = kani::any();
        kani::assume(len <= 22);
        let data: [u8; 22] = kani::any();
        match parse_packet(&data[..len]) {
            Some(p) => {
                assert!(p.payload.len() <= len);
                assert!(len >= HEADER_LEN);
            }
            None => {}
        }
    }

    #[kani::proof]
    #[kani::unwind(20)]
    fn parse_syn_eps_never_panics() {
        let len: usize = kani::any();
        kani::assume(len <= 16);
        let data: [u8; 16] = kani::any();
        let _ = parse_syn_eps(&data[..len]);
    }
}
