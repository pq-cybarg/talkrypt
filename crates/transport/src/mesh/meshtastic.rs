//! Meshtastic USB-serial [`MeshNode`] adapter (feature `mesh-radio`).
//!
//! Talks to a Meshtastic node (T-Deck, USB LoRa dongle, …) over its **Stream API**
//! serial framing, carrying talkrypt's opaque fragment bytes in a `PRIVATE_APP`
//! payload. The Meshtastic protobuf is encoded/decoded by a **hand-written minimal
//! codec** — only the handful of fields we use — so there is no `prost`/`protoc`
//! build dependency and the codec is fully unit-testable with golden byte vectors.
//!
//! Verified field numbers (meshtastic/protobufs `mesh.proto`, `portnums.proto`):
//! - `ToRadio.packet = 1` (len-delim), `ToRadio.want_config_id = 3` (varint)
//! - `FromRadio.packet = 2` (len-delim)
//! - `MeshPacket.from = 1` (fixed32), `.to = 2` (fixed32), `.channel = 3` (varint),
//!   `.decoded = 4` (len-delim, `Data`)
//! - `Data.portnum = 1` (varint), `.payload = 2` (len-delim)
//! - `PortNum::PRIVATE_APP = 256`
//!
//! Stream API framing: `0x94 0xC3 <len_hi> <len_lo> <protobuf>`, length big-endian,
//! payload ≤ 512 bytes; default serial baud 115200.
//!
//! The mesh's own per-channel crypto is an untrusted outer wrapper (see the module
//! docs); talkrypt's seal is the real envelope. This adapter moves only opaque,
//! already-sealed fragment bytes.

use std::sync::Arc;

use async_trait::async_trait;
use tokio::io::{AsyncReadExt, AsyncWriteExt, ReadHalf, WriteHalf};
use tokio::sync::Mutex as AsyncMutex;
use tokio_serial::{SerialPortBuilderExt, SerialStream};

use super::{MeshInbox, MeshNode, MeshPacket};
use crate::{Result, TransportError};

/// Meshtastic Stream API frame markers.
const START1: u8 = 0x94;
const START2: u8 = 0xc3;
/// Max protobuf payload per Stream API frame (device rejects larger).
const MAX_STREAM_PAYLOAD: usize = 512;
/// `PortNum::PRIVATE_APP` — the app port talkrypt fragments ride on.
const PRIVATE_APP: u64 = 256;
/// Meshtastic broadcast address (`0xffffffff`).
const BROADCAST: u32 = 0xffff_ffff;
/// Conservative usable `Data.payload` budget for one packet (region/preset
/// dependent; the default LoRa preset allows ~237, we leave headroom).
const DEFAULT_MTU: usize = 200;

// ---------------------------------------------------------------------------
// Minimal protobuf codec (only the fields we use). Encoding is standard
// LEB128 varints + length-delimited + fixed32; decoding skips unknown fields.
// ---------------------------------------------------------------------------

fn put_varint(out: &mut Vec<u8>, mut v: u64) {
    loop {
        let mut b = (v & 0x7f) as u8;
        v >>= 7;
        if v != 0 {
            b |= 0x80;
        }
        out.push(b);
        if v == 0 {
            break;
        }
    }
}

fn put_tag(out: &mut Vec<u8>, field: u32, wire: u32) {
    put_varint(out, ((field << 3) | wire) as u64);
}

fn put_len_delim(out: &mut Vec<u8>, field: u32, bytes: &[u8]) {
    put_tag(out, field, 2);
    put_varint(out, bytes.len() as u64);
    out.extend_from_slice(bytes);
}

fn put_varint_field(out: &mut Vec<u8>, field: u32, v: u64) {
    put_tag(out, field, 0);
    put_varint(out, v);
}

fn put_fixed32_field(out: &mut Vec<u8>, field: u32, v: u32) {
    put_tag(out, field, 5);
    out.extend_from_slice(&v.to_le_bytes());
}

/// Read a varint at `*pos`, advancing it. Bounded (≤10 bytes); returns `None` on
/// truncation or overflow.
fn get_varint(buf: &[u8], pos: &mut usize) -> Option<u64> {
    let mut result: u64 = 0;
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

/// One decoded protobuf field: its number and value slice/scalar.
enum Field<'a> {
    Varint(u32, u64),
    Fixed32(u32, u32),
    Bytes(u32, &'a [u8]),
}

/// Iterate the fields of a protobuf message, skipping ones we do not read. Flat,
/// bounded, never panics on malformed input (returns what it can, stops on error).
fn each_field(buf: &[u8], mut f: impl FnMut(Field<'_>)) {
    let mut pos = 0;
    while pos < buf.len() {
        let Some(tag) = get_varint(buf, &mut pos) else {
            return;
        };
        let field = (tag >> 3) as u32;
        let wire = (tag & 7) as u32;
        match wire {
            0 => {
                let Some(v) = get_varint(buf, &mut pos) else {
                    return;
                };
                f(Field::Varint(field, v));
            }
            5 => {
                if pos + 4 > buf.len() {
                    return;
                }
                let v = u32::from_le_bytes([buf[pos], buf[pos + 1], buf[pos + 2], buf[pos + 3]]);
                pos += 4;
                f(Field::Fixed32(field, v));
            }
            1 => {
                // fixed64 — skip.
                if pos + 8 > buf.len() {
                    return;
                }
                pos += 8;
            }
            2 => {
                let Some(len) = get_varint(buf, &mut pos) else {
                    return;
                };
                let len = len as usize;
                if pos + len > buf.len() {
                    return;
                }
                f(Field::Bytes(field, &buf[pos..pos + len]));
                pos += len;
            }
            _ => return, // groups / unknown wire types — stop.
        }
    }
}

/// Encode a `ToRadio { packet: MeshPacket { to: BROADCAST, channel, decoded:
/// Data { portnum: PRIVATE_APP, payload } } }` carrying `payload` on `channel`.
pub(crate) fn encode_toradio(channel: u8, payload: &[u8]) -> Vec<u8> {
    // Data { portnum=1: PRIVATE_APP, payload=2 }
    let mut data = Vec::new();
    put_varint_field(&mut data, 1, PRIVATE_APP);
    put_len_delim(&mut data, 2, payload);
    // MeshPacket { to=2: BROADCAST, channel=3, decoded=4: Data }
    let mut packet = Vec::new();
    put_fixed32_field(&mut packet, 2, BROADCAST);
    put_varint_field(&mut packet, 3, channel as u64);
    put_len_delim(&mut packet, 4, &data);
    // ToRadio { packet=1: MeshPacket }
    let mut toradio = Vec::new();
    put_len_delim(&mut toradio, 1, &packet);
    toradio
}

/// Encode a `ToRadio { want_config_id }` — sent on connect to engage the stream.
pub(crate) fn encode_want_config(nonce: u32) -> Vec<u8> {
    let mut toradio = Vec::new();
    put_varint_field(&mut toradio, 3, nonce as u64);
    toradio
}

/// A `PRIVATE_APP` payload recovered from a `FromRadio` protobuf.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct MeshtasticRx {
    pub channel: u8,
    pub from: Option<u32>,
    pub payload: Vec<u8>,
}

/// Parse a `FromRadio` protobuf; return the inner `PRIVATE_APP` payload (with its
/// channel + sender) if this frame carries one, else `None` (config, node-info,
/// text messages, other ports — all ignored).
pub(crate) fn parse_fromradio(buf: &[u8]) -> Option<MeshtasticRx> {
    let mut packet: Option<Vec<u8>> = None;
    each_field(buf, |fld| {
        if let Field::Bytes(2, b) = fld {
            packet = Some(b.to_vec()); // FromRadio.packet = 2
        }
    });
    let packet = packet?;

    let mut from: Option<u32> = None;
    let mut channel: u8 = 0;
    let mut decoded: Option<Vec<u8>> = None;
    each_field(&packet, |fld| match fld {
        Field::Fixed32(1, v) => from = Some(v),         // MeshPacket.from
        Field::Varint(3, v) => channel = v as u8,       // MeshPacket.channel
        Field::Bytes(4, b) => decoded = Some(b.to_vec()), // MeshPacket.decoded (Data)
        _ => {}
    });
    let decoded = decoded?;

    let mut portnum: u64 = 0;
    let mut payload: Option<Vec<u8>> = None;
    each_field(&decoded, |fld| match fld {
        Field::Varint(1, v) => portnum = v,             // Data.portnum
        Field::Bytes(2, b) => payload = Some(b.to_vec()), // Data.payload
        _ => {}
    });
    if portnum != PRIVATE_APP {
        return None;
    }
    Some(MeshtasticRx {
        channel,
        from,
        payload: payload?,
    })
}

/// Wrap a protobuf message in the Stream API frame (`0x94 0xC3 len16 …`).
pub(crate) fn frame(pb: &[u8]) -> Vec<u8> {
    let len = pb.len() as u16;
    let mut out = Vec::with_capacity(4 + pb.len());
    out.push(START1);
    out.push(START2);
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(pb);
    out
}

/// Incremental Stream API deframer: feed raw serial bytes, get complete protobuf
/// frames out. Resynchronizes on START1/START2 and drops the (debug-log) bytes in
/// between; discards over-long frames per the spec.
#[derive(Default)]
pub(crate) struct Deframer {
    buf: Vec<u8>,
}

impl Deframer {
    pub(crate) fn push(&mut self, bytes: &[u8], mut on_frame: impl FnMut(Vec<u8>)) {
        self.buf.extend_from_slice(bytes);
        loop {
            // Find START1 START2; drop anything before it (device debug output).
            let start = self
                .buf
                .windows(2)
                .position(|w| w[0] == START1 && w[1] == START2);
            let Some(s) = start else {
                // Keep at most the last byte (could be a lone START1).
                if self.buf.len() > 1 {
                    self.buf.drain(..self.buf.len() - 1);
                }
                return;
            };
            if s > 0 {
                self.buf.drain(..s);
            }
            if self.buf.len() < 4 {
                return; // need the length header
            }
            let len = u16::from_be_bytes([self.buf[2], self.buf[3]]) as usize;
            if len > MAX_STREAM_PAYLOAD {
                // Corrupt length — skip these two magic bytes and resync.
                self.buf.drain(..2);
                continue;
            }
            if self.buf.len() < 4 + len {
                return; // wait for the rest of the frame
            }
            let pb = self.buf[4..4 + len].to_vec();
            self.buf.drain(..4 + len);
            on_frame(pb);
        }
    }
}

/// A Meshtastic node reached over USB-serial, implementing [`MeshNode`].
pub struct MeshtasticSerial {
    writer: AsyncMutex<WriteHalf<SerialStream>>,
    reader: std::sync::Mutex<Option<ReadHalf<SerialStream>>>,
    mtu: usize,
}

impl MeshtasticSerial {
    /// Open the node at serial `path` (e.g. `/dev/tty.usbserial-XXX`) at `baud`
    /// (115200 for Meshtastic). Sends a `want_config_id` to engage the stream.
    pub async fn open(path: &str, baud: u32) -> Result<Arc<Self>> {
        Self::open_with_mtu(path, baud, DEFAULT_MTU).await
    }

    /// As [`open`](Self::open) with an explicit per-packet payload `mtu`.
    pub async fn open_with_mtu(path: &str, baud: u32, mtu: usize) -> Result<Arc<Self>> {
        let stream = tokio_serial::new(path, baud)
            .open_native_async()
            .map_err(|e| TransportError::Io(format!("open {path}: {e}")))?;
        let (rd, mut wr) = tokio::io::split(stream);
        // Engage the stream: a want_config_id nonce (correlation id only).
        let _ = wr.write_all(&frame(&encode_want_config(0x7401_7401))).await;
        let _ = wr.flush().await;
        Ok(Arc::new(Self {
            writer: AsyncMutex::new(wr),
            reader: std::sync::Mutex::new(Some(rd)),
            mtu,
        }))
    }
}

#[async_trait]
impl MeshNode for MeshtasticSerial {
    fn mtu(&self) -> usize {
        self.mtu
    }

    async fn send(&self, channel: u8, payload: &[u8]) -> Result<()> {
        let pkt = frame(&encode_toradio(channel, payload));
        let mut w = self.writer.lock().await;
        w.write_all(&pkt)
            .await
            .map_err(|e| TransportError::Io(e.to_string()))?;
        w.flush().await.map_err(|e| TransportError::Io(e.to_string()))?;
        Ok(())
    }

    async fn subscribe(&self) -> Result<MeshInbox> {
        let mut rd = self
            .reader
            .lock()
            .unwrap()
            .take()
            .ok_or_else(|| TransportError::Io("meshtastic reader already taken".into()))?;
        let (inbox, tx) = MeshInbox::channel();
        tokio::spawn(async move {
            let mut deframer = Deframer::default();
            let mut buf = [0u8; 512];
            loop {
                match rd.read(&mut buf).await {
                    Ok(0) => break, // port closed
                    Ok(n) => {
                        let mut packets = Vec::new();
                        deframer.push(&buf[..n], |pb| {
                            if let Some(rx) = parse_fromradio(&pb) {
                                packets.push(MeshPacket {
                                    channel: rx.channel,
                                    payload: rx.payload,
                                    from: rx.from,
                                });
                            }
                        });
                        for p in packets {
                            if tx.send(p).is_err() {
                                return; // inbox dropped
                            }
                        }
                    }
                    Err(_) => break,
                }
            }
        });
        Ok(inbox)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn toradio_roundtrips_through_a_fromradio_shaped_message() {
        // Encode what we'd SEND, then wrap the same MeshPacket as a FromRadio the
        // device would emit, and confirm our parser recovers the payload/channel.
        let payload = b"talkrypt-fragment-bytes";
        // Build the MeshPacket exactly as encode_toradio does, then wrap as
        // FromRadio { packet=2 } with a from=fixed32 added (device stamps it).
        let mut data = Vec::new();
        put_varint_field(&mut data, 1, PRIVATE_APP);
        put_len_delim(&mut data, 2, payload);
        let mut packet = Vec::new();
        put_fixed32_field(&mut packet, 1, 0x1234_5678); // from
        put_varint_field(&mut packet, 3, 5); // channel
        put_len_delim(&mut packet, 4, &data);
        let mut fromradio = Vec::new();
        put_len_delim(&mut fromradio, 2, &packet);

        let rx = parse_fromradio(&fromradio).expect("PRIVATE_APP payload recovered");
        assert_eq!(rx.channel, 5);
        assert_eq!(rx.from, Some(0x1234_5678));
        assert_eq!(rx.payload, payload);
    }

    #[test]
    fn encode_toradio_has_expected_shape() {
        let pb = encode_toradio(3, b"hi");
        // ToRadio.packet = field 1, wire 2 → first tag byte = (1<<3)|2 = 0x0a.
        assert_eq!(pb[0], 0x0a);
        // Re-parse the packet as if echoed back (add a portnum-bearing Data) — the
        // encoder must produce a PRIVATE_APP payload our parser accepts.
        let mut fromradio = Vec::new();
        put_len_delim(&mut fromradio, 2, &pb[2..]); // pb[2..] = the MeshPacket bytes
        let rx = parse_fromradio(&fromradio).unwrap();
        assert_eq!(rx.channel, 3);
        assert_eq!(rx.payload, b"hi");
    }

    #[test]
    fn parse_ignores_non_private_app_ports() {
        // A TEXT_MESSAGE_APP (portnum=1) packet must NOT surface as a talkrypt payload.
        let mut data = Vec::new();
        put_varint_field(&mut data, 1, 1); // TEXT_MESSAGE_APP
        put_len_delim(&mut data, 2, b"hello mesh");
        let mut packet = Vec::new();
        put_len_delim(&mut packet, 4, &data);
        let mut fromradio = Vec::new();
        put_len_delim(&mut fromradio, 2, &packet);
        assert!(parse_fromradio(&fromradio).is_none());
    }

    #[test]
    fn parse_tolerates_junk_and_truncation() {
        assert!(parse_fromradio(b"").is_none());
        assert!(parse_fromradio(b"\xff\xff\xff garbage").is_none());
        // Truncated length-delimited field must not panic.
        assert!(parse_fromradio(&[0x12, 0x40, 0x01, 0x02]).is_none());
    }

    #[test]
    fn frame_and_deframe_roundtrip() {
        let a = encode_toradio(1, b"one");
        let b = encode_toradio(2, b"two");
        let wire = [frame(&a), frame(&b)].concat();

        let mut d = Deframer::default();
        let mut got: Vec<Vec<u8>> = Vec::new();
        // Feed the stream in awkward 3-byte chunks to exercise reassembly.
        for chunk in wire.chunks(3) {
            d.push(chunk, |pb| got.push(pb));
        }
        assert_eq!(got, vec![a, b]);
    }

    #[test]
    fn deframer_resyncs_past_device_debug_output() {
        let a = encode_toradio(0, b"payload");
        let mut wire = b"INFO | some device debug log line\r\n".to_vec();
        wire.extend_from_slice(&frame(&a));
        let mut d = Deframer::default();
        let mut got = Vec::new();
        d.push(&wire, |pb| got.push(pb));
        assert_eq!(got, vec![a]);
    }

    #[test]
    fn deframer_skips_corrupt_overlong_length() {
        // START1 START2 followed by a >512 length must be skipped, then a good frame recovered.
        let good = encode_toradio(0, b"ok");
        let mut wire = vec![START1, START2, 0xff, 0xff]; // len 65535 > 512
        wire.extend_from_slice(&frame(&good));
        let mut d = Deframer::default();
        let mut got = Vec::new();
        d.push(&wire, |pb| got.push(pb));
        assert_eq!(got, vec![good]);
    }
}
