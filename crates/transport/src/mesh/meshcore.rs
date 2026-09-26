//! Meshcore USB-serial [`MeshNode`] adapter (feature `mesh-radio`).
//!
//! Talks to a Meshcore node over its **companion protocol**. Meshcore's channel
//! message carries a UTF-8 *text* field (not arbitrary binary), so talkrypt
//! fragments are **base64-wrapped** to stay text-safe regardless of firmware
//! handling. The mesh's own AES-128 channel key is an untrusted outer wrapper;
//! talkrypt's seal is the real envelope (this adapter moves only opaque,
//! already-sealed fragment bytes, base64-encoded).
//!
//! **Command / response payload layouts are verified** against the official
//! companion protocol doc
//! (<https://github.com/meshcore-dev/MeshCore/blob/main/docs/companion_protocol.md>):
//!
//! - `CMD_SEND_CHANNEL_TXT_MSG` (0x03): `[0x03][reserved=0][channel_idx]
//!   [timestamp u32 LE][text…]`
//! - `PACKET_CHANNEL_MSG_RECV` (0x08): `[0x08][channel_idx][path_len][text_type]
//!   [timestamp u32 LE][text…]`
//! - `PACKET_CHANNEL_MSG_RECV_V3` (0x11): `[0x11][snr i8][reserved u16]
//!   [channel_idx][path_len][text_type][timestamp u32 LE][text…]`
//!
//! **The serial OUTER framing is firmware-dependent** — this adapter uses the
//! companion serial framing `[type u8][len u16 LE][payload]` (`0x3C` app→radio,
//! `0x3E` radio→app). BLE companion transports instead treat each characteristic
//! write/notification as one whole frame (no length prefix). If your node speaks a
//! different serial framing, adjust [`frame`] / [`Deframer`] — the verified
//! command codec above is unaffected. **Validate end-to-end on your hardware.**

use std::sync::Arc;

use async_trait::async_trait;
use base64::Engine;
use tokio::io::{AsyncReadExt, AsyncWriteExt, ReadHalf, WriteHalf};
use tokio::sync::Mutex as AsyncMutex;
use tokio_serial::{SerialPortBuilderExt, SerialStream};

use super::{MeshInbox, MeshNode, MeshPacket};
use crate::{Result, TransportError};

/// Companion serial frame types (firmware-dependent — see module docs).
const TYPE_TO_RADIO: u8 = 0x3c;
const TYPE_FROM_RADIO: u8 = 0x3e;

/// Payload command / response codes (verified against the companion protocol doc).
const CMD_SEND_CHANNEL_TXT_MSG: u8 = 0x03;
const PACKET_CHANNEL_MSG_RECV: u8 = 0x08;
const PACKET_CHANNEL_MSG_RECV_V3: u8 = 0x11;

/// Fragment byte budget per packet. Meshcore channel text is UTF-8 and typically
/// capped ~160 bytes; base64 inflates by 4/3, so a 120-byte fragment → 160 text
/// chars. Chosen so `base64(fragment) <= 160`.
const DEFAULT_MTU: usize = 120;

fn b64() -> base64::engine::GeneralPurpose {
    base64::engine::general_purpose::STANDARD
}

/// Build a `CMD_SEND_CHANNEL_TXT_MSG` payload carrying `text` on `channel`.
pub(crate) fn encode_send_channel(channel: u8, timestamp: u32, text: &[u8]) -> Vec<u8> {
    let mut p = Vec::with_capacity(7 + text.len());
    p.push(CMD_SEND_CHANNEL_TXT_MSG);
    p.push(0x00); // reserved
    p.push(channel);
    p.extend_from_slice(&timestamp.to_le_bytes());
    p.extend_from_slice(text);
    p
}

/// A channel message recovered from a companion response payload.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct MeshcoreRx {
    pub channel: u8,
    pub text: Vec<u8>,
}

/// Parse a `PACKET_CHANNEL_MSG_RECV` (0x08) or `_V3` (0x11) payload; return the
/// channel + text. Returns `None` for any other code or a truncated frame.
pub(crate) fn parse_channel_recv(p: &[u8]) -> Option<MeshcoreRx> {
    match p.first().copied()? {
        PACKET_CHANNEL_MSG_RECV => {
            // [0x08][channel][path_len][text_type][ts u32][text…] → text at 8.
            if p.len() < 8 {
                return None;
            }
            Some(MeshcoreRx {
                channel: p[1],
                text: p[8..].to_vec(),
            })
        }
        PACKET_CHANNEL_MSG_RECV_V3 => {
            // [0x11][snr][rsv u16][channel][path_len][text_type][ts u32][text…] → text at 11.
            if p.len() < 11 {
                return None;
            }
            Some(MeshcoreRx {
                channel: p[4],
                text: p[11..].to_vec(),
            })
        }
        _ => None,
    }
}

/// Wrap a companion payload in the serial outer frame `[type][len u16 LE][payload]`.
pub(crate) fn frame(payload: &[u8]) -> Vec<u8> {
    let len = payload.len() as u16;
    let mut out = Vec::with_capacity(3 + payload.len());
    out.push(TYPE_TO_RADIO);
    out.extend_from_slice(&len.to_le_bytes());
    out.extend_from_slice(payload);
    out
}

/// Incremental deframer for radio→app (`0x3E`) serial frames `[0x3E][len u16 LE]
/// [payload]`. Resynchronizes on the type byte; drops other bytes.
#[derive(Default)]
pub(crate) struct Deframer {
    buf: Vec<u8>,
}

impl Deframer {
    pub(crate) fn push(&mut self, bytes: &[u8], mut on_payload: impl FnMut(Vec<u8>)) {
        self.buf.extend_from_slice(bytes);
        loop {
            let Some(s) = self.buf.iter().position(|&b| b == TYPE_FROM_RADIO) else {
                self.buf.clear();
                return;
            };
            if s > 0 {
                self.buf.drain(..s);
            }
            if self.buf.len() < 3 {
                return; // need type + len16
            }
            let len = u16::from_le_bytes([self.buf[1], self.buf[2]]) as usize;
            if self.buf.len() < 3 + len {
                return; // wait for the rest
            }
            let payload = self.buf[3..3 + len].to_vec();
            self.buf.drain(..3 + len);
            on_payload(payload);
        }
    }
}

/// A Meshcore node reached over USB-serial, implementing [`MeshNode`]. Fragments
/// are base64-wrapped into channel text (see module docs).
pub struct MeshcoreSerial {
    writer: AsyncMutex<WriteHalf<SerialStream>>,
    reader: std::sync::Mutex<Option<ReadHalf<SerialStream>>>,
    mtu: usize,
}

impl MeshcoreSerial {
    /// Open the node at serial `path` at `baud`.
    pub async fn open(path: &str, baud: u32) -> Result<Arc<Self>> {
        Self::open_with_mtu(path, baud, DEFAULT_MTU).await
    }

    /// As [`open`](Self::open) with an explicit per-packet fragment `mtu` (bytes;
    /// keep `base64(mtu) <= your firmware's channel text limit`).
    pub async fn open_with_mtu(path: &str, baud: u32, mtu: usize) -> Result<Arc<Self>> {
        let stream = tokio_serial::new(path, baud)
            .open_native_async()
            .map_err(|e| TransportError::Io(format!("open {path}: {e}")))?;
        let (rd, wr) = tokio::io::split(stream);
        Ok(Arc::new(Self {
            writer: AsyncMutex::new(wr),
            reader: std::sync::Mutex::new(Some(rd)),
            mtu,
        }))
    }
}

#[async_trait]
impl MeshNode for MeshcoreSerial {
    fn mtu(&self) -> usize {
        self.mtu
    }

    async fn send(&self, channel: u8, payload: &[u8]) -> Result<()> {
        // Base64 the opaque fragment so it survives the UTF-8 text field.
        let text = b64().encode(payload);
        let pkt = frame(&encode_send_channel(channel, 0, text.as_bytes()));
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
            .ok_or_else(|| TransportError::Io("meshcore reader already taken".into()))?;
        let (inbox, tx) = MeshInbox::channel();
        tokio::spawn(async move {
            let mut deframer = Deframer::default();
            let mut buf = [0u8; 512];
            loop {
                match rd.read(&mut buf).await {
                    Ok(0) => break,
                    Ok(n) => {
                        let mut packets = Vec::new();
                        deframer.push(&buf[..n], |payload| {
                            if let Some(rx) = parse_channel_recv(&payload) {
                                // Undo the base64 text wrapping → opaque fragment bytes.
                                if let Ok(frag) = b64().decode(&rx.text) {
                                    packets.push(MeshPacket {
                                        channel: rx.channel,
                                        payload: frag,
                                        from: None, // Meshcore channel msgs are not per-node addressed here
                                    });
                                }
                            }
                        });
                        for p in packets {
                            if tx.send(p).is_err() {
                                return;
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
    fn send_channel_payload_has_verified_layout() {
        // Spec example: 03 00 01 <ts LE> "Hello" on channel 1.
        let p = encode_send_channel(1, 0x4996_02d2, b"Hello");
        assert_eq!(p[0], 0x03);
        assert_eq!(p[1], 0x00);
        assert_eq!(p[2], 0x01);
        assert_eq!(&p[3..7], &0x4996_02d2u32.to_le_bytes());
        assert_eq!(&p[7..], b"Hello");
    }

    #[test]
    fn channel_recv_v1_and_v3_extract_channel_and_text() {
        // v1: [08][ch=2][path][ttype][ts u32][text]
        let mut v1 = vec![0x08, 2, 0xff, 0, 1, 2, 3, 4];
        v1.extend_from_slice(b"aGVsbG8=");
        let rx = parse_channel_recv(&v1).unwrap();
        assert_eq!(rx.channel, 2);
        assert_eq!(rx.text, b"aGVsbG8=");
        // v3: [11][snr][rsv u16][ch=5][path][ttype][ts u32][text]
        let mut v3 = vec![0x11, 0x10, 0, 0, 5, 0xff, 0, 9, 9, 9, 9];
        v3.extend_from_slice(b"d29ybGQ=");
        let rx3 = parse_channel_recv(&v3).unwrap();
        assert_eq!(rx3.channel, 5);
        assert_eq!(rx3.text, b"d29ybGQ=");
    }

    #[test]
    fn recv_ignores_other_codes_and_truncation() {
        assert!(parse_channel_recv(&[]).is_none());
        assert!(parse_channel_recv(&[0x07, 1, 2]).is_none()); // contact msg, not channel
        assert!(parse_channel_recv(&[0x08, 1, 2]).is_none()); // truncated (< 8)
    }

    #[test]
    fn fragment_base64_roundtrips_through_send_then_recv() {
        // A talkrypt fragment (arbitrary binary, incl. our 0xA7 0x6D magic) survives
        // the base64 text wrapping in both directions.
        let frag: Vec<u8> = [0xA7u8, 0x6D, 0x01, 0x01].iter().copied().chain(0..90u8).collect();
        let text = b64().encode(&frag);
        // build a recv frame carrying that text, parse + decode it back.
        let mut recv = vec![0x08, 3, 0xff, 0, 0, 0, 0, 0];
        recv.extend_from_slice(text.as_bytes());
        let rx = parse_channel_recv(&recv).unwrap();
        assert_eq!(rx.channel, 3);
        assert_eq!(b64().decode(&rx.text).unwrap(), frag);
    }

    #[test]
    fn frame_and_deframe_roundtrip() {
        // App→radio framing uses 0x3C; simulate the radio→app (0x3E) direction for
        // the deframer by re-typing the same length/payload.
        let a = encode_send_channel(0, 0, b"YQ==");
        let b = encode_send_channel(1, 0, b"Yg==");
        let mut wire = Vec::new();
        for p in [&a, &b] {
            wire.push(TYPE_FROM_RADIO);
            wire.extend_from_slice(&(p.len() as u16).to_le_bytes());
            wire.extend_from_slice(p);
        }
        let mut d = Deframer::default();
        let mut got = Vec::new();
        for chunk in wire.chunks(3) {
            d.push(chunk, |p| got.push(p));
        }
        assert_eq!(got, vec![a, b]);
    }

    #[test]
    fn app_to_radio_frame_has_type_and_le_len() {
        let f = frame(&[0xAA, 0xBB]);
        assert_eq!(f[0], TYPE_TO_RADIO);
        assert_eq!(&f[1..3], &2u16.to_le_bytes());
        assert_eq!(&f[3..], &[0xAA, 0xBB]);
    }
}
