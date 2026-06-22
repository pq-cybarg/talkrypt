//! Optional Nym mixnet transport (`nym` feature).
//!
//! Routes talkrypt's framed ciphertext over the Nym mixnet instead of (or
//! alongside) Tor. `dial` opens a mixnet stream to a peer's Nym address;
//! `listen` accepts inbound mixnet streams. Both exchange the same
//! length-framed bytes as every other transport — the engine is unchanged, so
//! this is a drop-in [`Transport`].
//!
//! ## Why offer Nym at all
//!
//! Not for post-quantum transport: Nym's **mixnet** path (Sphinx packets) is
//! still classical Curve25519 — its live PQ ("Lewes Protocol") covers only the
//! Fast-Mode VPN handshake, not the 5-hop mix path. The reason to offer Nym is
//! the mixnet's **traffic-analysis / timing-correlation resistance** (mixing +
//! cover traffic), a metadata property Tor fundamentally lacks. The classical
//! mixnet handshake is acceptable here because talkrypt's *content* is already
//! ML-KEM-1024 + ML-DSA-87 and rides *above* this transport: an adversary who
//! breaks the classical mixnet handshake gets routing metadata, not plaintext.
//!
//! ## SDK pin
//!
//! The `Stream` module (`mixnet::stream`) is Git-only — the crates.io release
//! predates it — so `nym-sdk` is pinned to a specific `nymtech/nym` revision in
//! `Cargo.toml`. The API used here (`MixnetClient::connect_new`,
//! `nym_address`, `listener`/`MixnetListener::accept`, `open_stream` →
//! `MixnetStream: AsyncRead + AsyncWrite`) is what that revision exposes; bump
//! the pin and re-verify against this module if the SDK API shifts.

use std::sync::Arc;

use async_trait::async_trait;
use nym_sdk::mixnet::{MixnetClient, MixnetStream, Recipient};
use tokio::io::{ReadHalf, WriteHalf};
use tokio::sync::{mpsc, Mutex};

use crate::framing::{read_frame, write_frame};
use crate::{
    Endpoint, FrameReader, FrameWriter, Listener, Result, Stream, Transport, TransportError,
    TransportStatus,
};

fn io<E: std::fmt::Display>(e: E) -> TransportError {
    TransportError::Io(e.to_string())
}

/// A Nym transport backed by a connected mixnet client.
///
/// A single client multiplexes every stream (inbound via [`listen`] and
/// outbound via [`dial`]) over one gateway connection, so — like the shared
/// Arti client — it is meant to be `Arc`-wrapped and reused across sessions
/// rather than reconnected per chat. The client is behind a [`Mutex`] only to
/// serialize the brief `listener()`/`open_stream()` registration calls; the
/// returned streams do their IO without holding the lock.
///
/// [`listen`]: Transport::listen
/// [`dial`]: Transport::dial
pub struct NymTransport {
    client: Arc<Mutex<MixnetClient>>,
    /// This client's mixnet address, cached at connect for advertising.
    nym_address: String,
}

impl NymTransport {
    /// Connect a fresh mixnet client (ephemeral identity).
    ///
    /// This performs the gateway handshake and is the slow part — like a Tor
    /// bootstrap — so connect once and share the result.
    pub async fn connect() -> Result<Self> {
        let client = MixnetClient::connect_new()
            .await
            .map_err(|e| io(format!("nym connect: {e}")))?;
        let nym_address = client.nym_address().to_string();
        Ok(Self {
            client: Arc::new(Mutex::new(client)),
            nym_address,
        })
    }

    /// This node's mixnet address (bare, without the `nym:` scheme prefix).
    pub fn nym_address(&self) -> &str {
        &self.nym_address
    }

    /// The advertisable endpoint for this node: the `nym:`-prefixed address a
    /// peer dials to reach us.
    pub fn endpoint(&self) -> Endpoint {
        format!("nym:{}", self.nym_address)
    }
}

/// A framed mixnet stream, pre-split into read/write halves.
pub struct NymStream {
    w: WriteHalf<MixnetStream>,
    r: ReadHalf<MixnetStream>,
}

impl NymStream {
    fn new(s: MixnetStream) -> Self {
        let (r, w) = tokio::io::split(s);
        Self { w, r }
    }
}

pub struct NymWriter(WriteHalf<MixnetStream>);
pub struct NymReader(ReadHalf<MixnetStream>);

#[async_trait]
impl FrameWriter for NymWriter {
    async fn send_frame(&mut self, frame: &[u8]) -> Result<()> {
        write_frame(&mut self.0, frame).await
    }
}

#[async_trait]
impl FrameReader for NymReader {
    async fn recv_frame(&mut self) -> Result<Vec<u8>> {
        read_frame(&mut self.0).await
    }
}

#[async_trait]
impl Stream for NymStream {
    async fn send_frame(&mut self, frame: &[u8]) -> Result<()> {
        write_frame(&mut self.w, frame).await
    }
    async fn recv_frame(&mut self) -> Result<Vec<u8>> {
        read_frame(&mut self.r).await
    }
    fn into_split(self: Box<Self>) -> (Box<dyn FrameWriter>, Box<dyn FrameReader>) {
        (Box::new(NymWriter(self.w)), Box::new(NymReader(self.r)))
    }
}

/// Listener that yields accepted inbound mixnet streams.
pub struct NymListener {
    endpoint: Endpoint,
    rx: mpsc::UnboundedReceiver<MixnetStream>,
}

#[async_trait]
impl Listener for NymListener {
    async fn accept(&mut self) -> Result<Box<dyn Stream>> {
        let s = self.rx.recv().await.ok_or(TransportError::Closed)?;
        Ok(Box::new(NymStream::new(s)))
    }
    fn endpoint(&self) -> Endpoint {
        self.endpoint.clone()
    }
}

#[async_trait]
impl Transport for NymTransport {
    async fn listen(&self) -> Result<Box<dyn Listener>> {
        // `listener()` may only be called once per client; it registers the
        // inbound handler and returns an owned listener we drive in a task,
        // feeding accepted streams into the fan-in queue. The lock is held only
        // for the brief registration, not for the accept loop.
        let mut mix_listener = {
            let mut guard = self.client.lock().await;
            guard
                .listener()
                .map_err(|e| io(format!("nym listener: {e}")))?
        };
        let (tx, rx) = mpsc::unbounded_channel();
        tokio::spawn(async move {
            // MixnetListener::accept yields `Some(stream)` per inbound peer and
            // `None` when the client shuts down (the listener is drained).
            while let Some(s) = mix_listener.accept().await {
                if tx.send(s).is_err() {
                    break;
                }
            }
        });
        Ok(Box::new(NymListener {
            endpoint: self.endpoint(),
            rx,
        }))
    }

    async fn dial(&self, endpoint: &Endpoint) -> Result<Box<dyn Stream>> {
        // Accept both the scheme-prefixed (`nym:<addr>`) and bare forms so this
        // leg behaves identically whether reached via MultiTransport or directly.
        let addr = endpoint.strip_prefix("nym:").unwrap_or(endpoint);
        let recipient = Recipient::try_from_base58_string(addr)
            .map_err(|e| io(format!("bad nym address {addr}: {e}")))?;
        let stream = {
            let mut guard = self.client.lock().await;
            guard
                .open_stream(recipient, None)
                .await
                .map_err(|e| io(format!("nym open_stream to {addr}: {e}")))?
        };
        Ok(Box::new(NymStream::new(stream)))
    }

    fn status(&self) -> TransportStatus {
        // A connected client is online at its mixnet address.
        TransportStatus::Online {
            endpoint: self.endpoint(),
        }
    }

    fn local_endpoint(&self) -> Endpoint {
        self.endpoint()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Live mixnet round-trip. Requires network access and a gateway handshake
    /// (slow). Run explicitly:
    ///   cargo test -p talkrypt-transport --features nym -- --ignored --nocapture
    #[tokio::test]
    #[ignore = "requires live Nym mixnet"]
    async fn mixnet_self_connect_roundtrip() {
        let server = NymTransport::connect().await.expect("connect server");
        let server_addr = server.endpoint();
        let mut listener = server.listen().await.expect("listen");
        eprintln!("nym endpoint: {server_addr}");

        let accept = tokio::spawn(async move {
            let mut s = listener.accept().await.unwrap();
            let got = s.recv_frame().await.unwrap();
            s.send_frame(b"pong").await.unwrap();
            got
        });

        let client = NymTransport::connect().await.expect("connect client");
        let mut cs = client.dial(&server_addr).await.expect("dial");
        cs.send_frame(b"ping").await.unwrap();
        assert_eq!(cs.recv_frame().await.unwrap(), b"pong");
        assert_eq!(accept.await.unwrap(), b"ping");
    }
}
