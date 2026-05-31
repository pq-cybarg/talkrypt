//! In-process loopback transport.
//!
//! A [`LoopbackFabric`] is a shared switchboard: transports register their
//! endpoint with it, and `dial` wires up a bidirectional channel pair, handing
//! one end to the dialer and delivering the other to the listener's accept
//! queue. No sockets, no network — deterministic and instant, ideal for tests
//! and offline operation.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use tokio::sync::mpsc;

use crate::{
    Endpoint, FrameReader, FrameWriter, Listener, Result, Stream, Transport, TransportError,
    TransportStatus,
};

/// One end of a bidirectional in-memory connection.
pub struct LoopStream {
    tx: mpsc::UnboundedSender<Vec<u8>>,
    rx: mpsc::UnboundedReceiver<Vec<u8>>,
}

/// Write half of a [`LoopStream`].
pub struct LoopWriter(mpsc::UnboundedSender<Vec<u8>>);
/// Read half of a [`LoopStream`].
pub struct LoopReader(mpsc::UnboundedReceiver<Vec<u8>>);

#[async_trait]
impl FrameWriter for LoopWriter {
    async fn send_frame(&mut self, frame: &[u8]) -> Result<()> {
        self.0
            .send(frame.to_vec())
            .map_err(|_| TransportError::Closed)
    }
}

#[async_trait]
impl FrameReader for LoopReader {
    async fn recv_frame(&mut self) -> Result<Vec<u8>> {
        self.0.recv().await.ok_or(TransportError::Closed)
    }
}

#[async_trait]
impl Stream for LoopStream {
    async fn send_frame(&mut self, frame: &[u8]) -> Result<()> {
        self.tx
            .send(frame.to_vec())
            .map_err(|_| TransportError::Closed)
    }

    async fn recv_frame(&mut self) -> Result<Vec<u8>> {
        self.rx.recv().await.ok_or(TransportError::Closed)
    }

    fn into_split(self: Box<Self>) -> (Box<dyn FrameWriter>, Box<dyn FrameReader>) {
        (Box::new(LoopWriter(self.tx)), Box::new(LoopReader(self.rx)))
    }
}

fn duplex() -> (LoopStream, LoopStream) {
    let (a_tx, a_rx) = mpsc::unbounded_channel();
    let (b_tx, b_rx) = mpsc::unbounded_channel();
    // a writes to a_tx -> b reads from a_rx; b writes to b_tx -> a reads b_rx.
    (
        LoopStream { tx: a_tx, rx: b_rx },
        LoopStream { tx: b_tx, rx: a_rx },
    )
}

/// Maps an endpoint to the sender that delivers inbound streams to its listener.
type ListenerMap = HashMap<Endpoint, mpsc::UnboundedSender<Box<dyn Stream>>>;

/// Shared switchboard mapping endpoints to their listener queues.
#[derive(Clone, Default)]
pub struct LoopbackFabric {
    inner: Arc<Mutex<ListenerMap>>,
}

impl LoopbackFabric {
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a transport bound to `endpoint` on this fabric.
    pub fn transport(&self, endpoint: impl Into<Endpoint>) -> LoopbackTransport {
        LoopbackTransport {
            fabric: self.clone(),
            local: endpoint.into(),
        }
    }

    fn register(&self, endpoint: Endpoint) -> mpsc::UnboundedReceiver<Box<dyn Stream>> {
        let (tx, rx) = mpsc::unbounded_channel();
        self.inner.lock().unwrap().insert(endpoint, tx);
        rx
    }

    fn connect(&self, endpoint: &Endpoint) -> Result<LoopStream> {
        let guard = self.inner.lock().unwrap();
        let listener_tx = guard
            .get(endpoint)
            .ok_or_else(|| TransportError::NoListener(endpoint.clone()))?;
        let (dialer_end, listener_end) = duplex();
        listener_tx
            .send(Box::new(listener_end))
            .map_err(|_| TransportError::NoListener(endpoint.clone()))?;
        Ok(dialer_end)
    }
}

/// A transport endpoint on a [`LoopbackFabric`].
#[derive(Clone)]
pub struct LoopbackTransport {
    fabric: LoopbackFabric,
    local: Endpoint,
}

pub struct LoopbackListener {
    endpoint: Endpoint,
    rx: mpsc::UnboundedReceiver<Box<dyn Stream>>,
}

#[async_trait]
impl Listener for LoopbackListener {
    async fn accept(&mut self) -> Result<Box<dyn Stream>> {
        self.rx.recv().await.ok_or(TransportError::Closed)
    }
    fn endpoint(&self) -> Endpoint {
        self.endpoint.clone()
    }
}

#[async_trait]
impl Transport for LoopbackTransport {
    async fn listen(&self) -> Result<Box<dyn Listener>> {
        let rx = self.fabric.register(self.local.clone());
        Ok(Box::new(LoopbackListener {
            endpoint: self.local.clone(),
            rx,
        }))
    }

    async fn dial(&self, endpoint: &Endpoint) -> Result<Box<dyn Stream>> {
        let stream = self.fabric.connect(endpoint)?;
        Ok(Box::new(stream))
    }

    fn status(&self) -> TransportStatus {
        TransportStatus::Online {
            endpoint: self.local.clone(),
        }
    }

    fn local_endpoint(&self) -> Endpoint {
        self.local.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn dial_then_bidirectional_exchange() {
        let fabric = LoopbackFabric::new();
        let alice = fabric.transport("alice.onion");
        let bob = fabric.transport("bob.onion");

        let mut bob_listener = bob.listen().await.unwrap();

        // Alice dials Bob; Bob accepts.
        let mut a_stream = alice.dial(&"bob.onion".to_string()).await.unwrap();
        let mut b_stream = bob_listener.accept().await.unwrap();

        a_stream.send_frame(b"ping").await.unwrap();
        assert_eq!(b_stream.recv_frame().await.unwrap(), b"ping");

        b_stream.send_frame(b"pong").await.unwrap();
        assert_eq!(a_stream.recv_frame().await.unwrap(), b"pong");
    }

    #[tokio::test]
    async fn dial_unknown_endpoint_errors() {
        let fabric = LoopbackFabric::new();
        let alice = fabric.transport("alice.onion");
        match alice.dial(&"ghost.onion".to_string()).await {
            Err(TransportError::NoListener(ep)) => assert_eq!(ep, "ghost.onion"),
            Err(e) => panic!("expected NoListener, got {e}"),
            Ok(_) => panic!("expected NoListener, got a stream"),
        }
    }

    #[tokio::test]
    async fn carries_opaque_bytes_unchanged() {
        let fabric = LoopbackFabric::new();
        let a = fabric.transport("a");
        let b = fabric.transport("b");
        let mut bl = b.listen().await.unwrap();
        let mut ax = a.dial(&"b".to_string()).await.unwrap();
        let mut bx = bl.accept().await.unwrap();

        let blob: Vec<u8> = (0..=255u8).cycle().take(5000).collect();
        ax.send_frame(&blob).await.unwrap();
        assert_eq!(bx.recv_frame().await.unwrap(), blob);
    }

    #[tokio::test]
    async fn multiple_dials_each_get_own_stream() {
        let fabric = LoopbackFabric::new();
        let server = fabric.transport("srv");
        let mut listener = server.listen().await.unwrap();
        let c1 = fabric.transport("c1");
        let c2 = fabric.transport("c2");

        let mut s1 = c1.dial(&"srv".to_string()).await.unwrap();
        let mut s2 = c2.dial(&"srv".to_string()).await.unwrap();
        let mut a1 = listener.accept().await.unwrap();
        let mut a2 = listener.accept().await.unwrap();

        s1.send_frame(b"from-c1").await.unwrap();
        s2.send_frame(b"from-c2").await.unwrap();
        let m1 = a1.recv_frame().await.unwrap();
        let m2 = a2.recv_frame().await.unwrap();
        // Order of accepts matches order of dials in this single-threaded test.
        assert_eq!(m1, b"from-c1");
        assert_eq!(m2, b"from-c2");
    }
}
