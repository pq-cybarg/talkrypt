//! A real, cross-process TCP transport.
//!
//! Frames are length-prefixed (`u32` big-endian, bounded by
//! `talkrypt_wire::MAX_FRAME`). This is the Tor-free way to run talkrypt
//! across machines/processes for development and testing; the Arti transport
//! (Phase 7) implements the same [`Transport`] trait and is a drop-in swap.
//!
//! The transport carries only opaque ciphertext — it sees no plaintext or keys.

use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::{TcpListener, TcpStream};

use async_trait::async_trait;

use crate::framing::{read_frame, write_frame};
use crate::{
    Endpoint, FrameReader, FrameWriter, Listener, Result, Stream, Transport, TransportError,
    TransportStatus,
};

fn io<E: std::fmt::Display>(e: E) -> TransportError {
    TransportError::Io(e.to_string())
}

/// A connected TCP stream carrying length-framed messages.
pub struct TcpFramed {
    inner: TcpStream,
}

pub struct TcpWriter(OwnedWriteHalf);
pub struct TcpReader(OwnedReadHalf);

#[async_trait]
impl FrameWriter for TcpWriter {
    async fn send_frame(&mut self, frame: &[u8]) -> Result<()> {
        write_frame(&mut self.0, frame).await
    }
}

#[async_trait]
impl FrameReader for TcpReader {
    async fn recv_frame(&mut self) -> Result<Vec<u8>> {
        read_frame(&mut self.0).await
    }
}

#[async_trait]
impl Stream for TcpFramed {
    async fn send_frame(&mut self, frame: &[u8]) -> Result<()> {
        write_frame(&mut self.inner, frame).await
    }
    async fn recv_frame(&mut self) -> Result<Vec<u8>> {
        read_frame(&mut self.inner).await
    }
    fn into_split(self: Box<Self>) -> (Box<dyn FrameWriter>, Box<dyn FrameReader>) {
        let (r, w) = self.inner.into_split();
        (Box::new(TcpWriter(w)), Box::new(TcpReader(r)))
    }
}

/// TCP transport. `local` is the bind address (host:port) for inbound; `dial`
/// connects to a peer host:port endpoint.
#[derive(Clone)]
pub struct TcpTransport {
    local: Endpoint,
}

impl TcpTransport {
    pub fn new(local: impl Into<Endpoint>) -> Self {
        Self {
            local: local.into(),
        }
    }
}

pub struct TcpListenerWrap {
    endpoint: Endpoint,
    listener: TcpListener,
}

#[async_trait]
impl Listener for TcpListenerWrap {
    async fn accept(&mut self) -> Result<Box<dyn Stream>> {
        let (stream, _addr) = self.listener.accept().await.map_err(io)?;
        stream.set_nodelay(true).ok();
        Ok(Box::new(TcpFramed { inner: stream }))
    }
    fn endpoint(&self) -> Endpoint {
        self.endpoint.clone()
    }
}

#[async_trait]
impl Transport for TcpTransport {
    async fn listen(&self) -> Result<Box<dyn Listener>> {
        let listener = TcpListener::bind(&self.local).await.map_err(io)?;
        let endpoint = listener
            .local_addr()
            .map(|a| a.to_string())
            .unwrap_or_else(|_| self.local.clone());
        Ok(Box::new(TcpListenerWrap { endpoint, listener }))
    }

    async fn dial(&self, endpoint: &Endpoint) -> Result<Box<dyn Stream>> {
        let stream = TcpStream::connect(endpoint).await.map_err(io)?;
        stream.set_nodelay(true).ok();
        Ok(Box::new(TcpFramed { inner: stream }))
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
    async fn tcp_roundtrip_over_localhost() {
        let server = TcpTransport::new("127.0.0.1:0");
        let mut listener = server.listen().await.unwrap();
        let bound = listener.endpoint();

        let accept = tokio::spawn(async move {
            let mut s = listener.accept().await.unwrap();
            let got = s.recv_frame().await.unwrap();
            s.send_frame(b"pong").await.unwrap();
            got
        });

        let client = TcpTransport::new("127.0.0.1:0");
        let mut cs = client.dial(&bound).await.unwrap();
        cs.send_frame(b"ping").await.unwrap();
        assert_eq!(cs.recv_frame().await.unwrap(), b"pong");
        assert_eq!(accept.await.unwrap(), b"ping");
    }

    #[tokio::test]
    async fn split_halves_work_independently() {
        let server = TcpTransport::new("127.0.0.1:0");
        let mut listener = server.listen().await.unwrap();
        let bound = listener.endpoint();
        let accept = tokio::spawn(async move { listener.accept().await.unwrap() });

        let client = TcpTransport::new("127.0.0.1:0");
        let cs = client.dial(&bound).await.unwrap();
        let server_stream = accept.await.unwrap();

        let (mut cw, mut _cr) = cs.into_split();
        let (mut _sw, mut sr) = server_stream.into_split();
        cw.send_frame(b"split-hello").await.unwrap();
        assert_eq!(sr.recv_frame().await.unwrap(), b"split-hello");
    }
}
