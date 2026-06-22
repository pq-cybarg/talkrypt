//! Transport abstraction for talkrypt.
//!
//! A [`Transport`] hosts an inbound listener and dials peers, exchanging
//! opaque, message-oriented frames. It never sees plaintext or keys — only
//! end-to-end ciphertext and routing addresses.
//!
//! Two implementations:
//!   * [`LoopbackTransport`] — in-process, for tests and offline use; the
//!     whole protocol/crypto/UI stack runs over it with zero network.
//!   * `ArtiTransport` (crate `tor` feature, Phase 7) — real Tor circuits and
//!     ephemeral/persistent onion services.

pub mod framing;
pub mod loopback;
pub mod multi;
pub mod tcp;

#[cfg(feature = "tor")]
pub mod arti;

#[cfg(feature = "nym")]
pub mod nym;

pub use loopback::{LoopbackFabric, LoopbackTransport};
pub use multi::{endpoint_scheme, select_endpoint, split_endpoints, MultiTransport, Scheme};
pub use tcp::TcpTransport;

#[cfg(feature = "tor")]
pub use arti::{AntiCensorship, ArtiTransport, OnionPersistence, PluggableTransport};

#[cfg(feature = "nym")]
pub use nym::NymTransport;

use async_trait::async_trait;
use thiserror::Error;

/// A routing address. For Tor this is an `.onion`; for loopback, a label.
pub type Endpoint = String;

#[derive(Debug, Error)]
pub enum TransportError {
    #[error("no listener at endpoint: {0}")]
    NoListener(Endpoint),
    #[error("connection closed")]
    Closed,
    #[error("transport not bootstrapped")]
    NotReady,
    #[error("io error: {0}")]
    Io(String),
}

pub type Result<T> = core::result::Result<T, TransportError>;

/// Bootstrap / connectivity status, surfaced to the UI status bar.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TransportStatus {
    /// In-process loopback is always ready.
    Ready,
    /// Tor bootstrap progress (0–100) with a human-readable phase.
    Bootstrapping { percent: u8, phase: String },
    /// Connected and serving an onion (or loopback) at this endpoint.
    Online { endpoint: Endpoint },
    /// Offline / failed, with reason.
    Offline { reason: String },
}

/// Write half of a split stream.
#[async_trait]
pub trait FrameWriter: Send {
    async fn send_frame(&mut self, frame: &[u8]) -> Result<()>;
}

/// Read half of a split stream.
#[async_trait]
pub trait FrameReader: Send {
    async fn recv_frame(&mut self) -> Result<Vec<u8>>;
}

/// A bidirectional, message-oriented byte stream to one peer.
#[async_trait]
pub trait Stream: Send {
    /// Send one frame (an opaque ciphertext message).
    async fn send_frame(&mut self, frame: &[u8]) -> Result<()>;
    /// Receive the next frame, or `Closed` when the peer hangs up.
    async fn recv_frame(&mut self) -> Result<Vec<u8>>;
    /// Split into independent read/write halves so a peer connection can be
    /// read and written concurrently from separate tasks.
    fn into_split(self: Box<Self>) -> (Box<dyn FrameWriter>, Box<dyn FrameReader>);
}

/// Accepts inbound connections.
#[async_trait]
pub trait Listener: Send {
    /// Block until a peer connects, returning the connection stream.
    async fn accept(&mut self) -> Result<Box<dyn Stream>>;
    /// The endpoint this listener serves.
    fn endpoint(&self) -> Endpoint;
}

/// Dials peers and hosts an inbound listener.
#[async_trait]
pub trait Transport: Send + Sync {
    /// Begin listening for inbound connections at our local endpoint.
    async fn listen(&self) -> Result<Box<dyn Listener>>;
    /// Connect to a peer endpoint.
    async fn dial(&self, endpoint: &Endpoint) -> Result<Box<dyn Stream>>;
    /// Current connectivity status.
    fn status(&self) -> TransportStatus;
    /// Our own endpoint (the address peers dial to reach us).
    fn local_endpoint(&self) -> Endpoint;
}
