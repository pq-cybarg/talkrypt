//! talkrypt-core — the transport- and crypto-agnostic chat engine.
//!
//! Wires an [`crate::engine::Core`] over a [`talkrypt_transport::Transport`]
//! using a [`talkrypt_crypto::CryptoSuite`], driven by a [`ChatDescriptor`]
//! invite. Contains no I/O of its own beyond the transport trait, so the whole
//! stack is testable over the in-memory loopback transport.

pub mod b32;
pub mod descriptor;
pub mod engine;
pub mod error;
pub mod handshake;

pub use descriptor::{ChatDescriptor, Persistence, TopologyKind, URI_SCHEME};
pub use engine::{Core, Event};
pub use error::{CoreError, Result};
