//! talkrypt-server — persistent onion-service support.
//!
//! Two pieces, both transport-agnostic and unit-tested:
//!   * [`keystore`] — encrypted-at-rest sealing of the persistent onion secret
//!     key (Argon2id + AES-256-GCM); the key never touches disk in plaintext.
//!   * [`keepalive`] — the three keep-alive strategies (AlwaysOn,
//!     ClientAnchored, ReplicatedFailover) as pure, testable publish decisions
//!     a driver loop applies to a `talkrypt_transport::ArtiTransport` running
//!     in persistent mode.
//!
//! Restricted-discovery (onion client authorization) and the live republish
//! loop are wired against the Arti transport under its `tor` feature.

pub mod keepalive;
pub mod keystore;

pub use keepalive::{KeepAlive, KeepAliveContext, Strategy};
pub use keystore::{seal, unseal, KeystoreError};
