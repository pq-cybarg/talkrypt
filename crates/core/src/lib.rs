//! talkrypt-core — the transport- and crypto-agnostic chat engine.
//!
//! Wires an [`crate::engine::Core`] over a [`talkrypt_transport::Transport`]
//! using a [`talkrypt_crypto::CryptoSuite`], driven by a [`ChatDescriptor`]
//! invite. Contains no I/O of its own beyond the transport trait, so the whole
//! stack is testable over the in-memory loopback transport.

pub mod advert;
pub mod atrest;
pub mod b32;
pub mod csfc;
pub mod custody;
pub mod contacts;
pub mod descriptor;
pub mod engine;
pub mod error;
pub mod handshake;
pub mod history;
pub mod keeper;
pub mod linkage;
/// Formal-verification companion for the nested-heap chain-embedding decoders:
/// a flat, heap-free grammar model that Kani proves total (the obligation the
/// heap decoders cannot carry) plus a differential test binding it to the
/// literal decoders. See `docs/fv-heap-decoder-spike.md` / SECURITY-AUDIT §5.
mod linkage_fv;
pub mod linking;
pub mod marking;
pub mod nametrust;
pub mod outbox;
pub mod presence;
pub mod registry;
pub mod relay;
pub mod seal;
pub mod vouch;

pub use advert::{build_advertisement, open_advertisement, AdvertStore, AdvertisePolicy};
pub use custody::{Capabilities, CustodyTier};
pub use seal::{seal, tier_of, unseal, KeyWrapper, SealOptions, WrapError};
pub use marking::{Classification, Marking};
pub use descriptor::{ChannelPassword, ChatDescriptor, Persistence, TopologyKind, URI_SCHEME};
pub use engine::{AccessPolicy, Core, Event, GroupRole, LeafSigMode};
pub use contacts::{Contact, ContactStore, Presentation, Resolved};
pub use linking::{LinkClient, LinkHost, Linked};
pub use registry::{resolve_across, RegistryClient, RegistryServer};
pub use error::{CoreError, Result};
pub use history::{HistoryRecord, HistoryStore, InMemoryHistory};
pub use atrest::SealedFileStore;
pub use relay::RelayHub;
