//! talkrypt-core — the transport- and crypto-agnostic chat engine.
//!
//! Wires an [`crate::engine::Core`] over a [`talkrypt_transport::Transport`]
//! using a [`talkrypt_crypto::CryptoSuite`], driven by a [`ChatDescriptor`]
//! invite. Contains no I/O of its own beyond the transport trait, so the whole
//! stack is testable over the in-memory loopback transport.

pub mod advert;
pub mod b32;
pub mod csfc;
pub mod custody;
pub mod descriptor;
pub mod engine;
pub mod error;
pub mod friends;
pub mod handshake;
pub mod linking;
pub mod marking;
pub mod registry;
pub mod relay;

pub use advert::{build_advertisement, open_advertisement, AdvertStore, AdvertisePolicy};
pub use custody::{Capabilities, CustodyTier};
pub use marking::{Classification, Marking};
pub use descriptor::{ChannelPassword, ChatDescriptor, Persistence, TopologyKind, URI_SCHEME};
pub use engine::{AccessPolicy, Core, Event, GroupRole};
pub use friends::{Friend, FriendStore, Presentation, Resolved};
pub use linking::{LinkClient, LinkHost, Linked};
pub use registry::{resolve_across, RegistryClient, RegistryServer};
pub use error::{CoreError, Result};
pub use relay::RelayHub;
