//! talkrypt-helper — the desktop **key-custody helper**, a Rust sidecar that
//! **reuses the audited talkrypt core** (no second-language reimplementation).
//!
//! The app talks to a local helper process over an owner-only IPC channel
//! (Unix socket on macOS/Linux; an ACL'd Named Pipe on Windows — see
//! [`endpoint`]) and asks it to perform OS-adjacent privileged work: sealing
//! secrets at rest (Argon2id + AES-256-GCM via `talkrypt_server::keystore`),
//! generating/holding ML-DSA-87 identities (`talkrypt_crypto::IdentityKeyPair`),
//! and parsing invites (`talkrypt_core::ChatDescriptor`). All crypto is the
//! same code the rest of talkrypt uses; the helper adds only IPC + custody.
//!
//! This resolves roadmap decision #1 (`docs/ROADMAP.md`) in favor of a single
//! audited Rust core with thin shells — not a separate Go helper.
//!
//! Like the rest of the project, the helper is **not certified or audited**
//! (see the README); it is a clean implementation, nothing more.

pub mod client;
pub mod custody;
pub mod endpoint;
pub mod error;
pub mod frame;
#[cfg(target_os = "macos")]
pub mod keychain;
pub mod parity;
pub mod protocol;
pub mod sddl;
#[cfg(target_os = "linux")]
pub mod secretservice;
pub mod server;
pub mod store;
#[cfg(windows)]
pub mod winpipe;

pub use client::Client;
pub use custody::{Capabilities, CustodyTier};
pub use parity::{audit, local_report, ParityReport, PlatformReport};
pub use error::{HelperError, Result};
pub use protocol::{Request, Response, PROTOCOL_VERSION};
pub use server::Helper;
pub use store::KeyStore;
