//! Helper error type.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum HelperError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("protocol: {0}")]
    Protocol(&'static str),
    #[error("frame too large ({0} bytes)")]
    FrameTooLarge(usize),
    #[error("connection closed")]
    Closed,
    #[error("keystore: {0}")]
    Keystore(#[from] talkrypt_server::KeystoreError),
    #[error("core: {0}")]
    Core(#[from] talkrypt_core::CoreError),
    #[error("wire: {0}")]
    Wire(#[from] talkrypt_wire::WireError),
    #[error("invalid key name (use [A-Za-z0-9._-], no separators)")]
    InvalidName,
    #[error("no such stored key")]
    NotFound,
    #[error("invalid invite: {0}")]
    InvalidInvite(&'static str),
    #[error("unsupported on this platform: {0}")]
    Unsupported(&'static str),
    #[error("os keystore error")]
    Keychain,
}

pub type Result<T> = std::result::Result<T, HelperError>;
