//! Core error type.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum CoreError {
    #[error("malformed data: {0}")]
    Malformed(&'static str),
    #[error("unsupported descriptor version: {0}")]
    UnsupportedVersion(u16),
    #[error("handshake failed: {0}")]
    Handshake(&'static str),
    #[error("peer identity verification failed")]
    PeerAuthFailed,
    #[error("unknown crypto suite '{0}'; enable this suite to join this chat")]
    UnknownSuite(String),
    #[error("crypto error: {0}")]
    Crypto(#[from] talkrypt_crypto::CryptoError),
    #[error("transport error: {0}")]
    Transport(#[from] talkrypt_transport::TransportError),
    #[error("wire error: {0}")]
    Wire(#[from] talkrypt_wire::WireError),
}

pub type Result<T> = core::result::Result<T, CoreError>;
