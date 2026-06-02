//! talkrypt-ffi — uniffi bindings exposing the core engine to other languages.
//!
//! This is the **single shared binding** consumed by the Android app (Kotlin)
//! and a desktop shell (Swift/Kotlin/Python), so the security-critical core is
//! implemented once and never reimplemented per platform. Generate bindings
//! with `uniffi-bindgen` against the built library; see `docs/PLATFORMS.md`.
//!
//! The async `Core` is wrapped behind a blocking facade: a multi-threaded
//! tokio runtime is owned by the client object, background tasks run on it, and
//! the exported methods are synchronous (mobile/desktop UIs poll `poll_event`).
//!
//! Transport is TCP here for portability; an Arti onion build is a feature swap.

use std::sync::{Arc, Mutex};

use tokio::runtime::Runtime;
use tokio::sync::mpsc::UnboundedReceiver;

use talkrypt_core::{ChatDescriptor, Core, Event, Persistence, TopologyKind};
use talkrypt_crypto::{dr_suite_id, IdentityKeyPair, KemProfile, SuiteRegistry};
use talkrypt_topology::for_kind;
use talkrypt_transport::TcpTransport;

uniffi::setup_scaffolding!();

/// Errors surfaced across the FFI boundary.
#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum FfiError {
    #[error("{0}")]
    Failed(String),
}

impl FfiError {
    fn from<E: std::fmt::Display>(e: E) -> Self {
        FfiError::Failed(e.to_string())
    }
}

/// An event delivered to the host UI via `poll_event`.
#[derive(uniffi::Enum)]
pub enum FfiEvent {
    Message {
        from: String,
        channel: String,
        text: String,
    },
    Connected {
        fingerprint: String,
    },
    Disconnected {
        fingerprint: String,
    },
    Error {
        message: String,
    },
}

fn hex_fp(fp: &[u8; 48]) -> String {
    fp.iter().map(|b| format!("{b:02x}")).collect()
}

fn map_event(e: Event) -> FfiEvent {
    match e {
        Event::Message {
            from,
            channel,
            text,
        } => FfiEvent::Message {
            from: hex_fp(&from),
            channel,
            text,
        },
        Event::Connected { fingerprint } => FfiEvent::Connected {
            fingerprint: hex_fp(&fingerprint),
        },
        Event::Disconnected { fingerprint } => FfiEvent::Disconnected {
            fingerprint: hex_fp(&fingerprint),
        },
        Event::Error(message) => FfiEvent::Error { message },
    }
}

/// Parse a posture string into a KEM profile (mirrors the CLI/TUI).
fn posture_from(s: &str) -> Option<KemProfile> {
    match s.to_ascii_lowercase().as_str() {
        "pq-pure" | "pqpure" | "pure" | "" => Some(KemProfile::pq_pure()),
        "hybrid" => Some(KemProfile::hybrid()),
        "pq-pure-compact" | "compact" => Some(KemProfile::pq_pure_compact()),
        _ => None,
    }
}

/// A talkrypt chat client, exported to other languages.
#[derive(uniffi::Object)]
pub struct TalkryptClient {
    rt: Runtime,
    core: Core,
    events: Mutex<UnboundedReceiver<Event>>,
}

#[uniffi::export]
impl TalkryptClient {
    /// Create and host a new chat; returns a client whose `invite_uri` can be
    /// shared with peers. `posture` selects the KEM posture: `pq-pure`
    /// (default/zero-EC), `hybrid`, or `pq-pure-compact`; an empty/unknown
    /// value falls back to PQ-pure.
    #[uniffi::constructor]
    pub fn host(listen: String, channel: String, posture: String) -> Result<Arc<Self>, FfiError> {
        let rt = Runtime::new().map_err(FfiError::from)?;
        let profile = posture_from(&posture).unwrap_or_else(KemProfile::pq_pure);
        let suite_id = dr_suite_id(profile);
        let suite = SuiteRegistry::with_defaults()
            .get(&suite_id)
            .map_err(FfiError::from)?;
        let desc = ChatDescriptor::new(
            TopologyKind::P2P,
            Persistence::Ephemeral,
            &suite_id,
            vec![listen.clone()],
            channel,
        );
        let transport = Arc::new(TcpTransport::new(&listen));
        let (core, rx) = Core::new(IdentityKeyPair::generate(), suite, transport, desc);
        rt.block_on(core.host()).map_err(FfiError::from)?;
        Ok(Arc::new(Self {
            rt,
            core,
            events: Mutex::new(rx),
        }))
    }

    /// Join an existing chat from a `talkrypt://` invite URI.
    #[uniffi::constructor]
    pub fn join(uri: String) -> Result<Arc<Self>, FfiError> {
        let rt = Runtime::new().map_err(FfiError::from)?;
        let desc = ChatDescriptor::from_uri(&uri).map_err(FfiError::from)?;
        // Resolve the chat's scheme by fingerprint (handles blank/optional
        // posture and custom schemes); must be registered in this build.
        let suite = SuiteRegistry::with_defaults()
            .get_by_scheme_hash(&desc.scheme_hash())
            .map_err(FfiError::from)?;
        let transport = Arc::new(TcpTransport::new("127.0.0.1:0"));
        let (core, rx) = Core::new(IdentityKeyPair::generate(), suite, transport, desc.clone());
        rt.block_on(async {
            for_kind(desc.topology)
                .establish(&core, &desc.endpoints)
                .await
        })
        .map_err(FfiError::from)?;
        Ok(Arc::new(Self {
            rt,
            core,
            events: Mutex::new(rx),
        }))
    }

    /// Send a message to the channel.
    pub fn send(&self, text: String) -> Result<(), FfiError> {
        self.rt
            .block_on(self.core.send(&text))
            .map_err(FfiError::from)
    }

    /// The shareable invite URI for this chat.
    pub fn invite_uri(&self) -> String {
        self.core.descriptor().to_uri()
    }

    /// Our safety number, for out-of-band verification.
    pub fn safety_number(&self) -> String {
        self.core.identity_public().safety_number()
    }

    /// Number of connected peers.
    pub fn peer_count(&self) -> u32 {
        self.core.peer_count() as u32
    }

    /// Non-blocking poll for the next event; `None` if none pending.
    pub fn poll_event(&self) -> Option<FfiEvent> {
        let mut rx = self.events.lock().unwrap();
        rx.try_recv().ok().map(map_event)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    /// Exercise the full FFI facade: host, join, send, receive — the exact
    /// surface other languages call.
    #[test]
    fn ffi_host_join_send_receive() {
        let addr = "127.0.0.1:19922".to_string();
        let host = TalkryptClient::host(addr, "#ffi".into(), "pq-pure".into()).expect("host");
        let uri = host.invite_uri();
        assert!(uri.starts_with("talkrypt://"));
        assert!(!host.safety_number().is_empty());

        let joiner = TalkryptClient::join(uri).expect("join");
        joiner.send("hello via ffi".into()).expect("send");

        // Poll the host for the decrypted message (background tasks are async).
        let mut got = None;
        for _ in 0..50 {
            while let Some(ev) = host.poll_event() {
                if let FfiEvent::Message { text, .. } = ev {
                    got = Some(text);
                }
            }
            if got.is_some() {
                break;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        assert_eq!(got.as_deref(), Some("hello via ffi"));
        assert_eq!(joiner.peer_count(), 1);
    }
}
