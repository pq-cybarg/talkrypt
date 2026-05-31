//! Real Tor transport via Arti (`tor` feature).
//!
//! `dial` connects to a peer `.onion` through the Tor network; `listen`
//! launches an onion service and yields inbound connections. Both directions
//! exchange the same length-framed ciphertext as every other transport, so the
//! engine is unchanged — this is a drop-in [`Transport`].
//!
//! Persistence:
//!   * [`OnionPersistence::Ephemeral`] — a temp state dir, so the onion key
//!     (and thus the `.onion` address) lives only for this process.
//!   * [`OnionPersistence::Persistent`] — a caller-provided state dir; the
//!     same `.onion` returns across restarts. (Encrypted-at-rest sealing of
//!     that directory is handled by `talkrypt-server`, Phase 8.)
//!
//! Runtime verification of the onion path requires a live Tor bootstrap; see
//! the `#[ignore]` integration test at the bottom.

use std::path::PathBuf;
use std::sync::Mutex;
use std::time::Duration;

use arti_client::config::CfgPath;
use arti_client::{DataStream, TorClient, TorClientConfig};
use async_trait::async_trait;
use futures::StreamExt;
use safelog::DisplayRedacted;
use tokio::io::{ReadHalf, WriteHalf};
use tokio::sync::mpsc;
use tor_cell::relaycell::msg::Connected;
use tor_hsservice::config::OnionServiceConfigBuilder;
use tor_hsservice::{handle_rend_requests, HsNickname};
use tor_rtcompat::PreferredRuntime;

use crate::framing::{read_frame, write_frame};
use crate::{
    Endpoint, FrameReader, FrameWriter, Listener, Result, Stream, Transport, TransportError,
    TransportStatus,
};

/// Virtual onion port the chat protocol uses.
const ONION_PORT: u16 = 9100;

fn io<E: std::fmt::Display>(e: E) -> TransportError {
    TransportError::Io(e.to_string())
}

/// Onion-service key persistence mode.
#[derive(Clone, Debug)]
pub enum OnionPersistence {
    /// Fresh onion key per process (temp state dir).
    Ephemeral,
    /// Stable onion key stored under this directory.
    Persistent { state_dir: PathBuf },
}

/// A Tor transport backed by a bootstrapped Arti client.
pub struct ArtiTransport {
    client: TorClient<PreferredRuntime>,
    nickname: String,
    onion_addr: Mutex<Option<String>>,
    // Kept alive so the ephemeral state dir is not deleted early.
    _tempdir: Option<tempfile::TempDir>,
}

impl ArtiTransport {
    /// Bootstrap a Tor client and prepare to host/dial onion services.
    pub async fn bootstrap(persistence: OnionPersistence, nickname: &str) -> Result<Self> {
        let (config, tempdir) = build_config(&persistence)?;
        let client = TorClient::create_bootstrapped(config)
            .await
            .map_err(|e| io(format!("tor bootstrap failed: {e}")))?;
        Ok(Self {
            client,
            nickname: nickname.to_string(),
            onion_addr: Mutex::new(None),
            _tempdir: tempdir,
        })
    }

    /// The hosted onion address, once `listen` has been called.
    pub fn onion_address(&self) -> Option<String> {
        self.onion_addr.lock().unwrap().clone()
    }
}

fn build_config(p: &OnionPersistence) -> Result<(TorClientConfig, Option<tempfile::TempDir>)> {
    let mut builder = TorClientConfig::builder();
    match p {
        OnionPersistence::Ephemeral => {
            let td = tempfile::tempdir().map_err(io)?;
            builder
                .storage()
                .state_dir(CfgPath::new_literal(td.path().join("state")))
                .cache_dir(CfgPath::new_literal(td.path().join("cache")));
            let config = builder.build().map_err(io)?;
            Ok((config, Some(td)))
        }
        OnionPersistence::Persistent { state_dir } => {
            builder
                .storage()
                .state_dir(CfgPath::new_literal(state_dir.join("state")))
                .cache_dir(CfgPath::new_literal(state_dir.join("cache")));
            let config = builder.build().map_err(io)?;
            Ok((config, None))
        }
    }
}

/// A framed Arti stream, pre-split into read/write halves (always `Unpin`).
pub struct ArtiStream {
    w: WriteHalf<DataStream>,
    r: ReadHalf<DataStream>,
}

impl ArtiStream {
    fn new(ds: DataStream) -> Self {
        let (r, w) = tokio::io::split(ds);
        Self { w, r }
    }
}

pub struct ArtiWriter(WriteHalf<DataStream>);
pub struct ArtiReader(ReadHalf<DataStream>);

#[async_trait]
impl FrameWriter for ArtiWriter {
    async fn send_frame(&mut self, frame: &[u8]) -> Result<()> {
        write_frame(&mut self.0, frame).await
    }
}

#[async_trait]
impl FrameReader for ArtiReader {
    async fn recv_frame(&mut self) -> Result<Vec<u8>> {
        read_frame(&mut self.0).await
    }
}

#[async_trait]
impl Stream for ArtiStream {
    async fn send_frame(&mut self, frame: &[u8]) -> Result<()> {
        write_frame(&mut self.w, frame).await
    }
    async fn recv_frame(&mut self) -> Result<Vec<u8>> {
        read_frame(&mut self.r).await
    }
    fn into_split(self: Box<Self>) -> (Box<dyn FrameWriter>, Box<dyn FrameReader>) {
        (Box::new(ArtiWriter(self.w)), Box::new(ArtiReader(self.r)))
    }
}

/// Listener that yields accepted onion-service connections.
pub struct ArtiListener {
    endpoint: Endpoint,
    rx: mpsc::UnboundedReceiver<DataStream>,
}

#[async_trait]
impl Listener for ArtiListener {
    async fn accept(&mut self) -> Result<Box<dyn Stream>> {
        let ds = self.rx.recv().await.ok_or(TransportError::Closed)?;
        Ok(Box::new(ArtiStream::new(ds)))
    }
    fn endpoint(&self) -> Endpoint {
        self.endpoint.clone()
    }
}

#[async_trait]
impl Transport for ArtiTransport {
    async fn listen(&self) -> Result<Box<dyn Listener>> {
        let nickname =
            HsNickname::new(self.nickname.clone()).map_err(|e| io(format!("nickname: {e}")))?;
        let svc_config = OnionServiceConfigBuilder::default()
            .nickname(nickname)
            .build()
            .map_err(io)?;

        let (service, rend_requests) = self
            .client
            .launch_onion_service(svc_config)
            .map_err(io)?
            .ok_or_else(|| TransportError::Io("onion service disabled in config".into()))?;

        // The HsId (and thus the .onion address) is available shortly after
        // launch, before the descriptor is even published.
        let mut onion = None;
        for _ in 0..50 {
            if let Some(addr) = service.onion_address() {
                // HsId's plain Display is redacted for safety; we need the real
                // .onion to advertise to invited peers.
                onion = Some(addr.display_unredacted().to_string());
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        let onion = onion.ok_or_else(|| TransportError::Io("onion address unavailable".into()))?;
        *self.onion_addr.lock().unwrap() = Some(onion.clone());

        // Pump inbound rendezvous → stream requests → accepted DataStreams.
        let (tx, rx) = mpsc::unbounded_channel();
        tokio::spawn(async move {
            // Hold the service alive for as long as we are accepting.
            let _service = service;
            let mut streams = Box::pin(handle_rend_requests(rend_requests));
            while let Some(stream_request) = streams.next().await {
                match stream_request.accept(Connected::new_empty()).await {
                    Ok(ds) => {
                        if tx.send(ds).is_err() {
                            break;
                        }
                    }
                    Err(_) => continue,
                }
            }
        });

        Ok(Box::new(ArtiListener {
            endpoint: format!("{onion}:{ONION_PORT}"),
            rx,
        }))
    }

    async fn dial(&self, endpoint: &Endpoint) -> Result<Box<dyn Stream>> {
        let target = if endpoint.contains(':') {
            endpoint.clone()
        } else {
            format!("{endpoint}:{ONION_PORT}")
        };
        let ds = self
            .client
            .connect(target.as_str())
            .await
            .map_err(|e| io(format!("connect {target}: {e}")))?;
        Ok(Box::new(ArtiStream::new(ds)))
    }

    fn status(&self) -> TransportStatus {
        match self.onion_address() {
            Some(endpoint) => TransportStatus::Online { endpoint },
            None => TransportStatus::Bootstrapping {
                percent: 100,
                phase: "bootstrapped; onion not yet launched".into(),
            },
        }
    }

    fn local_endpoint(&self) -> Endpoint {
        self.onion_address().unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Live end-to-end onion test. Requires network + several minutes for Tor
    /// bootstrap and descriptor publication. Run explicitly:
    ///   cargo test -p talkrypt-transport --features tor -- --ignored --nocapture
    #[tokio::test]
    #[ignore = "requires live Tor network"]
    async fn onion_self_connect_roundtrip() {
        let server = ArtiTransport::bootstrap(OnionPersistence::Ephemeral, "tk-test")
            .await
            .expect("bootstrap server");
        let mut listener = server.listen().await.expect("launch onion");
        let onion = listener.endpoint();
        eprintln!("onion endpoint: {onion}");

        let accept = tokio::spawn(async move {
            let mut s = listener.accept().await.unwrap();
            let got = s.recv_frame().await.unwrap();
            s.send_frame(b"pong").await.unwrap();
            got
        });

        // A second client dials the onion (descriptor must be published first).
        let client = ArtiTransport::bootstrap(OnionPersistence::Ephemeral, "tk-client")
            .await
            .expect("bootstrap client");
        let mut cs = client.dial(&onion).await.expect("dial onion");
        cs.send_frame(b"ping").await.unwrap();
        assert_eq!(cs.recv_frame().await.unwrap(), b"pong");
        assert_eq!(accept.await.unwrap(), b"ping");
    }
}
