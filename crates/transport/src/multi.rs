//! Multi-homed transport: dispatch by endpoint scheme + fan-in listening.
//!
//! A host may be reachable over several anonymity networks at once — a Tor
//! onion, a Nym mixnet address, and a LAN `host:port`. A [`MultiTransport`]
//! bundles one transport *leg* per network and presents the single
//! [`Transport`] the engine already speaks to:
//!
//!   * [`dial`](Transport::dial) routes by the endpoint's [`Scheme`] (a
//!     `nym:` address → the Nym leg, a `.onion` → the Tor leg, otherwise TCP),
//!     so a single [`Core`](talkrypt_core::Core) can reach peers that live on
//!     *different* networks — the Tor↔Nym cross-interaction.
//!   * [`listen`](Transport::listen) fans every leg's inbound connections into
//!     one accept queue, so one host is reachable over *every* network it runs.
//!     The listener advertises all of its endpoints (see [`split_endpoints`]),
//!     which is exactly a multi-homed invite `[onion, nym:…, host:port]`.
//!
//! The engine above never learns which network a peer used: it dials and
//! accepts opaque framed ciphertext exactly as with any single transport.

use std::sync::Arc;

use async_trait::async_trait;
use tokio::sync::mpsc;

use crate::{
    Endpoint, Listener, Result, Stream, Transport, TransportError, TransportStatus,
};

/// The network family an endpoint string names.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Scheme {
    /// Nym mixnet recipient, written `nym:<base58-address>`.
    Nym,
    /// Tor onion service — an address containing `.onion`.
    Onion,
    /// Plain TCP `host:port` (LAN / development).
    Tcp,
}

/// Classify an endpoint string by its network family.
///
/// The scheme is encoded structurally so invites stay a flat list of strings:
/// a `nym:` prefix marks a mixnet address, `.onion` anywhere marks a Tor onion,
/// and anything else is treated as a TCP `host:port`.
pub fn endpoint_scheme(ep: &str) -> Scheme {
    if ep.starts_with("nym:") {
        Scheme::Nym
    } else if ep.contains(".onion") {
        Scheme::Onion
    } else {
        Scheme::Tcp
    }
}

/// Delimiter joining a multi-homed listener's endpoints into one advertised
/// string. A space is safe: no onion, nym, or `host:port` address contains one.
const ENDPOINT_DELIM: char = ' ';

/// Expand an advertised endpoint string into its individual endpoints.
///
/// A [`MultiListener`] reports all of its legs' endpoints joined by
/// [`ENDPOINT_DELIM`]; advertisement code splits that back out into the flat
/// `descriptor.endpoints` list so each address is dialed (and scheme-routed)
/// on its own. Single-homed endpoints pass through unchanged.
pub fn split_endpoints(advertised: &str) -> Vec<String> {
    advertised
        .split(ENDPOINT_DELIM)
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
        .collect()
}

/// Pick the single best endpoint a multi-homed peer advertises, honoring a
/// scheme preference order.
///
/// Returns the first endpoint whose scheme is the highest-ranked available.
/// Falls back to the first endpoint if none match the preference list, so a
/// peer is never made unreachable merely because we lack a preference entry for
/// its scheme. This is the "joiner dials by preference" half of a multi-homed
/// invite (e.g. prefer Nym when paid-up, else Tor, else LAN).
pub fn select_endpoint<'a>(endpoints: &'a [String], prefs: &[Scheme]) -> Option<&'a str> {
    for pref in prefs {
        if let Some(ep) = endpoints.iter().find(|e| endpoint_scheme(e) == *pref) {
            return Some(ep.as_str());
        }
    }
    endpoints.first().map(|s| s.as_str())
}

/// One transport leg, tagged with the scheme it serves.
struct Leg {
    scheme: Scheme,
    transport: Arc<dyn Transport>,
}

/// A transport that hosts on, and dials across, several underlying transports
/// (e.g. Tor + Nym + LAN at once). See the module docs.
#[derive(Default)]
pub struct MultiTransport {
    legs: Vec<Leg>,
}

impl MultiTransport {
    /// An empty multi-transport. Add legs with [`with`](Self::with).
    pub fn new() -> Self {
        Self { legs: Vec::new() }
    }

    /// Add a transport leg serving `scheme`. The first leg added for a scheme
    /// wins when dialing that scheme; ordering also sets the host/advertise
    /// order. Returns `self` for chaining.
    pub fn with(mut self, scheme: Scheme, transport: Arc<dyn Transport>) -> Self {
        self.legs.push(Leg { scheme, transport });
        self
    }

    /// Whether any legs are configured.
    pub fn is_empty(&self) -> bool {
        self.legs.is_empty()
    }

    /// Number of configured legs.
    pub fn len(&self) -> usize {
        self.legs.len()
    }

    fn leg_for(&self, scheme: Scheme) -> Option<&Arc<dyn Transport>> {
        self.legs
            .iter()
            .find(|l| l.scheme == scheme)
            .map(|l| &l.transport)
    }
}

/// Listener that yields connections accepted on *any* leg.
pub struct MultiListener {
    /// All legs' endpoints joined by [`ENDPOINT_DELIM`]; expand with
    /// [`split_endpoints`] to advertise the multi-homed invite.
    endpoint: Endpoint,
    rx: mpsc::UnboundedReceiver<Box<dyn Stream>>,
}

#[async_trait]
impl Listener for MultiListener {
    async fn accept(&mut self) -> Result<Box<dyn Stream>> {
        self.rx.recv().await.ok_or(TransportError::Closed)
    }
    fn endpoint(&self) -> Endpoint {
        self.endpoint.clone()
    }
}

#[async_trait]
impl Transport for MultiTransport {
    async fn listen(&self) -> Result<Box<dyn Listener>> {
        if self.legs.is_empty() {
            return Err(TransportError::Io("multi-transport has no legs".into()));
        }
        let (tx, rx) = mpsc::unbounded_channel();
        let mut endpoints = Vec::new();
        let mut last_err: Option<TransportError> = None;
        for leg in &self.legs {
            let mut inner = match leg.transport.listen().await {
                Ok(l) => l,
                // A leg that can't host (e.g. Nym not bootstrapped) must not sink
                // the whole host — keep the legs that came up and advertise those.
                Err(e) => {
                    last_err = Some(e);
                    continue;
                }
            };
            endpoints.push(inner.endpoint());
            let tx = tx.clone();
            tokio::spawn(async move {
                loop {
                    match inner.accept().await {
                        Ok(s) => {
                            if tx.send(s).is_err() {
                                break;
                            }
                        }
                        Err(_) => break,
                    }
                }
            });
        }
        if endpoints.is_empty() {
            return Err(last_err
                .unwrap_or_else(|| TransportError::Io("no transport leg could host".into())));
        }
        Ok(Box::new(MultiListener {
            endpoint: endpoints.join(&ENDPOINT_DELIM.to_string()),
            rx,
        }))
    }

    async fn dial(&self, endpoint: &Endpoint) -> Result<Box<dyn Stream>> {
        let scheme = endpoint_scheme(endpoint);
        let leg = self.leg_for(scheme).ok_or_else(|| {
            TransportError::Io(format!(
                "no {scheme:?} transport leg available to dial {endpoint}"
            ))
        })?;
        // The leg receives the endpoint unchanged; address-format quirks (e.g.
        // the `nym:` prefix) are the leg's own concern, so a leg behaves the
        // same whether reached through here or used standalone.
        leg.dial(endpoint).await
    }

    fn status(&self) -> TransportStatus {
        // Online if any leg is online; otherwise surface the first leg's status.
        for leg in &self.legs {
            if let TransportStatus::Online { .. } = leg.transport.status() {
                return leg.transport.status();
            }
        }
        self.legs
            .first()
            .map(|l| l.transport.status())
            .unwrap_or(TransportStatus::Offline {
                reason: "no transport legs".into(),
            })
    }

    fn local_endpoint(&self) -> Endpoint {
        self.legs
            .first()
            .map(|l| l.transport.local_endpoint())
            .unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::loopback::LoopbackFabric;

    #[test]
    fn scheme_classification() {
        assert_eq!(endpoint_scheme("nym:D1abc...@gateway"), Scheme::Nym);
        assert_eq!(endpoint_scheme("abcdef0123456789.onion:9100"), Scheme::Onion);
        assert_eq!(endpoint_scheme("192.168.1.5:19933"), Scheme::Tcp);
        assert_eq!(endpoint_scheme("10.0.2.2:9100"), Scheme::Tcp);
    }

    #[test]
    fn select_endpoint_honors_preference() {
        let eps = vec![
            "abc.onion:9100".to_string(),
            "nym:Recipient123".to_string(),
            "192.168.1.5:19933".to_string(),
        ];
        // Prefer Nym → pick the nym address even though onion is listed first.
        assert_eq!(
            select_endpoint(&eps, &[Scheme::Nym, Scheme::Onion, Scheme::Tcp]),
            Some("nym:Recipient123")
        );
        // Prefer Tor → pick the onion.
        assert_eq!(
            select_endpoint(&eps, &[Scheme::Onion, Scheme::Tcp]),
            Some("abc.onion:9100")
        );
        // Prefer LAN first.
        assert_eq!(
            select_endpoint(&eps, &[Scheme::Tcp]),
            Some("192.168.1.5:19933")
        );
    }

    #[test]
    fn select_endpoint_falls_back_to_first() {
        let eps = vec!["abc.onion:9100".to_string()];
        // We only "prefer" Nym, but the peer offers none — fall back, don't strand.
        assert_eq!(
            select_endpoint(&eps, &[Scheme::Nym]),
            Some("abc.onion:9100")
        );
        // Empty list → nothing to dial.
        assert_eq!(select_endpoint(&[], &[Scheme::Nym]), None);
    }

    #[test]
    fn split_endpoints_roundtrips() {
        assert_eq!(
            split_endpoints("abc.onion:9100 nym:Recipient123 192.168.1.5:19933"),
            vec![
                "abc.onion:9100".to_string(),
                "nym:Recipient123".to_string(),
                "192.168.1.5:19933".to_string(),
            ]
        );
        // Single-homed passes through unchanged.
        assert_eq!(
            split_endpoints("abc.onion:9100"),
            vec!["abc.onion:9100".to_string()]
        );
    }

    #[tokio::test]
    async fn dial_routes_by_scheme_to_the_right_leg() {
        // Two loopback fabrics stand in for two distinct networks ("tor" and
        // "nym"). A peer is registered on each; MultiTransport must route each
        // dial to the leg matching the endpoint's scheme.
        let tor_net = LoopbackFabric::new();
        let nym_net = LoopbackFabric::new();

        // Hosts on each network. We tag endpoints with the scheme MultiTransport
        // keys on (`.onion` and `nym:`), and register the listener under the
        // exact dialable string.
        let tor_host = tor_net.transport("peerA.onion:9100");
        let nym_host = nym_net.transport("nym:peerB");
        let mut tor_listener = tor_host.listen().await.unwrap();
        let mut nym_listener = nym_host.listen().await.unwrap();

        let multi = MultiTransport::new()
            .with(Scheme::Onion, Arc::new(tor_net.transport("dialer.onion")))
            .with(Scheme::Nym, Arc::new(nym_net.transport("nym:dialer")));

        // Dial the onion peer → must arrive on the Tor leg's listener.
        let mut s_tor = multi.dial(&"peerA.onion:9100".to_string()).await.unwrap();
        let mut a_tor = tor_listener.accept().await.unwrap();
        s_tor.send_frame(b"via-tor").await.unwrap();
        assert_eq!(a_tor.recv_frame().await.unwrap(), b"via-tor");

        // Dial the nym peer → must arrive on the Nym leg's listener.
        let mut s_nym = multi.dial(&"nym:peerB".to_string()).await.unwrap();
        let mut a_nym = nym_listener.accept().await.unwrap();
        s_nym.send_frame(b"via-nym").await.unwrap();
        assert_eq!(a_nym.recv_frame().await.unwrap(), b"via-nym");
    }

    #[tokio::test]
    async fn dial_without_matching_leg_errors() {
        let nym_net = LoopbackFabric::new();
        let multi = MultiTransport::new()
            .with(Scheme::Nym, Arc::new(nym_net.transport("nym:dialer")));
        // No onion leg configured → dialing an onion endpoint is a clean error,
        // not a panic or a wrong-network misroute.
        match multi.dial(&"peerA.onion:9100".to_string()).await {
            Err(TransportError::Io(msg)) => assert!(msg.contains("Onion"), "msg was: {msg}"),
            Err(e) => panic!("expected Io error about missing Onion leg, got {e}"),
            Ok(_) => panic!("expected error, got a stream"),
        }
    }

    #[tokio::test]
    async fn listen_fans_in_all_legs_and_advertises_every_endpoint() {
        // One host on two networks; both legs' inbound connections must surface
        // on the single fanned-in accept queue, and the advertised endpoint must
        // expand to both addresses (the multi-homed invite).
        let tor_net = LoopbackFabric::new();
        let nym_net = LoopbackFabric::new();
        let host = MultiTransport::new()
            .with(Scheme::Onion, Arc::new(tor_net.transport("host.onion:9100")))
            .with(Scheme::Nym, Arc::new(nym_net.transport("nym:host")));

        let mut listener = host.listen().await.unwrap();
        let advertised = listener.endpoint();
        assert_eq!(
            split_endpoints(&advertised),
            vec!["host.onion:9100".to_string(), "nym:host".to_string()]
        );

        // A dialer on the Tor network reaches the host via its onion leg.
        let tor_dialer = tor_net.transport("tor-dialer.onion");
        let mut d1 = tor_dialer.dial(&"host.onion:9100".to_string()).await.unwrap();
        let mut accepted1 = listener.accept().await.unwrap();
        d1.send_frame(b"hello-from-tor").await.unwrap();
        assert_eq!(accepted1.recv_frame().await.unwrap(), b"hello-from-tor");

        // A dialer on the Nym network reaches the same host via its nym leg —
        // same fanned-in listener.
        let nym_dialer = nym_net.transport("nym:nym-dialer");
        let mut d2 = nym_dialer.dial(&"nym:host".to_string()).await.unwrap();
        let mut accepted2 = listener.accept().await.unwrap();
        d2.send_frame(b"hello-from-nym").await.unwrap();
        assert_eq!(accepted2.recv_frame().await.unwrap(), b"hello-from-nym");
    }
}
