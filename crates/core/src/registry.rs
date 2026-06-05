//! Username **registry** — an opt-in directory mapping `username → account key`,
//! served over the encrypted transport (an onion or any persistent channel).
//!
//! The registry is the optional name-discovery layer of the identity model
//! (`docs/identity-accounts.md`). The cryptographic identity is always the
//! **account key**, never the name; a registry only *advertises* a name. Each
//! stored binding is a [`SignedClaim`] — a `username → account` statement signed
//! by the **account key itself** — so a hostile registry cannot fabricate a
//! binding to a key it doesn't control, only refuse to serve or omit one.
//!
//! Redundancy + unforgeability comes from registering on **several** registries
//! and **cross-comparing**: a name resolves only if every queried registry
//! returns the *same* self-signed account key ([`resolve_across`], wrapping
//! [`talkrypt_crypto::cross_compare`]). No single registry is trusted.
//!
//! Security: a registry runs over the same authenticated, AEAD-encrypted
//! pairwise session as chat (a shared registry descriptor supplies the handshake
//! root). The registry learns the claims it serves (they are public by nature)
//! and routing metadata — nothing about chat content. Pure post-quantum
//! (ML-DSA-87 claims); no elliptic curve is load-bearing.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use talkrypt_crypto::suite::SessionHandle;
use talkrypt_crypto::{cross_compare, CryptoSuite, IdentityKeyPair, IdentityPublic, SignedClaim};
use talkrypt_transport::{Endpoint, Stream, Transport};
use talkrypt_wire::{Reader, Writer};

use crate::descriptor::ChatDescriptor;
use crate::error::{CoreError, Result};
use crate::handshake;

/// Cap on claims returned in one response (defensive bound).
const MAX_CLAIMS: u32 = 100_000;

/// A request from a client to a registry (sent inside the encrypted session).
enum Request {
    /// Publish (or refresh) a self-signed `username → account` binding.
    Register(SignedClaim),
    /// Look up a username; the registry returns its stored claim (0 or 1).
    Resolve(String),
    /// Dump every binding the registry holds (directory browse).
    List,
}

/// A registry's reply.
enum Response {
    /// The register succeeded.
    Registered,
    /// Zero or more claims (a `Resolve` returns ≤1; `List` returns all).
    Claims(Vec<SignedClaim>),
    /// The request was rejected (e.g. bad signature, name taken).
    Error(String),
}

impl Request {
    fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        match self {
            Request::Register(c) => {
                w.put_u8(0);
                w.put_bytes(&c.encode());
            }
            Request::Resolve(name) => {
                w.put_u8(1);
                w.put_bytes(name.as_bytes());
            }
            Request::List => w.put_u8(2),
        }
        w.into_vec()
    }
    fn decode(bytes: &[u8]) -> Result<Request> {
        let mut r = Reader::new(bytes);
        let req = match r.get_u8()? {
            0 => Request::Register(SignedClaim::decode(r.get_bytes()?)?),
            1 => Request::Resolve(
                String::from_utf8(r.get_vec()?)
                    .map_err(|_| CoreError::Malformed("resolve username utf-8"))?,
            ),
            2 => Request::List,
            _ => return Err(CoreError::Malformed("registry request tag")),
        };
        Ok(req)
    }
}

impl Response {
    fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        match self {
            Response::Registered => w.put_u8(0),
            Response::Claims(claims) => {
                w.put_u8(1);
                w.put_u32(claims.len() as u32);
                for c in claims {
                    w.put_bytes(&c.encode());
                }
            }
            Response::Error(msg) => {
                w.put_u8(2);
                w.put_bytes(msg.as_bytes());
            }
        }
        w.into_vec()
    }
    fn decode(bytes: &[u8]) -> Result<Response> {
        let mut r = Reader::new(bytes);
        let resp = match r.get_u8()? {
            0 => Response::Registered,
            1 => {
                let n = r.get_u32()?;
                if n > MAX_CLAIMS {
                    return Err(CoreError::Malformed("too many claims"));
                }
                let mut claims = Vec::with_capacity(n as usize);
                for _ in 0..n {
                    claims.push(SignedClaim::decode(r.get_bytes()?)?);
                }
                Response::Claims(claims)
            }
            2 => Response::Error(
                String::from_utf8(r.get_vec()?)
                    .map_err(|_| CoreError::Malformed("registry error utf-8"))?,
            ),
            _ => return Err(CoreError::Malformed("registry response tag")),
        };
        Ok(resp)
    }
}

/// A standalone registry server. Hosts a listener and answers
/// register/resolve/list requests; the binding store is shared across all
/// connections.
pub struct RegistryServer {
    identity: IdentityKeyPair,
    suite: Arc<dyn CryptoSuite>,
    transport: Arc<dyn Transport>,
    root0: [u8; 32],
    store: Arc<Mutex<HashMap<String, SignedClaim>>>,
}

impl RegistryServer {
    pub fn new(
        identity: IdentityKeyPair,
        suite: Arc<dyn CryptoSuite>,
        transport: Arc<dyn Transport>,
        descriptor: &ChatDescriptor,
    ) -> RegistryServer {
        RegistryServer {
            identity,
            suite,
            transport,
            root0: descriptor.derive_root(),
            store: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Number of names currently registered.
    pub fn len(&self) -> usize {
        self.store.lock().unwrap().len()
    }

    pub fn is_empty(&self) -> bool {
        self.store.lock().unwrap().is_empty()
    }

    /// Start listening and serving (spawns a background accept loop). Returns the
    /// endpoint to publish as the registry's address.
    pub async fn run(&self) -> Result<Endpoint> {
        let listener = self.transport.listen().await?;
        let endpoint = listener.endpoint();
        let mut listener = listener;
        let suite = self.suite.clone();
        let root0 = self.root0;
        let id_seed = self.identity.export_secret();
        let store = self.store.clone();

        tokio::spawn(async move {
            while let Ok(mut stream) = listener.accept().await {
                let identity = IdentityKeyPair::from_secret_bytes(id_seed);
                let hs =
                    handshake::respond(stream.as_mut(), &identity, suite.as_ref(), root0).await;
                let Ok(hs) = hs else { continue };
                tokio::spawn(serve_loop(store.clone(), stream, hs.session));
            }
        });
        Ok(endpoint)
    }
}

/// Per-connection request loop: decrypt a request, apply it to the store, send
/// the encrypted response. Each request is independent.
async fn serve_loop(
    store: Arc<Mutex<HashMap<String, SignedClaim>>>,
    stream: Box<dyn Stream>,
    session: Box<dyn SessionHandle>,
) {
    let mut stream = stream;
    let mut session = session;
    loop {
        let frame = match stream.recv_frame().await {
            Ok(f) => f,
            Err(_) => break,
        };
        let pt = match session.decrypt(&frame) {
            Ok(pt) => pt,
            Err(_) => continue,
        };
        let response = match Request::decode(&pt) {
            Ok(req) => apply(&store, req),
            Err(_) => Response::Error("malformed request".into()),
        };
        let ct = match session.encrypt(&response.encode()) {
            Ok(ct) => ct,
            Err(_) => break,
        };
        if stream.send_frame(&ct).await.is_err() {
            break;
        }
    }
}

/// Apply a request to the store. `Register` accepts a claim only if it is validly
/// self-signed by the account it names; a name already held by a *different*
/// account is refused (first-come per registry — equivocation across registries
/// is caught by [`resolve_across`], not here).
fn apply(store: &Mutex<HashMap<String, SignedClaim>>, req: Request) -> Response {
    match req {
        Request::Register(claim) => {
            if claim.verify().is_err() {
                return Response::Error("claim is not validly self-signed".into());
            }
            let name = claim.claim.username.clone();
            let mut map = store.lock().unwrap();
            if let Some(existing) = map.get(&name) {
                if existing.claim.account != claim.claim.account {
                    return Response::Error("username already registered to another account".into());
                }
            }
            map.insert(name, claim);
            Response::Registered
        }
        Request::Resolve(name) => {
            let map = store.lock().unwrap();
            Response::Claims(map.get(&name).cloned().into_iter().collect())
        }
        Request::List => {
            let map = store.lock().unwrap();
            Response::Claims(map.values().cloned().collect())
        }
    }
}

/// A client connection to one registry. Holds the encrypted session; each call
/// is one request/response round-trip.
pub struct RegistryClient {
    stream: Box<dyn Stream>,
    session: Box<dyn SessionHandle>,
}

impl RegistryClient {
    /// Dial a registry endpoint and run the authenticated handshake (using the
    /// shared registry `descriptor` for the session root).
    pub async fn connect(
        identity: &IdentityKeyPair,
        suite: Arc<dyn CryptoSuite>,
        transport: Arc<dyn Transport>,
        descriptor: &ChatDescriptor,
        endpoint: &str,
    ) -> Result<RegistryClient> {
        let mut stream = transport.dial(&endpoint.to_string()).await?;
        let hs =
            handshake::initiate(stream.as_mut(), identity, suite.as_ref(), descriptor.derive_root())
                .await?;
        Ok(RegistryClient {
            stream,
            session: hs.session,
        })
    }

    async fn round_trip(&mut self, req: Request) -> Result<Response> {
        let ct = self.session.encrypt(&req.encode())?;
        self.stream.send_frame(&ct).await?;
        let frame = self.stream.recv_frame().await?;
        let pt = self.session.decrypt(&frame)?;
        Response::decode(&pt)
    }

    /// Publish a self-signed username claim. Errors if the registry refuses it.
    pub async fn register(&mut self, claim: &SignedClaim) -> Result<()> {
        match self.round_trip(Request::Register(claim.clone())).await? {
            Response::Registered => Ok(()),
            Response::Error(msg) => Err(CoreError::Registry(msg)),
            _ => Err(CoreError::Malformed("unexpected registry response")),
        }
    }

    /// Resolve a username to the claim(s) this registry holds (≤1).
    pub async fn resolve(&mut self, username: &str) -> Result<Vec<SignedClaim>> {
        match self.round_trip(Request::Resolve(username.to_string())).await? {
            Response::Claims(claims) => Ok(claims),
            Response::Error(msg) => Err(CoreError::Registry(msg)),
            _ => Err(CoreError::Malformed("unexpected registry response")),
        }
    }

    /// List every binding the registry holds.
    pub async fn list(&mut self) -> Result<Vec<SignedClaim>> {
        match self.round_trip(Request::List).await? {
            Response::Claims(claims) => Ok(claims),
            Response::Error(msg) => Err(CoreError::Registry(msg)),
            _ => Err(CoreError::Malformed("unexpected registry response")),
        }
    }
}

/// Cross-compare the claims returned by several registries for `username`.
/// Returns the account key **only if** every claim is validly self-signed, names
/// `username`, and they all agree on the same account — so no single registry
/// could substitute a different key. Pass the (flattened) claims gathered from
/// each registry's `resolve`. Empty input ⇒ `None`.
pub fn resolve_across(username: &str, claims: &[SignedClaim]) -> Option<IdentityPublic> {
    cross_compare(username, claims)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::descriptor::{Persistence, TopologyKind};
    use talkrypt_crypto::{SuiteRegistry, DEFAULT_SUITE_ID};
    use talkrypt_transport::LoopbackFabric;

    const NOW: u64 = 1_700_000_000;

    fn suite() -> Arc<dyn CryptoSuite> {
        SuiteRegistry::with_defaults().get(DEFAULT_SUITE_ID).unwrap()
    }

    fn registry_desc(channel: &str) -> ChatDescriptor {
        ChatDescriptor::new(
            TopologyKind::Hub,
            Persistence::Persistent,
            DEFAULT_SUITE_ID,
            vec![],
            channel,
        )
    }

    /// Start a registry server on `fabric` at `addr` with descriptor `desc`.
    async fn start_registry(fabric: &LoopbackFabric, addr: &str, desc: &ChatDescriptor) {
        let server = RegistryServer::new(
            IdentityKeyPair::generate(),
            suite(),
            Arc::new(fabric.transport(addr)),
            desc,
        );
        // Leak the server so it lives for the test (its accept loop is spawned).
        let server = Box::leak(Box::new(server));
        server.run().await.unwrap();
    }

    async fn client(
        fabric: &LoopbackFabric,
        from: &str,
        desc: &ChatDescriptor,
        to: &str,
    ) -> RegistryClient {
        let id = IdentityKeyPair::generate();
        RegistryClient::connect(&id, suite(), Arc::new(fabric.transport(from)), desc, to)
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn register_then_resolve_roundtrip() {
        let fabric = LoopbackFabric::new();
        let desc = registry_desc("#reg");
        start_registry(&fabric, "reg", &desc).await;

        let account = IdentityKeyPair::generate();
        let claim = SignedClaim::issue(&account, "alice", NOW);

        let mut c = client(&fabric, "c1", &desc, "reg").await;
        c.register(&claim).await.unwrap();

        let got = c.resolve("alice").await.unwrap();
        assert_eq!(got.len(), 1);
        assert!(got[0].verify().is_ok());
        assert_eq!(got[0].claim.account, account.public().clone());

        // Unknown name resolves to nothing.
        assert!(c.resolve("nobody").await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn name_taken_by_another_account_is_refused() {
        let fabric = LoopbackFabric::new();
        let desc = registry_desc("#reg2");
        start_registry(&fabric, "reg2", &desc).await;

        let alice = IdentityKeyPair::generate();
        let mallory = IdentityKeyPair::generate();
        let mut c = client(&fabric, "c2", &desc, "reg2").await;
        c.register(&SignedClaim::issue(&alice, "alice", NOW)).await.unwrap();

        // Mallory tries to grab "alice" under his own account → refused.
        let err = c
            .register(&SignedClaim::issue(&mallory, "alice", NOW + 1))
            .await;
        assert!(err.is_err());
        // Alice can refresh her own binding.
        c.register(&SignedClaim::issue(&alice, "alice", NOW + 2)).await.unwrap();
    }

    #[tokio::test]
    async fn multi_registry_cross_compare_resolves_and_detects_disagreement() {
        let fabric = LoopbackFabric::new();
        let desc = registry_desc("#multi");
        start_registry(&fabric, "rA", &desc).await;
        start_registry(&fabric, "rB", &desc).await;

        let account = IdentityKeyPair::generate();
        // Register the SAME account on both registries.
        let mut ca = client(&fabric, "ca", &desc, "rA").await;
        let mut cb = client(&fabric, "cb", &desc, "rB").await;
        ca.register(&SignedClaim::issue(&account, "alice", NOW)).await.unwrap();
        cb.register(&SignedClaim::issue(&account, "alice", NOW + 1)).await.unwrap();

        // Gather from both and cross-compare → agreement on the account key.
        let mut claims = ca.resolve("alice").await.unwrap();
        claims.extend(cb.resolve("alice").await.unwrap());
        assert_eq!(resolve_across("alice", &claims), Some(account.public().clone()));

        // A hostile registry that serves a DIFFERENT account's (validly
        // self-signed) claim for "alice" makes cross-compare reject.
        let other = IdentityKeyPair::generate();
        let mut equivocating = ca.resolve("alice").await.unwrap();
        equivocating.push(SignedClaim::issue(&other, "alice", NOW));
        assert_eq!(resolve_across("alice", &equivocating), None);
    }
}
