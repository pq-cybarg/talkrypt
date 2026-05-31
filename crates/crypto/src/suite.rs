//! Crypto-suite abstraction and registry.
//!
//! A `CryptoSuite` packages a complete end-to-end construction (identity,
//! session establishment, message encryption) behind one trait, so the rest
//! of talkrypt is agnostic to *which* construction a chat uses. Suites are
//! registered at compile time — a static, auditable boundary with no runtime
//! code loading, which is what high-assurance regimes require.
//!
//! Built-in: `tk.dr.*` — the hybrid PQ Double Ratchet (this module).
//! Custom suites implement [`CryptoSuite`] and register against the floor.

use std::collections::HashMap;
use std::sync::Arc;

use crate::error::{CryptoError, Result};
use crate::hybrid::{RatchetPublic, RatchetSecret};
use crate::kdf::KEY_LEN;
use crate::noise::NoiseSession;
use crate::ratchet::Session;

/// Canonical id of the default suite.
pub const DEFAULT_SUITE_ID: &str = "tk.dr.x25519+mlkem1024.aes256gcm.sha384.mldsa87";

/// Id of the PQ-Noise suite (session-granularity forward secrecy).
pub const NOISE_SUITE_ID: &str = "tk.noise.x25519+mlkem1024.aes256gcm.sha384";

/// Coarse security level used to enforce a registry floor.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum SecurityLevel {
    /// Classical-only or sub-128-bit PQ. Rejected by default.
    Weak,
    /// Hybrid PQ at NIST category 3+. The default floor.
    PostQuantumHybrid,
}

/// Self-describing metadata a suite advertises (carried in chat descriptors).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SuiteDescriptor {
    pub id: String,
    pub version: u16,
    pub level: SecurityLevel,
    /// Opaque suite-defined parameters.
    pub params: Vec<u8>,
}

/// A complete end-to-end crypto construction.
pub trait CryptoSuite: Send + Sync {
    fn descriptor(&self) -> SuiteDescriptor;

    /// Generate a fresh prekey: returns the public half (to advertise) and an
    /// opaque secret handle (to retain for the responder role).
    fn generate_prekey(&self) -> (Vec<u8>, PrekeySecretHandle);

    /// Begin an initiator session toward a peer's advertised prekey.
    fn begin_session(
        &self,
        root0: [u8; KEY_LEN],
        peer_prekey: &[u8],
    ) -> Result<Box<dyn SessionHandle>>;

    /// Accept a responder session using our retained prekey secret.
    fn accept_session(
        &self,
        root0: [u8; KEY_LEN],
        prekey_secret: PrekeySecretHandle,
    ) -> Result<Box<dyn SessionHandle>>;
}

/// Opaque, suite-specific prekey secret. The concrete type is hidden behind
/// `Any` so the trait stays object-safe across heterogeneous suites.
pub struct PrekeySecretHandle(Box<dyn std::any::Any + Send + Sync>);

/// Object-safe handle over a live session.
pub trait SessionHandle: Send {
    fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>>;
    fn decrypt(&mut self, message: &[u8]) -> Result<Vec<u8>>;
}

// ----- Built-in: hybrid PQ Double Ratchet suite -----

/// The default suite. Sessions are [`Session`] (see [`crate::ratchet`]).
#[derive(Default)]
pub struct DoubleRatchetSuite;

struct DrPrekeySecret {
    secret: RatchetSecret,
    public: RatchetPublic,
}

impl CryptoSuite for DoubleRatchetSuite {
    fn descriptor(&self) -> SuiteDescriptor {
        SuiteDescriptor {
            id: DEFAULT_SUITE_ID.to_string(),
            version: 1,
            level: SecurityLevel::PostQuantumHybrid,
            params: Vec::new(),
        }
    }

    fn generate_prekey(&self) -> (Vec<u8>, PrekeySecretHandle) {
        let (secret, public) = RatchetSecret::generate();
        let pub_bytes = public.encode();
        let handle = PrekeySecretHandle(Box::new(DrPrekeySecret { secret, public }));
        (pub_bytes, handle)
    }

    fn begin_session(
        &self,
        root0: [u8; KEY_LEN],
        peer_prekey: &[u8],
    ) -> Result<Box<dyn SessionHandle>> {
        let peer = RatchetPublic::decode(peer_prekey)?;
        Ok(Box::new(Session::initiator(root0, peer)))
    }

    fn accept_session(
        &self,
        root0: [u8; KEY_LEN],
        prekey_secret: PrekeySecretHandle,
    ) -> Result<Box<dyn SessionHandle>> {
        let dr = prekey_secret
            .0
            .downcast::<DrPrekeySecret>()
            .map_err(|_| CryptoError::Malformed("prekey secret type mismatch"))?;
        Ok(Box::new(Session::responder(root0, dr.secret, dr.public)))
    }
}

impl SessionHandle for Session {
    fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>> {
        Session::encrypt(self, plaintext)
    }
    fn decrypt(&mut self, message: &[u8]) -> Result<Vec<u8>> {
        Session::decrypt(self, message)
    }
}

// ----- Built-in: PQ-Noise suite (session-granularity forward secrecy) -----

/// PQ-Noise suite: one hybrid step, then symmetric chains. See [`crate::noise`].
#[derive(Default)]
pub struct NoiseSuite;

impl CryptoSuite for NoiseSuite {
    fn descriptor(&self) -> SuiteDescriptor {
        SuiteDescriptor {
            id: NOISE_SUITE_ID.to_string(),
            version: 1,
            level: SecurityLevel::PostQuantumHybrid,
            params: Vec::new(),
        }
    }

    fn generate_prekey(&self) -> (Vec<u8>, PrekeySecretHandle) {
        let (secret, public) = RatchetSecret::generate();
        let pub_bytes = public.encode();
        // Noise responder needs only the secret half.
        (pub_bytes, PrekeySecretHandle(Box::new(secret)))
    }

    fn begin_session(
        &self,
        root0: [u8; KEY_LEN],
        peer_prekey: &[u8],
    ) -> Result<Box<dyn SessionHandle>> {
        let peer = RatchetPublic::decode(peer_prekey)?;
        Ok(Box::new(NoiseSession::initiator(root0, peer)))
    }

    fn accept_session(
        &self,
        root0: [u8; KEY_LEN],
        prekey_secret: PrekeySecretHandle,
    ) -> Result<Box<dyn SessionHandle>> {
        let secret = prekey_secret
            .0
            .downcast::<RatchetSecret>()
            .map_err(|_| CryptoError::Malformed("prekey secret type mismatch"))?;
        Ok(Box::new(NoiseSession::responder(root0, *secret)))
    }
}

impl SessionHandle for NoiseSession {
    fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>> {
        NoiseSession::encrypt(self, plaintext)
    }
    fn decrypt(&mut self, message: &[u8]) -> Result<Vec<u8>> {
        NoiseSession::decrypt(self, message)
    }
}

// ----- Registry -----

/// A compile-time registry of available suites, with a security floor.
pub struct SuiteRegistry {
    suites: HashMap<String, Arc<dyn CryptoSuite>>,
    floor: SecurityLevel,
}

impl SuiteRegistry {
    /// Empty registry at the post-quantum-hybrid floor.
    pub fn new() -> Self {
        Self {
            suites: HashMap::new(),
            floor: SecurityLevel::PostQuantumHybrid,
        }
    }

    /// Registry preloaded with all built-in pairwise suites (Double Ratchet
    /// and PQ-Noise). The Double Ratchet remains the default.
    pub fn with_defaults() -> Self {
        let mut r = Self::new();
        r.register(Arc::new(DoubleRatchetSuite))
            .expect("default suite meets floor");
        r.register(Arc::new(NoiseSuite))
            .expect("noise suite meets floor");
        r
    }

    /// Lower the floor (e.g. for a custom/experimental weak suite). Explicit by
    /// design: weakening the floor is a deliberate, visible act.
    pub fn set_floor(&mut self, floor: SecurityLevel) {
        self.floor = floor;
    }

    /// Register a suite. Rejected if it advertises below the current floor.
    pub fn register(&mut self, suite: Arc<dyn CryptoSuite>) -> Result<()> {
        let d = suite.descriptor();
        if d.level < self.floor {
            return Err(CryptoError::BelowFloor(d.id));
        }
        self.suites.insert(d.id, suite);
        Ok(())
    }

    /// Look up a suite by id.
    pub fn get(&self, id: &str) -> Result<Arc<dyn CryptoSuite>> {
        self.suites
            .get(id)
            .cloned()
            .ok_or_else(|| CryptoError::UnknownSuite(id.to_string()))
    }

    /// Ids of all registered suites.
    pub fn ids(&self) -> Vec<String> {
        let mut v: Vec<String> = self.suites.keys().cloned().collect();
        v.sort();
        v
    }
}

impl Default for SuiteRegistry {
    fn default() -> Self {
        Self::with_defaults()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_registry_has_double_ratchet() {
        let reg = SuiteRegistry::with_defaults();
        assert!(reg.get(DEFAULT_SUITE_ID).is_ok());
        assert!(reg.get(NOISE_SUITE_ID).is_ok());
        assert!(reg.ids().contains(&DEFAULT_SUITE_ID.to_string()));
        assert!(reg.ids().contains(&NOISE_SUITE_ID.to_string()));
    }

    #[test]
    fn unknown_suite_is_descriptive_error() {
        let reg = SuiteRegistry::with_defaults();
        match reg.get("tk.x.nonexistent") {
            Err(CryptoError::UnknownSuite(id)) => assert_eq!(id, "tk.x.nonexistent"),
            Err(e) => panic!("expected UnknownSuite, got error {e}"),
            Ok(_) => panic!("expected UnknownSuite, got a suite"),
        }
    }

    #[test]
    fn weak_suite_rejected_unless_floor_lowered() {
        struct WeakSuite;
        impl CryptoSuite for WeakSuite {
            fn descriptor(&self) -> SuiteDescriptor {
                SuiteDescriptor {
                    id: "tk.x.weak".into(),
                    version: 1,
                    level: SecurityLevel::Weak,
                    params: vec![],
                }
            }
            fn generate_prekey(&self) -> (Vec<u8>, PrekeySecretHandle) {
                (vec![], PrekeySecretHandle(Box::new(())))
            }
            fn begin_session(
                &self,
                _r: [u8; KEY_LEN],
                _p: &[u8],
            ) -> Result<Box<dyn SessionHandle>> {
                Err(CryptoError::Malformed("unused"))
            }
            fn accept_session(
                &self,
                _r: [u8; KEY_LEN],
                _s: PrekeySecretHandle,
            ) -> Result<Box<dyn SessionHandle>> {
                Err(CryptoError::Malformed("unused"))
            }
        }
        let mut reg = SuiteRegistry::with_defaults();
        assert!(matches!(
            reg.register(Arc::new(WeakSuite)),
            Err(CryptoError::BelowFloor(_))
        ));
        reg.set_floor(SecurityLevel::Weak);
        assert!(reg.register(Arc::new(WeakSuite)).is_ok());
    }

    #[test]
    fn end_to_end_through_suite_trait() {
        let reg = SuiteRegistry::with_defaults();
        let suite = reg.get(DEFAULT_SUITE_ID).unwrap();
        let root0 = [7u8; KEY_LEN];

        // Responder (Bob) advertises a prekey; initiator (Alice) uses it.
        let (bob_prekey_pub, bob_prekey_secret) = suite.generate_prekey();
        let mut alice = suite.begin_session(root0, &bob_prekey_pub).unwrap();
        let mut bob = suite.accept_session(root0, bob_prekey_secret).unwrap();

        let ct = alice.encrypt(b"via the suite trait").unwrap();
        assert_eq!(bob.decrypt(&ct).unwrap(), b"via the suite trait");
        let reply = bob.encrypt(b"and back").unwrap();
        assert_eq!(alice.decrypt(&reply).unwrap(), b"and back");
    }
}
