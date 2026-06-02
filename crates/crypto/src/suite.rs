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
use crate::hybrid::{KemPosture, KemProfile, RatchetPublic, RatchetSecret};
use crate::kdf::KEY_LEN;
use crate::noise::NoiseSession;
use crate::ratchet::Session;

/// Hash token for the active build (`sha3-384` by default, `sha384` under the
/// `cnsa-sha2` feature).
#[cfg(not(feature = "cnsa-sha2"))]
const HASH_TOKEN: &str = "sha3-384";
#[cfg(feature = "cnsa-sha2")]
const HASH_TOKEN: &str = "sha384";

/// KEM token for a profile. PQ-pure is written bare (`mlkem1024`); the padded
/// variant appends `+pad` (a wire option, not a different KEM); hybrid appends
/// the non-load-bearing `+x25519` defense-in-depth half.
fn kem_token(profile: KemProfile) -> &'static str {
    match (profile.posture, profile.pad_pure) {
        (KemPosture::Hybrid, _) => "mlkem1024+x25519",
        (KemPosture::PqPure, true) => "mlkem1024+pad",
        (KemPosture::PqPure, false) => "mlkem1024",
    }
}

/// Canonical Double-Ratchet suite id for a KEM profile, e.g.
/// `tk.dr.mlkem1024+pad.aes256gcm.sha3-384.mldsa87`. Identity is ML-DSA-87 in
/// every profile (pure PQ, zero EC).
pub fn dr_suite_id(profile: KemProfile) -> String {
    format!("tk.dr.{}.aes256gcm.{}.mldsa87", kem_token(profile), HASH_TOKEN)
}

/// Canonical PQ-Noise suite id for a KEM profile.
pub fn noise_suite_id(profile: KemProfile) -> String {
    format!("tk.noise.{}.aes256gcm.{}", kem_token(profile), HASH_TOKEN)
}

/// Length of a scheme fingerprint (SHA3-256).
pub const SCHEME_HASH_LEN: usize = 32;

/// Canonical **scheme fingerprint**: `SHA3-256(len(id) ‖ id ‖ len(params) ‖
/// params)`. A "scheme" is a complete crypto construction — its suite id plus
/// any opaque parameters. This fingerprint is how a chat's scheme is matched
/// against a receiver's registered schemes, and the identifier carried in
/// (always-encrypted) beacons. Length-prefixing prevents id/params boundary
/// ambiguity. SHA3-256 is used regardless of the build's KDF hash, so the
/// fingerprint is stable across `cnsa-sha2`.
pub fn scheme_hash(suite_id: &str, params: &[u8]) -> [u8; SCHEME_HASH_LEN] {
    use sha3::{Digest, Sha3_256};
    let mut h = Sha3_256::new();
    h.update((suite_id.len() as u32).to_be_bytes());
    h.update(suite_id.as_bytes());
    h.update((params.len() as u32).to_be_bytes());
    h.update(params);
    h.finalize().into()
}

/// Canonical id of the **default** suite: PQ-pure (zero EC), padded on the wire
/// to be frame-length-indistinguishable from hybrid. Hybrid and compact-pure
/// suites exist too — see [`dr_suite_id`] — but this is what a chat uses when
/// the creator states no preference.
#[cfg(not(feature = "cnsa-sha2"))]
pub const DEFAULT_SUITE_ID: &str = "tk.dr.mlkem1024+pad.aes256gcm.sha3-384.mldsa87";
#[cfg(feature = "cnsa-sha2")]
pub const DEFAULT_SUITE_ID: &str = "tk.dr.mlkem1024+pad.aes256gcm.sha384.mldsa87";

/// Id of the default PQ-Noise suite (session-granularity forward secrecy).
#[cfg(not(feature = "cnsa-sha2"))]
pub const NOISE_SUITE_ID: &str = "tk.noise.mlkem1024+pad.aes256gcm.sha3-384";
#[cfg(feature = "cnsa-sha2")]
pub const NOISE_SUITE_ID: &str = "tk.noise.mlkem1024+pad.aes256gcm.sha384";

/// Coarse security level used to enforce a registry floor.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum SecurityLevel {
    /// Classical-only or sub-128-bit PQ. Rejected by default.
    Weak,
    /// PQ at NIST category 3+ — ML-KEM-1024 based, whether pure or hybrid
    /// (the X25519 half adds defense-in-depth but does not change the floor).
    /// The default floor.
    PostQuantum,
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

impl SuiteDescriptor {
    /// This scheme's SHA3-256 fingerprint (see [`scheme_hash`]).
    pub fn fingerprint(&self) -> [u8; SCHEME_HASH_LEN] {
        scheme_hash(&self.id, &self.params)
    }
}

/// A complete end-to-end crypto construction.
pub trait CryptoSuite: Send + Sync {
    fn descriptor(&self) -> SuiteDescriptor;

    /// The KEM profile (posture + wire padding) this suite uses for ratchet and
    /// group keys, so group state (TreeKEM) matches the pairwise sessions.
    /// Defaults to the PQ-pure padded profile; suites with another posture
    /// override this.
    fn kem_profile(&self) -> KemProfile {
        KemProfile::default()
    }

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

// ----- Built-in: PQ Double Ratchet suite (posture-selectable) -----

/// The Double Ratchet suite, parameterized by [`KemProfile`]. The default
/// (`KemProfile::pq_pure`) is the zero-EC, padded posture; `with_profile` builds
/// the hybrid or compact-pure variants. Sessions are [`Session`] (see
/// [`crate::ratchet`]).
#[derive(Default)]
pub struct DoubleRatchetSuite {
    profile: KemProfile,
}

impl DoubleRatchetSuite {
    /// Build the suite for a specific KEM profile (hybrid / padded-pure /
    /// compact-pure).
    pub fn with_profile(profile: KemProfile) -> Self {
        Self { profile }
    }
}

struct DrPrekeySecret {
    secret: RatchetSecret,
    public: RatchetPublic,
}

impl CryptoSuite for DoubleRatchetSuite {
    fn descriptor(&self) -> SuiteDescriptor {
        SuiteDescriptor {
            id: dr_suite_id(self.profile),
            version: 1,
            level: SecurityLevel::PostQuantum,
            params: Vec::new(),
        }
    }

    fn kem_profile(&self) -> KemProfile {
        self.profile
    }

    fn generate_prekey(&self) -> (Vec<u8>, PrekeySecretHandle) {
        let (secret, public) = RatchetSecret::generate(self.profile);
        let pub_bytes = public.encode();
        let handle = PrekeySecretHandle(Box::new(DrPrekeySecret { secret, public }));
        (pub_bytes, handle)
    }

    fn begin_session(
        &self,
        root0: [u8; KEY_LEN],
        peer_prekey: &[u8],
    ) -> Result<Box<dyn SessionHandle>> {
        let peer = RatchetPublic::decode(self.profile, peer_prekey)?;
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

/// PQ-Noise suite: one asymmetric step, then symmetric chains, parameterized by
/// [`KemProfile`]. See [`crate::noise`].
#[derive(Default)]
pub struct NoiseSuite {
    profile: KemProfile,
}

impl NoiseSuite {
    /// Build the suite for a specific KEM profile.
    pub fn with_profile(profile: KemProfile) -> Self {
        Self { profile }
    }
}

impl CryptoSuite for NoiseSuite {
    fn descriptor(&self) -> SuiteDescriptor {
        SuiteDescriptor {
            id: noise_suite_id(self.profile),
            version: 1,
            level: SecurityLevel::PostQuantum,
            params: Vec::new(),
        }
    }

    fn kem_profile(&self) -> KemProfile {
        self.profile
    }

    fn generate_prekey(&self) -> (Vec<u8>, PrekeySecretHandle) {
        let (secret, public) = RatchetSecret::generate(self.profile);
        let pub_bytes = public.encode();
        // Noise responder needs only the secret half.
        (pub_bytes, PrekeySecretHandle(Box::new(secret)))
    }

    fn begin_session(
        &self,
        root0: [u8; KEY_LEN],
        peer_prekey: &[u8],
    ) -> Result<Box<dyn SessionHandle>> {
        let peer = RatchetPublic::decode(self.profile, peer_prekey)?;
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
    /// Empty registry at the post-quantum floor.
    pub fn new() -> Self {
        Self {
            suites: HashMap::new(),
            floor: SecurityLevel::PostQuantum,
        }
    }

    /// Registry preloaded with all built-in pairwise suites across every KEM
    /// profile. The default is PQ-pure (padded); the **hybrid** Double-Ratchet
    /// suite is always registered (defense-in-depth must remain available in
    /// every build), as is a compact (unpadded) PQ-pure variant for bandwidth-
    /// sensitive chats. PQ-Noise is offered in the default and hybrid profiles.
    pub fn with_defaults() -> Self {
        let mut r = Self::new();
        for profile in [
            KemProfile::pq_pure(),         // default
            KemProfile::hybrid(),          // mandatory defense-in-depth
            KemProfile::pq_pure_compact(), // bandwidth-sensitive, posture-visible
        ] {
            r.register(Arc::new(DoubleRatchetSuite::with_profile(profile)))
                .expect("double-ratchet suite meets floor");
        }
        for profile in [KemProfile::pq_pure(), KemProfile::hybrid()] {
            r.register(Arc::new(NoiseSuite::with_profile(profile)))
                .expect("noise suite meets floor");
        }
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

    /// Look up a suite by its **scheme fingerprint** (SHA3-256). This is how a
    /// receiver matches a chat's scheme — including a custom one they have
    /// registered — to a local construction. Returns `UnknownSuite` (with the
    /// hex fingerprint) if no registered scheme matches, which is exactly the
    /// "receiver lacks a matching scheme, cannot participate" case.
    pub fn get_by_scheme_hash(
        &self,
        hash: &[u8; SCHEME_HASH_LEN],
    ) -> Result<Arc<dyn CryptoSuite>> {
        for suite in self.suites.values() {
            if &suite.descriptor().fingerprint() == hash {
                return Ok(suite.clone());
            }
        }
        let hex: String = hash.iter().map(|b| format!("{b:02x}")).collect();
        Err(CryptoError::UnknownSuite(format!("scheme:{hex}")))
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
    fn default_registry_includes_hybrid_and_pure_variants() {
        // Hybrid must be available in every build; compact-pure too.
        let reg = SuiteRegistry::with_defaults();
        assert!(reg.get(&dr_suite_id(KemProfile::hybrid())).is_ok());
        assert!(reg.get(&dr_suite_id(KemProfile::pq_pure())).is_ok());
        assert!(reg.get(&dr_suite_id(KemProfile::pq_pure_compact())).is_ok());
        // The default is PQ-pure (zero EC).
        assert_eq!(DEFAULT_SUITE_ID, dr_suite_id(KemProfile::pq_pure()));
        assert!(DEFAULT_SUITE_ID.contains("mlkem1024+pad"));
        assert!(!DEFAULT_SUITE_ID.contains("x25519"));
    }

    #[test]
    fn scheme_hash_is_stable_and_distinguishes_schemes() {
        // Length-prefixing prevents id/params boundary collisions.
        assert_eq!(scheme_hash("ab", b"c"), scheme_hash("ab", b"c"));
        assert_ne!(scheme_hash("ab", b"c"), scheme_hash("abc", b""));
        assert_ne!(scheme_hash("a", b"bc"), scheme_hash("ab", b"c"));
    }

    #[test]
    fn lookup_by_scheme_hash_matches_registered_suite() {
        let reg = SuiteRegistry::with_defaults();
        let want = reg.get(DEFAULT_SUITE_ID).unwrap();
        let fp = want.descriptor().fingerprint();
        let got = reg.get_by_scheme_hash(&fp).unwrap();
        assert_eq!(got.descriptor().id, want.descriptor().id);
    }

    #[test]
    fn unknown_scheme_hash_is_rejected() {
        // A scheme the receiver hasn't registered → cannot participate.
        let reg = SuiteRegistry::with_defaults();
        let bogus = [0xABu8; SCHEME_HASH_LEN];
        match reg.get_by_scheme_hash(&bogus) {
            Err(CryptoError::UnknownSuite(s)) => assert!(s.starts_with("scheme:")),
            Err(e) => panic!("expected UnknownSuite, got error {e}"),
            Ok(_) => panic!("expected UnknownSuite, got a suite"),
        }
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
