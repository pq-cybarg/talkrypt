//! Chat descriptor — the shareable invite.
//!
//! Encodes everything a peer needs to join: topology, persistence, crypto
//! suite id + params, endpoint(s), a one-time invite token (first-contact
//! PSK), and the initial channel. Serialized to a `talkrypt://<base32>` URI
//! (also a QR payload).
//!
//! The invite token is the initial shared secret from which the session root
//! key is derived, so only descriptor holders can complete a handshake.

use rand::RngCore;

use crate::b32;
use crate::error::{CoreError, Result};

pub const URI_SCHEME: &str = "talkrypt://";
const DESCRIPTOR_VERSION: u16 = 1;
const ROOT_SALT: &[u8] = b"talkrypt-root-v1";
const PW_ROOT_SALT: &[u8] = b"talkrypt-pw-root-v1";

/// An out-of-band **channel password**. Never serialized into the invite URI —
/// it is shared separately (spoken, typed) and mixed into the session root via
/// Argon2id, so the invite token *alone* cannot derive the root: an attacker who
/// captures the `talkrypt://` link still cannot join without the password.
///
/// `Debug` is redacted so the password never lands in logs or error output.
#[derive(Clone, PartialEq, Eq)]
pub struct ChannelPassword(String);

impl ChannelPassword {
    pub fn new(password: impl Into<String>) -> Self {
        ChannelPassword(password.into())
    }
}

impl std::fmt::Debug for ChannelPassword {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ChannelPassword(<redacted>)")
    }
}

/// Argon2id (m=19 MiB, t=2, p=1) of a password under a salt → 32-byte key. This
/// is the memory-hard work factor that makes a weak channel password costly to
/// brute-force even if the invite token leaks.
fn argon2id_key(password: &[u8], salt: &[u8]) -> [u8; 32] {
    use argon2::{Algorithm, Argon2, Params, Version};
    let params = Params::new(19_456, 2, 1, Some(32)).expect("valid argon2 params");
    let a = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut out = [0u8; 32];
    a.hash_password_into(password, salt, &mut out)
        .expect("argon2id derivation");
    out
}

/// Network topology for a chat.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TopologyKind {
    /// Each peer hosts its own onion; messages flow peer-to-peer.
    P2P,
    /// One onion relays (IRC-like hub); relay sees ciphertext only.
    Hub,
    /// Hub for rendezvous; messages flow peer-to-peer.
    Hybrid,
}

impl TopologyKind {
    fn tag(self) -> u8 {
        match self {
            TopologyKind::P2P => 0,
            TopologyKind::Hub => 1,
            TopologyKind::Hybrid => 2,
        }
    }
    fn from_tag(t: u8) -> Result<Self> {
        Ok(match t {
            0 => TopologyKind::P2P,
            1 => TopologyKind::Hub,
            2 => TopologyKind::Hybrid,
            _ => return Err(CoreError::Malformed("topology tag")),
        })
    }
}

/// Onion-service persistence mode (meaningful for Hub/Hybrid).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Persistence {
    /// Fresh onion key per session.
    Ephemeral,
    /// Stable onion that survives restarts.
    Persistent,
}

impl Persistence {
    fn tag(self) -> u8 {
        match self {
            Persistence::Ephemeral => 0,
            Persistence::Persistent => 1,
        }
    }
    fn from_tag(t: u8) -> Result<Self> {
        Ok(match t {
            0 => Persistence::Ephemeral,
            1 => Persistence::Persistent,
            _ => return Err(CoreError::Malformed("persistence tag")),
        })
    }
}

/// The full, shareable chat descriptor.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChatDescriptor {
    pub version: u16,
    pub topology: TopologyKind,
    pub persistence: Persistence,
    pub suite_id: String,
    pub suite_params: Vec<u8>,
    /// Endpoint(s): the hub for Hub/Hybrid, or the inviter's rendezvous onion.
    pub endpoints: Vec<String>,
    /// One-time pre-shared secret authenticating first contact (32 bytes).
    pub invite_token: Vec<u8>,
    /// Initial channel name.
    pub channel: String,
    /// Whether this is a TreeKEM group chat (host coordinates membership).
    pub group: bool,
    /// Optional channel classification marking/policy (advisory). Present only
    /// for marked channels; consumer builds leave it `None`.
    pub channel_marking: Option<crate::marking::Marking>,
    /// Optional out-of-band channel password. **In-memory only — never encoded
    /// into the invite URI.** When set, it is folded into [`Self::derive_root`]
    /// via Argon2id, so both the invite token *and* the password are required to
    /// join (a password-gated channel). Set it on both sides out of band.
    pub password: Option<ChannelPassword>,
}

impl ChatDescriptor {
    /// Build a descriptor with a freshly generated 32-byte invite token.
    pub fn new(
        topology: TopologyKind,
        persistence: Persistence,
        suite_id: impl Into<String>,
        endpoints: Vec<String>,
        channel: impl Into<String>,
    ) -> Self {
        let mut invite_token = vec![0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut invite_token);
        Self {
            version: DESCRIPTOR_VERSION,
            topology,
            persistence,
            suite_id: suite_id.into(),
            suite_params: Vec::new(),
            endpoints,
            invite_token,
            channel: channel.into(),
            group: false,
            channel_marking: None,
            password: None,
        }
    }

    /// Set (or clear) the out-of-band channel password. Chainable.
    pub fn with_password(mut self, password: Option<ChannelPassword>) -> Self {
        self.password = password;
        self
    }

    /// The effective suite id: the stated one, or the protocol default
    /// (PQ-pure) when the descriptor leaves it blank. Posture is **optional** in
    /// an invite — a minimal/private invite need not state it; absent means the
    /// fixed protocol default so two peers still agree (and nothing extra is
    /// carried even in the private invite).
    pub fn resolved_suite_id(&self) -> &str {
        if self.suite_id.is_empty() {
            talkrypt_crypto::DEFAULT_SUITE_ID
        } else {
            &self.suite_id
        }
    }

    /// This chat's **scheme fingerprint** (SHA3-256 over the resolved suite id +
    /// params). A receiver can only participate if it has a registered scheme
    /// with this fingerprint. Also the value carried in (always-encrypted)
    /// beacons.
    pub fn scheme_hash(&self) -> [u8; talkrypt_crypto::SCHEME_HASH_LEN] {
        talkrypt_crypto::scheme_hash(self.resolved_suite_id(), &self.suite_params)
    }

    /// Derive the initial session root key from the invite token, bound to the
    /// resolved suite id. Both peers compute the same value — and because the
    /// suite id encodes the KEM posture, a posture mismatch yields a different
    /// root and the handshake fails closed.
    pub fn derive_root(&self) -> [u8; 32] {
        // Keyed by the secret invite token; resolved suite id as the domain
        // label. KMAC256 under SHA-3, HKDF-HMAC-SHA384 under cnsa-sha2.
        let mut base = [0u8; 32];
        talkrypt_crypto::kdf::mac_kdf(
            &self.invite_token,
            ROOT_SALT,
            self.resolved_suite_id().as_bytes(),
            &mut base,
        );
        match &self.password {
            // Unprotected channel: the invite token alone derives the root.
            None => base,
            // Password-gated channel: fold an Argon2id(password) key in as the
            // KDF key over the token-derived base. Without the password, the
            // base differs, so an invite-only holder fails the handshake closed.
            // The password itself is never transmitted — only the ability to
            // derive this root proves knowledge of it.
            Some(pw) => {
                let pw_key = argon2id_key(pw.0.as_bytes(), &self.invite_token);
                let mut out = [0u8; 32];
                talkrypt_crypto::kdf::mac_kdf(&pw_key, PW_ROOT_SALT, &base, &mut out);
                out
            }
        }
    }

    fn encode_bytes(&self) -> Vec<u8> {
        let mut w = talkrypt_wire::Writer::new();
        w.put_u32(self.version as u32);
        w.put_u8(self.topology.tag());
        w.put_u8(self.persistence.tag());
        w.put_bytes(self.suite_id.as_bytes());
        w.put_bytes(&self.suite_params);
        w.put_u32(self.endpoints.len() as u32);
        for e in &self.endpoints {
            w.put_bytes(e.as_bytes());
        }
        w.put_bytes(&self.invite_token);
        w.put_bytes(self.channel.as_bytes());
        w.put_u8(self.group as u8);
        crate::marking::put_opt(&mut w, &self.channel_marking);
        w.into_vec()
    }

    fn decode_bytes(bytes: &[u8]) -> Result<Self> {
        let mut r = talkrypt_wire::Reader::new(bytes);
        let version = r.get_u32()? as u16;
        if version != DESCRIPTOR_VERSION {
            return Err(CoreError::UnsupportedVersion(version));
        }
        let topology = TopologyKind::from_tag(r.get_u8()?)?;
        let persistence = Persistence::from_tag(r.get_u8()?)?;
        let suite_id = string(r.get_bytes()?)?;
        let suite_params = r.get_vec()?;
        let n = r.get_u32()? as usize;
        if n > 1024 {
            return Err(CoreError::Malformed("too many endpoints"));
        }
        let mut endpoints = Vec::with_capacity(n);
        for _ in 0..n {
            endpoints.push(string(r.get_bytes()?)?);
        }
        let invite_token = r.get_vec()?;
        let channel = string(r.get_bytes()?)?;
        let group = r.get_u8()? != 0;
        let channel_marking = crate::marking::get_opt(&mut r)?;
        r.finish()
            .map_err(|_| CoreError::Malformed("trailing descriptor bytes"))?;
        Ok(Self {
            version,
            topology,
            persistence,
            suite_id,
            suite_params,
            endpoints,
            invite_token,
            channel,
            group,
            channel_marking,
            // The password is out-of-band; a parsed invite never carries it.
            password: None,
        })
    }

    /// Encode to a `talkrypt://<base32>` URI.
    pub fn to_uri(&self) -> String {
        format!("{}{}", URI_SCHEME, b32::encode(&self.encode_bytes()))
    }

    /// Parse a `talkrypt://` URI back into a descriptor.
    pub fn from_uri(uri: &str) -> Result<Self> {
        let body = uri
            .strip_prefix(URI_SCHEME)
            .ok_or(CoreError::Malformed("missing talkrypt:// scheme"))?;
        let bytes = b32::decode(body.trim()).ok_or(CoreError::Malformed("bad base32"))?;
        Self::decode_bytes(&bytes)
    }
}

fn string(b: &[u8]) -> Result<String> {
    String::from_utf8(b.to_vec()).map_err(|_| CoreError::Malformed("invalid utf-8"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> ChatDescriptor {
        ChatDescriptor::new(
            TopologyKind::Hub,
            Persistence::Persistent,
            talkrypt_crypto::DEFAULT_SUITE_ID,
            vec!["abcdefghij.onion".into()],
            "#general",
        )
    }

    #[test]
    fn uri_roundtrip() {
        let d = sample();
        let uri = d.to_uri();
        assert!(uri.starts_with(URI_SCHEME));
        let d2 = ChatDescriptor::from_uri(&uri).unwrap();
        assert_eq!(d, d2);
    }

    #[test]
    fn both_sides_derive_same_root() {
        let d = sample();
        let d2 = ChatDescriptor::from_uri(&d.to_uri()).unwrap();
        assert_eq!(d.derive_root(), d2.derive_root());
    }

    #[test]
    fn different_tokens_give_different_roots() {
        let a = sample();
        let b = sample(); // fresh random invite token
        assert_ne!(a.invite_token, b.invite_token);
        assert_ne!(a.derive_root(), b.derive_root());
    }

    #[test]
    fn invite_token_is_32_bytes() {
        assert_eq!(sample().invite_token.len(), 32);
    }

    #[test]
    fn blank_suite_id_resolves_to_default() {
        let mut d = sample();
        d.suite_id = String::new();
        assert_eq!(d.resolved_suite_id(), talkrypt_crypto::DEFAULT_SUITE_ID);
        // A blank-posture invite and an explicit-default invite derive the same
        // root (so they interoperate) and share a scheme fingerprint.
        let mut explicit = d.clone();
        explicit.suite_id = talkrypt_crypto::DEFAULT_SUITE_ID.to_string();
        assert_eq!(d.derive_root(), explicit.derive_root());
        assert_eq!(d.scheme_hash(), explicit.scheme_hash());
    }

    #[test]
    fn distinct_postures_have_distinct_scheme_hashes_and_roots() {
        let mut hybrid = sample();
        hybrid.suite_id = talkrypt_crypto::dr_suite_id(talkrypt_crypto::KemProfile::hybrid());
        let mut pure = hybrid.clone();
        pure.suite_id = talkrypt_crypto::dr_suite_id(talkrypt_crypto::KemProfile::pq_pure());
        // Same invite token, different posture → different fingerprint and a
        // different root, so a posture mismatch fails closed.
        assert_ne!(hybrid.scheme_hash(), pure.scheme_hash());
        assert_ne!(hybrid.derive_root(), pure.derive_root());
    }

    #[test]
    fn password_gates_the_root_and_must_match() {
        let base = sample();
        // Same invite token; only the password differs.
        let no_pw = base.clone();
        let pw = base.clone().with_password(Some(ChannelPassword::new("hunter2")));
        // Invite-only (no password) derives a DIFFERENT root than the gated one,
        // so leaking the URI without the password doesn't grant access.
        assert_ne!(no_pw.derive_root(), pw.derive_root());
        // Matching password on both sides → same root (they can talk).
        let pw2 = base.clone().with_password(Some(ChannelPassword::new("hunter2")));
        assert_eq!(pw.derive_root(), pw2.derive_root());
        // Wrong password → different root → handshake fails closed.
        let wrong = base.with_password(Some(ChannelPassword::new("nope")));
        assert_ne!(pw.derive_root(), wrong.derive_root());
    }

    #[test]
    fn password_is_never_serialized_into_the_uri() {
        let d = sample().with_password(Some(ChannelPassword::new("topsecret")));
        let uri = d.to_uri();
        let parsed = ChatDescriptor::from_uri(&uri).unwrap();
        // The URI carries no password — a recipient must obtain it out of band.
        assert!(parsed.password.is_none());
        // And so the URI-only parse derives the *unprotected* base root, which
        // differs from the password-gated root.
        assert_ne!(parsed.derive_root(), d.derive_root());
    }

    #[test]
    fn password_debug_is_redacted() {
        let p = ChannelPassword::new("supersecret");
        assert!(!format!("{p:?}").contains("supersecret"));
    }

    #[test]
    fn bad_uri_rejected() {
        assert!(ChatDescriptor::from_uri("http://nope").is_err());
        assert!(ChatDescriptor::from_uri("talkrypt://!!!").is_err());
    }

    #[test]
    fn all_topologies_roundtrip() {
        for topo in [TopologyKind::P2P, TopologyKind::Hub, TopologyKind::Hybrid] {
            let mut d = sample();
            d.topology = topo;
            let d2 = ChatDescriptor::from_uri(&d.to_uri()).unwrap();
            assert_eq!(d2.topology, topo);
        }
    }
}

#[cfg(test)]
mod kat {
    use super::*;

    /// Known-answer vector locking the descriptor wire format (talkrypt-mlspq
    /// wire v1). A canonical descriptor with fixed fields must always produce
    /// this exact `talkrypt://` URI; any change to the field order, tags, or
    /// base32 encoding breaks it.
    #[test]
    fn descriptor_uri_kat() {
        let d = ChatDescriptor {
            version: 1,
            topology: TopologyKind::P2P,
            persistence: Persistence::Ephemeral,
            suite_id: "tk.dr.kat".to_string(),
            suite_params: vec![],
            endpoints: vec![],
            invite_token: vec![0u8; 32],
            channel: "#kat".to_string(),
            group: false,
            channel_marking: None,
            password: None,
        };
        assert_eq!(
            d.to_uri(),
            "talkrypt://aaaaaaiaaaaaaaajorvs4zdsfzvwc5aaaaaaaaaaaaaaaaaaeaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaccg23boqaaa"
        );
        // And it must round-trip back to the same descriptor.
        assert_eq!(ChatDescriptor::from_uri(&d.to_uri()).unwrap(), d);
    }
}
