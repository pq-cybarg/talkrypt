//! Friends + account resolution for live sessions.
//!
//! A **friend** is a *pinned account key* (ML-DSA-87). When a peer presents an
//! [`IdentityChain`] for the device key it just authenticated in the handshake,
//! we (1) bind the chain's leaf to that authenticated device and (2) check the
//! chain's account root against the [`FriendStore`]. Forging a chain that roots
//! at a pinned account needs that account's ML-DSA private key, which is
//! post-quantum-unforgeable — so an impersonator can never resolve as a friend.
//! See `docs/identity-accounts.md` and `talkrypt_crypto::account`.
//!
//! Everything here is pure post-quantum (ML-DSA-87 chains, SHA3-384
//! fingerprints); elliptic curve is never load-bearing.
//!
//! ## Security of the presentation
//!
//! The presentation is **never** sent in the plaintext handshake. It rides as
//! the first frame *inside* the established ratchet/Noise session — so the
//! account↔device linkage (sensitive: it deanonymizes which devices belong to
//! which account) is AEAD-protected and forward-secret like any chat message.
//! A pseudonym simply presents nothing.

use talkrypt_crypto::{CryptoError, IdentityChain, IdentityPublic, FINGERPRINT_LEN};
use talkrypt_wire::{Reader, Writer};

use crate::error::Result;

/// What a peer sends to claim "this authenticated device belongs to my account"
/// — the account→…→device certificate chain, plus an optional self-asserted
/// username (display convenience; the *account key* is the cryptographic id).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Presentation {
    pub chain: IdentityChain,
    pub username: Option<String>,
}

impl Presentation {
    /// A linked presentation: certify this device under an account.
    pub fn new(chain: IdentityChain, username: Option<String>) -> Self {
        Self { chain, username }
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.put_bytes(&self.chain.encode());
        match &self.username {
            Some(u) => {
                w.put_u8(1);
                w.put_bytes(u.as_bytes());
            }
            None => w.put_u8(0),
        }
        w.into_vec()
    }

    pub fn decode(bytes: &[u8]) -> Result<Presentation> {
        let mut r = Reader::new(bytes);
        let chain = IdentityChain::decode(r.get_bytes()?)?;
        let username = match r.get_u8()? {
            0 => None,
            1 => Some(
                String::from_utf8(r.get_vec()?)
                    .map_err(|_| CryptoError::Malformed("username utf-8"))?,
            ),
            _ => return Err(CryptoError::Malformed("presentation username tag").into()),
        };
        r.finish().map_err(|_| CryptoError::Malformed("presentation trailing bytes"))?;
        Ok(Presentation { chain, username })
    }
}

/// A pinned friend: an account public key plus a remembered username.
#[derive(Clone, Debug)]
pub struct Friend {
    pub account: IdentityPublic,
    pub account_fingerprint: [u8; FINGERPRINT_LEN],
    pub username: Option<String>,
}

/// The set of accounts the user has friended (pinned). Pinning is the trust
/// decision; everything downstream is pure verification against these keys.
#[derive(Clone, Debug, Default)]
pub struct FriendStore {
    friends: Vec<Friend>,
}

impl FriendStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Pin (or update the username of) a friend by account key. Pinning the same
    /// account twice replaces the stored username rather than duplicating.
    pub fn pin(&mut self, account: IdentityPublic, username: Option<String>) {
        let fp = account.fingerprint();
        if let Some(existing) = self.friends.iter_mut().find(|f| f.account == account) {
            existing.username = username;
            return;
        }
        self.friends.push(Friend {
            account,
            account_fingerprint: fp,
            username,
        });
    }

    /// Is this account a pinned friend?
    pub fn is_pinned(&self, account: &IdentityPublic) -> bool {
        self.friends.iter().any(|f| &f.account == account)
    }

    /// The pinned friend for an account, if any.
    pub fn get(&self, account: &IdentityPublic) -> Option<&Friend> {
        self.friends.iter().find(|f| &f.account == account)
    }

    pub fn len(&self) -> usize {
        self.friends.len()
    }

    pub fn is_empty(&self) -> bool {
        self.friends.is_empty()
    }

    /// Iterate the pinned friends.
    pub fn iter(&self) -> impl Iterator<Item = &Friend> {
        self.friends.iter()
    }
}

/// The outcome of resolving a peer's presented [`IdentityChain`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Resolved {
    /// The account key the (internally-valid) chain roots at.
    pub account: IdentityPublic,
    pub account_fingerprint: [u8; FINGERPRINT_LEN],
    /// The leaf (device) fingerprint, equal to the authenticated peer.
    pub leaf_fingerprint: [u8; FINGERPRINT_LEN],
    /// Whether `account` is a pinned friend.
    pub friend: bool,
}

/// Resolve a presented chain to an account, binding it to the **already
/// authenticated** device (`peer_fp`).
///
/// Returns `None` (reject) unless ALL hold:
/// 1. the chain ends at a leaf whose fingerprint equals `peer_fp` — so the
///    chain describes *this* peer's authenticated device, not some other key;
/// 2. the chain is internally valid at `now` — rooted at its account, every
///    link signed by its issuer, properly chained, and unexpired.
///
/// `friend` is then `true` iff that account is pinned in `store`. Because (2)
/// requires the account's signature over the device cert, a `friend == true`
/// result is unforgeable without the friend's account private key.
pub fn resolve_chain(
    store: &FriendStore,
    chain: &IdentityChain,
    peer_fp: [u8; FINGERPRINT_LEN],
    now: u64,
) -> Option<Resolved> {
    let leaf = chain.leaf()?;
    let leaf_fingerprint = leaf.fingerprint();
    // (1) Bind: the chain must describe the device we authenticated. Without
    // this, anyone could replay a friend's real chain over their own session.
    if leaf_fingerprint != peer_fp {
        return None;
    }
    // The account is the chain's root issuer.
    let account = chain.links.first()?.issuer.clone();
    // (2) The chain must be internally valid and end at this leaf.
    chain.verify(&account, leaf, now).ok()?;
    let account_fingerprint = account.fingerprint();
    let friend = store.is_pinned(&account);
    Some(Resolved {
        account,
        account_fingerprint,
        leaf_fingerprint,
        friend,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use talkrypt_crypto::IdentityKeyPair;

    const NOW: u64 = 1_700_000_000;

    // Helper: an account that certifies a device, returning (account, device, chain).
    fn linked() -> (IdentityKeyPair, IdentityKeyPair, IdentityChain) {
        let account = IdentityKeyPair::generate();
        let device = IdentityKeyPair::generate();
        let chain =
            IdentityChain::device(&account, device.public(), "device:phone", NOW - 10, NOW + 1000);
        (account, device, chain)
    }

    #[test]
    fn pinned_friend_resolves_as_friend() {
        let (account, device, chain) = linked();
        let mut store = FriendStore::new();
        store.pin(account.public().clone(), Some("alice".into()));

        let res = resolve_chain(&store, &chain, device.public().fingerprint(), NOW).unwrap();
        assert!(res.friend);
        assert_eq!(res.account_fingerprint, account.public().fingerprint());
        assert_eq!(res.leaf_fingerprint, device.public().fingerprint());
    }

    #[test]
    fn unpinned_account_resolves_but_is_not_friend() {
        let (_account, device, chain) = linked();
        let store = FriendStore::new(); // nobody pinned
        let res = resolve_chain(&store, &chain, device.public().fingerprint(), NOW).unwrap();
        assert!(!res.friend, "valid chain, but account isn't a friend");
    }

    #[test]
    fn chain_not_bound_to_peer_is_rejected() {
        // Alice's real chain, replayed by Mallory over Mallory's session: the
        // leaf fingerprint won't match Mallory's authenticated device fp.
        let (account, _device, chain) = linked();
        let mut store = FriendStore::new();
        store.pin(account.public().clone(), Some("alice".into()));

        let mallory = IdentityKeyPair::generate();
        assert!(resolve_chain(&store, &chain, mallory.public().fingerprint(), NOW).is_none());
    }

    #[test]
    fn impostor_chain_does_not_resolve_as_pinned_friend() {
        // Mallory mints a chain for HIS own device under HIS own account, but
        // claims to be Alice. He controls his device, so the binding passes —
        // but his account isn't pinned as Alice, so friend == false. He can
        // never produce friend == true for Alice without Alice's account key.
        let alice = IdentityKeyPair::generate();
        let mut store = FriendStore::new();
        store.pin(alice.public().clone(), Some("alice".into()));

        let mallory_acct = IdentityKeyPair::generate();
        let mallory_dev = IdentityKeyPair::generate();
        let fake =
            IdentityChain::device(&mallory_acct, mallory_dev.public(), "device", NOW - 1, NOW + 1);
        let res = resolve_chain(&store, &fake, mallory_dev.public().fingerprint(), NOW).unwrap();
        assert!(!res.friend, "impostor must not resolve as the pinned friend");
        assert_ne!(res.account_fingerprint, alice.public().fingerprint());
    }

    #[test]
    fn expired_chain_is_rejected() {
        let account = IdentityKeyPair::generate();
        let device = IdentityKeyPair::generate();
        let chain = IdentityChain::device(&account, device.public(), "device", 0, NOW - 1);
        let mut store = FriendStore::new();
        store.pin(account.public().clone(), None);
        assert!(resolve_chain(&store, &chain, device.public().fingerprint(), NOW).is_none());
    }

    #[test]
    fn presentation_wire_roundtrip_with_and_without_username() {
        let (_a, _d, chain) = linked();
        let p = Presentation::new(chain.clone(), Some("alice".into()));
        let decoded = Presentation::decode(&p.encode()).unwrap();
        assert_eq!(decoded, p);

        let bare = Presentation::new(chain, None);
        let decoded_bare = Presentation::decode(&bare.encode()).unwrap();
        assert_eq!(decoded_bare, bare);
        assert!(decoded_bare.username.is_none());
    }

    #[test]
    fn pin_updates_username_without_duplicating() {
        let account = IdentityKeyPair::generate();
        let mut store = FriendStore::new();
        store.pin(account.public().clone(), Some("old".into()));
        store.pin(account.public().clone(), Some("new".into()));
        assert_eq!(store.len(), 1);
        assert_eq!(store.get(account.public()).unwrap().username.as_deref(), Some("new"));
    }

    #[test]
    fn segmented_leaf_binds_and_resolves() {
        // account → device → segment: the segment leaf is what authenticates.
        let account = IdentityKeyPair::generate();
        let device = IdentityKeyPair::generate();
        let segment = IdentityKeyPair::generate();
        let chain = IdentityChain::device(&account, device.public(), "device:laptop", NOW - 5, 0)
            .extend(&device, segment.public(), "segment:work", NOW - 5, 0);
        let mut store = FriendStore::new();
        store.pin(account.public().clone(), None);
        let res = resolve_chain(&store, &chain, segment.public().fingerprint(), NOW).unwrap();
        assert!(res.friend);
        assert_eq!(res.leaf_fingerprint, segment.public().fingerprint());
    }
}
