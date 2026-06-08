//! Contacts + account resolution for live sessions.
//!
//! Two ideas kept deliberately separate (see also the engine's access policy):
//!
//! - **Contact** — an account you *recognize*: you've pinned its key so a peer
//!   presenting it resolves to a known identity. Adding a contact is entirely
//!   **unilateral** — you can have someone as a contact without them having you,
//!   and it grants them nothing.
//! - **Friend** — just an *elevated label* on a contact (a closeness marker in
//!   your own view). Still unilateral; not mutual; not an access grant.
//!
//! Neither implies **access**. Letting an account into a channel/group is a
//! separate, unilateral grant (the engine's `AccessPolicy`) — nobody needs to be
//! a contact, a friend, or a mutual to be allowed in, and being a friend doesn't
//! auto-grant access.
//!
//! When a peer presents an [`IdentityChain`] for the device key it authenticated
//! in the handshake, we (1) bind the chain's leaf to that authenticated device
//! and (2) check the chain's account root against the [`ContactStore`]. Forging
//! a chain that roots at a recognized account needs that account's ML-DSA private
//! key, which is post-quantum-unforgeable — so an impostor can never resolve as a
//! known contact. See `docs/identity-accounts.md` and `talkrypt_crypto::account`.
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

/// A recognized account: its public key, a remembered name, and whether you've
/// elevated it to **friend**. Recognition is unilateral; the `friend` flag is
/// just your own label and is never sent to or required of the other party.
#[derive(Clone, Debug)]
pub struct Contact {
    pub account: IdentityPublic,
    pub account_fingerprint: [u8; FINGERPRINT_LEN],
    pub name: Option<String>,
    /// Your elevated label. Does **not** grant access (see `AccessPolicy`).
    pub friend: bool,
}

/// The set of accounts you recognize. Adding a contact is the recognition
/// decision; everything downstream is pure verification against these keys.
#[derive(Clone, Debug, Default)]
pub struct ContactStore {
    contacts: Vec<Contact>,
}

impl ContactStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Add (or update) a contact by account key. Re-adding the same account
    /// updates its name/friend label rather than duplicating.
    pub fn add(&mut self, account: IdentityPublic, name: Option<String>, friend: bool) {
        let fp = account.fingerprint();
        if let Some(existing) = self.contacts.iter_mut().find(|c| c.account == account) {
            existing.name = name;
            existing.friend = friend;
            return;
        }
        self.contacts.push(Contact {
            account,
            account_fingerprint: fp,
            name,
            friend,
        });
    }

    /// Set (or clear) the friend label on an existing contact. Returns whether a
    /// matching contact was found.
    pub fn set_friend(&mut self, account: &IdentityPublic, friend: bool) -> bool {
        if let Some(c) = self.contacts.iter_mut().find(|c| &c.account == account) {
            c.friend = friend;
            true
        } else {
            false
        }
    }

    /// Is this account a recognized contact?
    pub fn is_contact(&self, account: &IdentityPublic) -> bool {
        self.contacts.iter().any(|c| &c.account == account)
    }

    /// Is this account a contact you've labeled a friend?
    pub fn is_friend(&self, account: &IdentityPublic) -> bool {
        self.contacts
            .iter()
            .any(|c| &c.account == account && c.friend)
    }

    /// The contact for an account, if any.
    pub fn get(&self, account: &IdentityPublic) -> Option<&Contact> {
        self.contacts.iter().find(|c| &c.account == account)
    }

    pub fn len(&self) -> usize {
        self.contacts.len()
    }

    pub fn is_empty(&self) -> bool {
        self.contacts.is_empty()
    }

    /// Iterate the contacts.
    pub fn iter(&self) -> impl Iterator<Item = &Contact> {
        self.contacts.iter()
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
    /// Whether `account` is a recognized contact.
    pub contact: bool,
    /// Whether that contact is labeled a friend (implies `contact`).
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
/// `contact`/`friend` are then set from `store`. Because (2) requires the
/// account's signature over the device cert, a `contact == true` result is
/// unforgeable without that account's ML-DSA private key.
pub fn resolve_chain(
    store: &ContactStore,
    chain: &IdentityChain,
    peer_fp: [u8; FINGERPRINT_LEN],
    now: u64,
) -> Option<Resolved> {
    let leaf = chain.leaf()?;
    let leaf_fingerprint = leaf.fingerprint();
    // (1) Bind: the chain must describe the device we authenticated. Without
    // this, anyone could replay a contact's real chain over their own session.
    if leaf_fingerprint != peer_fp {
        return None;
    }
    // The account is the chain's root issuer.
    let account = chain.links.first()?.issuer.clone();
    // (2) The chain must be internally valid and end at this leaf.
    chain.verify(&account, leaf, now).ok()?;
    let account_fingerprint = account.fingerprint();
    let contact = store.is_contact(&account);
    let friend = store.is_friend(&account);
    Some(Resolved {
        account,
        account_fingerprint,
        leaf_fingerprint,
        contact,
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
    fn contact_resolves_as_contact_not_necessarily_friend() {
        let (account, device, chain) = linked();
        let mut store = ContactStore::new();
        store.add(account.public().clone(), Some("alice".into()), false);

        let res = resolve_chain(&store, &chain, device.public().fingerprint(), NOW).unwrap();
        assert!(res.contact, "recognized account is a contact");
        assert!(!res.friend, "but not elevated to friend");
        assert_eq!(res.account_fingerprint, account.public().fingerprint());
        assert_eq!(res.leaf_fingerprint, device.public().fingerprint());
    }

    #[test]
    fn friend_label_is_unilateral_and_separate() {
        let (account, device, chain) = linked();
        let mut store = ContactStore::new();
        store.add(account.public().clone(), Some("alice".into()), true);
        let res = resolve_chain(&store, &chain, device.public().fingerprint(), NOW).unwrap();
        assert!(res.contact && res.friend);
        // Clearing the friend label keeps them a contact.
        store.set_friend(account.public(), false);
        let res2 = resolve_chain(&store, &chain, device.public().fingerprint(), NOW).unwrap();
        assert!(res2.contact && !res2.friend);
    }

    #[test]
    fn unknown_account_resolves_but_is_not_a_contact() {
        let (_account, device, chain) = linked();
        let store = ContactStore::new(); // nobody recognized
        let res = resolve_chain(&store, &chain, device.public().fingerprint(), NOW).unwrap();
        assert!(!res.contact, "valid chain, but account isn't recognized");
        assert!(!res.friend);
    }

    #[test]
    fn chain_not_bound_to_peer_is_rejected() {
        // Alice's real chain, replayed by Mallory over Mallory's session: the
        // leaf fingerprint won't match Mallory's authenticated device fp.
        let (account, _device, chain) = linked();
        let mut store = ContactStore::new();
        store.add(account.public().clone(), Some("alice".into()), true);

        let mallory = IdentityKeyPair::generate();
        assert!(resolve_chain(&store, &chain, mallory.public().fingerprint(), NOW).is_none());
    }

    #[test]
    fn impostor_chain_does_not_resolve_as_known_contact() {
        // Mallory mints a chain for HIS own device under HIS own account, but
        // claims to be Alice. He controls his device, so the binding passes —
        // but his account isn't recognized as Alice, so contact == false. He can
        // never produce contact == true for Alice without Alice's account key.
        let alice = IdentityKeyPair::generate();
        let mut store = ContactStore::new();
        store.add(alice.public().clone(), Some("alice".into()), true);

        let mallory_acct = IdentityKeyPair::generate();
        let mallory_dev = IdentityKeyPair::generate();
        let fake =
            IdentityChain::device(&mallory_acct, mallory_dev.public(), "device", NOW - 1, NOW + 1);
        let res = resolve_chain(&store, &fake, mallory_dev.public().fingerprint(), NOW).unwrap();
        assert!(!res.contact, "impostor must not resolve as the known contact");
        assert_ne!(res.account_fingerprint, alice.public().fingerprint());
    }

    #[test]
    fn expired_chain_is_rejected() {
        let account = IdentityKeyPair::generate();
        let device = IdentityKeyPair::generate();
        // Expire beyond the clock-skew grace so it is unambiguously expired
        // (a cert expired within tolerance is intentionally still accepted).
        let chain = IdentityChain::device(
            &account,
            device.public(),
            "device",
            0,
            NOW - talkrypt_crypto::CLOCK_SKEW_TOLERANCE - 1,
        );
        let mut store = ContactStore::new();
        store.add(account.public().clone(), None, false);
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
    fn add_updates_without_duplicating() {
        let account = IdentityKeyPair::generate();
        let mut store = ContactStore::new();
        store.add(account.public().clone(), Some("old".into()), false);
        store.add(account.public().clone(), Some("new".into()), true);
        assert_eq!(store.len(), 1);
        let c = store.get(account.public()).unwrap();
        assert_eq!(c.name.as_deref(), Some("new"));
        assert!(c.friend);
    }

    #[test]
    fn segmented_leaf_binds_and_resolves() {
        // account → device → segment: the segment leaf is what authenticates.
        let account = IdentityKeyPair::generate();
        let device = IdentityKeyPair::generate();
        let segment = IdentityKeyPair::generate();
        let chain = IdentityChain::device(&account, device.public(), "device:laptop", NOW - 5, 0)
            .extend(&device, segment.public(), "segment:work", NOW - 5, 0);
        let mut store = ContactStore::new();
        store.add(account.public().clone(), None, false);
        let res = resolve_chain(&store, &chain, segment.public().fingerprint(), NOW).unwrap();
        assert!(res.contact);
        assert_eq!(res.leaf_fingerprint, segment.public().fingerprint());
    }
}
