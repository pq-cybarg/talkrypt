//! Account identity — an **account key certifies device/segment keys** via an
//! ML-DSA-87 certificate chain (a *signature tree*). This is the cryptographic
//! core for: username accounts, **friending** (impersonation-proof), **opt-in**
//! multi-device linking, **segmented** on-device identities, and pseudonyms.
//! Everything here is ML-DSA-87 — no elliptic curve. See `docs/identity-accounts.md`.
//!
//! Keys at every layer are just an [`IdentityKeyPair`] (the existing ML-DSA-87
//! identity). An **account** key signs a [`Cert`] for each **device** key; a
//! device key may in turn sign certs for **segment** keys, forming a tree:
//!
//! ```text
//!   account ──cert──► device ──cert──► segment   (a 2-link chain to a segment)
//!           └─cert──► device2                     (another device)
//! ```
//!
//! An [`IdentityChain`] is a path from the account root to a leaf. Verifying it
//! against a *pinned* account key proves the leaf legitimately belongs to that
//! account — and forging such a chain needs the account's ML-DSA private key,
//! which is post-quantum-unforgeable, so a friended account cannot be spoofed.
//!
//! A **pseudonym** is simply a leaf key presented with *no* chain; a **rotating**
//! identity is a fresh uncertified key per conversation. Both fall out of "the
//! chain is optional" — and neither can ever *claim* a friended account, because
//! claiming account A still requires a chain rooting at A.

use crate::error::{CryptoError, Result};
use crate::identity::{IdentityKeyPair, IdentityPublic};

fn put_pub(w: &mut talkrypt_wire::Writer, p: &IdentityPublic) {
    w.put_bytes(&p.sig_vk);
}
fn get_pub(r: &mut talkrypt_wire::Reader) -> Result<IdentityPublic> {
    Ok(IdentityPublic {
        sig_vk: r.get_vec()?,
    })
}
fn put_u64(w: &mut talkrypt_wire::Writer, v: u64) {
    w.put_bytes(&v.to_be_bytes());
}
fn get_u64(r: &mut talkrypt_wire::Reader) -> Result<u64> {
    let b = r.get_bytes()?;
    if b.len() != 8 {
        return Err(CryptoError::Malformed("u64 length"));
    }
    let mut a = [0u8; 8];
    a.copy_from_slice(b);
    Ok(u64::from_be_bytes(a))
}

/// The certified facts about a subject key (the bytes an issuer signs).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Cert {
    /// The key being certified (a device or segment key).
    pub subject: IdentityPublic,
    /// Human label, e.g. `device:phone` or `segment:work`.
    pub label: String,
    /// Unix seconds the cert is valid from (caller-supplied; crypto has no clock).
    pub valid_from: u64,
    /// Unix-seconds expiry; `0` means no expiry.
    pub expiry: u64,
}

impl Cert {
    fn encode(&self) -> Vec<u8> {
        let mut w = talkrypt_wire::Writer::new();
        put_pub(&mut w, &self.subject);
        w.put_bytes(self.label.as_bytes());
        put_u64(&mut w, self.valid_from);
        put_u64(&mut w, self.expiry);
        w.into_vec()
    }
    fn read(r: &mut talkrypt_wire::Reader) -> Result<Cert> {
        let subject = get_pub(r)?;
        let label = String::from_utf8(r.get_vec()?)
            .map_err(|_| CryptoError::Malformed("cert label utf-8"))?;
        let valid_from = get_u64(r)?;
        let expiry = get_u64(r)?;
        Ok(Cert {
            subject,
            label,
            valid_from,
            expiry,
        })
    }
    fn valid_at(&self, now: u64) -> bool {
        now >= self.valid_from && (self.expiry == 0 || now <= self.expiry)
    }
}

/// A [`Cert`] signed by its **issuer** (the parent key in the tree).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedCert {
    pub issuer: IdentityPublic,
    pub cert: Cert,
    pub sig: Vec<u8>,
}

impl SignedCert {
    /// `issuer` certifies `subject` with `label` and validity window.
    pub fn issue(
        issuer: &IdentityKeyPair,
        subject: &IdentityPublic,
        label: impl Into<String>,
        valid_from: u64,
        expiry: u64,
    ) -> SignedCert {
        let cert = Cert {
            subject: subject.clone(),
            label: label.into(),
            valid_from,
            expiry,
        };
        let sig = issuer.sign(&cert.encode());
        SignedCert {
            issuer: issuer.public().clone(),
            cert,
            sig,
        }
    }

    /// Verify the issuer's signature over the cert (does NOT check chaining).
    pub fn verify_signature(&self) -> Result<()> {
        self.issuer.verify(&self.cert.encode(), &self.sig)
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut w = talkrypt_wire::Writer::new();
        put_pub(&mut w, &self.issuer);
        w.put_bytes(&self.cert.encode());
        w.put_bytes(&self.sig);
        w.into_vec()
    }
    fn read(r: &mut talkrypt_wire::Reader) -> Result<SignedCert> {
        let issuer = get_pub(r)?;
        let mut cr = talkrypt_wire::Reader::new(r.get_bytes()?);
        let cert = Cert::read(&mut cr)?;
        cr.finish()?;
        let sig = r.get_vec()?;
        Ok(SignedCert { issuer, cert, sig })
    }
}

/// A path of certs from the account root to a leaf key (a device, or a segment
/// under a device). One link = a directly-certified device; two = a segment.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct IdentityChain {
    pub links: Vec<SignedCert>,
}

impl IdentityChain {
    /// A single account→device chain.
    pub fn device(account: &IdentityKeyPair, device: &IdentityPublic, label: impl Into<String>, valid_from: u64, expiry: u64) -> IdentityChain {
        IdentityChain {
            links: vec![SignedCert::issue(account, device, label, valid_from, expiry)],
        }
    }

    /// Extend this chain by having its current leaf's keypair certify a sub-key
    /// (e.g. a device certifying a segment). `leaf_kp` must own the current leaf.
    pub fn extend(&self, leaf_kp: &IdentityKeyPair, sub: &IdentityPublic, label: impl Into<String>, valid_from: u64, expiry: u64) -> IdentityChain {
        let mut links = self.links.clone();
        links.push(SignedCert::issue(leaf_kp, sub, label, valid_from, expiry));
        IdentityChain { links }
    }

    /// The leaf (certified) key this chain ends at.
    pub fn leaf(&self) -> Option<&IdentityPublic> {
        self.links.last().map(|l| &l.cert.subject)
    }

    /// Verify the chain **roots at `account`**, every link is validly signed by
    /// its issuer, each issuer equals the previous link's subject, every link is
    /// within its validity at `now`, and it ends at `leaf`. `Ok` ⇒ `leaf`
    /// legitimately belongs to `account` (the impersonation-proof check).
    pub fn verify(&self, account: &IdentityPublic, leaf: &IdentityPublic, now: u64) -> Result<()> {
        if self.links.is_empty() {
            return Err(CryptoError::Malformed("empty identity chain"));
        }
        if &self.links[0].issuer != account {
            return Err(CryptoError::BadSignature); // not rooted at the pinned account
        }
        for (i, link) in self.links.iter().enumerate() {
            link.verify_signature()?;
            if !link.cert.valid_at(now) {
                return Err(CryptoError::BadSignature); // expired / not yet valid
            }
            if i > 0 && link.issuer != self.links[i - 1].cert.subject {
                return Err(CryptoError::BadSignature); // broken chaining
            }
        }
        if self.leaf() != Some(leaf) {
            return Err(CryptoError::BadSignature); // chain doesn't end at this key
        }
        Ok(())
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut w = talkrypt_wire::Writer::new();
        w.put_u32(self.links.len() as u32);
        for l in &self.links {
            w.put_bytes(&l.encode());
        }
        w.into_vec()
    }
    pub fn decode(bytes: &[u8]) -> Result<IdentityChain> {
        let mut r = talkrypt_wire::Reader::new(bytes);
        let n = r.get_u32()?;
        if n > 16 {
            return Err(CryptoError::Malformed("identity chain too long"));
        }
        let mut links = Vec::with_capacity(n as usize);
        for _ in 0..n {
            let mut lr = talkrypt_wire::Reader::new(r.get_bytes()?);
            links.push(SignedCert::read(&mut lr)?);
            lr.finish()?;
        }
        r.finish()?;
        Ok(IdentityChain { links })
    }
}

/// Friend check: is `leaf` a legitimate device/segment of the **pinned**
/// `account` at time `now`? Forging a yes needs the account's ML-DSA private key.
pub fn belongs_to_account(account: &IdentityPublic, chain: &IdentityChain, leaf: &IdentityPublic, now: u64) -> bool {
    chain.verify(account, leaf, now).is_ok()
}

// ----- registry: username → account, self-signed, cross-compared -----

/// An account's self-signed claim that it owns a username (served by a
/// registry). The signature is by the **account** key, so a registry cannot
/// fabricate a binding to a key it doesn't control.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UsernameClaim {
    pub username: String,
    pub account: IdentityPublic,
    pub issued: u64,
}

impl UsernameClaim {
    fn encode_signed(&self) -> Vec<u8> {
        let mut w = talkrypt_wire::Writer::new();
        w.put_bytes(self.username.as_bytes());
        put_pub(&mut w, &self.account);
        put_u64(&mut w, self.issued);
        w.into_vec()
    }
    fn read(r: &mut talkrypt_wire::Reader) -> Result<UsernameClaim> {
        let username = String::from_utf8(r.get_vec()?)
            .map_err(|_| CryptoError::Malformed("username utf-8"))?;
        let account = get_pub(r)?;
        let issued = get_u64(r)?;
        Ok(UsernameClaim {
            username,
            account,
            issued,
        })
    }
}

/// A [`UsernameClaim`] signed by the account key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedClaim {
    pub claim: UsernameClaim,
    pub sig: Vec<u8>,
}

impl SignedClaim {
    pub fn issue(account: &IdentityKeyPair, username: impl Into<String>, issued: u64) -> SignedClaim {
        let claim = UsernameClaim {
            username: username.into(),
            account: account.public().clone(),
            issued,
        };
        let sig = account.sign(&claim.encode_signed());
        SignedClaim { claim, sig }
    }
    pub fn verify(&self) -> Result<()> {
        self.claim.account.verify(&self.claim.encode_signed(), &self.sig)
    }

    /// Wire-encode the full signed claim (claim fields + account signature) for
    /// transmission to/from a registry.
    pub fn encode(&self) -> Vec<u8> {
        let mut w = talkrypt_wire::Writer::new();
        w.put_bytes(&self.claim.encode_signed());
        w.put_bytes(&self.sig);
        w.into_vec()
    }
    pub fn decode(bytes: &[u8]) -> Result<SignedClaim> {
        let mut r = talkrypt_wire::Reader::new(bytes);
        let mut cr = talkrypt_wire::Reader::new(r.get_bytes()?);
        let claim = UsernameClaim::read(&mut cr)?;
        cr.finish()?;
        let sig = r.get_vec()?;
        r.finish()?;
        Ok(SignedClaim { claim, sig })
    }
}

/// **Cross-compare** claims for `username` from several independent registries.
/// Returns the account key only if *every* claim is validly self-signed, names
/// the same `username`, and agrees on the same account key — so no single
/// (possibly hostile) registry can substitute a different key, and redundancy
/// across hosts defends against any one being attacked. Any disagreement, bad
/// signature, or wrong username ⇒ `None`.
pub fn cross_compare(username: &str, claims: &[SignedClaim]) -> Option<IdentityPublic> {
    let first = claims.first()?;
    let account = &first.claim.account;
    for c in claims {
        if c.claim.username != username {
            return None;
        }
        if c.verify().is_err() {
            return None;
        }
        if &c.claim.account != account {
            return None; // equivocation between registries
        }
    }
    Some(account.clone())
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: u64 = 1_700_000_000;

    #[test]
    fn device_cert_proves_account_membership() {
        let account = IdentityKeyPair::generate();
        let device = IdentityKeyPair::generate();
        let chain = IdentityChain::device(&account, device.public(), "device:phone", 0, 0);

        assert!(belongs_to_account(account.public(), &chain, device.public(), NOW));
        // the leaf is the device key
        assert_eq!(chain.leaf(), Some(device.public()));
    }

    #[test]
    fn impostor_account_cannot_forge_membership() {
        let account = IdentityKeyPair::generate();
        let impostor = IdentityKeyPair::generate();
        let device = IdentityKeyPair::generate();
        // Impostor certifies the device under ITS key.
        let fake = IdentityChain::device(&impostor, device.public(), "device:phone", 0, 0);
        // Pinned to the real account, the fake chain does NOT verify.
        assert!(!belongs_to_account(account.public(), &fake, device.public(), NOW));
        // And a chain can't be re-rooted at the real account without its key.
        assert!(fake.verify(account.public(), device.public(), NOW).is_err());
    }

    #[test]
    fn segmented_tree_account_device_segment() {
        let account = IdentityKeyPair::generate();
        let device = IdentityKeyPair::generate();
        let segment = IdentityKeyPair::generate();
        // account → device → segment
        let chain = IdentityChain::device(&account, device.public(), "device:laptop", 0, 0)
            .extend(&device, segment.public(), "segment:work", 0, 0);
        assert_eq!(chain.links.len(), 2);
        assert_eq!(chain.leaf(), Some(segment.public()));
        // The segment legitimately belongs to the account.
        assert!(belongs_to_account(account.public(), &chain, segment.public(), NOW));
        // But presenting the segment as if it were the DEVICE key fails.
        assert!(!belongs_to_account(account.public(), &chain, device.public(), NOW));
    }

    #[test]
    fn broken_chaining_is_rejected() {
        let account = IdentityKeyPair::generate();
        let device = IdentityKeyPair::generate();
        let other = IdentityKeyPair::generate();
        let segment = IdentityKeyPair::generate();
        // Splice: account→device, but the 2nd link is issued by `other`, not device.
        let mut chain = IdentityChain::device(&account, device.public(), "device", 0, 0);
        chain.links.push(SignedCert::issue(&other, segment.public(), "segment", 0, 0));
        assert!(chain.verify(account.public(), segment.public(), NOW).is_err());
    }

    #[test]
    fn expired_cert_is_rejected() {
        let account = IdentityKeyPair::generate();
        let device = IdentityKeyPair::generate();
        let chain = IdentityChain::device(&account, device.public(), "device", 0, NOW - 1);
        assert!(chain.verify(account.public(), device.public(), NOW).is_err());
        // valid before expiry
        assert!(chain.verify(account.public(), device.public(), NOW - 100).is_ok());
    }

    #[test]
    fn tampered_cert_fails_signature() {
        let account = IdentityKeyPair::generate();
        let device = IdentityKeyPair::generate();
        let mut chain = IdentityChain::device(&account, device.public(), "device", 0, 0);
        chain.links[0].cert.label = "device:evil".into(); // not what was signed
        assert!(chain.verify(account.public(), device.public(), NOW).is_err());
    }

    #[test]
    fn chain_wire_roundtrip() {
        let account = IdentityKeyPair::generate();
        let device = IdentityKeyPair::generate();
        let segment = IdentityKeyPair::generate();
        // Non-zero, currently-valid windows to exercise timestamp encoding.
        let chain = IdentityChain::device(&account, device.public(), "device:laptop", NOW - 50, NOW + 1000)
            .extend(&device, segment.public(), "segment:work", NOW - 10, NOW + 500);
        let decoded = IdentityChain::decode(&chain.encode()).unwrap();
        assert_eq!(decoded, chain);
        assert!(belongs_to_account(account.public(), &decoded, segment.public(), NOW));
    }

    #[test]
    fn registry_cross_compare_agrees_and_detects_equivocation() {
        let account = IdentityKeyPair::generate();
        // Two registries serve the same self-signed claim → agree.
        let c1 = SignedClaim::issue(&account, "alice", NOW);
        let c2 = SignedClaim::issue(&account, "alice", NOW + 10);
        assert_eq!(cross_compare("alice", &[c1.clone(), c2]), Some(account.public().clone()));

        // A hostile registry substitutes a different account key → its claim
        // can't be validly self-signed by the real account, so cross-compare
        // rejects (returns None).
        let evil = IdentityKeyPair::generate();
        let forged = SignedClaim {
            claim: UsernameClaim { username: "alice".into(), account: evil.public().clone(), issued: NOW },
            sig: evil.sign(b"whatever"), // not over the canonical bytes / different key
        };
        assert_eq!(cross_compare("alice", &[c1.clone(), forged]), None);

        // Wrong username is rejected.
        let c3 = SignedClaim::issue(&account, "bob", NOW);
        assert_eq!(cross_compare("alice", &[c1, c3]), None);
    }

    #[test]
    fn signed_claim_wire_roundtrip_and_verifies() {
        let account = IdentityKeyPair::generate();
        let claim = SignedClaim::issue(&account, "alice", NOW);
        let decoded = SignedClaim::decode(&claim.encode()).unwrap();
        assert_eq!(decoded, claim);
        assert!(decoded.verify().is_ok());
        // A wire-decoded claim still cross-compares against a second registry's.
        let c2 = SignedClaim::issue(&account, "alice", NOW + 5);
        assert_eq!(
            cross_compare("alice", &[decoded, c2]),
            Some(account.public().clone())
        );
    }

    #[test]
    fn pseudonym_has_no_chain_and_cannot_claim_an_account() {
        // A pseudonym is just a bare key with no chain. An empty chain never
        // verifies against any account — so it can't impersonate a friend.
        let account = IdentityKeyPair::generate();
        let pseudonym = IdentityKeyPair::generate();
        let empty = IdentityChain::default();
        assert!(!belongs_to_account(account.public(), &empty, pseudonym.public(), NOW));
    }
}
