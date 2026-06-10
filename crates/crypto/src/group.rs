//! Sender-key group messaging (`tk.group.*`).
//!
//! Each member owns a **sender key** — a symmetric chain that ratchets forward
//! once per message (forward secrecy: spent message keys are unrecoverable).
//! A member broadcasts one ciphertext to the whole channel; every other member
//! decrypts it with that sender's chain. Sender keys are distributed to other
//! members over the pairwise PQ Double Ratchet sessions the engine already
//! maintains, so distribution inherits hybrid-PQ confidentiality.
//!
//! This is the sender-keys construction (as used by Signal groups), suitable
//! for the Hub topology. Full RFC 9420 **MLS** with TreeKEM continuous group
//! key agreement is the heavier alternative and remains future work; it would
//! register as its own `tk.mls.*` suite behind the same engine seams.

use std::collections::BTreeMap;

use rand::RngCore;
use zeroize::{Zeroize, Zeroizing};

use crate::aead::{open as aead_open, seal as aead_seal};
use crate::error::{CryptoError, Result};
use crate::kdf::{kdf_ck, kdf_mk, KEY_LEN};
use crate::ratchet::MAX_SKIP;

/// Identifier for a group member (its identity fingerprint).
pub type MemberId = [u8; 48];

/// The sending half of a member's sender key.
#[derive(Clone)]
pub struct SenderKey {
    chain: [u8; KEY_LEN],
    n: u32,
}

impl SenderKey {
    /// Create a fresh sender key; returns it plus the initial chain key to
    /// distribute (privately) to the other members.
    pub fn new() -> (SenderKey, [u8; KEY_LEN]) {
        let mut chain = [0u8; KEY_LEN];
        rand::rngs::OsRng.fill_bytes(&mut chain);
        (SenderKey { chain, n: 0 }, chain)
    }

    fn seal(&mut self, plaintext: &[u8], aad: &[u8]) -> Result<(u32, Vec<u8>)> {
        let (next, mk_seed) = kdf_ck(&self.chain); // both Zeroizing
        let (key, nonce) = kdf_mk(&mk_seed); // key: Zeroizing
        let ct = aead_seal(&key, &nonce, plaintext, aad)?;
        let n = self.n;
        self.chain = *next;
        self.n += 1;
        Ok((n, ct))
    }
}

/// Wipe a sender key's chain key on drop (sender-key forward secrecy is per
/// message; this clears the residual state too). SECURITY-AUDIT F-3.
impl Drop for SenderKey {
    fn drop(&mut self) {
        self.chain.zeroize();
    }
}

/// The receiving half for one member's sender key.
#[derive(Clone)]
pub struct SenderKeyReceiver {
    chain: [u8; KEY_LEN],
    n: u32,
    skipped: BTreeMap<u32, [u8; KEY_LEN]>,
}

impl SenderKeyReceiver {
    pub fn from_initial(chain: [u8; KEY_LEN]) -> Self {
        Self {
            chain,
            n: 0,
            skipped: BTreeMap::new(),
        }
    }

    fn open(&mut self, n: u32, ct: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
        if let Some(mk_seed) = self.skipped.get(&n).copied() {
            let mk_seed = Zeroizing::new(mk_seed);
            let (key, nonce) = kdf_mk(&mk_seed); // key: Zeroizing
            let pt = aead_open(&key, &nonce, ct, aad)?;
            self.skipped.remove(&n);
            return Ok(pt);
        }
        if n < self.n {
            return Err(CryptoError::DecryptionFailed); // replay / already consumed
        }
        if (n - self.n) as usize > MAX_SKIP {
            return Err(CryptoError::TooManySkipped(MAX_SKIP));
        }
        let mut chain = Zeroizing::new(self.chain);
        let mut idx = self.n;
        while idx < n {
            let (next, mk_seed) = kdf_ck(&chain); // both Zeroizing
            self.skipped.insert(idx, *mk_seed);
            chain = next;
            idx += 1;
        }
        let (next, mk_seed) = kdf_ck(&chain);
        let (key, nonce) = kdf_mk(&mk_seed); // key: Zeroizing
        let pt = aead_open(&key, &nonce, ct, aad)?;
        self.chain = *next;
        self.n = n + 1;
        Ok(pt)
    }
}

/// Wipe the receiver's chain key and any cached skipped message-key seeds on
/// drop. SECURITY-AUDIT F-3.
impl Drop for SenderKeyReceiver {
    fn drop(&mut self) {
        self.chain.zeroize();
        for seed in self.skipped.values_mut() {
            seed.zeroize();
        }
    }
}

/// A member's view of a group: its own sender key plus a receiver per peer.
pub struct GroupSession {
    own: SenderKey,
    receivers: BTreeMap<MemberId, SenderKeyReceiver>,
}

impl GroupSession {
    /// Start a group membership. Returns the session and the initial sender
    /// chain key to hand to other members (over their pairwise sessions).
    pub fn new() -> (GroupSession, [u8; KEY_LEN]) {
        let (own, initial) = SenderKey::new();
        (
            GroupSession {
                own,
                receivers: BTreeMap::new(),
            },
            initial,
        )
    }

    /// Register another member's distributed initial sender chain key.
    pub fn add_member(&mut self, member: MemberId, initial_chain: [u8; KEY_LEN]) {
        self.receivers
            .insert(member, SenderKeyReceiver::from_initial(initial_chain));
    }

    /// Seal a message to broadcast to the whole channel.
    pub fn seal(&mut self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let n_placeholder = self.own.n;
        let aad = aad_for(n_placeholder);
        let (n, ct) = self.own.seal(plaintext, &aad)?;
        let mut w = talkrypt_wire::Writer::new();
        w.put_u32(n);
        w.put_bytes(&ct);
        Ok(w.into_vec())
    }

    /// Open a broadcast message from `sender`.
    pub fn open(&mut self, sender: &MemberId, message: &[u8]) -> Result<Vec<u8>> {
        let mut r = talkrypt_wire::Reader::new(message);
        let n = r.get_u32()?;
        let ct = r.get_vec()?;
        r.finish()?;
        let aad = aad_for(n);
        let recv = self
            .receivers
            .get_mut(sender)
            .ok_or(CryptoError::Malformed("unknown group sender"))?;
        recv.open(n, &ct, &aad)
    }

    pub fn member_count(&self) -> usize {
        self.receivers.len()
    }
}

fn aad_for(n: u32) -> Vec<u8> {
    let mut w = talkrypt_wire::Writer::new();
    w.put_u32(n);
    w.into_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fp(b: u8) -> MemberId {
        [b; 48]
    }

    /// Build a 3-member group with all sender keys distributed.
    fn trio() -> (GroupSession, GroupSession, GroupSession) {
        let (mut a, a_key) = GroupSession::new();
        let (mut b, b_key) = GroupSession::new();
        let (mut c, c_key) = GroupSession::new();
        // Everyone learns everyone else's initial sender chain.
        a.add_member(fp(2), b_key);
        a.add_member(fp(3), c_key);
        b.add_member(fp(1), a_key);
        b.add_member(fp(3), c_key);
        c.add_member(fp(1), a_key);
        c.add_member(fp(2), b_key);
        (a, b, c)
    }

    #[test]
    fn broadcast_reaches_all_members() {
        let (mut a, mut b, mut c) = trio();
        let msg = a.seal(b"hello group").unwrap();
        assert_eq!(b.open(&fp(1), &msg).unwrap(), b"hello group");
        assert_eq!(c.open(&fp(1), &msg).unwrap(), b"hello group");
    }

    #[test]
    fn each_member_can_send() {
        let (mut a, mut b, mut c) = trio();
        let from_b = b.seal(b"from B").unwrap();
        assert_eq!(a.open(&fp(2), &from_b).unwrap(), b"from B");
        assert_eq!(c.open(&fp(2), &from_b).unwrap(), b"from B");
    }

    #[test]
    fn out_of_order_and_replay() {
        let (mut a, mut b, _c) = trio();
        let m0 = a.seal(b"0").unwrap();
        let m1 = a.seal(b"1").unwrap();
        let m2 = a.seal(b"2").unwrap();
        assert_eq!(b.open(&fp(1), &m2).unwrap(), b"2");
        assert_eq!(b.open(&fp(1), &m0).unwrap(), b"0");
        assert_eq!(b.open(&fp(1), &m1).unwrap(), b"1");
        // replay of m0 fails
        assert!(b.open(&fp(1), &m0).is_err());
    }

    #[test]
    fn unknown_sender_rejected() {
        let (mut a, _b, _c) = trio();
        let m = a.seal(b"x").unwrap();
        // a has no receiver for itself
        assert!(a.open(&fp(9), &m).is_err());
    }

    #[test]
    fn member_count_tracks_peers() {
        let (a, _b, _c) = trio();
        assert_eq!(a.member_count(), 2);
    }
}
