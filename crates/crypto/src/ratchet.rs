//! Post-quantum Double Ratchet (posture-selectable).
//!
//! Structure follows the Signal Double Ratchet, but the asymmetric ("DH")
//! ratchet step is replaced by the posture-selectable primitive in
//! [`crate::hybrid`]: each step performs an ML-KEM-1024 encapsulation and,
//! under [`KemPosture::Hybrid`], additionally an X25519 DH. The ML-KEM
//! ciphertext travels in the message header. The posture (PQ-pure by default,
//! or hybrid) is fixed for the session by the chosen suite.
//!
//! Guarantees:
//!   * **Forward secrecy** — symmetric chain keys are one-way (HKDF), and
//!     message keys are deleted after use.
//!   * **Post-compromise recovery** — each asymmetric step injects fresh
//!     hybrid entropy, healing the session after a key compromise.
//!   * **Out-of-order delivery** — skipped message keys are cached (bounded by
//!     `MAX_SKIP`).
//!   * **No state corruption** — `decrypt` runs on a cloned state and commits
//!     only on success, so replays/forgeries cannot poison the ratchet.

use std::collections::BTreeMap;

use zeroize::{Zeroize, Zeroizing};

use crate::aead::{open as aead_open, seal as aead_seal};
use crate::error::{CryptoError, Result};
use crate::hybrid::{KemProfile, RatchetPublic, RatchetSecret};
use crate::kdf::{kdf_ck, kdf_mk, kdf_rk, KEY_LEN};

/// Maximum number of skipped message keys retained (per session). Bounds the
/// memory a peer can force us to allocate by claiming large message numbers.
pub const MAX_SKIP: usize = 1000;

/// Per-message header, authenticated as AEAD associated data.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Header {
    /// Sender's current sending-ratchet public key.
    ratchet_pub: RatchetPublic,
    /// ML-KEM ciphertext encapsulated to the receiver's current ratchet key.
    /// Meaningful only when `ratchet_pub` is new to the receiver.
    ct: Vec<u8>,
    /// Number of messages in the sender's previous sending chain.
    pn: u32,
    /// Message number within the sender's current sending chain.
    n: u32,
}

impl Header {
    fn encode(&self) -> Vec<u8> {
        let mut w = talkrypt_wire::Writer::new();
        w.put_bytes(&self.ratchet_pub.encode());
        w.put_bytes(&self.ct);
        w.put_u32(self.pn);
        w.put_u32(self.n);
        w.into_vec()
    }

    fn decode(profile: KemProfile, bytes: &[u8]) -> Result<Header> {
        let mut r = talkrypt_wire::Reader::new(bytes);
        let ratchet_pub = RatchetPublic::decode(profile, r.get_bytes()?)?;
        let ct = r.get_vec()?;
        let pn = r.get_u32()?;
        let n = r.get_u32()?;
        r.finish()?;
        Ok(Header {
            ratchet_pub,
            ct,
            pn,
            n,
        })
    }
}

/// A Double Ratchet session with one peer.
#[derive(Clone)]
pub struct Session {
    /// KEM profile (posture + wire padding), fixed by the suite for the session.
    profile: KemProfile,
    root: [u8; KEY_LEN],

    // Sending side.
    self_ratchet: Option<RatchetSecret>,
    self_ratchet_pub: Option<RatchetPublic>,
    self_send_ct: Vec<u8>,
    send_ck: Option<[u8; KEY_LEN]>,
    send_n: u32,
    prev_send_n: u32,

    // Receiving side.
    peer_ratchet: Option<RatchetPublic>,
    recv_ck: Option<[u8; KEY_LEN]>,
    recv_n: u32,
    need_send_ratchet: bool,

    /// Skipped message-key seeds, keyed by (sender ratchet pub bytes, n).
    skipped: BTreeMap<(Vec<u8>, u32), [u8; KEY_LEN]>,
}

/// Wipe the live symmetric secrets (root, both chain keys, and every cached
/// skipped message-key seed) when a session is dropped — including the transient
/// clones made for trial-decryption, whose drop wipes their copies too. The
/// asymmetric ratchet secret zeroizes itself (the X25519 half via dalek's
/// `ZeroizeOnDrop`). Closes SECURITY-AUDIT finding F-3 for the ratchet session.
impl Drop for Session {
    fn drop(&mut self) {
        self.root.zeroize();
        if let Some(ck) = self.send_ck.as_mut() {
            ck.zeroize();
        }
        if let Some(ck) = self.recv_ck.as_mut() {
            ck.zeroize();
        }
        for seed in self.skipped.values_mut() {
            seed.zeroize();
        }
    }
}

impl Session {
    /// Initiator session. `root0` is the initial shared secret (derived from
    /// the invite-token PSK by the caller); `peer_prekey` is the responder's
    /// signed prekey public.
    pub fn initiator(root0: [u8; KEY_LEN], peer_prekey: RatchetPublic) -> Session {
        Session {
            profile: peer_prekey.profile,
            root: root0,
            self_ratchet: None,
            self_ratchet_pub: None,
            self_send_ct: Vec::new(),
            send_ck: None,
            send_n: 0,
            prev_send_n: 0,
            peer_ratchet: Some(peer_prekey),
            recv_ck: None,
            recv_n: 0,
            need_send_ratchet: true,
            skipped: BTreeMap::new(),
        }
    }

    /// Responder session, holding the prekey whose public was advertised.
    pub fn responder(
        root0: [u8; KEY_LEN],
        prekey_secret: RatchetSecret,
        prekey_public: RatchetPublic,
    ) -> Session {
        Session {
            profile: prekey_secret.profile(),
            root: root0,
            self_ratchet: Some(prekey_secret),
            self_ratchet_pub: Some(prekey_public),
            self_send_ct: Vec::new(),
            send_ck: None,
            send_n: 0,
            prev_send_n: 0,
            peer_ratchet: None,
            recv_ck: None,
            recv_n: 0,
            need_send_ratchet: false,
            skipped: BTreeMap::new(),
        }
    }

    /// Encrypt `plaintext`, advancing the sending ratchet. Returns the full
    /// wire message (header ‖ AEAD ciphertext).
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>> {
        if self.need_send_ratchet || self.send_ck.is_none() {
            self.ratchet_send()?;
        }
        let ck = Zeroizing::new(self.send_ck.expect("send chain set after ratchet_send"));
        // kdf_ck / kdf_mk now return the chain key, message-key seed, and AEAD key
        // in Zeroizing, so these locals (and the early-return error path) wipe.
        let (next_ck, mk_seed) = kdf_ck(&ck);
        let (key, nonce) = kdf_mk(&mk_seed);

        let header = Header {
            ratchet_pub: self.self_ratchet_pub.clone().expect("self ratchet pub set"),
            ct: self.self_send_ct.clone(),
            pn: self.prev_send_n,
            n: self.send_n,
        };
        let aad = header.encode();
        let ciphertext = aead_seal(&key, &nonce, plaintext, &aad)?;

        self.send_ck = Some(*next_ck);
        self.send_n += 1;

        let mut w = talkrypt_wire::Writer::new();
        w.put_bytes(&aad);
        w.put_bytes(&ciphertext);
        Ok(w.into_vec())
    }

    /// Decrypt a wire message. Runs on a cloned state and commits only on
    /// success, so hostile input cannot corrupt the session.
    pub fn decrypt(&mut self, message: &[u8]) -> Result<Vec<u8>> {
        let mut trial = self.clone();
        let pt = trial.decrypt_inner(message)?;
        *self = trial;
        Ok(pt)
    }

    fn decrypt_inner(&mut self, message: &[u8]) -> Result<Vec<u8>> {
        let mut r = talkrypt_wire::Reader::new(message);
        let aad = r.get_vec()?;
        let ciphertext = r.get_vec()?;
        r.finish()?;
        let header = Header::decode(self.profile, &aad)?;

        // 1. A previously-skipped key for this exact (chain, n)?
        if let Some(pt) = self.try_skipped(&header, &ciphertext, &aad)? {
            return Ok(pt);
        }

        // 2. New sending ratchet from the peer? Skip the tail of the old recv
        //    chain, then perform the asymmetric step.
        let is_new = match &self.peer_ratchet {
            Some(p) => *p != header.ratchet_pub,
            None => true,
        };
        if is_new {
            self.skip_recv(header.pn)?;
            self.ratchet_recv(&header)?;
        }

        // 3. Skip within the current recv chain up to this message number.
        self.skip_recv(header.n)?;

        // 4. Derive the message key for the current position and open. The chain
        //    key, seed, and AEAD key come back in Zeroizing (kdf), so they wipe.
        let ck = Zeroizing::new(self.recv_ck.ok_or(CryptoError::DecryptionFailed)?);
        let (next_ck, mk_seed) = kdf_ck(&ck);
        let (key, nonce) = kdf_mk(&mk_seed);
        let pt = aead_open(&key, &nonce, &ciphertext, &aad)?;
        self.recv_ck = Some(*next_ck);
        self.recv_n += 1;
        Ok(pt)
    }

    /// Perform a sending-side asymmetric ratchet step: new hybrid key, fresh
    /// root and sending chain.
    fn ratchet_send(&mut self) -> Result<()> {
        let peer = self
            .peer_ratchet
            .clone()
            .ok_or(CryptoError::Malformed("no peer ratchet key"))?;
        let (new_secret, new_public) = RatchetSecret::generate(self.profile);
        let (ct, ikm) = new_secret.step_to(&peer)?; // ikm: Zeroizing (raw shared secret)
        let (root, ck) = kdf_rk(&self.root, &ikm);

        self.root = *root;
        self.prev_send_n = self.send_n;
        self.send_n = 0;
        self.send_ck = Some(*ck);
        self.self_ratchet = Some(new_secret);
        self.self_ratchet_pub = Some(new_public);
        self.self_send_ct = ct;
        self.need_send_ratchet = false;
        Ok(())
    }

    /// Perform a receiving-side asymmetric ratchet step from a peer header.
    fn ratchet_recv(&mut self, header: &Header) -> Result<()> {
        let self_r = self
            .self_ratchet
            .as_ref()
            .ok_or(CryptoError::Malformed("no self ratchet key"))?;
        let ikm = self_r.step_from(&header.ratchet_pub, &header.ct)?; // Zeroizing
        let (root, ck) = kdf_rk(&self.root, &ikm);

        self.root = *root;
        self.peer_ratchet = Some(header.ratchet_pub.clone());
        self.recv_ck = Some(*ck);
        self.recv_n = 0;
        self.need_send_ratchet = true;
        Ok(())
    }

    /// Advance the receiving chain to `until`, caching skipped message keys.
    fn skip_recv(&mut self, until: u32) -> Result<()> {
        if self.recv_ck.is_none() || until <= self.recv_n {
            return Ok(());
        }
        let to_skip = (until - self.recv_n) as usize;
        if self.skipped.len() + to_skip > MAX_SKIP {
            return Err(CryptoError::TooManySkipped(MAX_SKIP));
        }
        let chain_id = self
            .peer_ratchet
            .as_ref()
            .map(|p| p.encode())
            .unwrap_or_default();
        while self.recv_n < until {
            let ck = Zeroizing::new(self.recv_ck.expect("recv chain present"));
            let (next_ck, mk_seed) = kdf_ck(&ck);
            self.skipped
                .insert((chain_id.clone(), self.recv_n), *mk_seed);
            self.recv_ck = Some(*next_ck);
            self.recv_n += 1;
        }
        Ok(())
    }

    fn try_skipped(&mut self, header: &Header, ct: &[u8], aad: &[u8]) -> Result<Option<Vec<u8>>> {
        let id = (header.ratchet_pub.encode(), header.n);
        if let Some(mk_seed) = self.skipped.get(&id).copied() {
            let mk_seed = Zeroizing::new(mk_seed);
            let (key, nonce) = kdf_mk(&mk_seed); // key: Zeroizing
            let pt = aead_open(&key, &nonce, ct, aad)?;
            self.skipped.remove(&id);
            Ok(Some(pt))
        } else {
            Ok(None)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build an initiator/responder pair sharing a root and the responder's
    /// prekey, mirroring what the handshake layer will set up. PQ-pure is the
    /// default posture; a hybrid pair is exercised separately below.
    fn pair() -> (Session, Session) {
        pair_with(KemProfile::pq_pure())
    }

    fn pair_with(profile: KemProfile) -> (Session, Session) {
        let root0 = [42u8; KEY_LEN];
        let (prekey_secret, prekey_public) = RatchetSecret::generate(profile);
        let alice = Session::initiator(root0, prekey_public.clone());
        let bob = Session::responder(root0, prekey_secret, prekey_public);
        (alice, bob)
    }

    #[test]
    fn single_message_roundtrip() {
        let (mut alice, mut bob) = pair();
        let ct = alice.encrypt(b"hello bob").unwrap();
        assert_eq!(bob.decrypt(&ct).unwrap(), b"hello bob");
    }

    /// Miri-verified: `Session::drop` actually zeroes its `root` (the session's
    /// most sensitive symmetric field). Built with synthetic secrets and no
    /// ratchet keys so it runs under Miri without PQ keygen. SECURITY-AUDIT F-3.
    #[test]
    fn drop_zeroizes_session_root() {
        let session = Session {
            profile: KemProfile::pq_pure(),
            root: [0xAA; KEY_LEN],
            self_ratchet: None,
            self_ratchet_pub: None,
            self_send_ct: Vec::new(),
            send_ck: Some([0xAA; KEY_LEN]),
            send_n: 0,
            prev_send_n: 0,
            peer_ratchet: None,
            recv_ck: Some([0xAA; KEY_LEN]),
            recv_n: 0,
            need_send_ratchet: false,
            skipped: BTreeMap::new(),
        };
        unsafe {
            crate::assert_drop_zeroes(session, core::mem::offset_of!(Session, root), KEY_LEN);
        }
    }

    #[test]
    fn jumbo_message_roundtrips() {
        // Large ("jumbo") payloads must encrypt/decrypt intact — a 4 MiB
        // message, well within MAX_FRAME, round-trips byte-for-byte.
        let (mut alice, mut bob) = pair();
        let big: Vec<u8> = (0..4 * 1024 * 1024).map(|i| (i * 31 + 7) as u8).collect();
        let ct = alice.encrypt(&big).unwrap();
        assert_eq!(bob.decrypt(&ct).unwrap(), big);
    }

    #[test]
    fn full_duplex_conversation() {
        let (mut alice, mut bob) = pair();
        let m1 = alice.encrypt(b"hi").unwrap();
        assert_eq!(bob.decrypt(&m1).unwrap(), b"hi");
        let m2 = bob.encrypt(b"hey back").unwrap();
        assert_eq!(alice.decrypt(&m2).unwrap(), b"hey back");
        let m3 = alice.encrypt(b"how are you").unwrap();
        assert_eq!(bob.decrypt(&m3).unwrap(), b"how are you");
        let m4 = bob.encrypt(b"good").unwrap();
        assert_eq!(alice.decrypt(&m4).unwrap(), b"good");
    }

    #[test]
    fn dropping_active_session_runs_zeroize_drop() {
        // Populate every secret field — root, both chain keys, and a non-empty
        // skipped-key map — then drop. Exercises the F-3 zeroize-on-drop path for
        // all field combinations (a regression here, e.g. a field type that no
        // longer zeroizes, would surface as a compile error or a Drop panic).
        let (mut alice, mut bob) = pair();
        let m0 = alice.encrypt(b"0").unwrap();
        let _m1 = alice.encrypt(b"1").unwrap(); // never delivered → stays skipped
        let m2 = alice.encrypt(b"2").unwrap();
        bob.decrypt(&m2).unwrap(); // skips 0 and 1 into bob.skipped
        bob.decrypt(&m0).unwrap(); // drains one; n=1 remains cached
        let r = bob.encrypt(b"reply").unwrap();
        alice.decrypt(&r).unwrap(); // both sides now hold send + recv chain keys
        assert!(!bob.skipped.is_empty(), "a skipped key must remain at drop");
        drop(alice);
        drop(bob); // Drop::drop zeroizes the secrets; must not panic
    }

    #[test]
    fn out_of_order_within_chain() {
        let (mut alice, mut bob) = pair();
        let m0 = alice.encrypt(b"zero").unwrap();
        let m1 = alice.encrypt(b"one").unwrap();
        let m2 = alice.encrypt(b"two").unwrap();
        // Deliver 2, then 0, then 1.
        assert_eq!(bob.decrypt(&m2).unwrap(), b"two");
        assert_eq!(bob.decrypt(&m0).unwrap(), b"zero");
        assert_eq!(bob.decrypt(&m1).unwrap(), b"one");
    }

    #[test]
    fn out_of_order_across_ratchets() {
        let (mut alice, mut bob) = pair();
        // Alice sends two, Bob replies (ratchet), Alice sends two more (ratchet).
        let a0 = alice.encrypt(b"a0").unwrap();
        let a1 = alice.encrypt(b"a1").unwrap();
        bob.decrypt(&a0).unwrap();
        let b0 = bob.encrypt(b"b0").unwrap();
        alice.decrypt(&b0).unwrap();
        let a2 = alice.encrypt(b"a2").unwrap(); // new ratchet
        let a3 = alice.encrypt(b"a3").unwrap();
        // Bob receives, badly ordered: a3, a1 (old chain), a2.
        assert_eq!(bob.decrypt(&a3).unwrap(), b"a3");
        assert_eq!(bob.decrypt(&a1).unwrap(), b"a1");
        assert_eq!(bob.decrypt(&a2).unwrap(), b"a2");
    }

    #[test]
    fn replay_is_rejected_without_corrupting_state() {
        let (mut alice, mut bob) = pair();
        let m0 = alice.encrypt(b"first").unwrap();
        let m1 = alice.encrypt(b"second").unwrap();
        assert_eq!(bob.decrypt(&m0).unwrap(), b"first");
        // Replaying m0 must fail...
        assert!(bob.decrypt(&m0).is_err());
        // ...and the session must still work for the next legitimate message.
        assert_eq!(bob.decrypt(&m1).unwrap(), b"second");
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let (mut alice, mut bob) = pair();
        let mut ct = alice.encrypt(b"integrity").unwrap();
        let last = ct.len() - 1;
        ct[last] ^= 0x01;
        assert!(bob.decrypt(&ct).is_err());
        // State uncorrupted: a fresh message still decrypts.
        let ok = alice.encrypt(b"again").unwrap();
        assert_eq!(bob.decrypt(&ok).unwrap(), b"again");
    }

    #[test]
    fn too_many_skipped_is_bounded() {
        let (mut alice, mut bob) = pair();
        // Force a huge gap by sending many but only delivering the last.
        let mut last = Vec::new();
        for i in 0..(MAX_SKIP + 5) {
            last = alice.encrypt(format!("m{i}").as_bytes()).unwrap();
        }
        // Delivering only the last requires skipping > MAX_SKIP keys -> error.
        assert!(matches!(
            bob.decrypt(&last),
            Err(CryptoError::TooManySkipped(_))
        ));
    }

    use proptest::prelude::*;

    proptest! {
        // ML-KEM keygen per message makes each case costly; keep case counts
        // and schedule lengths modest so the suite stays fast while still
        // exercising many random schedules.
        #![proptest_config(ProptestConfig::with_cases(24))]

        /// Arbitrary bidirectional schedule with in-order delivery per step:
        /// every delivered message must decrypt to exactly what was sent.
        /// (Alice is the initiator; Bob may only send after his first receive.)
        #[test]
        fn prop_arbitrary_direction_schedule(dirs in prop::collection::vec(any::<bool>(), 0..24)) {
            let (mut alice, mut bob) = pair();
            let mut bob_can_send = false;
            for (counter, want_alice) in dirs.into_iter().enumerate() {
                let send_from_alice = want_alice || !bob_can_send;
                let msg = format!("msg-{counter}");
                if send_from_alice {
                    let ct = alice.encrypt(msg.as_bytes()).unwrap();
                    prop_assert_eq!(bob.decrypt(&ct).unwrap(), msg.as_bytes());
                    bob_can_send = true;
                } else {
                    let ct = bob.encrypt(msg.as_bytes()).unwrap();
                    prop_assert_eq!(alice.decrypt(&ct).unwrap(), msg.as_bytes());
                }
            }
        }

        /// N one-directional messages delivered in an arbitrary permutation
        /// (within the skip bound) all decrypt to the right plaintext.
        #[test]
        fn prop_out_of_order_permutation(n in 1usize..20, seed in any::<u64>()) {
            let (mut alice, mut bob) = pair();
            let msgs: Vec<String> = (0..n).map(|i| format!("p{i}")).collect();
            let cts: Vec<Vec<u8>> = msgs.iter().map(|m| alice.encrypt(m.as_bytes()).unwrap()).collect();
            // Deterministic Fisher-Yates shuffle driven by `seed`.
            let mut order: Vec<usize> = (0..n).collect();
            let mut s = seed | 1;
            for i in (1..n).rev() {
                s = s.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
                let j = (s >> 33) as usize % (i + 1);
                order.swap(i, j);
            }
            for &idx in &order {
                prop_assert_eq!(bob.decrypt(&cts[idx]).unwrap(), msgs[idx].as_bytes());
            }
        }
    }

    #[test]
    fn keys_evolve_post_compromise() {
        // After a ratchet step, the sending ratchet public changes — evidence
        // that fresh asymmetric entropy was injected (post-compromise recovery).
        let (mut alice, mut bob) = pair();
        let a0 = alice.encrypt(b"a0").unwrap();
        bob.decrypt(&a0).unwrap();
        let b0 = bob.encrypt(b"b0").unwrap();
        alice.decrypt(&b0).unwrap();
        let a_pub_1 = alice.self_ratchet_pub.clone().unwrap();
        let a1 = alice.encrypt(b"a1").unwrap(); // triggers new ratchet
        bob.decrypt(&a1).unwrap();
        let a_pub_2 = alice.self_ratchet_pub.clone().unwrap();
        assert_ne!(a_pub_1, a_pub_2);
    }
}
