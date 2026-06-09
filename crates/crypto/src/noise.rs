//! PQ-Noise suite (`tk.noise.*`) — a lighter alternative to the Double
//! Ratchet for short-lived, ordered sessions.
//!
//! A single hybrid (X25519 + ML-KEM-1024) step at session start establishes a
//! session root; two independent symmetric chains (one per direction) then
//! advance per message. This gives **per-message forward secrecy within the
//! session** (chains are one-way) but, unlike the Double Ratchet, **no
//! post-compromise recovery** — there is no re-ratchet. Rekey by starting a
//! new session.
//!
//! Assumes an ordered, reliable channel (our stream transports are): the
//! establishment header rides only on the initiator's first message.

use std::collections::BTreeMap;

use zeroize::{Zeroize, Zeroizing};

use crate::aead::{open as aead_open, seal as aead_seal};
use crate::error::{CryptoError, Result};
use crate::hybrid::{KemProfile, RatchetPublic, RatchetSecret};
use crate::kdf::{kdf_ck, kdf_mk, kdf_rk, KEY_LEN};
use crate::ratchet::MAX_SKIP;

const I2R: &[u8] = b"talkrypt-noise-i2r";
const R2I: &[u8] = b"talkrypt-noise-r2i";

/// A PQ-Noise session.
pub struct NoiseSession {
    initiator: bool,
    /// KEM profile (posture + wire padding), fixed by the suite for the session.
    profile: KemProfile,
    root0: [u8; KEY_LEN],
    // Initiator: peer's prekey public. Responder: our prekey secret.
    peer_prekey: Option<RatchetPublic>,
    self_prekey: Option<RatchetSecret>,
    // Establishment material the initiator emits on its first message.
    eph_public: Option<RatchetPublic>,
    eph_ct: Vec<u8>,
    send_chain: Option<[u8; KEY_LEN]>,
    recv_chain: Option<[u8; KEY_LEN]>,
    send_n: u32,
    recv_n: u32,
    skipped: BTreeMap<u32, [u8; KEY_LEN]>,
}

/// Wipe the session root and both direction chains (plus any cached skipped
/// message-key seeds) when the session drops. The X25519 prekey secret zeroizes
/// itself via dalek. Closes SECURITY-AUDIT finding F-3 for the PQ-Noise session.
impl Drop for NoiseSession {
    fn drop(&mut self) {
        self.root0.zeroize();
        if let Some(c) = self.send_chain.as_mut() {
            c.zeroize();
        }
        if let Some(c) = self.recv_chain.as_mut() {
            c.zeroize();
        }
        for seed in self.skipped.values_mut() {
            seed.zeroize();
        }
    }
}

impl NoiseSession {
    pub fn initiator(root0: [u8; KEY_LEN], peer_prekey: RatchetPublic) -> Self {
        Self {
            initiator: true,
            profile: peer_prekey.profile,
            root0,
            peer_prekey: Some(peer_prekey),
            self_prekey: None,
            eph_public: None,
            eph_ct: Vec::new(),
            send_chain: None,
            recv_chain: None,
            send_n: 0,
            recv_n: 0,
            skipped: BTreeMap::new(),
        }
    }

    pub fn responder(root0: [u8; KEY_LEN], prekey_secret: RatchetSecret) -> Self {
        Self {
            initiator: false,
            profile: prekey_secret.profile(),
            root0,
            peer_prekey: None,
            self_prekey: Some(prekey_secret),
            eph_public: None,
            eph_ct: Vec::new(),
            send_chain: None,
            recv_chain: None,
            send_n: 0,
            recv_n: 0,
            skipped: BTreeMap::new(),
        }
    }

    fn chains_from_root(&self, session_root: [u8; KEY_LEN]) -> ([u8; KEY_LEN], [u8; KEY_LEN]) {
        let i2r = kdf_rk(&session_root, I2R).1;
        let r2i = kdf_rk(&session_root, R2I).1;
        if self.initiator {
            (i2r, r2i) // (send, recv)
        } else {
            (r2i, i2r)
        }
    }

    /// Initiator: derive the session root and chains, generating the ephemeral.
    fn establish_initiator(&mut self) -> Result<()> {
        let peer = self
            .peer_prekey
            .clone()
            .ok_or(CryptoError::Malformed("noise: no peer prekey"))?;
        let (eph_secret, eph_public) = RatchetSecret::generate(self.profile);
        let (ct, ikm) = eph_secret.step_to(&peer)?;
        let session_root = kdf_rk(&self.root0, &ikm).0;
        let (send, recv) = self.chains_from_root(session_root);
        self.send_chain = Some(send);
        self.recv_chain = Some(recv);
        self.eph_public = Some(eph_public);
        self.eph_ct = ct;
        Ok(())
    }

    /// Responder: derive the session root and chains from the initiator header.
    fn establish_responder(&mut self, eph_public: &RatchetPublic, ct: &[u8]) -> Result<()> {
        let prekey = self
            .self_prekey
            .as_ref()
            .ok_or(CryptoError::Malformed("noise: no prekey secret"))?;
        let ikm = prekey.step_from(eph_public, ct)?;
        let session_root = kdf_rk(&self.root0, &ikm).0;
        let (send, recv) = self.chains_from_root(session_root);
        self.send_chain = Some(send);
        self.recv_chain = Some(recv);
        Ok(())
    }

    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>> {
        if self.send_chain.is_none() {
            if self.initiator {
                self.establish_initiator()?;
            } else {
                return Err(CryptoError::Malformed(
                    "noise: responder cannot send before receiving",
                ));
            }
        }
        let ck = Zeroizing::new(self.send_chain.expect("send chain established"));
        let (next, mk_seed) = kdf_ck(&ck);
        let mk_seed = Zeroizing::new(mk_seed);
        let (key, nonce) = kdf_mk(&mk_seed);
        let key = Zeroizing::new(key);

        // The initiator carries the (fixed) establishment header on every
        // message, so the responder can establish from whichever message
        // arrives first even under loss/reorder. The responder ignores it once
        // established. Cost: ~1.6 KiB header overhead on the initiator's
        // direction — acceptable for short-lived sessions; the Double Ratchet
        // suite is preferred when that overhead matters.
        let include_header = self.initiator;
        let mut hw = talkrypt_wire::Writer::new();
        hw.put_u8(include_header as u8);
        if include_header {
            hw.put_bytes(&self.eph_public.clone().unwrap().encode());
            hw.put_bytes(&self.eph_ct);
        }
        hw.put_u32(self.send_n);
        let aad = hw.into_vec();

        let ciphertext = aead_seal(&key, &nonce, plaintext, &aad)?;
        self.send_chain = Some(next);
        self.send_n += 1;

        let mut w = talkrypt_wire::Writer::new();
        w.put_bytes(&aad);
        w.put_bytes(&ciphertext);
        Ok(w.into_vec())
    }

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

        let mut hr = talkrypt_wire::Reader::new(&aad);
        let has_header = hr.get_u8()? != 0;
        if has_header {
            let eph_public = RatchetPublic::decode(self.profile, hr.get_bytes()?)?;
            let eph_ct = hr.get_vec()?;
            if self.recv_chain.is_none() && !self.initiator {
                self.establish_responder(&eph_public, &eph_ct)?;
            }
        }
        let n = hr.get_u32()?;
        hr.finish()?;

        // Skipped key for this n?
        if let Some(mk_seed) = self.skipped.get(&n).copied() {
            let mk_seed = Zeroizing::new(mk_seed);
            let (key, nonce) = kdf_mk(&mk_seed);
            let key = Zeroizing::new(key);
            let pt = aead_open(&key, &nonce, &ciphertext, &aad)?;
            self.skipped.remove(&n);
            return Ok(pt);
        }

        let mut ck = Zeroizing::new(self.recv_chain.ok_or(CryptoError::DecryptionFailed)?);
        if n < self.recv_n {
            // already consumed in-order and not skipped → replay/garbage
            return Err(CryptoError::DecryptionFailed);
        }
        if (n - self.recv_n) as usize > MAX_SKIP {
            return Err(CryptoError::TooManySkipped(MAX_SKIP));
        }
        while self.recv_n < n {
            let (next, mk_seed) = kdf_ck(&ck);
            self.skipped.insert(self.recv_n, mk_seed);
            ck = Zeroizing::new(next);
            self.recv_n += 1;
        }
        let (next, mk_seed) = kdf_ck(&ck);
        let mk_seed = Zeroizing::new(mk_seed);
        let (key, nonce) = kdf_mk(&mk_seed);
        let key = Zeroizing::new(key);
        let pt = aead_open(&key, &nonce, &ciphertext, &aad)?;
        self.recv_chain = Some(next);
        self.recv_n += 1;
        Ok(pt)
    }
}

impl Clone for NoiseSession {
    fn clone(&self) -> Self {
        Self {
            initiator: self.initiator,
            profile: self.profile,
            root0: self.root0,
            peer_prekey: self.peer_prekey.clone(),
            self_prekey: self.self_prekey.clone(),
            eph_public: self.eph_public.clone(),
            eph_ct: self.eph_ct.clone(),
            send_chain: self.send_chain,
            recv_chain: self.recv_chain,
            send_n: self.send_n,
            recv_n: self.recv_n,
            skipped: self.skipped.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pair() -> (NoiseSession, NoiseSession) {
        pair_with(KemProfile::pq_pure())
    }

    fn pair_with(profile: KemProfile) -> (NoiseSession, NoiseSession) {
        let root0 = [5u8; KEY_LEN];
        let (sec, pubk) = RatchetSecret::generate(profile);
        (
            NoiseSession::initiator(root0, pubk),
            NoiseSession::responder(root0, sec),
        )
    }

    #[test]
    fn roundtrip_and_duplex() {
        let (mut a, mut b) = pair();
        let m = a.encrypt(b"hello noise").unwrap();
        assert_eq!(b.decrypt(&m).unwrap(), b"hello noise");
        let r = b.encrypt(b"reply").unwrap();
        assert_eq!(a.decrypt(&r).unwrap(), b"reply");
        let m2 = a.encrypt(b"again").unwrap();
        assert_eq!(b.decrypt(&m2).unwrap(), b"again");
    }

    #[test]
    fn out_of_order_within_chain() {
        let (mut a, mut b) = pair();
        let m0 = a.encrypt(b"0").unwrap();
        let m1 = a.encrypt(b"1").unwrap();
        let m2 = a.encrypt(b"2").unwrap();
        assert_eq!(b.decrypt(&m2).unwrap(), b"2");
        assert_eq!(b.decrypt(&m0).unwrap(), b"0");
        assert_eq!(b.decrypt(&m1).unwrap(), b"1");
    }

    #[test]
    fn replay_rejected() {
        let (mut a, mut b) = pair();
        let m0 = a.encrypt(b"x").unwrap();
        let m1 = a.encrypt(b"y").unwrap();
        assert_eq!(b.decrypt(&m0).unwrap(), b"x");
        assert!(b.decrypt(&m0).is_err());
        assert_eq!(b.decrypt(&m1).unwrap(), b"y");
    }

    #[test]
    fn tampered_fails_without_corrupting() {
        let (mut a, mut b) = pair();
        let mut m = a.encrypt(b"data").unwrap();
        let last = m.len() - 1;
        m[last] ^= 1;
        assert!(b.decrypt(&m).is_err());
        let ok = a.encrypt(b"ok").unwrap();
        assert_eq!(b.decrypt(&ok).unwrap(), b"ok");
    }

    #[test]
    fn wrong_root_cannot_decrypt() {
        let (sec, pubk) = RatchetSecret::generate(KemProfile::pq_pure());
        let mut a = NoiseSession::initiator([1u8; KEY_LEN], pubk);
        let mut b = NoiseSession::responder([2u8; KEY_LEN], sec);
        let m = a.encrypt(b"secret").unwrap();
        assert!(b.decrypt(&m).is_err());
    }
}
