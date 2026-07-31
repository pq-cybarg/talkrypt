//! Self-declared name presence ("callsign") payloads. A `NamePresence` is what a
//! peer broadcasts to say "this is <name>". The `Linked` variant is device-signed
//! and chat-context-bound, so it is unforgeable even by a malicious group member
//! (group message attribution is sender-key and insider-spoofable — see
//! `docs/superpowers/specs/2026-07-04-self-declared-names-cq-beacon-subspec-a-design.md`).

use crate::contacts::Presentation;
use crate::error::{CoreError, Result};
use crate::nametrust::NameTier;
use sha2::{Digest, Sha256};
use talkrypt_crypto::{IdentityChain, IdentityKeyPair};
use talkrypt_wire::{Reader, Writer};

/// `u64` over the `u32`-only wire, big-endian hi‖lo (no `wire` crate change).
pub(crate) fn put_u64(w: &mut Writer, v: u64) {
    w.put_u32((v >> 32) as u32);
    w.put_u32((v & 0xFFFF_FFFF) as u32);
}
pub(crate) fn get_u64(r: &mut Reader) -> Result<u64> {
    let hi = r.get_u32().map_err(|_| CoreError::Malformed("u64 hi"))? as u64;
    let lo = r.get_u32().map_err(|_| CoreError::Malformed("u64 lo"))? as u64;
    Ok((hi << 32) | lo)
}

/// A self-declared name announcement.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NamePresence {
    /// Cosmetic, unauthenticated. Attribution rides the (insider-spoofable) group
    /// sender key / pairwise transport fp.
    Bare { seq: u64, label: String },
    /// Account-linked: a device-key signature over `(seq ‖ label ‖ context)`, plus
    /// the account→device certificate chain. Insider-unforgeable.
    Linked {
        seq: u64,
        presentation: Presentation,
        context: [u8; 32],
        sig: Vec<u8>,
    },
}

impl NamePresence {
    pub fn seq(&self) -> u64 {
        match self {
            NamePresence::Bare { seq, .. } | NamePresence::Linked { seq, .. } => *seq,
        }
    }

    pub fn label(&self) -> &str {
        match self {
            NamePresence::Bare { label, .. } => label,
            NamePresence::Linked { presentation, .. } => {
                presentation.username.as_deref().unwrap_or("")
            }
        }
    }

    /// Build a signed account-linked presence. `signer` MUST be the chain's leaf
    /// (device) key; `presentation.username` is set to `label`.
    pub fn linked(
        seq: u64,
        chain: IdentityChain,
        label: &str,
        context: [u8; 32],
        signer: &IdentityKeyPair,
    ) -> NamePresence {
        let sig = signer.sign(&sign_input(seq, label, &context));
        NamePresence::Linked {
            seq,
            presentation: Presentation::new(chain, Some(label.to_string())),
            context,
            sig,
        }
    }

    /// Verify a `Linked` presence end to end: chain internally valid, signature by
    /// the chain's device leaf over `(seq ‖ label ‖ context)`. Returns the account
    /// + device fingerprints. `None` for `Bare` or any failure. Does NOT check the
    /// context matches the current chat (the caller does, having the descriptor) or
    /// revocation (the engine does, having the revocation set).
    pub fn verify_linked(&self, now: u64) -> Option<VerifiedName> {
        let NamePresence::Linked {
            seq,
            presentation,
            context,
            sig,
        } = self
        else {
            return None;
        };
        let leaf = presentation.chain.leaf()?;
        let account = presentation.chain.links.first()?.issuer.clone();
        presentation.chain.verify(&account, leaf, now).ok()?;
        let label = presentation.username.clone()?;
        leaf.verify(&sign_input(*seq, &label, context), sig).ok()?;
        Some(VerifiedName {
            account_fp: account.fingerprint(),
            device_fp: leaf.fingerprint(),
            label,
            seq: *seq,
        })
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        match self {
            NamePresence::Bare { seq, label } => {
                w.put_u8(0);
                put_u64(&mut w, *seq);
                w.put_bytes(label.as_bytes());
            }
            NamePresence::Linked {
                seq,
                presentation,
                context,
                sig,
            } => {
                w.put_u8(1);
                put_u64(&mut w, *seq);
                w.put_bytes(&presentation.encode());
                w.put_bytes(context);
                w.put_bytes(sig);
            }
        }
        w.into_vec()
    }

    pub fn decode(bytes: &[u8]) -> Result<NamePresence> {
        let mut r = Reader::new(bytes);
        let np = match r.get_u8().map_err(|_| CoreError::Malformed("presence tag"))? {
            0 => {
                let seq = get_u64(&mut r)?;
                let label = String::from_utf8(
                    r.get_vec().map_err(|_| CoreError::Malformed("bare label"))?,
                )
                .map_err(|_| CoreError::Malformed("bare label utf-8"))?;
                NamePresence::Bare { seq, label }
            }
            1 => {
                let seq = get_u64(&mut r)?;
                let presentation = Presentation::decode(
                    r.get_bytes()
                        .map_err(|_| CoreError::Malformed("linked presentation"))?,
                )?;
                let ctx = r
                    .get_bytes()
                    .map_err(|_| CoreError::Malformed("linked context"))?;
                if ctx.len() != 32 {
                    return Err(CoreError::Malformed("context len"));
                }
                let mut context = [0u8; 32];
                context.copy_from_slice(ctx);
                let sig = r.get_vec().map_err(|_| CoreError::Malformed("linked sig"))?;
                NamePresence::Linked {
                    seq,
                    presentation,
                    context,
                    sig,
                }
            }
            _ => return Err(CoreError::Malformed("presence variant")),
        };
        r.finish()
            .map_err(|_| CoreError::Malformed("presence trailing"))?;
        Ok(np)
    }
}

/// SHA-256(invite_token ‖ channel) — binds a `Linked` presence to THIS chat so it
/// cannot be replayed into another chat to impersonate.
pub fn chat_context(invite_token: &[u8], channel: &str) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(invite_token);
    h.update(channel.as_bytes());
    h.finalize().into()
}

/// The exact bytes the device key signs / a verifier reconstructs.
pub fn sign_input(seq: u64, label: &str, context: &[u8; 32]) -> Vec<u8> {
    let mut w = Writer::new();
    put_u64(&mut w, seq);
    w.put_bytes(label.as_bytes());
    w.put_bytes(context);
    w.into_vec()
}

/// A short, non-secret tag identifying "which name at which seq" a sender is using,
/// stamped on outgoing messages when the on-message cadence mode is on. A viewer
/// whose cached tag differs knows its name cache is stale and awaits a presence.
pub fn name_tag(label: &str, context: &[u8; 32], seq: u64) -> [u8; 8] {
    let mut h = Sha256::new();
    h.update(context);
    h.update(seq.to_be_bytes());
    h.update(label.as_bytes());
    let d = h.finalize();
    let mut out = [0u8; 8];
    out.copy_from_slice(&d[..8]);
    out
}

/// A verified account-linked name.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedName {
    pub account_fp: [u8; 48],
    pub device_fp: [u8; 48],
    pub label: String,
    pub seq: u64,
}

/// How a name entry is cryptographically backed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NameBacking {
    Bare,
    Account { chain: IdentityChain },
}

/// One saved name in the user's name book.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NameEntry {
    pub id: String,
    pub label: String,
    pub backing: NameBacking,
}

/// The user's saved set of names, plus which is the default leading name.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct NameBook {
    pub entries: Vec<NameEntry>,
    pub default: Option<String>,
}

impl NameBook {
    pub fn get(&self, id: &str) -> Option<&NameEntry> {
        self.entries.iter().find(|e| e.id == id)
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.put_u32(self.entries.len() as u32);
        for e in &self.entries {
            w.put_bytes(e.id.as_bytes());
            w.put_bytes(e.label.as_bytes());
            match &e.backing {
                NameBacking::Bare => w.put_u8(0),
                NameBacking::Account { chain } => {
                    w.put_u8(1);
                    w.put_bytes(&chain.encode());
                }
            }
        }
        match &self.default {
            Some(d) => {
                w.put_u8(1);
                w.put_bytes(d.as_bytes());
            }
            None => w.put_u8(0),
        }
        w.into_vec()
    }

    pub fn decode(bytes: &[u8]) -> Result<NameBook> {
        let mut r = Reader::new(bytes);
        let n = r.get_u32().map_err(|_| CoreError::Malformed("book len"))? as usize;
        if n > 4096 {
            return Err(CoreError::Malformed("too many names"));
        }
        let mut entries = Vec::with_capacity(n);
        for _ in 0..n {
            let id = String::from_utf8(r.get_vec().map_err(|_| CoreError::Malformed("id"))?)
                .map_err(|_| CoreError::Malformed("id utf-8"))?;
            let label = String::from_utf8(r.get_vec().map_err(|_| CoreError::Malformed("label"))?)
                .map_err(|_| CoreError::Malformed("label utf-8"))?;
            let backing = match r.get_u8().map_err(|_| CoreError::Malformed("backing tag"))? {
                0 => NameBacking::Bare,
                1 => NameBacking::Account {
                    chain: IdentityChain::decode(
                        r.get_bytes().map_err(|_| CoreError::Malformed("chain"))?,
                    )?,
                },
                _ => return Err(CoreError::Malformed("backing variant")),
            };
            entries.push(NameEntry { id, label, backing });
        }
        let default = match r.get_u8().map_err(|_| CoreError::Malformed("default tag"))? {
            0 => None,
            1 => Some(
                String::from_utf8(r.get_vec().map_err(|_| CoreError::Malformed("default"))?)
                    .map_err(|_| CoreError::Malformed("default utf-8"))?,
            ),
            _ => return Err(CoreError::Malformed("default variant")),
        };
        r.finish()
            .map_err(|_| CoreError::Malformed("book trailing"))?;
        Ok(NameBook { entries, default })
    }
}

/// A viewer's cached, resolved name for one peer fingerprint.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NameRecord {
    pub label: String,
    pub tier: NameTier,
    pub seq: u64,
    pub account_fp: Option<[u8; 48]>,
}

pub const MIN_PERIODIC_SECS: u64 = 60;

/// CQ emission cadence: an optional periodic re-beacon (clamped to a floor) and
/// whether to stamp a name-id onto outgoing messages.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct PresenceCadence {
    pub periodic_secs: Option<u64>,
    pub on_message_id: bool,
}
impl PresenceCadence {
    /// Periodic interval clamped to the floor; `None` = periodic disabled.
    pub fn effective_periodic(&self) -> Option<u64> {
        self.periodic_secs.map(|s| s.max(MIN_PERIODIC_SECS))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bare_presence_roundtrip() {
        let p = NamePresence::Bare {
            seq: 7,
            label: "K1ABC".to_string(),
        };
        let bytes = p.encode();
        assert_eq!(NamePresence::decode(&bytes).unwrap(), p);
        assert_eq!(NamePresence::decode(&bytes).unwrap().seq(), 7);
    }

    #[test]
    fn u64_helpers_roundtrip() {
        let mut w = Writer::new();
        put_u64(&mut w, 0x0123_4567_89AB_CDEF);
        let v = w.into_vec();
        let mut r = Reader::new(&v);
        assert_eq!(get_u64(&mut r).unwrap(), 0x0123_4567_89AB_CDEF);
    }

    #[test]
    fn linked_presence_signs_and_verifies() {
        let now = 1_000_000u64;
        let account = IdentityKeyPair::generate();
        let device = IdentityKeyPair::generate();
        let chain = IdentityChain::device(&account, device.public(), "dev", now, now + 10_000);
        let ctx = chat_context(&[9u8; 32], "#general");
        let p = NamePresence::linked(3, chain, "K1ABC", ctx, &device);
        let v = p.verify_linked(now).expect("verifies");
        assert_eq!(v.label, "K1ABC");
        assert_eq!(v.account_fp, account.public().fingerprint());
        assert_eq!(v.device_fp, device.public().fingerprint());
    }

    #[test]
    fn linked_presence_rejects_forged_sig() {
        let now = 1_000_000u64;
        let account = IdentityKeyPair::generate();
        let device = IdentityKeyPair::generate();
        let chain = IdentityChain::device(&account, device.public(), "dev", now, now + 10_000);
        let ctx = chat_context(&[9u8; 32], "#general");
        let mut p = NamePresence::linked(3, chain, "K1ABC", ctx, &device);
        if let NamePresence::Linked { sig, .. } = &mut p {
            sig[0] ^= 0xFF;
        }
        assert!(p.verify_linked(now).is_none());
    }

    #[test]
    fn namebook_roundtrip() {
        let now = 1u64;
        let account = IdentityKeyPair::generate();
        let device = IdentityKeyPair::generate();
        let chain = IdentityChain::device(&account, device.public(), "dev", now, now + 10);
        let book = NameBook {
            entries: vec![
                NameEntry {
                    id: "1".into(),
                    label: "Whiskey".into(),
                    backing: NameBacking::Bare,
                },
                NameEntry {
                    id: "2".into(),
                    label: "K1ABC".into(),
                    backing: NameBacking::Account { chain },
                },
            ],
            default: Some("2".into()),
        };
        let bytes = book.encode();
        assert_eq!(NameBook::decode(&bytes).unwrap(), book);
    }

    #[test]
    fn cadence_enforces_floor() {
        let c = PresenceCadence {
            periodic_secs: Some(1),
            on_message_id: false,
        };
        assert_eq!(c.effective_periodic(), Some(MIN_PERIODIC_SECS));
        assert_eq!(PresenceCadence::default().effective_periodic(), None);
    }

    #[test]
    fn name_tag_is_stable_and_seq_sensitive() {
        let ctx = chat_context(b"t", "#c");
        assert_eq!(name_tag("Alice", &ctx, 1), name_tag("Alice", &ctx, 1));
        assert_ne!(name_tag("Alice", &ctx, 1), name_tag("Alice", &ctx, 2));
        assert_ne!(name_tag("Alice", &ctx, 1), name_tag("Bob", &ctx, 1));
    }
}
