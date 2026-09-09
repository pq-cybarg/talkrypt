//! SUB-SPEC D at-rest persistence: a sealed, on-disk [`OutboxStore`] + [`HistoryStore`]
//! so a serverless client's un-acked outbox and (consented) history survive an app/phone
//! restart — the whole point of persistence when there is no server and users turn their
//! devices off.
//!
//! **Custody:** one 32-byte data-encryption key (DEK) per store is sealed ONCE, via the
//! same [`crate::seal`] primitive (and thus the same passphrase and/or hardware wrapper)
//! the device uses for its ML-DSA identity, into `<dir>/keyfile`. Every record is then
//! AEAD-sealed under that DEK with a fresh nonce — so a restart re-derives the DEK with a
//! single unlock and each record stays confidential + tamper-evident at rest.
//!
//! **Why a per-store DEK (not per-record `seal()`):** `seal()` runs Argon2id per call for a
//! passphrase factor; doing that per message would be unusable. The DEK pays that cost once.
//!
//! **Layout:** `<dir>/keyfile`, `<dir>/outbox/<sha256(chat)>/<gid_hex>`,
//! `<dir>/history/<sha256(chat)>/<gid_hex>`. Chat names are hashed (never written in the
//! clear); the two traits use disjoint subdirs so one instance backs both without collision.
//! Each record file is `nonce(12) ‖ AEAD_ct`; the AAD binds `subdir ‖ sha256(chat) ‖ gid`
//! so a record cannot be silently moved to another chat, id, or store kind.
//!
//! **Best-effort writes:** the store trait methods are infallible, so a write/crypto error
//! degrades to "not persisted this run" (in-memory delivery still works) rather than
//! crashing. Only [`SealedFileStore::open`] is fallible (wrong custody / corrupt keyfile).

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use rand::RngCore;
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

use crate::error::{CoreError, Result};
use crate::history::HistoryStore;
use crate::outbox::OutboxStore;
use crate::seal::{seal, unseal, KeyWrapper, SealOptions};

const DEK_LEN: usize = 32;
const NONCE_LEN: usize = 12;
const KEYFILE: &str = "keyfile";
const OUTBOX_SUBDIR: &str = "outbox";
const HISTORY_SUBDIR: &str = "history";

/// A sealed, on-disk store implementing BOTH [`OutboxStore`] and [`HistoryStore`]. Inject
/// one instance for restart survival: `core.set_outbox_store(store.clone())` and/or
/// `core.set_history_store(store)`.
pub struct SealedFileStore {
    root: PathBuf,
    dek: [u8; DEK_LEN],
    /// Serializes the temp-write+rename so concurrent puts don't race the rename.
    write_lock: Mutex<()>,
}

impl SealedFileStore {
    /// Open (or initialize on first use) a sealed store rooted at `dir`. `passphrase`
    /// and/or `wrapper` are the SAME custody factors the host uses for the identity (at
    /// least one is required, matching [`crate::seal::seal`]). First open generates a fresh
    /// random DEK and seals it to `<dir>/keyfile`; later opens unseal it (wrong custody or a
    /// tampered keyfile fails closed).
    pub fn open(
        dir: &Path,
        passphrase: Option<&[u8]>,
        wrapper: Option<&dyn KeyWrapper>,
    ) -> Result<Self> {
        // QROM / L5 at-rest rule (message data stays baseline-safe — no weak opt-out here):
        // a non-PQ hardware wrapper may protect the KEK with a CLASSICAL, quantum-breakable
        // wrap, so a hardware-ONLY store is refused UNLESS the wrapper attests a symmetric
        // (QROM-safe) wrap. Otherwise pair it with a passphrase, whose Argon2id 256-bit key
        // is mixed into the KEK (seal::derive_kek) so the stored AES-256-GCM contents stay
        // L5/QROM-safe even if the hardware wrap is later broken. Fail fast with a clear
        // message before touching the fs (`seal` enforces the same rule regardless).
        if wrapper.is_some()
            && passphrase.is_none()
            && !wrapper.map(|w| w.qrom_safe()).unwrap_or(false)
        {
            return Err(CoreError::Seal(
                "at-rest hardware custody must be QROM-safe (a symmetric wrapper) or paired \
                 with a passphrase (QROM/L5): a classical secure element may wrap the key \
                 with quantum-breakable crypto",
            ));
        }
        fs::create_dir_all(dir).map_err(|_| CoreError::Seal("cannot create store dir"))?;
        let keyfile = dir.join(KEYFILE);
        let dek = if keyfile.exists() {
            let blob = fs::read(&keyfile).map_err(|_| CoreError::Seal("cannot read keyfile"))?;
            let mut raw = unseal(&blob, passphrase, wrapper)?;
            if raw.len() != DEK_LEN {
                raw.zeroize();
                return Err(CoreError::Seal("sealed DEK has wrong length"));
            }
            let mut dek = [0u8; DEK_LEN];
            dek.copy_from_slice(&raw);
            raw.zeroize();
            dek
        } else {
            let mut dek = [0u8; DEK_LEN];
            rand::rngs::OsRng.fill_bytes(&mut dek);
            let blob = seal(&dek, SealOptions { passphrase, wrapper, ..Default::default() })?;
            write_atomic(&keyfile, &blob).map_err(|_| CoreError::Seal("cannot write keyfile"))?;
            dek
        };
        Ok(Self { root: dir.to_path_buf(), dek, write_lock: Mutex::new(()) })
    }

    fn chat_hash(chat: &str) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(chat.as_bytes());
        h.finalize().into()
    }

    fn chat_dir(&self, subdir: &str, chat_hash: &[u8; 32]) -> PathBuf {
        self.root.join(subdir).join(hex(chat_hash))
    }

    /// AAD binds the record to its store kind, chat, and id — so a ciphertext moved to a
    /// different location (or across the outbox/history split) fails to open.
    fn aad(subdir: &str, chat_hash: &[u8; 32], gid: &[u8; 32]) -> Vec<u8> {
        let mut aad = Vec::with_capacity(subdir.len() + 64);
        aad.extend_from_slice(subdir.as_bytes());
        aad.extend_from_slice(chat_hash);
        aad.extend_from_slice(gid);
        aad
    }

    fn put_record(&self, subdir: &str, chat: &str, gid: [u8; 32], record: &[u8]) {
        let ch = Self::chat_hash(chat);
        let dir = self.chat_dir(subdir, &ch);
        if fs::create_dir_all(&dir).is_err() {
            return; // best-effort: degrade to non-persistent
        }
        let mut nonce = [0u8; NONCE_LEN];
        rand::rngs::OsRng.fill_bytes(&mut nonce);
        let aad = Self::aad(subdir, &ch, &gid);
        let Ok(ct) = talkrypt_crypto::aead::seal(&self.dek, &nonce, record, &aad) else {
            return;
        };
        let mut blob = Vec::with_capacity(NONCE_LEN + ct.len());
        blob.extend_from_slice(&nonce);
        blob.extend_from_slice(&ct);
        let _guard = self.write_lock.lock().unwrap();
        let _ = write_atomic(&dir.join(hex(&gid)), &blob);
    }

    fn load_records(&self, subdir: &str, chat: &str) -> Vec<([u8; 32], Vec<u8>)> {
        let ch = Self::chat_hash(chat);
        let dir = self.chat_dir(subdir, &ch);
        let Ok(entries) = fs::read_dir(&dir) else {
            return Vec::new();
        };
        let mut out = Vec::new();
        for entry in entries.flatten() {
            let name = entry.file_name();
            let Some(name) = name.to_str() else { continue };
            let Some(gid) = unhex32(name) else { continue }; // skips stray/.tmp files
            let Ok(blob) = fs::read(entry.path()) else { continue };
            if blob.len() < NONCE_LEN {
                continue;
            }
            let mut nonce = [0u8; NONCE_LEN];
            nonce.copy_from_slice(&blob[..NONCE_LEN]);
            let aad = Self::aad(subdir, &ch, &gid);
            if let Ok(rec) = talkrypt_crypto::aead::open(&self.dek, &nonce, &blob[NONCE_LEN..], &aad) {
                out.push((gid, rec)); // tampered/foreign records fail open() and are skipped
            }
        }
        out
    }

    fn remove_record(&self, subdir: &str, chat: &str, gid: [u8; 32]) {
        let ch = Self::chat_hash(chat);
        let _ = fs::remove_file(self.chat_dir(subdir, &ch).join(hex(&gid)));
    }

    fn purge_chat(&self, subdir: &str, chat: &str) {
        let ch = Self::chat_hash(chat);
        let _ = fs::remove_dir_all(self.chat_dir(subdir, &ch));
    }
}

impl Drop for SealedFileStore {
    fn drop(&mut self) {
        self.dek.zeroize();
    }
}

impl OutboxStore for SealedFileStore {
    fn put(&self, chat: &str, gid: [u8; 32], frame: &[u8]) {
        self.put_record(OUTBOX_SUBDIR, chat, gid, frame);
    }
    fn remove(&self, chat: &str, gid: [u8; 32]) {
        self.remove_record(OUTBOX_SUBDIR, chat, gid);
    }
    fn load(&self, chat: &str) -> Vec<([u8; 32], Vec<u8>)> {
        self.load_records(OUTBOX_SUBDIR, chat)
    }
}

impl HistoryStore for SealedFileStore {
    fn put(&self, chat: &str, gid: [u8; 32], record: &[u8]) {
        self.put_record(HISTORY_SUBDIR, chat, gid, record);
    }
    fn load(&self, chat: &str) -> Vec<([u8; 32], Vec<u8>)> {
        self.load_records(HISTORY_SUBDIR, chat)
    }
    fn purge(&self, chat: &str) {
        self.purge_chat(HISTORY_SUBDIR, chat);
    }
}

/// Write `bytes` to `path` atomically: write a sibling temp file, then rename over the
/// target (rename is atomic on the platforms we support).
fn write_atomic(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let tmp = path.with_extension("tmp");
    fs::write(&tmp, bytes)?;
    fs::rename(&tmp, path)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Parse exactly 64 lowercase-hex chars into a `[u8; 32]`; `None` for anything else (so
/// non-record files like `<gid>.tmp` are ignored during load).
fn unhex32(s: &str) -> Option<[u8; 32]> {
    if s.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, chunk) in s.as_bytes().chunks(2).enumerate() {
        let hi = (chunk[0] as char).to_digit(16)?;
        let lo = (chunk[1] as char).to_digit(16)?;
        out[i] = (hi * 16 + lo) as u8;
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmpdir(tag: &str) -> PathBuf {
        // A unique-enough scratch dir under the OS temp root (tests are single-process).
        let mut p = std::env::temp_dir();
        let mut n = [0u8; 8];
        rand::rngs::OsRng.fill_bytes(&mut n);
        p.push(format!("tk-atrest-{tag}-{}", hex(&n)));
        p
    }

    const PW: &[u8] = b"correct horse battery staple";

    #[test]
    fn outbox_roundtrips_across_reopen() {
        let dir = tmpdir("ob");
        let gid = [7u8; 32];
        {
            let s = SealedFileStore::open(&dir, Some(PW), None).unwrap();
            <SealedFileStore as OutboxStore>::put(&s, "#general", gid, b"opaque-frame-bytes");
            assert_eq!(<SealedFileStore as OutboxStore>::load(&s, "#general").len(), 1);
        }
        // Reopen (simulates a restart): the DEK is unsealed and the record decrypts.
        {
            let s = SealedFileStore::open(&dir, Some(PW), None).unwrap();
            let loaded = <SealedFileStore as OutboxStore>::load(&s, "#general");
            assert_eq!(loaded.len(), 1, "record survives reopen");
            assert_eq!(loaded[0].0, gid);
            assert_eq!(loaded[0].1, b"opaque-frame-bytes");
            <SealedFileStore as OutboxStore>::remove(&s, "#general", gid);
            assert!(<SealedFileStore as OutboxStore>::load(&s, "#general").is_empty());
        }
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn wrong_passphrase_fails_to_open() {
        let dir = tmpdir("wpw");
        {
            let s = SealedFileStore::open(&dir, Some(PW), None).unwrap();
            <SealedFileStore as HistoryStore>::put(&s, "#c", [1u8; 32], b"secret history");
        }
        // A different passphrase cannot unseal the DEK.
        assert!(SealedFileStore::open(&dir, Some(b"wrong passphrase"), None).is_err());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn hardware_wrapper_custody_roundtrips_and_wrong_device_fails() {
        use crate::seal::{KeyWrapper, WrapError};
        // A toy "secure element": device-bound because only a wrapper with the same key
        // byte reverses the wrap (a real SE binds to hardware). Wraps a SYMMETRIC DEK —
        // permitted even though the SE cannot custody the PQ identity key (R-8 / §3b).
        struct Se(u8);
        impl KeyWrapper for Se {
            fn wrap(&self, k: &[u8]) -> std::result::Result<Vec<u8>, WrapError> {
                Ok(k.iter().map(|b| b ^ self.0).collect())
            }
            fn unwrap(&self, w: &[u8]) -> std::result::Result<Vec<u8>, WrapError> {
                Ok(w.iter().map(|b| b ^ self.0).collect())
            }
        }
        let dir = tmpdir("hw");
        let gid = [2u8; 32];
        // Two-factor: hardware wrapper + passphrase (device-bound AND QROM/L5-safe at rest).
        {
            let s = SealedFileStore::open(&dir, Some(PW), Some(&Se(0x5a))).unwrap();
            <SealedFileStore as OutboxStore>::put(&s, "#c", gid, b"hw-sealed");
        }
        // Reopen on the SAME device with both factors: the DEK unwraps and the record decrypts.
        {
            let s = SealedFileStore::open(&dir, Some(PW), Some(&Se(0x5a))).unwrap();
            let loaded = <SealedFileStore as OutboxStore>::load(&s, "#c");
            assert_eq!(loaded.len(), 1);
            assert_eq!(loaded[0].1, b"hw-sealed");
        }
        // A DIFFERENT device (different wrapper), even with the right passphrase, fails closed.
        assert!(SealedFileStore::open(&dir, Some(PW), Some(&Se(0x33))).is_err());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn hardware_wrapper_alone_is_refused_for_qrom_l5() {
        use crate::seal::{KeyWrapper, WrapError};
        struct Se;
        impl KeyWrapper for Se {
            fn wrap(&self, k: &[u8]) -> std::result::Result<Vec<u8>, WrapError> { Ok(k.to_vec()) }
            fn unwrap(&self, w: &[u8]) -> std::result::Result<Vec<u8>, WrapError> { Ok(w.to_vec()) }
        }
        let dir = tmpdir("hwonly");
        // A classical hardware wrapper alone could be quantum-breakable at rest → refused.
        assert!(SealedFileStore::open(&dir, None, Some(&Se)).is_err());
        // A passphrase alone is fully PQ-safe → allowed.
        assert!(SealedFileStore::open(&dir, Some(PW), None).is_ok());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn outbox_and_history_do_not_collide() {
        let dir = tmpdir("split");
        let s = SealedFileStore::open(&dir, Some(PW), None).unwrap();
        let gid = [9u8; 32];
        // Same (chat, gid) in both stores — disjoint subdirs keep them independent.
        <SealedFileStore as OutboxStore>::put(&s, "#x", gid, b"outbox-record");
        <SealedFileStore as HistoryStore>::put(&s, "#x", gid, b"history-record");
        assert_eq!(<SealedFileStore as OutboxStore>::load(&s, "#x")[0].1, b"outbox-record");
        assert_eq!(<SealedFileStore as HistoryStore>::load(&s, "#x")[0].1, b"history-record");
        // purge is history-only and per-chat.
        <SealedFileStore as HistoryStore>::purge(&s, "#x");
        assert!(<SealedFileStore as HistoryStore>::load(&s, "#x").is_empty());
        assert_eq!(<SealedFileStore as OutboxStore>::load(&s, "#x").len(), 1, "purge left outbox intact");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn tampered_record_is_skipped_not_returned() {
        let dir = tmpdir("tamper");
        let gid = [3u8; 32];
        let s = SealedFileStore::open(&dir, Some(PW), None).unwrap();
        <SealedFileStore as OutboxStore>::put(&s, "#c", gid, b"data");
        // Flip a byte in the stored ciphertext.
        let rec_path = s.chat_dir(OUTBOX_SUBDIR, &SealedFileStore::chat_hash("#c")).join(hex(&gid));
        let mut blob = fs::read(&rec_path).unwrap();
        let last = blob.len() - 1;
        blob[last] ^= 0xff;
        fs::write(&rec_path, &blob).unwrap();
        assert!(
            <SealedFileStore as OutboxStore>::load(&s, "#c").is_empty(),
            "a tampered record fails AEAD open and is skipped"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn open_requires_a_custody_factor() {
        let dir = tmpdir("nofactor");
        assert!(SealedFileStore::open(&dir, None, None).is_err());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn unhex32_rejects_non_records() {
        assert!(unhex32("deadbeef").is_none()); // too short
        assert!(unhex32(&"z".repeat(64)).is_none()); // non-hex
        assert!(unhex32(&format!("{}.tmp", "aa".repeat(31))).is_none());
        assert!(unhex32(&"ab".repeat(32)).is_some());
    }
}
