//! PKCS#11-backed [`HsmToken`] (feature `pkcs11`).
//!
//! Drives any PKCS#11 token — YubiKey (via `ykcs11`/OpenSC), Nitrokey, SoftHSM2,
//! YubiHSM, Thales/Utimaco, AWS CloudHSM — to wrap/unwrap the 32-byte KEK with a
//! **token-resident AES-256 key**, loaded from the vendor module at runtime (no
//! build-time C dependency). No Apple/OS code-signing identity or entitlement is
//! involved.
//!
//! The mechanism is **AES-256-GCM** (`CKM_AES_GCM`): a valid `C_Encrypt` /
//! `C_Decrypt` mechanism for arbitrary data (unlike the key-wrap mechanisms,
//! which PKCS#11 defines only for `C_WrapKey` on key *objects*), AEAD, and a
//! symmetric ≥256-bit wrap → [`HsmToken::qrom_safe`] `= true` (PQ-at-rest
//! hardware custody with no Apple identity and no passphrase). A fresh 12-byte IV
//! is generated per wrap and stored ahead of the ciphertext+tag.
//!
//! Runtime-validated against **SoftHSM2** (software PKCS#11 token) via the
//! env-gated integration test below; also runs on real tokens.

use cryptoki::context::{CInitializeArgs, CInitializeFlags, Pkcs11};
use cryptoki::mechanism::aead::GcmParams;
use cryptoki::mechanism::Mechanism;
use cryptoki::object::{Attribute, ObjectClass, ObjectHandle};
use cryptoki::session::{Session, UserType};
use cryptoki::types::AuthPin;

use talkrypt_core::WrapError;

use super::HsmToken;

/// IV length for AES-GCM (96-bit, the standard GCM nonce).
const GCM_IV_LEN: usize = 12;
/// GCM authentication tag length in bits.
const GCM_TAG_BITS: u64 = 128;

/// Configuration for a PKCS#11 token wrapping key.
#[derive(Clone, Debug)]
pub struct Pkcs11Config {
    /// Path to the vendor PKCS#11 module (e.g. `/usr/lib/opensc-pkcs11.so`,
    /// `/opt/homebrew/lib/softhsm/libsofthsm2.so`, a YubiHSM module).
    pub module_path: String,
    /// Index into the list of slots-with-token to use (default 0).
    pub slot_index: usize,
    /// Label (`CKA_LABEL`) of the resident AES-256 wrapping key.
    pub key_label: String,
    /// User PIN, if the token requires login for crypto ops.
    pub user_pin: Option<String>,
}

/// A [`HsmToken`] over a PKCS#11 token. Holds the initialized module; each
/// wrap/unwrap opens a session, logs in if needed, finds the AES key by label,
/// and runs AES-256-GCM.
pub struct Pkcs11Token {
    cfg: Pkcs11Config,
    ctx: Pkcs11,
}

impl Pkcs11Token {
    /// Load the vendor module and initialize the PKCS#11 context.
    pub fn open(cfg: Pkcs11Config) -> Result<Self, WrapError> {
        let ctx = Pkcs11::new(&cfg.module_path)
            .map_err(|e| WrapError(format!("pkcs11: load module {}: {e}", cfg.module_path)))?;
        ctx.initialize(CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK))
            .map_err(|e| WrapError(format!("pkcs11: initialize: {e}")))?;
        Ok(Self { cfg, ctx })
    }

    /// Open a logged-in R/W session on the configured slot.
    fn session(&self) -> Result<Session, WrapError> {
        let slots = self
            .ctx
            .get_slots_with_token()
            .map_err(|e| WrapError(format!("pkcs11: list slots: {e}")))?;
        let slot = slots
            .get(self.cfg.slot_index)
            .copied()
            .ok_or_else(|| WrapError(format!("pkcs11: no slot at index {}", self.cfg.slot_index)))?;
        let session = self
            .ctx
            .open_rw_session(slot)
            .map_err(|e| WrapError(format!("pkcs11: open session: {e}")))?;
        if let Some(pin) = &self.cfg.user_pin {
            session
                .login(UserType::User, Some(&AuthPin::from(pin.clone())))
                .map_err(|e| WrapError(format!("pkcs11: login: {e}")))?;
        }
        Ok(session)
    }

    /// Find the AES wrapping key (a secret key with the configured label).
    fn key(&self, session: &Session) -> Result<ObjectHandle, WrapError> {
        let template = [
            Attribute::Class(ObjectClass::SECRET_KEY),
            Attribute::Label(self.cfg.key_label.clone().into_bytes()),
        ];
        let objects = session
            .find_objects(&template)
            .map_err(|e| WrapError(format!("pkcs11: find key: {e}")))?;
        objects
            .into_iter()
            .next()
            .ok_or_else(|| WrapError(format!("pkcs11: no key labelled {}", self.cfg.key_label)))
    }
}

impl HsmToken for Pkcs11Token {
    fn token_wrap(&self, kek: &[u8]) -> Result<Vec<u8>, WrapError> {
        let session = self.session()?;
        let key = self.key(&session)?;
        let mut iv = [0u8; GCM_IV_LEN];
        talkrypt_crypto::fill_secure(&mut iv);
        let ct = {
            let params = GcmParams::new(&mut iv, &[], GCM_TAG_BITS.into())
                .map_err(|e| WrapError(format!("pkcs11: gcm params: {e}")))?;
            session
                .encrypt(&Mechanism::AesGcm(params), key, kek)
                .map_err(|e| WrapError(format!("pkcs11: wrap: {e}")))?
        };
        // Store the (possibly token-updated) IV ahead of the ciphertext+tag.
        let mut out = iv.to_vec();
        out.extend_from_slice(&ct);
        Ok(out)
    }

    fn token_unwrap(&self, blob: &[u8]) -> Result<Vec<u8>, WrapError> {
        if blob.len() < GCM_IV_LEN {
            return Err(WrapError("pkcs11: short blob".into()));
        }
        let session = self.session()?;
        let key = self.key(&session)?;
        let mut iv = [0u8; GCM_IV_LEN];
        iv.copy_from_slice(&blob[..GCM_IV_LEN]);
        let ct = &blob[GCM_IV_LEN..];
        let params = GcmParams::new(&mut iv, &[], GCM_TAG_BITS.into())
            .map_err(|e| WrapError(format!("pkcs11: gcm params: {e}")))?;
        session
            .decrypt(&Mechanism::AesGcm(params), key, ct)
            .map_err(|e| WrapError(format!("pkcs11: unwrap: {e}")))
    }

    fn qrom_safe(&self) -> bool {
        true // AES-256-GCM: symmetric ≥256-bit wrap
    }
}

#[cfg(test)]
mod it {
    //! Integration test against a real PKCS#11 module. `#[ignore]` by default;
    //! run it with SoftHSM2 (software token — no special hardware):
    //!
    //! ```text
    //! export TALKRYPT_PKCS11_MODULE=/opt/homebrew/lib/softhsm/libsofthsm2.so
    //! export TALKRYPT_PKCS11_PIN=1234 TALKRYPT_PKCS11_LABEL=talkrypt-kek
    //! cargo test -p talkrypt-helper --features pkcs11 -- --ignored pkcs11_
    //! ```
    //! The test finds-or-generates the AES-256 key, so no `pkcs11-tool` needed.
    use super::*;
    use crate::hsm::HsmKeyWrapper;
    use std::sync::Arc;
    use talkrypt_core::KeyWrapper;

    /// Ensure an AES-256 key with `label` exists in the token; generate it if not.
    fn ensure_key(tok: &Pkcs11Token) -> Result<(), WrapError> {
        let session = tok.session()?;
        if tok.key(&session).is_ok() {
            return Ok(());
        }
        let template = [
            Attribute::Token(true),
            Attribute::Private(true),
            Attribute::Encrypt(true),
            Attribute::Decrypt(true),
            Attribute::ValueLen(32u64.into()),
            Attribute::Label(tok.cfg.key_label.clone().into_bytes()),
        ];
        session
            .generate_key(&Mechanism::AesKeyGen, &template)
            .map_err(|e| WrapError(format!("pkcs11: generate key: {e}")))?;
        Ok(())
    }

    #[test]
    #[ignore = "needs a PKCS#11 module; set TALKRYPT_PKCS11_MODULE (e.g. SoftHSM2) + _PIN/_LABEL/_SLOT"]
    fn pkcs11_token_gcm_roundtrip_against_real_module() {
        let Ok(module) = std::env::var("TALKRYPT_PKCS11_MODULE") else {
            panic!("set TALKRYPT_PKCS11_MODULE to the PKCS#11 .so/.dylib");
        };
        let slot = std::env::var("TALKRYPT_PKCS11_SLOT")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);
        let label = std::env::var("TALKRYPT_PKCS11_LABEL").unwrap_or_else(|_| "talkrypt-kek".into());
        let pin = std::env::var("TALKRYPT_PKCS11_PIN").ok();

        let tok = Pkcs11Token::open(Pkcs11Config {
            module_path: module,
            slot_index: slot,
            key_label: label,
            user_pin: pin,
        })
        .expect("open token");
        ensure_key(&tok).expect("ensure AES key");

        let w = HsmKeyWrapper::new(Arc::new(tok));
        assert!(w.qrom_safe());
        let kek = [0x5au8; 32];
        let blob = w.wrap(&kek).expect("wrap");
        assert!(blob.windows(kek.len()).all(|x| x != kek), "KEK must not appear in blob");
        assert_eq!(w.unwrap(&blob).expect("unwrap"), kek);
        // A tampered blob must fail the GCM tag (defense in depth over the core seal).
        let mut bad = blob.clone();
        let last = bad.len() - 1;
        bad[last] ^= 1;
        assert!(w.unwrap(&bad).is_err(), "GCM tag must reject tamper");
    }
}
