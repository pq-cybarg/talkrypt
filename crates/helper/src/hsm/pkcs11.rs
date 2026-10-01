//! PKCS#11-backed [`HsmToken`] (feature `pkcs11`).
//!
//! Drives any PKCS#11 token — YubiKey (via `ykcs11`/OpenSC), Nitrokey, SoftHSM2,
//! YubiHSM, Thales/Utimaco, AWS CloudHSM — to wrap/unwrap the 32-byte KEK with a
//! **token-resident key**, loaded from the vendor module at runtime (no build-time
//! C dependency). No Apple/OS code-signing identity or entitlement is involved.
//!
//! The default mechanism is **AES-Key-Wrap-Pad** against a resident **AES-256**
//! key: a symmetric ≥256-bit wrap, so [`HsmToken::qrom_safe`] is `true` — the KEK
//! at rest is post-quantum without needing a passphrase (the same property SEALSQ
//! gives, via symmetric AES rather than ML-KEM). An asymmetric (RSA/ECC) token
//! key would be classical (`qrom_safe = false`) and the seam would require a
//! passphrase; only the symmetric mechanism is wired here.
//!
//! **Compile-checked, not runtime-validated in CI** (no token/SoftHSM in the test
//! environment). Point [`Pkcs11Config::module_path`] at your token's `.so`/`.dylib`
//! and plug the resulting token via
//! [`crate::store::KeyStore::with_wrapper`]`(dir, Arc::new(HsmKeyWrapper::new(Arc::new(token))))`.

use cryptoki::context::{CInitializeArgs, CInitializeFlags, Pkcs11};
use cryptoki::mechanism::Mechanism;
use cryptoki::object::{Attribute, ObjectClass, ObjectHandle};
use cryptoki::session::{Session, UserType};
use cryptoki::types::AuthPin;

use talkrypt_core::WrapError;

use super::HsmToken;

/// How the token wraps the KEK.
#[derive(Clone, Copy, Debug)]
pub enum HsmMechanism {
    /// `CKM_AES_KEY_WRAP_PAD` against a resident AES-256 key — symmetric ≥256-bit,
    /// so QROM-safe at rest. The recommended mechanism.
    AesKeyWrapPad,
}

impl HsmMechanism {
    fn mechanism(self) -> Mechanism<'static> {
        match self {
            HsmMechanism::AesKeyWrapPad => Mechanism::AesKeyWrapPad,
        }
    }

    fn qrom_safe(self) -> bool {
        match self {
            HsmMechanism::AesKeyWrapPad => true, // AES-256 symmetric wrap
        }
    }
}

/// Configuration for a PKCS#11 token wrapping key.
#[derive(Clone, Debug)]
pub struct Pkcs11Config {
    /// Path to the vendor PKCS#11 module (e.g. `/usr/lib/opensc-pkcs11.so`,
    /// `/opt/homebrew/lib/softhsm/libsofthsm2.so`, a YubiHSM module).
    pub module_path: String,
    /// Index into the list of slots-with-token to use (default 0).
    pub slot_index: usize,
    /// Label (`CKA_LABEL`) of the resident wrapping key.
    pub key_label: String,
    /// User PIN, if the token requires login for crypto ops.
    pub user_pin: Option<String>,
    /// Wrap mechanism.
    pub mechanism: HsmMechanism,
}

/// A [`HsmToken`] over a PKCS#11 token. Holds the initialized module; each
/// wrap/unwrap opens a session, logs in if needed, finds the key by label, and
/// runs the mechanism.
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

    /// Open a logged-in session on the configured slot.
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

    /// Find the wrapping key (a secret key with the configured label).
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
        session
            .encrypt(&self.cfg.mechanism.mechanism(), key, kek)
            .map_err(|e| WrapError(format!("pkcs11: wrap: {e}")))
    }

    fn token_unwrap(&self, blob: &[u8]) -> Result<Vec<u8>, WrapError> {
        let session = self.session()?;
        let key = self.key(&session)?;
        session
            .decrypt(&self.cfg.mechanism.mechanism(), key, blob)
            .map_err(|e| WrapError(format!("pkcs11: unwrap: {e}")))
    }

    fn qrom_safe(&self) -> bool {
        self.cfg.mechanism.qrom_safe()
    }
}
