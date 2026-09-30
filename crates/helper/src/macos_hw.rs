//! macOS hardware-adjacent KEK wrappers for the `HardwareBacked` custody tier.
//!
//! Two backends, with deliberately different trust and validation stories — pick
//! per deployment and plug via [`crate::store::KeyStore::with_wrapper`]:
//!
//! * [`KeychainAesWrapper`] — a random **AES-256** wrapping key custodied in the
//!   login **Keychain**; the KEK is wrapped with AES-256-GCM. The wrap is
//!   symmetric ≥256-bit, so it is [`KeyWrapper::qrom_safe`] `= true`: the KEK at
//!   rest is not quantum-recoverable. The wrapping key is protected by the
//!   Keychain (on a T2 / Apple-silicon Mac the Keychain's own class keys are
//!   Secure-Enclave-protected), but it is **readable by this process** — this is
//!   *OS-keystore-grade* custody, NOT a Secure-Enclave non-exportable key. Needs
//!   no entitlement, so it is testable from a plain binary and **is** covered by
//!   a unit test here.
//!
//! * [`SecureEnclaveWrapper`] — a P-256 key minted **inside the Secure Enclave**
//!   (non-exportable); the KEK is wrapped with ECIES (`SecKeyCreateEncryptedData`
//!   / `…DecryptedData`) against it. This is a true hardware-bound key. ECIES is
//!   classical (P-256), so it is `qrom_safe() = false`: the core seal seam then
//!   **requires a passphrase**, whose Argon2id-256 key is mixed into the KEK and
//!   keeps the AES-256-GCM seed post-quantum-safe at rest even if P-256 later
//!   falls (the "PQ security inside a non-PQ HSM" property). For a *hardware*-PQ
//!   wrap with no passphrase, use the SEALSQ PQ secure element instead
//!   ([`crate::pqse`]).
//!
//! # Validation status of [`SecureEnclaveWrapper`]
//!
//! Secure Enclave key creation requires a **code-signed** build carrying the
//! keychain-access-group / Secure-Enclave entitlement. From an unsigned binary
//! (e.g. `cargo test`) `SecKeyCreateRandomKey` returns `errSecMissingEntitlement`.
//! This code therefore **compiles and is type-checked here but is not runtime-
//! validated** — its unit test probes [`SecureEnclaveWrapper::available`] and
//! skips when the Enclave is not reachable. Ship it only in a signed app bundle;
//! [`crate::store::KeyStore`] never selects it automatically (see
//! `platform_hw_wrapper`), so an unsigned build silently falls back rather than
//! failing.

#![cfg(all(target_os = "macos", feature = "macos-se"))]

use std::sync::Arc;

use talkrypt_core::{KeyWrapper, WrapError};

use crate::keychain;

// ---------------------------------------------------------------------------
// KeychainAesWrapper — OS-keystore-grade symmetric (QROM-safe) KEK wrap.
// ---------------------------------------------------------------------------

/// Default Keychain account under which the AES-256 wrapping key is stored.
const AES_WRAP_ACCOUNT: &str = "tk-kek-wrap-aes256";
const KC_MAGIC: &[u8; 4] = b"TKMK"; // talkrypt macOS keychain wrap
const KC_VERSION: u8 = 1;
const NONCE_LEN: usize = 12;
const AES_KEY_LEN: usize = 32;

/// Wraps the KEK with an AES-256 key custodied in the login Keychain.
///
/// `qrom_safe() = true` — a symmetric ≥256-bit wrap, so a hardware-only seal is
/// permitted and the KEK at rest is post-quantum. See the module docs for the
/// (important) caveat that the wrapping key is OS-keystore-grade, not a Secure
/// Enclave non-exportable key.
pub struct KeychainAesWrapper {
    account: String,
}

impl Default for KeychainAesWrapper {
    fn default() -> Self {
        Self::new()
    }
}

impl KeychainAesWrapper {
    /// Use the default wrapping-key account.
    pub fn new() -> Self {
        Self {
            account: AES_WRAP_ACCOUNT.to_string(),
        }
    }

    /// Use a caller-chosen Keychain account name for the wrapping key (lets an
    /// operator scope distinct keys per profile).
    pub fn with_account(account: impl Into<String>) -> Self {
        Self {
            account: account.into(),
        }
    }

    /// Fetch the AES-256 wrapping key from the Keychain, minting and persisting
    /// a fresh one on first use.
    fn wrapping_key(&self) -> Result<[u8; AES_KEY_LEN], WrapError> {
        match keychain::get(&self.account) {
            Ok(bytes) if bytes.len() == AES_KEY_LEN => {
                let mut k = [0u8; AES_KEY_LEN];
                k.copy_from_slice(&bytes);
                Ok(k)
            }
            Ok(_) => Err(WrapError("keychain wrapping key has wrong length".into())),
            Err(crate::error::HelperError::NotFound) => {
                let mut k = [0u8; AES_KEY_LEN];
                talkrypt_crypto::fill_secure(&mut k);
                keychain::set(&self.account, &k)
                    .map_err(|e| WrapError(format!("keychain store wrapping key: {e}")))?;
                Ok(k)
            }
            Err(e) => Err(WrapError(format!("keychain fetch wrapping key: {e}"))),
        }
    }
}

impl KeyWrapper for KeychainAesWrapper {
    fn wrap(&self, kek: &[u8]) -> Result<Vec<u8>, WrapError> {
        let key = self.wrapping_key()?;
        let mut nonce = [0u8; NONCE_LEN];
        talkrypt_crypto::fill_secure(&mut nonce);
        let mut header = Vec::with_capacity(5 + NONCE_LEN);
        header.extend_from_slice(KC_MAGIC);
        header.push(KC_VERSION);
        header.extend_from_slice(&nonce);
        let ct = talkrypt_crypto::aead::seal(&key, &nonce, kek, &header)
            .map_err(|e| WrapError(format!("keychain-aes seal: {e}")))?;
        let mut out = header;
        out.extend_from_slice(&ct);
        Ok(out)
    }

    fn unwrap(&self, wrapped: &[u8]) -> Result<Vec<u8>, WrapError> {
        if wrapped.len() < 5 + NONCE_LEN || &wrapped[..4] != KC_MAGIC || wrapped[4] != KC_VERSION {
            return Err(WrapError("keychain-aes: bad header".into()));
        }
        let key = self.wrapping_key()?;
        let header = &wrapped[..5 + NONCE_LEN];
        let mut nonce = [0u8; NONCE_LEN];
        nonce.copy_from_slice(&wrapped[5..5 + NONCE_LEN]);
        let ct = &wrapped[5 + NONCE_LEN..];
        talkrypt_crypto::aead::open(&key, &nonce, ct, header)
            .map_err(|e| WrapError(format!("keychain-aes open: {e}")))
    }

    fn qrom_safe(&self) -> bool {
        true // AES-256 symmetric wrap
    }
}

// ---------------------------------------------------------------------------
// SecureEnclaveWrapper — true hardware-bound P-256 ECIES KEK wrap.
//   Classical (qrom_safe=false) → the seal seam forces a passphrase.
//   COMPILE-CHECKED ONLY without a signed build (see module docs).
// ---------------------------------------------------------------------------

mod se {
    //! Thin, RAII-wrapped FFI over the Security framework SecKey API. Kept in a
    //! submodule so the `unsafe` surface is small and auditable.

    use core_foundation::base::{TCFType, ToVoid};
    use core_foundation::boolean::CFBoolean;
    use core_foundation::data::CFData;
    use core_foundation::dictionary::CFMutableDictionary;
    use core_foundation::number::CFNumber;
    use core_foundation::string::CFString;
    use security_framework::access_control::{ProtectionMode, SecAccessControl};
    use security_framework::key::SecKey;
    use security_framework_sys::access_control::kSecAccessControlPrivateKeyUsage;
    use security_framework_sys::item::{
        kSecAttrAccessControl, kSecAttrIsPermanent, kSecAttrKeySizeInBits, kSecAttrKeyType,
        kSecAttrKeyTypeECSECPrimeRandom, kSecAttrLabel, kSecAttrTokenID,
        kSecAttrTokenIDSecureEnclave, kSecClass, kSecClassKey, kSecPrivateKeyAttrs, kSecReturnRef,
    };
    use security_framework_sys::key::{
        kSecKeyAlgorithmECIESEncryptionCofactorX963SHA256AESGCM, SecKeyCopyPublicKey,
        SecKeyCreateDecryptedData, SecKeyCreateEncryptedData, SecKeyCreateRandomKey,
    };
    use security_framework_sys::keychain_item::SecItemCopyMatching;

    use core_foundation_sys::base::{CFRelease, CFTypeRef};
    use core_foundation_sys::error::CFErrorRef;
    use security_framework_sys::base::SecKeyRef;

    use talkrypt_core::WrapError;

    /// The Keychain label identifying our Secure-Enclave KEK key.
    const SE_KEY_LABEL: &str = "talkrypt-se-kek-p256";

    fn cf_err(msg: &str) -> WrapError {
        WrapError(format!("secure-enclave: {msg}"))
    }

    /// Load the persistent SE key, or mint one if absent. Returns an owned
    /// [`SecKey`] (RAII — released on drop).
    fn load_or_create() -> Result<SecKey, WrapError> {
        if let Some(k) = load()? {
            return Ok(k);
        }
        create()
    }

    /// Look up the persistent SE key by label.
    fn load() -> Result<Option<SecKey>, WrapError> {
        let label = CFString::new(SE_KEY_LABEL);
        let query = CFMutableDictionary::from_CFType_pairs(&[
            (unsafe { kSecClass }.to_void(), unsafe { kSecClassKey }.to_void()),
            (unsafe { kSecAttrLabel }.to_void(), label.to_void()),
            (
                unsafe { kSecReturnRef }.to_void(),
                CFBoolean::true_value().to_void(),
            ),
        ])
        .to_immutable();
        let mut out: CFTypeRef = std::ptr::null();
        let status = unsafe { SecItemCopyMatching(query.as_concrete_TypeRef(), &mut out) };
        const ERR_SEC_ITEM_NOT_FOUND: i32 = -25300;
        if status == ERR_SEC_ITEM_NOT_FOUND {
            return Ok(None);
        }
        if status != 0 || out.is_null() {
            return Err(cf_err(&format!("SecItemCopyMatching status {status}")));
        }
        // CopyMatching with kSecReturnRef gives a +1 retained SecKeyRef.
        Ok(Some(unsafe {
            SecKey::wrap_under_create_rule(out as SecKeyRef)
        }))
    }

    /// Mint a fresh non-exportable P-256 key inside the Secure Enclave.
    fn create() -> Result<SecKey, WrapError> {
        // Access control: private-key usage, available after first unlock, bound
        // to this device only. RAII via the safe `SecAccessControl` wrapper.
        let ac = SecAccessControl::create_with_protection(
            Some(ProtectionMode::AccessibleAfterFirstUnlockThisDeviceOnly),
            kSecAccessControlPrivateKeyUsage,
        )
        .map_err(|_| cf_err("SecAccessControlCreateWithFlags failed"))?;

        let label = CFString::new(SE_KEY_LABEL);
        let key_size = CFNumber::from(256i32);

        // Private-key sub-attributes: permanent + access control.
        let priv_attrs = CFMutableDictionary::from_CFType_pairs(&[
            (
                unsafe { kSecAttrIsPermanent }.to_void(),
                CFBoolean::true_value().to_void(),
            ),
            (unsafe { kSecAttrAccessControl }.to_void(), ac.to_void()),
        ])
        .to_immutable();

        let params = CFMutableDictionary::from_CFType_pairs(&[
            (
                unsafe { kSecAttrKeyType }.to_void(),
                unsafe { kSecAttrKeyTypeECSECPrimeRandom }.to_void(),
            ),
            (unsafe { kSecAttrKeySizeInBits }.to_void(), key_size.to_void()),
            (
                unsafe { kSecAttrTokenID }.to_void(),
                unsafe { kSecAttrTokenIDSecureEnclave }.to_void(),
            ),
            (unsafe { kSecAttrLabel }.to_void(), label.to_void()),
            (unsafe { kSecPrivateKeyAttrs }.to_void(), priv_attrs.to_void()),
        ])
        .to_immutable();

        let mut gen_err: CFErrorRef = std::ptr::null_mut();
        let key = unsafe { SecKeyCreateRandomKey(params.as_concrete_TypeRef(), &mut gen_err) };
        if key.is_null() {
            let detail = if gen_err.is_null() {
                "no CFError".to_string()
            } else {
                let e = unsafe { core_foundation::error::CFError::wrap_under_create_rule(gen_err) };
                e.to_string()
            };
            return Err(cf_err(&format!(
                "SecKeyCreateRandomKey failed (needs a signed build with the \
                 Secure-Enclave entitlement): {detail}"
            )));
        }
        Ok(unsafe { SecKey::wrap_under_create_rule(key) })
    }

    /// Mint a **non-permanent** Secure Enclave key (not written to the keychain).
    /// Needs only a code signature — not the `keychain-access-groups` entitlement
    /// that permanent storage requires — so it can exercise real Enclave ECIES on
    /// a dev machine. For a self-test / capability probe only; a non-persisted key
    /// is useless for at-rest custody across restarts.
    fn create_ephemeral() -> Result<SecKey, WrapError> {
        let ac = SecAccessControl::create_with_protection(
            Some(ProtectionMode::AccessibleAfterFirstUnlockThisDeviceOnly),
            kSecAccessControlPrivateKeyUsage,
        )
        .map_err(|_| cf_err("SecAccessControlCreateWithFlags failed"))?;
        let key_size = CFNumber::from(256i32);
        // Private-key attrs WITHOUT kSecAttrIsPermanent → nothing is added to the
        // keychain, so no entitlement is needed.
        let priv_attrs = CFMutableDictionary::from_CFType_pairs(&[(
            unsafe { kSecAttrAccessControl }.to_void(),
            ac.to_void(),
        )])
        .to_immutable();
        let params = CFMutableDictionary::from_CFType_pairs(&[
            (
                unsafe { kSecAttrKeyType }.to_void(),
                unsafe { kSecAttrKeyTypeECSECPrimeRandom }.to_void(),
            ),
            (unsafe { kSecAttrKeySizeInBits }.to_void(), key_size.to_void()),
            (
                unsafe { kSecAttrTokenID }.to_void(),
                unsafe { kSecAttrTokenIDSecureEnclave }.to_void(),
            ),
            (unsafe { kSecPrivateKeyAttrs }.to_void(), priv_attrs.to_void()),
        ])
        .to_immutable();
        let mut gen_err: CFErrorRef = std::ptr::null_mut();
        let key = unsafe { SecKeyCreateRandomKey(params.as_concrete_TypeRef(), &mut gen_err) };
        if key.is_null() {
            let detail = if gen_err.is_null() {
                "no CFError".to_string()
            } else {
                let e = unsafe { core_foundation::error::CFError::wrap_under_create_rule(gen_err) };
                e.to_string()
            };
            return Err(cf_err(&format!("ephemeral SE keygen failed: {detail}")));
        }
        Ok(unsafe { SecKey::wrap_under_create_rule(key) })
    }

    /// Exercise the real Secure Enclave ECIES wrap/unwrap on an ephemeral SE key:
    /// encrypt `kek` to the key's public half and decrypt with the Enclave,
    /// asserting the round-trip. Proves the hardware path without needing the
    /// permanent-storage entitlement. Returns `Ok(())` on a verified round-trip.
    pub fn ephemeral_hardware_selftest(kek: &[u8]) -> Result<(), WrapError> {
        let key = create_ephemeral()?;
        let ct = wrap_with(&key, kek)?;
        let pt = unwrap_with(&key, &ct)?;
        if pt != kek {
            return Err(cf_err("ephemeral SE round-trip mismatch"));
        }
        Ok(())
    }

    /// ECIES-encrypt `kek` to `priv_key`'s public half.
    fn wrap_with(priv_key: &SecKey, kek: &[u8]) -> Result<Vec<u8>, WrapError> {
        let pub_ref = unsafe { SecKeyCopyPublicKey(priv_key.as_concrete_TypeRef()) };
        if pub_ref.is_null() {
            return Err(cf_err("SecKeyCopyPublicKey failed"));
        }
        let pub_key = unsafe { SecKey::wrap_under_create_rule(pub_ref) };
        let pt = CFData::from_buffer(kek);
        let mut err: CFErrorRef = std::ptr::null_mut();
        let ct = unsafe {
            SecKeyCreateEncryptedData(
                pub_key.as_concrete_TypeRef(),
                kSecKeyAlgorithmECIESEncryptionCofactorX963SHA256AESGCM,
                pt.as_concrete_TypeRef(),
                &mut err,
            )
        };
        if ct.is_null() {
            if !err.is_null() {
                unsafe { CFRelease(err as CFTypeRef) };
            }
            return Err(cf_err("SecKeyCreateEncryptedData failed"));
        }
        Ok(unsafe { CFData::wrap_under_create_rule(ct) }.to_vec())
    }

    /// ECIES-decrypt `wrapped` with `priv_key`.
    fn unwrap_with(priv_key: &SecKey, wrapped: &[u8]) -> Result<Vec<u8>, WrapError> {
        let ctd = CFData::from_buffer(wrapped);
        let mut err: CFErrorRef = std::ptr::null_mut();
        let pt = unsafe {
            SecKeyCreateDecryptedData(
                priv_key.as_concrete_TypeRef(),
                kSecKeyAlgorithmECIESEncryptionCofactorX963SHA256AESGCM,
                ctd.as_concrete_TypeRef(),
                &mut err,
            )
        };
        if pt.is_null() {
            if !err.is_null() {
                unsafe { CFRelease(err as CFTypeRef) };
            }
            return Err(cf_err("SecKeyCreateDecryptedData failed"));
        }
        Ok(unsafe { CFData::wrap_under_create_rule(pt) }.to_vec())
    }

    /// Is a usable Secure Enclave key reachable (loadable or mintable) right now?
    pub fn available() -> bool {
        load_or_create().is_ok()
    }

    /// Can the Secure Enclave mint a key and perform ECIES at all (ignoring the
    /// permanent-storage entitlement)? True on a code-signed dev build on Enclave
    /// hardware; false on an unsigned build or a Mac without an Enclave.
    pub fn hardware_usable() -> bool {
        ephemeral_hardware_selftest(&[0u8; 32]).is_ok()
    }

    /// Wrap `kek` to the persistent SE key via ECIES.
    pub fn wrap(kek: &[u8]) -> Result<Vec<u8>, WrapError> {
        let priv_key = load_or_create()?;
        wrap_with(&priv_key, kek)
    }

    /// Unwrap an ECIES blob with the persistent SE private key.
    pub fn unwrap(wrapped: &[u8]) -> Result<Vec<u8>, WrapError> {
        let priv_key = load_or_create()?;
        unwrap_with(&priv_key, wrapped)
    }
}

/// A [`KeyWrapper`] backed by a non-exportable **Secure Enclave** P-256 key
/// (ECIES KEK wrap). Classical → `qrom_safe() = false`, so the seal seam pairs
/// it with a passphrase for post-quantum at-rest safety. See the module docs for
/// the signed-build / validation caveat.
pub struct SecureEnclaveWrapper;

impl SecureEnclaveWrapper {
    /// Construct a wrapper. Cheap; the SE key is loaded/minted lazily on first
    /// `wrap`/`unwrap`. Use [`SecureEnclaveWrapper::available`] to probe first.
    pub fn new() -> Self {
        SecureEnclaveWrapper
    }

    /// Whether the persistent SE-backed key can be loaded or minted right now —
    /// i.e. the full production path works. False on a build without the
    /// `keychain-access-groups` entitlement (permanent storage), or hardware with
    /// no Enclave.
    pub fn available() -> bool {
        se::available()
    }

    /// Whether the Secure Enclave can mint a key and perform ECIES **at all**,
    /// ignoring the permanent-storage entitlement. True on a code-signed dev
    /// build on Enclave hardware even when [`available`](Self::available) is false
    /// (no keychain entitlement). Useful to validate the hardware ECIES path.
    pub fn hardware_usable() -> bool {
        se::hardware_usable()
    }

    /// Run a real Secure Enclave ECIES wrap/unwrap round-trip on an ephemeral
    /// Enclave key and verify it. `Ok(())` proves the hardware path; errors carry
    /// the underlying `CFError`.
    pub fn hardware_selftest() -> Result<(), WrapError> {
        se::ephemeral_hardware_selftest(&[0x42u8; 32])
    }
}

impl Default for SecureEnclaveWrapper {
    fn default() -> Self {
        Self::new()
    }
}

impl KeyWrapper for SecureEnclaveWrapper {
    fn wrap(&self, kek: &[u8]) -> Result<Vec<u8>, WrapError> {
        se::wrap(kek)
    }
    fn unwrap(&self, wrapped: &[u8]) -> Result<Vec<u8>, WrapError> {
        se::unwrap(wrapped)
    }
    fn qrom_safe(&self) -> bool {
        false // classical P-256 ECIES
    }
}

/// Convenience: the recommended macOS wrapper for a *given* posture.
///
/// Returns a Secure-Enclave wrapper when the Enclave is reachable (true hardware
/// binding; the seam will require a passphrase), else the Keychain-AES wrapper
/// (QROM-safe, passphrase-optional). Callers that want a specific backend should
/// construct it directly and pass it to [`crate::store::KeyStore::with_wrapper`].
pub fn recommended_wrapper() -> Arc<dyn KeyWrapper + Send + Sync> {
    if SecureEnclaveWrapper::available() {
        Arc::new(SecureEnclaveWrapper::new())
    } else {
        Arc::new(KeychainAesWrapper::new())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use talkrypt_core::seal::{seal, unseal, SealOptions};

    #[test]
    fn keychain_aes_roundtrip_and_qrom_safe() {
        let w = KeychainAesWrapper::with_account(format!(
            "tk-test-kek-{}",
            std::process::id()
        ));
        assert!(w.qrom_safe());
        let kek = [0x24u8; 32];
        let blob = w.wrap(&kek).unwrap();
        assert!(blob.windows(kek.len()).all(|x| x != kek));
        assert_eq!(w.unwrap(&blob).unwrap(), kek.to_vec());
        // Tamper detection.
        let mut t = blob.clone();
        let last = t.len() - 1;
        t[last] ^= 1;
        assert!(w.unwrap(&t).is_err());
        // Clean up the test wrapping key.
        let _ = crate::keychain::delete(&format!("tk-test-kek-{}", std::process::id()));
    }

    #[test]
    fn keychain_aes_enables_hardware_only_qrom_seal() {
        // qrom_safe wrapper → hardware-only (passphrase-less) seal is permitted.
        let w = KeychainAesWrapper::with_account(format!(
            "tk-test-seal-{}",
            std::process::id()
        ));
        let seed = [9u8; 32];
        let blob = seal(
            &seed,
            SealOptions {
                passphrase: None,
                wrapper: Some(&w),
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(unseal(&blob, None, Some(&w)).unwrap(), seed.to_vec());
        let _ = crate::keychain::delete(&format!("tk-test-seal-{}", std::process::id()));
    }

    /// REAL Secure Enclave ECIES round-trip on this machine's Enclave.
    ///
    /// `#[ignore]` — a default `cargo test` reports this as **ignored**, never a
    /// pass, because the Enclave is unreachable from an unsigned binary. It does
    /// NOT skip-and-pass. Run it for real on a **code-signed** build:
    ///
    /// ```text
    /// cargo test -p talkrypt-helper --features macos-se --no-run
    /// codesign --force --sign "<Apple Development identity>" \
    ///   --entitlements crates/helper/macos-se.entitlements <lib-test-binary>
    /// <lib-test-binary> --ignored secure_enclave_hardware_ecies_roundtrip --nocapture
    /// ```
    ///
    /// Minting an SE key registers a keychain reference, which needs the
    /// `keychain-access-groups` entitlement and therefore a real provisioning
    /// profile (ad-hoc signing + that entitlement is killed by amfid). When run
    /// on a properly signed build this exercises the Enclave and fails loudly if
    /// the hardware path is broken — see `docs/hardware-backed-sealing.md`.
    #[test]
    #[ignore = "needs a code-signed build with the Secure-Enclave/keychain entitlement; run with --ignored"]
    fn secure_enclave_hardware_ecies_roundtrip() {
        // No skip: reaching here (via --ignored) means we intend to hit hardware.
        // A failure to reach the Enclave is a real failure, with the CFError.
        SecureEnclaveWrapper::hardware_selftest().expect("SE ECIES round-trip");
        assert!(!SecureEnclaveWrapper::new().qrom_safe());
    }
}
