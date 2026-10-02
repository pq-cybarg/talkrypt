//! Windows **CNG / TPM** KEK wrapper for the `HardwareBacked` custody tier
//! (feature `windows-tpm`).
//!
//! Wraps the KEK with a persisted RSA key held by CNG's **Microsoft Platform
//! Crypto Provider** — the TPM-backed key-storage provider — via `NCryptEncrypt`
//! / `NCryptDecrypt` (RSA-OAEP-SHA256). The private key is non-exportable and
//! lives in the TPM, so the wrapped KEK cannot be unwrapped off the machine.
//!
//! RSA-OAEP is classical, so [`KeyWrapper::qrom_safe`] is `false`: the core seal
//! seam then **requires a passphrase**, whose Argon2id-256 key keeps the sealed
//! seed post-quantum-safe at rest even if RSA later falls — the same
//! "PQ-inside-a-non-PQ-HSM" property as the macOS Secure Enclave path. For a
//! hardware wrap that is itself PQ, use the SEALSQ PQ secure element
//! ([`crate::pqse`]).
//!
//! # Validation status
//!
//! **Compile-checked against `x86_64-pc-windows-gnu`; not runtime-validated** (no
//! Windows host / TPM in this environment) — mirrors the macOS Secure Enclave and
//! PKCS#11 drivers. [`CngWrapper::available`] probes at runtime (opening the
//! provider + key), and [`crate::store::KeyStore`] never auto-selects this backend,
//! so a host without a usable TPM falls back cleanly. Validate on a real Windows
//! box with a TPM before relying on it.

#![cfg(all(windows, feature = "windows-tpm"))]

use talkrypt_core::{KeyWrapper, WrapError};

/// A [`KeyWrapper`] backed by a TPM-held RSA key via Windows CNG.
pub struct CngWrapper;

impl CngWrapper {
    /// Construct the wrapper. The TPM key is opened/created lazily on first use.
    pub fn new() -> Self {
        CngWrapper
    }

    /// Whether a usable Platform-Crypto-Provider RSA key can be opened or created
    /// right now (false on a host without a TPM / CNG platform provider).
    pub fn available() -> bool {
        cng::with_key(|_| Ok(())).is_ok()
    }
}

impl Default for CngWrapper {
    fn default() -> Self {
        Self::new()
    }
}

impl KeyWrapper for CngWrapper {
    fn wrap(&self, kek: &[u8]) -> Result<Vec<u8>, WrapError> {
        cng::with_key(|key| cng::crypt(key, kek, true))
    }
    fn unwrap(&self, wrapped: &[u8]) -> Result<Vec<u8>, WrapError> {
        cng::with_key(|key| cng::crypt(key, wrapped, false))
    }
    fn qrom_safe(&self) -> bool {
        false // RSA-OAEP is classical
    }
}

mod cng {
    //! Small, RAII-guarded FFI over CNG NCrypt. Unsafe surface kept here.

    use core::ffi::c_void;
    use talkrypt_core::WrapError;
    use windows_sys::Win32::Security::Cryptography::{
        BCRYPT_OAEP_PADDING_INFO, BCRYPT_RSA_ALGORITHM, BCRYPT_SHA256_ALGORITHM,
        MS_PLATFORM_CRYPTO_PROVIDER, NCRYPT_KEY_HANDLE, NCRYPT_LENGTH_PROPERTY,
        NCRYPT_PAD_OAEP_FLAG, NCRYPT_PROV_HANDLE,
        NCryptCreatePersistedKey, NCryptDecrypt, NCryptEncrypt, NCryptFinalizeKey, NCryptFreeObject,
        NCryptOpenKey, NCryptOpenStorageProvider, NCryptSetProperty,
    };

    /// Persisted key name in the Platform Crypto Provider.
    const KEY_NAME: &str = "talkrypt-cng-kek";
    const RSA_BITS: u32 = 2048;
    /// `NTE_EXISTS` — key already present (treat as "open it instead").
    const NTE_EXISTS: i32 = 0x8009000F_u32 as i32;
    /// `NTE_BAD_KEYSET` — key not found on open.
    const NTE_BAD_KEYSET: i32 = 0x80090016_u32 as i32;

    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }

    fn ok(hr: i32, ctx: &str) -> Result<(), WrapError> {
        if hr == 0 {
            Ok(())
        } else {
            Err(WrapError(format!("windows-cng: {ctx} failed (0x{hr:08x})")))
        }
    }

    /// RAII for an NCrypt handle (provider or key); frees on drop.
    struct Handle(usize);
    impl Drop for Handle {
        fn drop(&mut self) {
            if self.0 != 0 {
                unsafe { NCryptFreeObject(self.0) };
            }
        }
    }

    /// Open the TPM-backed provider, open-or-create the persisted RSA key, and run
    /// `f` with the key handle. Handles are freed on return.
    pub fn with_key<T>(f: impl FnOnce(NCRYPT_KEY_HANDLE) -> Result<T, WrapError>) -> Result<T, WrapError> {
        unsafe {
            let mut prov: NCRYPT_PROV_HANDLE = 0;
            ok(
                NCryptOpenStorageProvider(&mut prov, MS_PLATFORM_CRYPTO_PROVIDER, 0),
                "open provider",
            )?;
            let prov_guard = Handle(prov);

            let name = wide(KEY_NAME);
            let mut key: NCRYPT_KEY_HANDLE = 0;
            let open = NCryptOpenKey(prov, &mut key, name.as_ptr(), 0, 0);
            if open == NTE_BAD_KEYSET {
                // Not present yet — create a persisted RSA key in the TPM.
                ok(
                    NCryptCreatePersistedKey(
                        prov,
                        &mut key,
                        BCRYPT_RSA_ALGORITHM,
                        name.as_ptr(),
                        0,
                        0,
                    ),
                    "create key",
                )?;
                let bits = RSA_BITS;
                ok(
                    NCryptSetProperty(
                        key,
                        NCRYPT_LENGTH_PROPERTY,
                        &bits as *const u32 as *const u8,
                        core::mem::size_of::<u32>() as u32,
                        0,
                    ),
                    "set length",
                )?;
                let fin = NCryptFinalizeKey(key, 0);
                if fin != 0 && fin != NTE_EXISTS {
                    let _k = Handle(key);
                    return Err(WrapError(format!("windows-cng: finalize failed (0x{fin:08x})")));
                }
            } else {
                ok(open, "open key")?;
            }
            let key_guard = Handle(key);

            let out = f(key);
            drop(key_guard);
            drop(prov_guard);
            out
        }
    }

    /// RSA-OAEP-SHA256 encrypt (`encrypt=true`) or decrypt the given bytes with the
    /// TPM key, using the CNG two-call size convention.
    pub fn crypt(key: NCRYPT_KEY_HANDLE, input: &[u8], encrypt: bool) -> Result<Vec<u8>, WrapError> {
        unsafe {
            let sha = wide("SHA256");
            // Prefer the provider's SHA-256 alg id constant; fall back to our own
            // wide "SHA256" string (both are valid OAEP hash identifiers).
            let alg = if BCRYPT_SHA256_ALGORITHM.is_null() {
                sha.as_ptr()
            } else {
                BCRYPT_SHA256_ALGORITHM
            };
            let pad = BCRYPT_OAEP_PADDING_INFO {
                pszAlgId: alg,
                pbLabel: core::ptr::null_mut(),
                cbLabel: 0,
            };
            let pad_ptr = &pad as *const _ as *const c_void;
            let flags = NCRYPT_PAD_OAEP_FLAG;

            let run = |out: *mut u8, out_cap: u32, cb: &mut u32| -> i32 {
                if encrypt {
                    NCryptEncrypt(key, input.as_ptr(), input.len() as u32, pad_ptr, out, out_cap, cb, flags)
                } else {
                    NCryptDecrypt(key, input.as_ptr(), input.len() as u32, pad_ptr, out, out_cap, cb, flags)
                }
            };

            let mut cb: u32 = 0;
            ok(run(core::ptr::null_mut(), 0, &mut cb), "crypt size")?;
            let mut buf = vec![0u8; cb as usize];
            ok(run(buf.as_mut_ptr(), cb, &mut cb), "crypt")?;
            buf.truncate(cb as usize);
            Ok(buf)
        }
    }
}
