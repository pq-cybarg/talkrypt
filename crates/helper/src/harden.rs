//! Permissive-security hardening — re-provide, in our own code, the integrity
//! protections the OS stops enforcing when a user relaxes it.
//!
//! A user may disable macOS **SIP + AMFI** (`amfi_get_out_of_my_way`) to reach the
//! built-in Secure Enclave without an Apple provisioning identity (see
//! `docs/custody-options.md`, option 5c). Doing so turns off Apple's
//! code-signature/entitlement enforcement and its debugger/injection guards. This
//! module lets talkrypt reassert equivalents itself, so a hardened-mode user is
//! not left exposed:
//!
//! - **PQ self-integrity attestation** — verify this executable (and optionally
//!   the helper) against an **ML-DSA-87** signature under a trusted key
//!   ([`talkrypt_crypto::attest`]). Post-quantum, and bound to a key the user
//!   trusts rather than Apple's classical PKI.
//! - **Anti-debug** — `ptrace(PT_DENY_ATTACH)` on macOS
//!   ([`talkrypt_crypto::deny_debugger`]).
//! - **Injection-env detection** — flag `DYLD_*` / `LD_PRELOAD` style dynamic-
//!   loader overrides that a compromised launcher could use to inject code.
//! - **Core-dump / dumpable hardening** — via
//!   [`talkrypt_crypto::harden_process`].
//!
//! The caller decides policy from the returned [`PostureReport`] — e.g. refuse to
//! unseal if `self_attested == Some(false)`. Nothing here aborts on its own.

use talkrypt_crypto::{deny_debugger, harden_process, HardeningReport};

/// Dynamic-loader override environment variables an injector might set. Presence
/// of any of these is a red flag in hardened mode (a benign run rarely sets them).
const INJECTION_VARS: &[&str] = &[
    // macOS dyld
    "DYLD_INSERT_LIBRARIES",
    "DYLD_LIBRARY_PATH",
    "DYLD_FRAMEWORK_PATH",
    "DYLD_FALLBACK_LIBRARY_PATH",
    // Linux/glibc loader
    "LD_PRELOAD",
    "LD_LIBRARY_PATH",
    "LD_AUDIT",
];

/// A trusted-key + detached-signature pair for [`talkrypt_crypto::attest::verify_self`].
pub struct SelfAttest<'a> {
    /// The trusted ML-DSA-87 public key (raw encoded verifying key).
    pub pubkey: &'a [u8],
    /// The detached signature over this executable (from `relsign sign`).
    pub signature: &'a [u8],
}

/// What the hardening pass applied and observed. Surface it so the UI can show
/// exactly which protections are self-enforced.
#[derive(Debug, Clone, Default)]
pub struct PostureReport {
    /// Core-dump / dumpable hardening (see [`HardeningReport`]).
    pub hardening: HardeningReport,
    /// Debugger attach was denied (`PT_DENY_ATTACH` / non-dumpable).
    pub debugger_denied: bool,
    /// Dynamic-loader override env vars found set (injection risk).
    pub injection_env: Vec<String>,
    /// `Some(true)`/`Some(false)` if a self-attestation was requested and
    /// passed/failed; `None` if none was requested.
    pub self_attested: Option<bool>,
}

impl PostureReport {
    /// Whether the posture is acceptable for hardened-mode operation: no injection
    /// override present, and — if attestation was requested — it passed. Callers
    /// in permissive-security mode should refuse to unseal when this is `false`.
    pub fn is_acceptable(&self) -> bool {
        self.injection_env.is_empty() && self.self_attested != Some(false)
    }
}

/// Detect dynamic-loader override env vars currently set.
fn scan_injection_env() -> Vec<String> {
    INJECTION_VARS
        .iter()
        .filter(|v| std::env::var_os(v).is_some_and(|val| !val.is_empty()))
        .map(|v| (*v).to_string())
        .collect()
}

/// Apply the permissive-security hardening pass and report the resulting posture.
///
/// Idempotent and best-effort (the underlying syscalls no-op on repeat). Pass
/// `attest = Some(..)` to also verify this executable's PQ signature; the result
/// is in [`PostureReport::self_attested`]. This function never aborts — inspect
/// the report (or [`PostureReport::is_acceptable`]) and enforce policy in the
/// caller.
pub fn harden(attest: Option<SelfAttest<'_>>) -> PostureReport {
    let hardening = harden_process();
    let debugger_denied = deny_debugger();
    let injection_env = scan_injection_env();
    let self_attested = attest.map(|a| talkrypt_crypto::attest::verify_self(a.pubkey, a.signature).is_ok());
    PostureReport {
        hardening,
        debugger_denied,
        injection_env,
        self_attested,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use talkrypt_crypto::IdentityKeyPair;

    #[test]
    fn injection_env_is_detected_then_clear() {
        let var = "DYLD_INSERT_LIBRARIES";
        std::env::set_var(var, "/tmp/evil.dylib");
        let found = scan_injection_env();
        assert!(found.iter().any(|v| v == var));
        std::env::remove_var(var);
        assert!(!scan_injection_env().iter().any(|v| v == var));
    }

    #[test]
    fn self_attest_none_is_not_a_failure() {
        // No attestation requested → self_attested is None, posture acceptable
        // (assuming no injection env in the test process).
        let r = harden(None);
        assert_eq!(r.self_attested, None);
    }

    #[test]
    fn self_attest_true_for_valid_signature_over_this_binary() {
        let exe = std::env::current_exe().unwrap();
        let image = std::fs::read(&exe).unwrap();
        let kp = IdentityKeyPair::generate();
        let sig = kp.sign(&image);
        let r = harden(Some(SelfAttest {
            pubkey: &kp.public().sig_vk,
            signature: &sig,
        }));
        assert_eq!(r.self_attested, Some(true));
    }

    #[test]
    fn self_attest_false_for_wrong_signature() {
        let kp = IdentityKeyPair::generate();
        let bad = kp.sign(b"not this binary");
        let r = harden(Some(SelfAttest {
            pubkey: &kp.public().sig_vk,
            signature: &bad,
        }));
        assert_eq!(r.self_attested, Some(false));
        assert!(!r.is_acceptable());
    }
}
