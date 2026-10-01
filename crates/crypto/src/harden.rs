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
//! - **PQ self-integrity attestation** — verify this executable against an
//!   **ML-DSA-87** signature under a trusted key ([`crate::attest`]). Post-quantum,
//!   and bound to a key the user trusts rather than Apple's classical PKI.
//! - **Anti-debug** — `ptrace(PT_DENY_ATTACH)` on macOS ([`crate::deny_debugger`]).
//! - **Injection-env detection** — flag `DYLD_*` / `LD_PRELOAD` style dynamic-
//!   loader overrides that a compromised launcher could use to inject code.
//! - **Core-dump / dumpable hardening** — via [`crate::harden_process`].
//!
//! Lives in `talkrypt-crypto` so every entry point (CLI, desktop GUI, the custody
//! helper, FFI) shares one hardening seam. The caller decides policy from the
//! returned [`PostureReport`] — e.g. refuse to unseal if
//! `self_attested == Some(false)`. Nothing here aborts on its own.

use crate::mem::{deny_debugger, harden_process, HardeningReport};

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

/// A trusted-key + detached-signature pair for [`crate::attest::verify_self`].
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
    let self_attested = attest.map(|a| crate::attest::verify_self(a.pubkey, a.signature).is_ok());
    PostureReport {
        hardening,
        debugger_denied,
        injection_env,
        self_attested,
    }
}

/// Env var that opts a process into permissive-security hardening at startup.
pub const HARDEN_ENV: &str = "TALKRYPT_HARDEN";
/// Env var holding the trusted ML-DSA-87 public key (hex, or a path to a file of
/// hex) for launch-time self-attestation.
pub const ATTEST_PUBKEY_ENV: &str = "TALKRYPT_ATTEST_PUBKEY";
/// Env var holding the detached signature over this executable (hex, or a path).
pub const ATTEST_SIG_ENV: &str = "TALKRYPT_ATTEST_SIG";

/// Read an env var as hex bytes. The value may be the hex itself, or a path to a
/// file containing hex (matching `talkrypt-relsign`'s output). Returns `None` if
/// unset/empty; `None` on a decode error (treated as "no material provided").
fn env_hex(name: &str) -> Option<Vec<u8>> {
    let raw = std::env::var(name).ok().filter(|s| !s.trim().is_empty())?;
    let text = match std::fs::read_to_string(raw.trim()) {
        Ok(file) => file, // it was a path
        Err(_) => raw,    // it was the hex itself
    };
    hex_decode(text.trim())
}

/// Minimal hex decoder (lower/upper), or `None` on any non-hex / odd length.
fn hex_decode(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    let nibble = |c: u8| match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    };
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(s.len() / 2);
    for pair in b.chunks_exact(2) {
        out.push((nibble(pair[0])? << 4) | nibble(pair[1])?);
    }
    Some(out)
}

/// Apply the hardening pass configured from the environment. Runs self-attestation
/// when both [`ATTEST_PUBKEY_ENV`] and [`ATTEST_SIG_ENV`] are set (hex or a path).
/// Entry points call this when [`HARDEN_ENV`] is set and refuse to proceed if
/// [`PostureReport::is_acceptable`] is false.
pub fn from_env() -> PostureReport {
    match (env_hex(ATTEST_PUBKEY_ENV), env_hex(ATTEST_SIG_ENV)) {
        (Some(pubkey), Some(signature)) => harden(Some(SelfAttest {
            pubkey: &pubkey,
            signature: &signature,
        })),
        _ => harden(None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::IdentityKeyPair;

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
    fn hex_decode_roundtrips_and_rejects_junk() {
        assert_eq!(hex_decode("00ff1A"), Some(vec![0x00, 0xff, 0x1a]));
        assert_eq!(hex_decode(""), Some(vec![]));
        assert_eq!(hex_decode("abc"), None); // odd length
        assert_eq!(hex_decode("zz"), None); // non-hex
    }

    #[test]
    fn from_env_attests_when_material_is_set_as_hex() {
        let exe = std::env::current_exe().unwrap();
        let image = std::fs::read(&exe).unwrap();
        let kp = IdentityKeyPair::generate();
        let sig = kp.sign(&image);
        let to_hex = |b: &[u8]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();
        std::env::set_var(ATTEST_PUBKEY_ENV, to_hex(&kp.public().sig_vk));
        std::env::set_var(ATTEST_SIG_ENV, to_hex(&sig));
        let r = from_env();
        std::env::remove_var(ATTEST_PUBKEY_ENV);
        std::env::remove_var(ATTEST_SIG_ENV);
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
