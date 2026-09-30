//! Randomness: the OS CSPRNG, gated by SP 800-90B startup health tests (F-4).
//!
//! **What we use.** All keys, nonces and seeds draw from the operating system's
//! CSPRNG via [`rand::rngs::OsRng`] (`getrandom(2)` / `BCryptGenRandom` /
//! `SecRandomCopyBytes`). On every platform talkrypt targets that source is an
//! **SP 800-90A-approved DRBG** continuously reseeded from the kernel entropy
//! pool. talkrypt deliberately does **not** interpose its own user-space DRBG: a
//! hand-rolled, unaudited DRBG would be strictly *worse* than the kernel's
//! approved, audited one, and would add a bug surface to the most sensitive code
//! in the system.
//!
//! **What F-4 adds.** For FIPS / SP 800-90B *form* — and as a genuine backstop
//! against a catastrophically broken source (a stuck-at fault, an all-zero VM
//! snapshot, a mis-seeded early-boot pool) — this module runs the two SP 800-90B
//! §4.4 **startup health tests** over a fresh block from the source before any key
//! is generated:
//!
//! - **Repetition Count Test** (§4.4.1): fails if a single byte value repeats for
//!   an implausibly long run — the signature of a stuck source.
//! - **Adaptive Proportion Test** (§4.4.2): fails if, within a window, one byte
//!   value recurs far more often than full-entropy output ever would — the
//!   signature of a grossly low-entropy source.
//!
//! The health check is wired into the power-on self-test ([`crate::self_test`]),
//! so a failure aborts the process before a weak key can be minted, exactly like a
//! failed primitive KAT.
//!
//! **Cutoffs.** Samples are bytes; the conditioned CSPRNG is treated as
//! full-entropy (min-entropy `H = 8` bits/byte). Cutoffs are chosen for a
//! false-positive bound `alpha ~= 2^-40`, so a healthy source essentially never
//! trips a test (no flaky aborts) while a broken one always does.
//!   RCT cutoff  C = 1 + ceil((-log2 alpha) / H) = 1 + ceil(40/8) = 6.
//!   APT window  W = 512 (SP 800-90B non-binary window); cutoff chosen so that
//!               P(Binomial(512, 2^-8) >= C) << 2^-40, comfortably C = 66.

use crate::error::{CryptoError, Result};
use rand::rngs::OsRng;
use rand::RngCore;

/// Repetition Count Test cutoff: this many identical consecutive bytes fails.
/// C = 1 + ceil(40 / 8) for alpha ~= 2^-40 at H = 8 bits/byte (SP 800-90B §4.4.1).
const RCT_CUTOFF: usize = 6;
/// Adaptive Proportion Test window (SP 800-90B §4.4.2, non-binary source).
const APT_WINDOW: usize = 512;
/// APT cutoff: within a window, this many occurrences of the window's first byte
/// fails. P(Binomial(512, 1/256) >= 66) is far below 2^-40, and a stuck source
/// (all 512 equal) always exceeds it.
const APT_CUTOFF: usize = 66;
/// Bytes drawn for the startup health check. A few windows' worth: enough to make
/// the tests meaningful, cheap enough to run at every boot.
const HEALTH_SAMPLE_LEN: usize = 4096;

/// Repetition Count Test (SP 800-90B §4.4.1): scan for a run of identical bytes of
/// length `>= RCT_CUTOFF`.
fn repetition_count_test(sample: &[u8]) -> Result<()> {
    let mut run = 1usize;
    for pair in sample.windows(2) {
        if pair[0] == pair[1] {
            run += 1;
            if run >= RCT_CUTOFF {
                return Err(CryptoError::SelfTest("entropy RCT: stuck source"));
            }
        } else {
            run = 1;
        }
    }
    Ok(())
}

/// Adaptive Proportion Test (SP 800-90B §4.4.2): in each `APT_WINDOW` block, count
/// occurrences of the block's first byte; fail if it reaches `APT_CUTOFF`.
fn adaptive_proportion_test(sample: &[u8]) -> Result<()> {
    for window in sample.chunks(APT_WINDOW) {
        // A trailing short window still exercises the test on its own length; a
        // stuck source trips it regardless of window size.
        let Some(&first) = window.first() else { continue };
        let count = window.iter().filter(|&&b| b == first).count();
        if count >= APT_CUTOFF {
            return Err(CryptoError::SelfTest("entropy APT: low-entropy source"));
        }
    }
    Ok(())
}

/// Run the SP 800-90B startup health tests over `sample` (exposed for testing with
/// crafted inputs). Prefer [`health_check_entropy`] for the live source.
pub(crate) fn run_health_tests(sample: &[u8]) -> Result<()> {
    repetition_count_test(sample)?;
    adaptive_proportion_test(sample)?;
    Ok(())
}

/// Draw a fresh block from the OS CSPRNG and run the SP 800-90B startup health
/// tests over it (F-4). Called from [`crate::self_test`]; a failure aborts start-up
/// before any key is generated. Ok on a healthy source.
pub fn health_check_entropy() -> Result<()> {
    let mut sample = [0u8; HEALTH_SAMPLE_LEN];
    OsRng.fill_bytes(&mut sample);
    run_health_tests(&sample)
}

/// Fill `dest` with cryptographically secure random bytes from the health-checked
/// OS CSPRNG. Ensures the power-on self-test (including the entropy health check)
/// has run once before returning any randomness.
pub fn fill_secure(dest: &mut [u8]) {
    crate::selftest::ensure_self_tested();
    OsRng.fill_bytes(dest);
}

/// A health-gated [`RngCore`] for KEY generation. Constructing one via [`new`] runs
/// the power-on self-test (including the SP 800-90B entropy health check, F-4) once,
/// then every draw delegates to the OS CSPRNG. Use it wherever a keygen API wants
/// `&mut impl RngCore` (e.g. ML-KEM / X25519 keypair generation, KEM encapsulation)
/// so no long-term or session key is minted from an unchecked source.
///
/// [`new`]: SecureRng::new
#[derive(Clone, Copy)]
pub struct SecureRng;

impl SecureRng {
    /// Create a health-gated RNG, ensuring the entropy self-test has passed.
    pub fn new() -> Self {
        crate::selftest::ensure_self_tested();
        SecureRng
    }
}

impl Default for SecureRng {
    fn default() -> Self {
        Self::new()
    }
}

impl rand::RngCore for SecureRng {
    fn next_u32(&mut self) -> u32 {
        OsRng.next_u32()
    }
    fn next_u64(&mut self) -> u64 {
        OsRng.next_u64()
    }
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        OsRng.fill_bytes(dest)
    }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> core::result::Result<(), rand::Error> {
        OsRng.try_fill_bytes(dest)
    }
}

// The OS CSPRNG is cryptographically secure; the wrapper only adds the health gate.
impl rand::CryptoRng for SecureRng {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn healthy_os_source_passes_repeatedly() {
        // A correct CSPRNG must never trip the tests; run many boots' worth.
        for _ in 0..200 {
            health_check_entropy().expect("healthy OS entropy must pass");
        }
    }

    #[test]
    fn stuck_source_fails_rct() {
        // All-identical bytes = a stuck source; RCT must reject it.
        let stuck = [0x5au8; HEALTH_SAMPLE_LEN];
        assert!(run_health_tests(&stuck).is_err());
        assert!(repetition_count_test(&stuck).is_err());
    }

    #[test]
    fn zeroed_source_fails() {
        // An all-zero VM-snapshot / mis-seeded pool must be caught.
        assert!(run_health_tests(&[0u8; HEALTH_SAMPLE_LEN]).is_err());
    }

    #[test]
    fn rct_allows_short_runs_but_rejects_at_cutoff() {
        // Distinct filler (no incidental runs), then a run just below the cutoff —
        // must pass.
        let mut ok: Vec<u8> = (0..64u8).collect();
        for slot in ok.iter_mut().take(RCT_CUTOFF - 1) {
            *slot = 7;
        }
        assert!(repetition_count_test(&ok).is_ok());
        // A run at the cutoff must fail.
        let bad = vec![7u8; RCT_CUTOFF];
        assert!(repetition_count_test(&bad).is_err());
    }

    #[test]
    fn apt_flags_a_concentrated_window() {
        // A window where the first byte recurs at the cutoff must fail, even though
        // the run is not consecutive (so RCT alone would miss it).
        let mut win = vec![0u8; APT_WINDOW];
        for i in 0..APT_CUTOFF {
            win[i * 2 % APT_WINDOW] = 0xAB; // spread the repeats out
        }
        win[0] = 0xAB;
        let count = win.iter().filter(|&&b| b == 0xAB).count();
        // Ensure the crafted window actually reaches the cutoff, then assert reject.
        if count >= APT_CUTOFF {
            assert!(adaptive_proportion_test(&win).is_err());
        }
    }

    #[test]
    fn fill_secure_produces_distinct_output() {
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        fill_secure(&mut a);
        fill_secure(&mut b);
        assert_ne!(a, b, "two secure draws must differ");
        assert_ne!(a, [0u8; 32], "must not be all-zero");
    }

    #[test]
    fn secure_rng_is_a_usable_rngcore() {
        use rand::RngCore;
        let mut rng = SecureRng::new();
        // Fills, u32, u64 all work and produce non-trivial output.
        let mut buf = [0u8; 48];
        rng.fill_bytes(&mut buf);
        assert_ne!(buf, [0u8; 48]);
        assert!(rng.next_u32() != 0 || rng.next_u64() != 0);
        assert!(rng.try_fill_bytes(&mut buf).is_ok());
    }
}
