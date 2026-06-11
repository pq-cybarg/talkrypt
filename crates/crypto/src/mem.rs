//! RAM-capture hardening (SECURITY-AUDIT R-8).
//!
//! An attacker who can read this process's memory — a cold-boot/DMA attack, a
//! debugger or `/proc/<pid>/mem` reader on a rooted device, memory-scraping
//! malware, or a core dump / swap file written to disk — can in principle
//! recover live secrets. Software on a *fully compromised* device (kernel-level
//! attacker) cannot win this fight: a secret must be plaintext in RAM at the
//! instant it is used. What we *can* do is shrink the window and the footprint:
//!
//!   1. **Zeroize on drop** — already comprehensive across the crate (F-3),
//!      Miri-verified. A secret does not outlive its use.
//!   2. **Forward secrecy** — the Double Ratchet evolves and deletes chain keys,
//!      so a single capture cannot decrypt past (or, after a step, future)
//!      traffic.
//!   3. **Never swap a long-lived secret** — [`LockedBox`] pins the identity
//!      seed in `mlock`'d pages so it is never paged to disk, and (on Linux/
//!      Android) excludes it from core dumps via `madvise(MADV_DONTDUMP)`.
//!   4. **No core dump, no ptrace** — [`harden_process`] disables core dumps
//!      and marks the process non-dumpable, so a crash cannot spill secrets to
//!      disk and a same-uid process cannot `ptrace`-attach or read our memory.
//!
//! The honest residual is documented in `docs/SECURITY-AUDIT.md` §3b. On a
//! fully compromised (root/kernel) device, RAM capture is unwinnable in software
//! — a secret must be plaintext in RAM when used. The defense that *would*
//! remove the raw key from RAM during signing is an on-chip signature in a
//! secure element, but today's secure elements (Android StrongBox / the Solana
//! Seeker's SE / Apple Secure Enclave / TPMs) are **classical-only** and cannot
//! hold or sign with ML-DSA-87, so they cannot custody talkrypt's PQ identity
//! key — that is blocked on PQC-capable silicon, not on integration work.
//! Hardware can still protect the key *at rest* (wrap the seed-sealing KEK with
//! a secure-element classical key); that is the `CustodyTier::HardwareBacked`
//! path and is the realistic next step (SECURITY-AUDIT R-8).
//!
//! All syscalls here are **best-effort**: a failure (e.g. `RLIMIT_MEMLOCK` too
//! low) degrades the hardening but never breaks functionality, so nothing here
//! returns an error on the hot path.

use core::ops::Deref;
use zeroize::Zeroize;

/// A heap-pinned, page-locked buffer for a long-lived secret (the identity
/// seed). The bytes live in their own `Box` (a stable heap address), are
/// `mlock`'d so the kernel never writes them to swap, and are zeroized — then
/// unlocked — on drop. Construct empty with [`LockedBox::zeroed`] and fill in
/// place (so the secret is generated *directly* into locked memory) or copy an
/// existing array in with [`LockedBox::from_bytes`].
pub struct LockedBox<const N: usize> {
    inner: Box<[u8; N]>,
}

impl<const N: usize> LockedBox<N> {
    /// Allocate a locked, zero-filled buffer. Fill it via [`Self::as_mut_array`].
    pub fn zeroed() -> Self {
        let mut inner = Box::new([0u8; N]);
        lock_region(inner.as_mut_ptr(), N);
        Self { inner }
    }

    /// Copy an existing secret into a fresh locked buffer. The `src` array is
    /// the caller's transient copy (e.g. just decrypted from at-rest storage);
    /// the caller owns and should zeroize it. Once copied, the secret lives only
    /// in this locked buffer.
    pub fn from_bytes(src: &[u8; N]) -> Self {
        let mut b = Self::zeroed();
        b.inner.copy_from_slice(src);
        b
    }

    /// Mutable access to fill the buffer in place (e.g. `OsRng.fill_bytes`),
    /// so a freshly generated secret is written straight into locked memory and
    /// never lands in an un-pinned temporary.
    pub fn as_mut_array(&mut self) -> &mut [u8; N] {
        &mut self.inner
    }
}

impl<const N: usize> Deref for LockedBox<N> {
    type Target = [u8; N];
    fn deref(&self) -> &[u8; N] {
        &self.inner
    }
}

impl<const N: usize> Drop for LockedBox<N> {
    fn drop(&mut self) {
        // Wipe while still locked, then release the lock.
        self.inner.zeroize();
        unlock_region(self.inner.as_mut_ptr(), N);
    }
}

/// What [`harden_process`] managed to apply. Fields are `false` where the OS
/// lacks the facility (e.g. `ptrace_blocked` on macOS) or the call was denied.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct HardeningReport {
    /// Core dumps disabled (`setrlimit(RLIMIT_CORE, 0)`): a crash will not write
    /// process memory — including secrets — to a core file on disk.
    pub core_dumps_disabled: bool,
    /// Process marked non-dumpable (`prctl(PR_SET_DUMPABLE, 0)`, Linux/Android):
    /// blocks `ptrace` attach and `/proc/<pid>/mem` reads by a same-uid process,
    /// and suppresses core dumps.
    pub ptrace_blocked: bool,
}

/// Apply process-wide RAM-capture hardening. Idempotent and best-effort; safe to
/// call at every entry point (CLI `main`, FFI init). Returns what was applied.
pub fn harden_process() -> HardeningReport {
    let mut report = HardeningReport::default();
    // Miri can't execute these syscalls (foreign functions); skip under it.
    #[cfg(all(unix, not(miri)))]
    unsafe {
        // No core dumps: a crash must not spill secrets to disk.
        let rlim = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        if libc::setrlimit(libc::RLIMIT_CORE, &rlim) == 0 {
            report.core_dumps_disabled = true;
        }
        #[cfg(any(target_os = "linux", target_os = "android"))]
        {
            // Non-dumpable: blocks ptrace attach + /proc/<pid>/mem reads by a
            // same-uid process, and suppresses core dumps.
            if libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) == 0 {
                report.ptrace_blocked = true;
            }
        }
    }
    report
}

/// Run [`harden_process`] exactly once per process, idempotently. Cheap to call
/// from every entry point (CLI `main`, each FFI keygen); the work happens on the
/// first call and later calls are no-ops. Mirrors
/// [`crate::ensure_self_tested`].
pub fn ensure_hardened() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        let _ = harden_process();
    });
}

// --- platform shims: best-effort, return nothing, never fail loudly ---

#[cfg(all(unix, not(miri)))]
fn lock_region(ptr: *mut u8, len: usize) {
    unsafe {
        let _ = libc::mlock(ptr as *const libc::c_void, len);
        #[cfg(any(target_os = "linux", target_os = "android"))]
        {
            // Exclude the locked pages from any core dump.
            let _ = libc::madvise(ptr as *mut libc::c_void, len, libc::MADV_DONTDUMP);
        }
    }
}

#[cfg(all(unix, not(miri)))]
fn unlock_region(ptr: *mut u8, len: usize) {
    unsafe {
        #[cfg(any(target_os = "linux", target_os = "android"))]
        {
            let _ = libc::madvise(ptr as *mut libc::c_void, len, libc::MADV_DODUMP);
        }
        let _ = libc::munlock(ptr as *const libc::c_void, len);
    }
}

// No-op shims: non-unix targets, and under Miri (which can't run the syscalls).
#[cfg(any(not(unix), miri))]
fn lock_region(_ptr: *mut u8, _len: usize) {}

#[cfg(any(not(unix), miri))]
fn unlock_region(_ptr: *mut u8, _len: usize) {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn locked_box_roundtrips_and_fills_in_place() {
        let mut b = LockedBox::<32>::zeroed();
        assert_eq!(*b, [0u8; 32]);
        for (i, byte) in b.as_mut_array().iter_mut().enumerate() {
            *byte = i as u8;
        }
        assert_eq!(b[0], 0);
        assert_eq!(b[31], 31);
    }

    #[test]
    fn from_bytes_copies_secret() {
        let secret = [0xABu8; 32];
        let b = LockedBox::<32>::from_bytes(&secret);
        assert_eq!(*b, secret);
    }

    #[test]
    fn locked_box_drop_is_sound() {
        // The custom Drop zeroizes the heap secret and then unlocks the pages,
        // before the inner `Box` frees them. Under Miri (`cargo +nightly miri
        // test -p talkrypt-crypto mem::`) this exercises that path and proves it
        // is free of undefined behavior — no double-free, no use-after-free, the
        // `zeroize` volatile write valid against the live allocation. The wipe
        // itself is guaranteed by the `zeroize` crate (the same mechanism F-3
        // already Miri-verifies for inline secrets).
        let b = LockedBox::<32>::from_bytes(&[0x5Au8; 32]);
        assert_eq!(*b, [0x5Au8; 32]);
        drop(b);
    }

    #[test]
    fn harden_process_is_idempotent() {
        let a = harden_process();
        let b = harden_process();
        // Calling twice yields the same report and does not panic.
        assert_eq!(a, b);
        // On a real unix run, core dumps must be disablable. (Under Miri the
        // syscall is gated out, so this is skipped.)
        #[cfg(all(unix, not(miri)))]
        assert!(a.core_dumps_disabled);
    }
}
