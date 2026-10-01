//! Post-quantum **self-integrity attestation** (ML-DSA-87).
//!
//! Verify that a binary — or *this* running executable — matches a detached
//! signature under a trusted public key, so talkrypt can enforce its **own** code
//! integrity when the operating system is not. This is the mechanism behind the
//! permissive-security hardening mode (see `docs/custody-options.md`): a user who
//! disables macOS SIP/AMFI to reach the built-in Secure Enclave loses Apple's
//! code-signature enforcement, so talkrypt re-provides it here — and *better*,
//! because this check is **post-quantum** (ML-DSA-87) and bound to a key the user
//! trusts, not Apple's classical PKI.
//!
//! Same primitive as `talkrypt-relsign` (artifact → ML-DSA-87 signature →
//! verify against a trusted public key), exposed as a library for a launch-time
//! check. The signature is produced at build/release time with `relsign sign`;
//! ship the detached signature and embed (or configure) the trusted public key.

use std::path::Path;

use crate::error::{CryptoError, Result};
use crate::identity::IdentityPublic;

/// Verify `sig` over `msg` under the ML-DSA-87 public key `pubkey` (the raw
/// encoded verifying key, 2592 bytes). `Ok(())` iff the signature is valid.
pub fn verify_bytes(pubkey: &[u8], msg: &[u8], sig: &[u8]) -> Result<()> {
    let public = IdentityPublic {
        sig_vk: pubkey.to_vec(),
    };
    public.verify(msg, sig)
}

/// Verify the contents of the file at `path` against `sig` under `pubkey`.
pub fn verify_file(pubkey: &[u8], path: &Path, sig: &[u8]) -> Result<()> {
    let data =
        std::fs::read(path).map_err(|_| CryptoError::Malformed("attest: cannot read binary"))?;
    verify_bytes(pubkey, &data, sig)
}

/// Verify **this running executable** against `sig` under `pubkey`. Call at
/// launch (and before unsealing) in the hardening mode; refuse to proceed on
/// error. Resolves the binary via [`std::env::current_exe`].
pub fn verify_self(pubkey: &[u8], sig: &[u8]) -> Result<()> {
    let exe = std::env::current_exe()
        .map_err(|_| CryptoError::Malformed("attest: cannot resolve current exe"))?;
    verify_file(pubkey, &exe, sig)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::IdentityKeyPair;

    #[test]
    fn verify_bytes_roundtrips_and_rejects_tamper() {
        let kp = IdentityKeyPair::generate();
        let pubkey = &kp.public().sig_vk;
        let msg = b"talkrypt binary image bytes";
        let sig = kp.sign(msg);

        assert!(verify_bytes(pubkey, msg, &sig).is_ok());
        // Tampered message → reject.
        assert!(verify_bytes(pubkey, b"TAMPERED image bytes", &sig).is_err());
        // Wrong key → reject.
        let attacker = IdentityKeyPair::generate();
        assert!(verify_bytes(&attacker.public().sig_vk, msg, &sig).is_err());
    }

    #[test]
    fn verify_self_passes_for_a_correct_signature_over_this_binary() {
        // Sign the actual running test binary, then self-verify — the exact
        // launch-time check the hardening mode performs, end to end.
        let exe = std::env::current_exe().unwrap();
        let image = std::fs::read(&exe).unwrap();
        let kp = IdentityKeyPair::generate();
        let sig = kp.sign(&image);

        assert!(verify_self(&kp.public().sig_vk, &sig).is_ok());
        // A signature over different bytes must not verify against this binary.
        let bad = kp.sign(b"not this binary");
        assert!(verify_self(&kp.public().sig_vk, &bad).is_err());
    }
}
