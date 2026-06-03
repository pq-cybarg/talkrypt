//! Key-**custody tiers** (roadmap #2 / parity #305).
//!
//! A custody tier describes *how strongly* a key is held at rest, independent of
//! the (uniform, post-quantum) algorithms used with it. This is the model the
//! mobile hardware-keystore bridges and the cross-platform "PQ + custody-tier
//! parity" audit hang off: every platform reports the tiers it supports, and a
//! parity check compares them.
//!
//! Today the desktop helper implements exactly one tier — `SoftwareSealed`
//! (Argon2id + AES-256-GCM at rest). The stronger tiers are slots for future
//! bridges (OS key stores; hardware-backed enclaves) and are reported as
//! *unsupported* here so a parity audit sees the gap honestly rather than
//! assuming coverage.

use talkrypt_wire::Reader;

use crate::error::{HelperError, Result};

/// How strongly a key is held at rest, ordered weakest → strongest.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum CustodyTier {
    /// Sealed at rest with Argon2id + AES-256-GCM in an owner-only file.
    /// Software-only: a key is exposed if the passphrase and the file are both
    /// obtained. This is the desktop helper's tier today.
    SoftwareSealed,
    /// Held by the OS key store (macOS Keychain, Windows DPAPI/CNG, Linux
    /// Secret Service / kernel keyring). Future bridge — not yet implemented.
    OsKeystore,
    /// Held by hardware that never releases the private key (Secure Enclave,
    /// Android StrongBox, a TPM). Future bridge — not yet implemented.
    HardwareBacked,
}

impl CustodyTier {
    pub fn tag(self) -> u8 {
        match self {
            CustodyTier::SoftwareSealed => 0,
            CustodyTier::OsKeystore => 1,
            CustodyTier::HardwareBacked => 2,
        }
    }

    pub fn from_tag(t: u8) -> Result<Self> {
        Ok(match t {
            0 => CustodyTier::SoftwareSealed,
            1 => CustodyTier::OsKeystore,
            2 => CustodyTier::HardwareBacked,
            _ => return Err(HelperError::Protocol("unknown custody tier tag")),
        })
    }

    /// Human-readable label.
    pub fn label(self) -> &'static str {
        match self {
            CustodyTier::SoftwareSealed => "software-sealed (Argon2id + AES-256-GCM)",
            CustodyTier::OsKeystore => "os-keystore",
            CustodyTier::HardwareBacked => "hardware-backed",
        }
    }

    /// Whether the private key is held by hardware that never releases it.
    pub fn is_hardware_backed(self) -> bool {
        matches!(self, CustodyTier::HardwareBacked)
    }
}

/// The custody tiers this build actually supports, strongest first. Extending
/// this is how an OS-keystore or hardware bridge is "turned on" for a platform;
/// a parity audit reads it to find gaps.
pub fn supported_tiers() -> Vec<CustodyTier> {
    #[allow(unused_mut)]
    let mut tiers = vec![CustodyTier::SoftwareSealed];
    // macOS: the login Keychain backs the OsKeystore tier (see `keychain`).
    #[cfg(target_os = "macos")]
    tiers.push(CustodyTier::OsKeystore);
    tiers
}

/// The default tier used when none is requested (the strongest supported).
pub fn default_tier() -> CustodyTier {
    supported_tiers()
        .into_iter()
        .max()
        .expect("at least one supported tier")
}

/// Whether identity keys are post-quantum (ML-DSA-87) — the "PQ" half of the
/// PQ + custody-tier parity target (#305). Always true for talkrypt.
pub fn pq_identity() -> bool {
    true
}

/// Encode the platform capabilities for the `Capabilities` response:
/// `pq_identity ‖ u32 n ‖ (tier_tag)*` (tiers strongest-first).
pub fn encode_capabilities() -> Vec<u8> {
    let mut w = talkrypt_wire::Writer::new();
    w.put_u8(pq_identity() as u8);
    let tiers = supported_tiers();
    w.put_u32(tiers.len() as u32);
    for t in tiers {
        w.put_u8(t.tag());
    }
    w.into_vec()
}

/// Decoded platform capabilities (client side).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Capabilities {
    pub pq_identity: bool,
    pub tiers: Vec<CustodyTier>,
}

impl Capabilities {
    pub fn decode(bytes: &[u8]) -> Result<Capabilities> {
        let mut r = Reader::new(bytes);
        let pq_identity = r.get_u8()? != 0;
        let n = r.get_u32()?;
        if n > 16 {
            return Err(HelperError::Protocol("too many custody tiers"));
        }
        let mut tiers = Vec::with_capacity(n as usize);
        for _ in 0..n {
            tiers.push(CustodyTier::from_tag(r.get_u8()?)?);
        }
        r.finish()?;
        Ok(Capabilities { pq_identity, tiers })
    }

    /// The strongest supported tier.
    pub fn strongest(&self) -> Option<CustodyTier> {
        self.tiers.iter().copied().max()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tiers_are_ordered_and_tagged() {
        assert!(CustodyTier::SoftwareSealed < CustodyTier::OsKeystore);
        assert!(CustodyTier::OsKeystore < CustodyTier::HardwareBacked);
        for t in [
            CustodyTier::SoftwareSealed,
            CustodyTier::OsKeystore,
            CustodyTier::HardwareBacked,
        ] {
            assert_eq!(CustodyTier::from_tag(t.tag()).unwrap(), t);
        }
        assert!(CustodyTier::HardwareBacked.is_hardware_backed());
        assert!(!CustodyTier::SoftwareSealed.is_hardware_backed());
    }

    #[test]
    fn software_sealing_is_always_supported_plus_platform_tiers() {
        let tiers = supported_tiers();
        assert!(tiers.contains(&CustodyTier::SoftwareSealed));
        // macOS adds the Keychain-backed OsKeystore tier; other platforms not yet.
        #[cfg(target_os = "macos")]
        assert!(tiers.contains(&CustodyTier::OsKeystore));
        #[cfg(not(target_os = "macos"))]
        assert_eq!(tiers, vec![CustodyTier::SoftwareSealed]);
        // The default is the strongest supported tier.
        assert_eq!(default_tier(), tiers.into_iter().max().unwrap());
        assert!(pq_identity());
    }

    #[test]
    fn capabilities_roundtrip() {
        let caps = Capabilities::decode(&encode_capabilities()).unwrap();
        assert!(caps.pq_identity);
        assert_eq!(caps.tiers, supported_tiers());
        assert_eq!(caps.strongest(), Some(default_tier()));
    }
}
