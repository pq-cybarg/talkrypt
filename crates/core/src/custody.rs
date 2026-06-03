//! Key-**custody tier** model, shared across platforms (desktop helper and the
//! mobile FFI), so every platform feeds one parity contract (#305).
//!
//! A custody tier describes *how strongly* a key is held at rest, independent of
//! the (uniform, post-quantum) algorithms used with it. The *enum and wire
//! encoding* live here (platform-agnostic data); *which tiers a given platform
//! supports* is decided by that platform (the desktop helper inspects its
//! keystore backends; the mobile app queries Android Keystore / StrongBox).

use talkrypt_wire::Reader;

use crate::error::{CoreError, Result};

/// How strongly a key is held at rest, ordered weakest → strongest.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum CustodyTier {
    /// Sealed at rest with Argon2id + AES-256-GCM in an owner-only file.
    /// Software-only: a key is exposed if the passphrase *and* the file are both
    /// obtained.
    SoftwareSealed,
    /// Held by the OS key store (macOS Keychain, Linux Secret Service, Windows
    /// Credential Manager, Android software Keystore) — the OS protects it at
    /// rest and there is no app-held passphrase.
    OsKeystore,
    /// Held by hardware that never releases the private key (Secure Enclave,
    /// Android StrongBox / TEE, a TPM).
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
            _ => return Err(CoreError::Malformed("custody tier tag")),
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

/// A platform's PQ + custody capabilities. `pq_identity` is the "PQ" half of the
/// PQ + custody-tier parity target; `tiers` are the custody tiers it supports.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Capabilities {
    pub pq_identity: bool,
    pub tiers: Vec<CustodyTier>,
}

impl Capabilities {
    /// Wire form: `pq_identity(u8) ‖ u32 n ‖ (tier_tag)*`.
    pub fn encode(&self) -> Vec<u8> {
        let mut w = talkrypt_wire::Writer::new();
        w.put_u8(self.pq_identity as u8);
        w.put_u32(self.tiers.len() as u32);
        for t in &self.tiers {
            w.put_u8(t.tag());
        }
        w.into_vec()
    }

    pub fn decode(bytes: &[u8]) -> Result<Capabilities> {
        let mut r = Reader::new(bytes);
        let pq_identity = r.get_u8()? != 0;
        let n = r.get_u32()?;
        if n > 16 {
            return Err(CoreError::Malformed("too many custody tiers"));
        }
        let mut tiers = Vec::with_capacity(n as usize);
        for _ in 0..n {
            tiers.push(CustodyTier::from_tag(r.get_u8()?)?);
        }
        r.finish()
            .map_err(|_| CoreError::Malformed("trailing capabilities bytes"))?;
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
    fn tiers_ordered_and_tagged() {
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
    }

    #[test]
    fn capabilities_roundtrip_and_strongest() {
        let caps = Capabilities {
            pq_identity: true,
            tiers: vec![CustodyTier::SoftwareSealed, CustodyTier::HardwareBacked],
        };
        assert_eq!(Capabilities::decode(&caps.encode()).unwrap(), caps);
        assert_eq!(caps.strongest(), Some(CustodyTier::HardwareBacked));
    }

    #[test]
    fn bad_tier_tag_rejected() {
        // pq=0, one tier, bogus tag 99.
        let mut w = talkrypt_wire::Writer::new();
        w.put_u8(0);
        w.put_u32(1);
        w.put_u8(99);
        assert!(Capabilities::decode(&w.into_vec()).is_err());
    }
}
