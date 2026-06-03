//! Desktop-platform custody-tier **detection** (roadmap #2 / parity #305).
//!
//! A custody tier describes *how strongly* a key is held at rest, independent of
//! the (uniform, post-quantum) algorithms used with it. This is the model the
//! mobile hardware-keystore bridges and the cross-platform "PQ + custody-tier
//! parity" audit hang off: every platform reports the tiers it supports, and a
//! parity check compares them.
//!
//! The tier *enum and wire encoding* ([`CustodyTier`], [`Capabilities`]) live in
//! `talkrypt_core` so desktop and mobile feed one parity contract; this module
//! only decides *which* tiers the running desktop helper supports (its keystore
//! backends) and builds the local capability report. Tiers a platform lacks are
//! simply absent from [`supported_tiers`], so a parity audit sees the gap
//! honestly rather than assuming coverage.

pub use talkrypt_core::custody::{Capabilities, CustodyTier};

/// The custody tiers this build actually supports, strongest first. Extending
/// this is how an OS-keystore or hardware bridge is "turned on" for a platform;
/// a parity audit reads it to find gaps.
pub fn supported_tiers() -> Vec<CustodyTier> {
    #[allow(unused_mut)]
    let mut tiers = vec![CustodyTier::SoftwareSealed];
    // OS-keystore-backed tier: the macOS login Keychain (`keychain`) or the
    // Linux Secret Service (`secretservice`) back it.
    #[cfg(any(target_os = "macos", target_os = "linux"))]
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

/// Encode this platform's capabilities for the `Capabilities` response
/// (`pq_identity ‖ u32 n ‖ (tier_tag)*`, tiers strongest-first).
pub fn encode_capabilities() -> Vec<u8> {
    Capabilities {
        pq_identity: pq_identity(),
        tiers: supported_tiers(),
    }
    .encode()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn software_sealing_is_always_supported_plus_platform_tiers() {
        let tiers = supported_tiers();
        assert!(tiers.contains(&CustodyTier::SoftwareSealed));
        // macOS (Keychain) and Linux (Secret Service) add the OsKeystore tier;
        // other platforms not yet.
        #[cfg(any(target_os = "macos", target_os = "linux"))]
        assert!(tiers.contains(&CustodyTier::OsKeystore));
        #[cfg(not(any(target_os = "macos", target_os = "linux")))]
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
