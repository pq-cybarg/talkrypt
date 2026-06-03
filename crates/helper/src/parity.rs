//! PQ + custody-tier **parity audit** (roadmap #305).
//!
//! Every platform variant reports its [`Capabilities`] (post-quantum identity?
//! which custody tiers?); this module compares those reports and produces a
//! verdict:
//!
//!   * **PQ parity is a hard requirement** — *every* platform must use
//!     post-quantum identities. A platform that doesn't is a parity failure.
//!   * **Custody-tier differences are expected, not failures** — a phone with a
//!     Secure Enclave legitimately reaches a stronger tier than a headless
//!     desktop. The audit *surfaces* each platform's gap below the best
//!     observed tier so it is visible, rather than failing on it or hiding it.
//!
//! Aggregating reports across machines/platforms is the caller's job (CI runs
//! each platform's `local_report` and feeds the set here).

use crate::custody::{self, Capabilities, CustodyTier};

/// One platform's self-report.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PlatformReport {
    pub name: String,
    pub caps: Capabilities,
}

/// This platform's report, built from the live capabilities.
pub fn local_report(name: impl Into<String>) -> PlatformReport {
    PlatformReport {
        name: name.into(),
        caps: Capabilities::decode(&custody::encode_capabilities())
            .expect("locally-encoded capabilities decode"),
    }
}

/// A custody gap: a platform's strongest tier is below the best tier observed
/// across all reports.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CustodyGap {
    pub platform: String,
    pub has: Option<CustodyTier>,
    pub best_observed: CustodyTier,
}

/// The audit verdict.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParityReport {
    /// Platforms that do **not** use post-quantum identities (a hard failure).
    pub non_pq: Vec<String>,
    /// Custody tiers every platform supports (the common floor).
    pub common_tiers: Vec<CustodyTier>,
    /// The strongest tier any platform reaches.
    pub best_tier: Option<CustodyTier>,
    /// Per-platform custody gaps below `best_tier` (informational).
    pub custody_gaps: Vec<CustodyGap>,
}

impl ParityReport {
    /// True iff PQ parity holds: every reporting platform uses PQ identities.
    /// Custody differences do NOT affect this — they are surfaced, not failed.
    pub fn pq_parity_ok(&self) -> bool {
        self.non_pq.is_empty()
    }
}

/// Audit a set of platform reports.
pub fn audit(reports: &[PlatformReport]) -> ParityReport {
    let non_pq = reports
        .iter()
        .filter(|r| !r.caps.pq_identity)
        .map(|r| r.name.clone())
        .collect();

    // Common tiers = intersection of every platform's supported set.
    let common_tiers = if reports.is_empty() {
        Vec::new()
    } else {
        let mut common: Vec<CustodyTier> = reports[0].caps.tiers.clone();
        for r in &reports[1..] {
            common.retain(|t| r.caps.tiers.contains(t));
        }
        common.sort();
        common
    };

    let best_tier = reports.iter().filter_map(|r| r.caps.strongest()).max();

    let custody_gaps = match best_tier {
        Some(best) => reports
            .iter()
            .filter(|r| r.caps.strongest() < Some(best))
            .map(|r| CustodyGap {
                platform: r.name.clone(),
                has: r.caps.strongest(),
                best_observed: best,
            })
            .collect(),
        None => Vec::new(),
    };

    ParityReport {
        non_pq,
        common_tiers,
        best_tier,
        custody_gaps,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn report(name: &str, pq: bool, tiers: &[CustodyTier]) -> PlatformReport {
        PlatformReport {
            name: name.into(),
            caps: Capabilities {
                pq_identity: pq,
                tiers: tiers.to_vec(),
            },
        }
    }

    #[test]
    fn local_report_is_pq_with_platform_tiers() {
        let r = local_report("desktop");
        assert!(r.caps.pq_identity);
        assert!(r.caps.tiers.contains(&CustodyTier::SoftwareSealed));
        assert_eq!(r.caps.strongest(), Some(custody::default_tier()));
    }

    #[test]
    fn all_pq_passes_parity() {
        let reports = [
            report("desktop", true, &[CustodyTier::SoftwareSealed]),
            report(
                "android",
                true,
                &[CustodyTier::SoftwareSealed, CustodyTier::HardwareBacked],
            ),
        ];
        let audit = audit(&reports);
        assert!(audit.pq_parity_ok());
        assert!(audit.non_pq.is_empty());
    }

    #[test]
    fn a_non_pq_platform_fails_parity() {
        let reports = [
            report("desktop", true, &[CustodyTier::SoftwareSealed]),
            report("legacy", false, &[CustodyTier::SoftwareSealed]),
        ];
        let audit = audit(&reports);
        assert!(!audit.pq_parity_ok());
        assert_eq!(audit.non_pq, vec!["legacy".to_string()]);
    }

    #[test]
    fn custody_gaps_are_surfaced_not_failed() {
        // Desktop (software) vs phone (hardware): PQ parity still holds; the
        // desktop's custody gap is reported, not failed.
        let reports = [
            report("desktop", true, &[CustodyTier::SoftwareSealed]),
            report(
                "iphone",
                true,
                &[CustodyTier::SoftwareSealed, CustodyTier::HardwareBacked],
            ),
        ];
        let audit = audit(&reports);
        assert!(audit.pq_parity_ok(), "custody differences don't fail PQ parity");
        assert_eq!(audit.best_tier, Some(CustodyTier::HardwareBacked));
        assert_eq!(audit.common_tiers, vec![CustodyTier::SoftwareSealed]);
        assert_eq!(audit.custody_gaps.len(), 1);
        assert_eq!(audit.custody_gaps[0].platform, "desktop");
        assert_eq!(audit.custody_gaps[0].has, Some(CustodyTier::SoftwareSealed));
        assert_eq!(audit.custody_gaps[0].best_observed, CustodyTier::HardwareBacked);
    }

    #[test]
    fn empty_set_is_vacuously_ok() {
        let audit = audit(&[]);
        assert!(audit.pq_parity_ok());
        assert_eq!(audit.best_tier, None);
        assert!(audit.common_tiers.is_empty());
        assert!(audit.custody_gaps.is_empty());
    }
}
