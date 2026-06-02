//! CSfC architectural preflight.
//!
//! Evaluates the Commercial-Solutions-for-Classified preconditions that
//! software *can* check (two independent layers, PQ suite floor, FIPS backend,
//! protected keys) and enumerates the ones only an organization can satisfy
//! (Components-List products, Capability-Package conformance, Trusted
//! Integrator, NSA registration, continuous monitoring).
//!
//! This never returns a "compliant" verdict — CSfC accreditation is an
//! external process. It returns an honest checklist. See `docs/CSFC.md`.

/// A deployment's checkable security posture.
#[derive(Clone, Copy, Debug)]
pub struct CsfcConfig {
    /// Inner end-to-end encryption layer present (the PQ Double Ratchet).
    pub inner_e2e: bool,
    /// Outer independent transport layer present (Tor onion service).
    pub outer_onion: bool,
    /// Inner suite meets the post-quantum floor — ML-KEM-1024 based, whether
    /// PQ-pure (the default) or hybrid; no weak suite. The pure-vs-hybrid choice
    /// is an *intra-layer* posture, distinct from the CSfC two-layer
    /// requirement (the outer onion is the second layer).
    pub suite_is_post_quantum: bool,
    /// AEAD runs through a FIPS-validated module (`fips` feature).
    pub fips_backend: bool,
    /// Long-term keys are ephemeral or sealed at rest (never plaintext).
    pub keys_protected: bool,
}

/// One checkable criterion and its result.
#[derive(Clone, Debug)]
pub struct Criterion {
    pub name: &'static str,
    pub satisfied: bool,
    pub detail: &'static str,
}

/// The preflight result.
#[derive(Clone, Debug)]
pub struct PreflightReport {
    /// Criteria talkrypt can evaluate.
    pub criteria: Vec<Criterion>,
    /// Requirements only an organization/accreditation can satisfy.
    pub organizational: Vec<&'static str>,
}

impl PreflightReport {
    /// True if every *checkable* criterion is satisfied. This is necessary but
    /// NOT sufficient for CSfC accreditation (see `organizational`).
    pub fn all_checkable_satisfied(&self) -> bool {
        self.criteria.iter().all(|c| c.satisfied)
    }

    /// Names of unmet checkable criteria.
    pub fn unmet(&self) -> Vec<&'static str> {
        self.criteria
            .iter()
            .filter(|c| !c.satisfied)
            .map(|c| c.name)
            .collect()
    }
}

/// Evaluate the CSfC architectural preconditions for a deployment.
pub fn preflight(cfg: &CsfcConfig) -> PreflightReport {
    let criteria = vec![
        Criterion {
            name: "two-layer-encryption",
            satisfied: cfg.inner_e2e && cfg.outer_onion,
            detail: "inner E2E PQ layer nested inside the outer Tor onion layer",
        },
        Criterion {
            name: "layer-independence",
            satisfied: cfg.inner_e2e && cfg.outer_onion,
            detail: "inner E2E crypto and the outer Tor onion are independent \
                     implementations and keys — this layering is the CSfC second \
                     layer (not the inner hybrid's X25519 half)",
        },
        Criterion {
            name: "post-quantum-suite-floor",
            satisfied: cfg.suite_is_post_quantum,
            detail: "inner suite is post-quantum (ML-KEM-1024; PQ-pure default or \
                     hybrid), CNSA-2.0-aligned; no weak suite",
        },
        Criterion {
            name: "fips-validated-aead",
            satisfied: cfg.fips_backend,
            detail: "AES-256-GCM via a FIPS-validated module (build with --features fips)",
        },
        Criterion {
            name: "key-protection",
            satisfied: cfg.keys_protected,
            detail: "long-term keys ephemeral or sealed at rest (Argon2id + AES-256-GCM)",
        },
    ];

    let organizational = vec![
        "components on the CSfC Components List (NIAP CC + FIPS 140 product validation)",
        "conformance to a specific NSA Capability Package (e.g. MA or MSC)",
        "deployment by an NSA-recognized Trusted Integrator",
        "registration of the solution with NSA",
        "per-layer key management / separate CAs, red-black separation",
        "continuous monitoring and supply-chain controls",
    ];

    PreflightReport {
        criteria,
        organizational,
    }
}

/// The recommended secure-deployment config (onion outer + PQ inner + FIPS +
/// protected keys). `fips` reflects the active build.
pub fn recommended(fips_backend: bool) -> CsfcConfig {
    CsfcConfig {
        inner_e2e: true,
        outer_onion: true,
        suite_is_post_quantum: true,
        fips_backend,
        keys_protected: true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fully_configured_meets_all_checkable() {
        let report = preflight(&recommended(true));
        assert!(report.all_checkable_satisfied());
        assert!(report.unmet().is_empty());
        // Organizational requirements are always surfaced, never auto-satisfied.
        assert!(!report.organizational.is_empty());
    }

    #[test]
    fn missing_fips_is_flagged() {
        let report = preflight(&recommended(false));
        assert!(!report.all_checkable_satisfied());
        assert_eq!(report.unmet(), vec!["fips-validated-aead"]);
    }

    #[test]
    fn single_layer_fails_two_layer_and_independence() {
        let cfg = CsfcConfig {
            outer_onion: false,
            ..recommended(true)
        };
        let report = preflight(&cfg);
        let unmet = report.unmet();
        assert!(unmet.contains(&"two-layer-encryption"));
        assert!(unmet.contains(&"layer-independence"));
    }

    #[test]
    fn weak_suite_fails_floor() {
        let cfg = CsfcConfig {
            suite_is_post_quantum: false,
            ..recommended(true)
        };
        assert!(preflight(&cfg)
            .unmet()
            .contains(&"post-quantum-suite-floor"));
    }
}
