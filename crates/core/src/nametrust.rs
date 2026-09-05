//! Trust tiers + per-chat display policy for self-declared names. The render surface
//! (`NameRender`) exposes a `tint` colour slot that Sub-specs B (isolation marking)
//! and C (vouch thresholds) fill via the `Tint::Isolated` / `Tint::Vouched` hooks.

use crate::presence::NameRecord;
use std::collections::HashMap;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NameTier {
    Bare,
    Linked,
    RegistryConfirmed,
}
impl NameTier {
    pub fn rank(self) -> u8 {
        match self {
            NameTier::Bare => 0,
            NameTier::Linked => 1,
            NameTier::RegistryConfirmed => 2,
        }
    }
    pub fn badge(self) -> Badge {
        match self {
            NameTier::Bare => Badge(""),
            NameTier::Linked => Badge("\u{1F517}"),           // 🔗
            NameTier::RegistryConfirmed => Badge("\u{2713}"), // ✓
        }
    }
}

/// How a chat handles a lower-tier name that collides with a verified one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NameTrustPolicy {
    SignalStyle,
    WarnOnCollision,
    SuppressColliding,
}
impl Default for NameTrustPolicy {
    fn default() -> Self {
        NameTrustPolicy::SignalStyle
    }
}
impl NameTrustPolicy {
    pub fn tag(self) -> u8 {
        match self {
            Self::SignalStyle => 0,
            Self::WarnOnCollision => 1,
            Self::SuppressColliding => 2,
        }
    }
    pub fn from_tag(t: u8) -> Option<Self> {
        match t {
            0 => Some(Self::SignalStyle),
            1 => Some(Self::WarnOnCollision),
            2 => Some(Self::SuppressColliding),
            _ => None,
        }
    }
}

/// Colour slot. `Default`/`Verified` are set by Sub-spec A; `Isolated` (B) and
/// `Vouched` (C) are reserved hooks that later sub-specs populate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tint {
    Default,
    Verified,
    Isolated,
    Vouched,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Badge(pub &'static str);

/// A renderable name: what a client draws over a peer's messages.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NameRender {
    pub label: Option<String>,
    pub tier: NameTier,
    pub badge: Badge,
    pub tint: Tint,
    pub caveat: Option<String>,
    pub safety_number: String,
}

/// v1 confusable fold: NFKC + Unicode case-fold (via `to_lowercase`) + strip
/// combining marks + a small cross-script homoglyph table. A full Unicode
/// confusables skeleton is a noted refinement.
pub fn confusable_fold(s: &str) -> String {
    use unicode_normalization::UnicodeNormalization;
    let nfkc: String = s.nfkc().collect::<String>().to_lowercase();
    nfkc.chars().filter_map(homoglyph_to_ascii).collect()
}

fn homoglyph_to_ascii(c: char) -> Option<char> {
    // Drop combining marks entirely.
    if ('\u{0300}'..='\u{036F}').contains(&c) {
        return None;
    }
    Some(match c {
        // Cyrillic look-alikes.
        'а' => 'a',
        'е' => 'e',
        'о' => 'o',
        'р' => 'p',
        'с' => 'c',
        'х' => 'x',
        'у' => 'y',
        'ѕ' => 's',
        'і' => 'i',
        'ј' => 'j',
        'ԁ' => 'd',
        // Greek look-alikes.
        'ο' => 'o',
        'α' => 'a',
        'ρ' => 'p',
        other => other,
    })
}

/// Resolve one peer's cached name into a renderable form, applying the chat policy's
/// collision handling. `others` is the current name cache for the rest of the chat.
pub fn resolve_render(
    subject_fp: [u8; 48],
    rec: &NameRecord,
    others: &HashMap<[u8; 48], NameRecord>,
    policy: NameTrustPolicy,
    safety_number: String,
    // SUB-SPEC B: `isolated` = the viewer can verify NO linkage for this subject
    // (not a contact/friend, no Linked name, no grouping) — a possible sybil.
    // `amplify_isolated` = the GROUP's display policy wants isolation surfaced with
    // a caveat (disclosure != display: the group only controls its own rendering).
    isolated: bool,
    amplify_isolated: bool,
    // SUB-SPEC C: `vouched` = this subject cleared the viewer's effective weighted
    // vouch threshold (never set from a below-neutral/inflation-rejected score —
    // invariant 1). `vouch_badge` carries the weighted count (e.g. "✳ vouched · 6").
    vouched: bool,
    vouch_badge: Option<String>,
) -> NameRender {
    let folded = confusable_fold(&rec.label);
    // A collision: some OTHER peer holds a HIGHER-tier name that folds the same.
    let collides = others.iter().any(|(fp, o)| {
        *fp != subject_fp && o.tier.rank() > rec.tier.rank() && confusable_fold(&o.label) == folded
    });
    // Precedence: a Verified name is NEVER downgraded to Isolated; a bare, unlinked
    // subject gets the subtle isolated tint (a possible sybil).
    let tint = match rec.tier {
        NameTier::Linked | NameTier::RegistryConfirmed => Tint::Verified,
        NameTier::Bare if isolated => Tint::Isolated,
        NameTier::Bare => Tint::Default,
    };
    let (label, caveat) = match (collides, policy) {
        (false, _) => (Some(rec.label.clone()), None),
        (true, NameTrustPolicy::SignalStyle) => (Some(rec.label.clone()), None),
        (true, NameTrustPolicy::WarnOnCollision) => (
            Some(rec.label.clone()),
            Some(format!(
                "claims to be “{}” — unverified, does not match the verified “{}”",
                rec.label, rec.label
            )),
        ),
        (true, NameTrustPolicy::SuppressColliding) => (
            None,
            Some(format!(
                "a peer tried to use the name “{}” (suppressed — not verified)",
                rec.label
            )),
        ),
    };
    // Group-display amplification (disclosure != display): if the group's policy
    // wants isolation surfaced, add a subtle caveat for an isolated subject — but a
    // collision caveat, being more specific, takes precedence.
    let caveat = caveat.or_else(|| {
        (tint == Tint::Isolated && amplify_isolated)
            .then(|| "unverified — no linkage to a known identity".to_string())
    });
    // SUB-SPEC C: Vouched is the strongest, peer-corroborated tint — it outranks
    // Verified and Isolated (precedence Vouched > Verified > Isolated > Default) but
    // retains the tier badge. A below-threshold subject is untouched (no regression);
    // the engine passes vouched=false when inflation was rejected (invariant 1).
    let tint = if vouched { Tint::Vouched } else { tint };
    let caveat = if vouched { vouch_badge.or(caveat) } else { caveat };
    NameRender {
        label,
        tier: rec.tier,
        badge: rec.tier.badge(),
        tint,
        caveat,
        safety_number,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::presence::NameRecord;
    use std::collections::HashMap;

    fn rec(label: &str, tier: NameTier, acct: u8) -> NameRecord {
        NameRecord {
            label: label.into(),
            tier,
            seq: 1,
            account_fp: Some([acct; 48]),
        }
    }

    #[test]
    fn confusable_fold_collapses_cyrillic() {
        assert_eq!(confusable_fold("Аlice"), confusable_fold("alice")); // Cyrillic А
    }

    #[test]
    fn signal_style_never_warns() {
        let mut others = HashMap::new();
        others.insert([1u8; 48], rec("Alice", NameTier::RegistryConfirmed, 1));
        let r = resolve_render(
            [2u8; 48],
            &rec("Alice", NameTier::Bare, 2),
            &others,
            NameTrustPolicy::SignalStyle,
            "SN".into(),
            false,
            false,
            false,
            None,
        );
        assert_eq!(r.label.as_deref(), Some("Alice"));
        assert!(r.caveat.is_none());
    }

    #[test]
    fn warn_flags_bare_collision_with_verified() {
        let mut others = HashMap::new();
        others.insert([1u8; 48], rec("Alice", NameTier::RegistryConfirmed, 1));
        let r = resolve_render(
            [2u8; 48],
            &rec("Alice", NameTier::Bare, 2),
            &others,
            NameTrustPolicy::WarnOnCollision,
            "SN".into(),
            false,
            false,
            false,
            None,
        );
        assert_eq!(r.label.as_deref(), Some("Alice"));
        assert!(r.caveat.as_deref().unwrap().contains("does not match"));
    }

    #[test]
    fn suppress_hides_bare_collision() {
        let mut others = HashMap::new();
        others.insert([1u8; 48], rec("Alice", NameTier::Linked, 1));
        let r = resolve_render(
            [2u8; 48],
            &rec("Alice", NameTier::Bare, 2),
            &others,
            NameTrustPolicy::SuppressColliding,
            "SN".into(),
            false,
            false,
            false,
            None,
        );
        assert!(r.label.is_none());
        assert!(r.caveat.as_deref().unwrap().contains("suppressed"));
    }

    #[test]
    fn verified_name_keeps_verified_tint() {
        let r = resolve_render(
            [1u8; 48],
            &rec("Alice", NameTier::RegistryConfirmed, 1),
            &HashMap::new(),
            NameTrustPolicy::SignalStyle,
            "SN".into(),
            false,
            false,
            false,
            None,
        );
        assert_eq!(r.tint, Tint::Verified);
    }

    // SUB-SPEC B (Task 6): isolated sybil tint + disclosure!=display amplification.

    #[test]
    fn isolated_bare_gets_isolated_tint() {
        let r = resolve_render(
            [2u8; 48],
            &rec("Whiskey", NameTier::Bare, 2),
            &HashMap::new(),
            NameTrustPolicy::SignalStyle,
            "SN".into(),
            true,  // isolated
            false, // group does not amplify
            false,
            None,
        );
        assert_eq!(r.tint, Tint::Isolated);
        assert!(r.caveat.is_none(), "no caveat unless the group amplifies");
    }

    #[test]
    fn verified_is_never_downgraded_to_isolated() {
        // Even if flagged isolated, a Linked/RegistryConfirmed name stays Verified.
        let r = resolve_render(
            [1u8; 48],
            &rec("Alice", NameTier::Linked, 1),
            &HashMap::new(),
            NameTrustPolicy::SignalStyle,
            "SN".into(),
            true,
            true,
            false,
            None,
        );
        assert_eq!(r.tint, Tint::Verified);
        assert!(r.caveat.is_none());
    }

    // SUB-SPEC C (Task 5): Vouched tint precedence.

    #[test]
    fn vouched_outranks_verified_and_isolated() {
        // A verified name that is ALSO vouched shows the Vouched tint, badge retained.
        let r = resolve_render(
            [1u8; 48],
            &rec("Alice", NameTier::Linked, 1),
            &HashMap::new(),
            NameTrustPolicy::SignalStyle,
            "SN".into(),
            false,
            false,
            true,
            Some("✳ vouched · 6".into()),
        );
        assert_eq!(r.tint, Tint::Vouched);
        assert_eq!(r.badge, NameTier::Linked.badge()); // verified badge kept
        assert_eq!(r.caveat.as_deref(), Some("✳ vouched · 6"));
        // An isolated bare subject that is vouched also shows Vouched (outranks Isolated).
        let r2 = resolve_render(
            [2u8; 48],
            &rec("Bravo", NameTier::Bare, 2),
            &HashMap::new(),
            NameTrustPolicy::SignalStyle,
            "SN".into(),
            true,
            true,
            true,
            Some("✳ vouched · 3".into()),
        );
        assert_eq!(r2.tint, Tint::Vouched);
        // Not vouched → unchanged (no regression): isolated stays Isolated.
        let r3 = resolve_render(
            [3u8; 48],
            &rec("Charlie", NameTier::Bare, 3),
            &HashMap::new(),
            NameTrustPolicy::SignalStyle,
            "SN".into(),
            true,
            false,
            false,
            None,
        );
        assert_eq!(r3.tint, Tint::Isolated);
    }

    #[test]
    fn group_amplify_adds_isolated_caveat() {
        let r = resolve_render(
            [2u8; 48],
            &rec("Whiskey", NameTier::Bare, 2),
            &HashMap::new(),
            NameTrustPolicy::SignalStyle,
            "SN".into(),
            true, // isolated
            true, // group amplifies its own display
            false,
            None,
        );
        assert_eq!(r.tint, Tint::Isolated);
        assert!(r.caveat.as_deref().unwrap().contains("no linkage"));
    }
}
