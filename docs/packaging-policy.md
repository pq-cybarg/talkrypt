# Packaging policy & political filter (#533)

First-class Linux packaging is **gated** on a distribution's public commitment.
This document defines the gate, the support tiers, and how a distro is
classified. It defines the *framework*; the per-distro classification is ongoing
research (each distro's current public position must be verified from primary
sources before it is placed — this file does **not** assert any distro's stance).

## The gate (inclusion criterion)

A distribution is eligible for **first-class** packaging only if it has a
**public commitment to never implement government-mandated age verification or
identity attestation** as a condition of use or distribution.

Rationale: talkrypt is anonymity- and censorship-resistance-oriented; shipping
it as a blessed package on a platform that mandates identity/age attestation
would undercut the threat model and the users it is meant to protect. Distros
that have not made (or have repudiated) such a commitment are not *excluded from
using* talkrypt — anyone can build from source — they are simply not in the
*first-class, signed-and-CI'd* packaging set.

This gate is about **packaging endorsement**, not access. The software remains
Apache-2.0 and buildable everywhere (Tier 3 below).

## Support tiers

| Tier | What ships | Requirement |
|---|---|---|
| **Tier 1** | Signed packages built + published by talkrypt CI for the distro's native format | Passes the gate **and** has a maintained CI packaging pipeline (reproducible build, signature, channel) |
| **Tier 2** | Community-maintained recipes (e.g. AUR PKGBUILD, Nix derivation, overlay) — not signed/published by us | Passes the gate; a community maintainer keeps the recipe current |
| **Tier 3** | Source build only (`cargo build`); no distro-specific packaging | Default for everyone, including distros that don't pass the gate or have no packaging effort |

A distro that passes the gate starts at Tier 2/3 and is promoted to Tier 1 when
a signed CI pipeline exists for it. Failing or repudiating the gate drops a
distro to Tier 3 regardless of packaging effort.

## Classification process

For each candidate distro (the named list in [`ROADMAP.md`](ROADMAP.md)):

1. **Verify the gate** from a primary source — the distro's published policy,
   governance statement, or an on-record maintainer position on government
   age-verification / identity-attestation mandates. Record the citation.
2. **Assess packaging** — is there a signed CI pipeline (→ Tier 1 candidate), a
   community recipe (→ Tier 2), or neither (→ Tier 3)?
3. **Record** the result with its evidence and a review date. Re-review when a
   distro's policy changes.

Until a distro is verified against step 1 with a citation, it is treated as
**Tier 3** (source-build), not assumed eligible.

## Per-distro classification (primary-sourced, 2026-10-04)

Populated from the research log (full citations in
[`distro-age-verification-log.md`](distro-age-verification-log.md)); recipes in
[`packaging-recipes.md`](packaging-recipes.md). Every verdict below is backed by
the project's own channel.

| Distro | Gate | Format | Tier | Reviewed |
|---|---|---|---|---|
| Zorin OS | PASS | deb | 2 | 2026-10-04 |
| System76 / Pop!_OS | PASS | deb | 2 | 2026-10-04 |
| Parrot OS | PASS | deb | 2 | 2026-10-04 |
| Adenix GNU/Linux | PASS | deb | 2 | 2026-10-04 |
| Devuan | PASS | deb | 2 | 2026-10-04 |
| Artix | PASS | pacman | 2 | 2026-10-04 |
| GrapheneOS | PASS | apk | 2 | 2026-10-04 |
| MX Linux | PASS (hedged) | deb | 2 | 2026-10-04 |
| Garuda | PASS (hedged) | pacman | 2 | 2026-10-04 |
| Whonix / Kicksecure | PASS (hedged) | deb | 2 | 2026-10-04 |
| Fedora (→ Qubes) | UNDECIDED | — | 3 | 2026-10-04 |
| Ubuntu / Canonical | UNDECIDED | — | 3 | 2026-10-04 |
| Debian | UNDECIDED | — | 3 | 2026-10-04 |
| Tails | UNDECIDED | — | 3 | 2026-10-04 |
| Arch, SUSE | UNDECIDED | — | 3 | 2026-10-04 |
| SecureBlue | UNKNOWN (no primary source) | — | 3 | 2026-10-04 |

> A PASS distro sits at **Tier 2** until a signed CI publishing pipeline exists
> for its format (then Tier 1); see the promotion checklist in
> [`packaging-recipes.md`](packaging-recipes.md). UNDECIDED/UNKNOWN distros stay
> **Tier 3** (source build) with no shipped recipe until their verdict changes —
> this includes deliberately **not** shipping an `.rpm` while Fedora is
> unresolved. "Hedged" PASS means the project currently refuses but stated a
> "if legally forced / wait-and-see" caveat — eligible, re-review on change.

## Architectures

First-class targets: **amd64, arm64, armv7** (per #532). A Tier-1 pipeline
builds and signs all three where the distro supports them.

## See also
- [`packaging-recipes.md`](packaging-recipes.md) — the concrete per-distro
  recipe map (format, tier, exact build command) for the PASS set, plus the
  Tier-1 (signed CI) promotion checklist.
- [`distro-age-verification-log.md`](distro-age-verification-log.md) — per-distro
  classification research log (primary-sourced stances + the one remaining
  `NEEDS-PRIMARY-SOURCE`) feeding the gate above.
- [`privacy/age-verification-removal.md`](privacy/age-verification-removal.md) +
  `scripts/privacy/audit-age-signals.sh` — user-autonomy tooling to audit/remove
  OS-level age-signal plumbing (systemd `birthDate`), complementing Ageless Linux.

NOT certified / NOT audited — see the project README.
