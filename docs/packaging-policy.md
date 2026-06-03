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

## Per-distro classification (TO BE FILLED FROM PRIMARY SOURCES)

| Distro | Gate (cite) | Packaging | Tier | Reviewed |
|---|---|---|---|---|
| _(each distro from ROADMAP)_ | _pending verification_ | — | 3 (default) | — |

> Deliberately left unfilled: classifying a distro's political commitment is a
> factual claim about that project and must cite a primary source, not be
> guessed. Populating this table is the remaining work of #533.

## Architectures

First-class targets: **amd64, arm64, armv7** (per #532). A Tier-1 pipeline
builds and signs all three where the distro supports them.

NOT certified / NOT audited — see the project README.
