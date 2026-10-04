# Distro age-verification / ID classification — research log

Working notes for the packaging gate in [`packaging-policy.md`](packaging-policy.md):
a distro is eligible for **first-class** (Tier 1/2) packaging only with a **public
commitment to never implement government-mandated age-verification or
identity-attestation** as a condition of use or distribution.

> **Verification status:** rows marked **[PRIMARY]** are confirmed from the
> project's own source (forum/blog/mailing-list/issue tracker) and cited inline;
> rows marked **[REPORTED]** are from secondary coverage and still need a primary
> source. This is a **live 2025–2026 controversy** — re-review quarterly.
> First primary-source pass: 2026-10-04.

## Legal + technical context
- **California AB 1043** (Digital Age Assurance) and **Colorado SB26-051** (Age
  Attestation) push an age *signal* to the OS; CO effective 2027-01-01. ~9 US
  states + Brazil ECA Digital + AU/EU in the same wave. **Both CA and CO were
  amended with open-source exemptions** — a win the open-source community (incl.
  System76) lobbied for.
- Proposed cross-desktop mechanism: a D-Bus interface
  **`org.freedesktop.AgeVerification1`** (proposed on freedesktop/Debian/Fedora/
  Ubuntu lists by A. Rainbolt), exposing one of **four self-declared brackets**
  (<13, 13–16, 16–18, 18+). It is **self-declared, not verified** (suggested
  rename "declaration"); **optional**, "implemented by arbitrary applications as a
  distro sees fit." [debian-devel](https://lists.debian.org/debian-devel/2026/03/msg00016.html)
- **systemd `birthDate`** field (PR #40954): optional, admin-set-only, unset by
  default, "zero policy." A data source, not verification. See
  [`privacy/age-verification-removal.md`](privacy/age-verification-removal.md).

## Target set (project decision, 2026-10-04)
In scope: **all candidates below except Omarchy** (**Omarchy excluded by project
decision**). In-scope ≠ a Tier — the gate decides.

## Candidates

### Bucket A — refusal confirmed / strongly leaning (first-class candidates)
| Distro | Stance | Source | Gate |
|---|---|---|---|
| **Zorin OS** | "no plans to introduce mandatory age or ID verification"; founder "we will not comply" even if Ubuntu does; Ireland-based (CA likely unenforceable); would strip invasive bits from Ubuntu | **[PRIMARY]** [forum statement, 2026-03-25](https://forum.zorin.com/t/statement-about-age-verification-laws/61052) | **PASS** (maintainer statement, not a charter — re-confirm if governance changes) |
| **System76 / Pop!_OS** | "Pop!_OS and the COSMIC Desktop Environment **will not include Age Verification or Age Attestation**"; ignores the systemd `birthDate`; led the open-source-exemption lobbying | **[PRIMARY]** [System76 blog, 2026-05-26](https://system76.com/blog/post/co-and-ca-exempt-open-source-from-age-attestation) + [opposition post](https://blog.system76.com/post/system76-on-age-verification/) | **PASS** (supersedes the earlier "may comply" secondary report — that was wrong) |
| **Whonix / Kicksecure** | explored a privacy-preserving age-API, hit heavy pushback, **reversed**: "do not expect to add an age API… this assessment may become more definite later"; dev: "unlikely" | **[PRIMARY]** [Whonix forum](https://forums.whonix.org/t/whonix-adding-age-verification/22969) | **PASS (hedged)** — currently refusing; "may become more definite," so re-review |
| MX Linux | rejects integrating age verification | [REPORTED] [Linux Journal](https://www.linuxjournal.com/content/mx-linux-pushes-back-against-age-verification-stand-privacy-and-open-source-principles) | PASS? — NEEDS-PRIMARY-SOURCE |
| Parrot OS, Garuda, Adenix | reported independent no-implement determinations | [REPORTED] [itsfoss](https://itsfoss.com/news/distros-response-age-verification-laws/) | PASS? — NEEDS-PRIMARY-SOURCE |
| Devuan, Artix | systemd-free → no `birthDate`/userdb age plumbing (structural immunity) + init-freedom ethos | [structural] | PASS? — confirm a governance statement |
| ~~Omarchy~~ | — | — | **EXCLUDED by project decision** |

### Bucket B — undecided / deliberating (Tier-3 until resolved)
| Distro | Stance | Source | Gate |
|---|---|---|---|
| **Tails** | discussing internally; no decision | **[PRIMARY-ish]** Tails GitLab work item #21457 (per Whonix thread) | UNDECIDED |
| **Debian** | an **unadopted proposal** by one dev for the optional `org.freedesktop.AgeVerification1` D-Bus iface; community-skeptical ("censorship API"); **no GR, no DPL statement** | **[PRIMARY]** [debian-devel](https://lists.debian.org/debian-devel/2026/03/msg00016.html) | UNDECIDED — not a Debian position; systemd `birthDate` rides in via upstream but is inert |
| **Qubes OS** | would follow **Fedora's** decision | [REPORTED] tracker (Whonix thread, 2026-03-21) | UNDECIDED — **gate inherits Fedora** (verify Fedora primary) |

### Bucket C — reported to comply / silent (Tier-3)
| Distro | Stance | Source | Gate |
|---|---|---|---|
| SecureBlue | intended to comply | [REPORTED] tracker | FAIL? — NEEDS-PRIMARY-SOURCE |
| Ubuntu / Canonical | "no plans at the moment" (relayed by Zorin; FreeDesktop proposal cross-posted) | [REPORTED] | NEEDS-PRIMARY-SOURCE (Canonical) |
| Fedora | pivotal (Qubes + others follow it); position not yet pinned | — | NEEDS-PRIMARY-SOURCE |
| GrapheneOS | tracker says "would not comply"; earlier coverage said "floated, undecided" | [REPORTED] (conflicting) | NEEDS-PRIMARY-SOURCE (lean PASS) |
| Arch, SUSE | publicly silent | [REPORTED] [itsfoss](https://itsfoss.com/news/distros-response-age-verification-laws/) | UNDECIDED |

## Privacy / opsec / throwaway distros (purpose reference; orthogonal to the gate)
Amnesic/throwaway: **Tails**, **Kodachi**. Compartmentalization: **Qubes** (+**Whonix**).
Offensive/intel: **Kali**, **Parrot (Security)**, **BlackArch**, **Pentoo**, **Athena**.
Minimal/DIY: **Arch**, **Alpine**, **Gentoo**. systemd-free (sidestep `birthDate`):
**Devuan**, **Artix**, **Gentoo (OpenRC)**, **Alpine (OpenRC)**. Libre: **Trisquel**, **PureOS**.
*Privacy-focused ≠ gate-pass* — Whonix/Tails were the clearest example (both explored or are weighing an age API).

## Remaining step-1 work
Primary sources still to capture: **MX, Parrot, Garuda, Adenix** (refuser claims),
**Fedora** (drives Qubes), **Canonical/Ubuntu**, **GrapheneOS**, **SecureBlue**.
Promote/demote the Gate column as each is confirmed, with date.
