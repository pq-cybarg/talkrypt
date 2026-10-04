# Distro age-verification / ID classification — research log

Working notes for the packaging gate in [`packaging-policy.md`](packaging-policy.md):
a distro is eligible for **first-class** (Tier 1/2) packaging only with a **public
commitment to never implement government-mandated age-verification or
identity-attestation** as a condition of use or distribution.

> **Verification status:** rows marked **[PRIMARY]** are confirmed from the
> project's own source (forum/blog/mailing-list/issue tracker) and cited inline;
> rows marked **[REPORTED]** are from secondary coverage and still need a primary
> source. This is a **live 2025–2026 controversy** — re-review quarterly.
> First primary-source pass: 2026-10-04. Round-3 pass (same day) resolved MX,
> Garuda, Adenix, GrapheneOS; only SecureBlue remains without a primary source.

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
| **Parrot OS** | official blog "We don't want your ID": "will not proactively implement any Age Verification"; nothing until legally forced, and even then "intentionally porous and easily bypassed" | **[PRIMARY]** [parrotsec.org, 2026-04-02](https://parrotsec.org/blog/2026-04-02-our-statement-about-age-verification/) | **PASS** |
| **MX Linux** | team statement in the official weekly update: "no one on the team at MX wants to implement something like age verification"; "wait and observe" pending court challenges; redirects users to lobby lawmakers, not the distro | **[PRIMARY-ish]** MX weekly update, quoted verbatim by [linuxiac](https://linuxiac.com/mx-linux-takes-clear-stance-against-age-verification-requirements/) / [Linux Journal](https://www.linuxjournal.com/content/mx-linux-pushes-back-against-age-verification-stand-privacy-and-open-source-principles) | **PASS (hedged)** — official team channel, but "wait and observe" not an absolute charter; re-review |
| **Garuda Linux** | official forum announcement: "Garuda Linux will not implement any age verification measures, since Garuda Linux's legal jurisdictions have no laws mandating age verification" (infra in FI/DE/AT); if ever legally forced, only minimal self-declaration ("a checkbox like 'I am legally an adult'"), never third-party ID | **[PRIMARY]** [Garuda forum announcement](https://forum.garudalinux.org/t/a-statement-on-age-verification-the-state-of-the-community-discourse/47652) | **PASS (hedged — jurisdictional)** — refusal is contingent on no EU/local mandate; would do minimal self-declaration if forced |
| **Adenix GNU/Linux** | strongest stance: founder J. Mazzullo — distro "will NOT have any age checks" and is "not for use in California or any other regions with age verification laws that affect operating systems"; asked Debian for a root-removable age package + region blacklist | **[PRIMARY]** founder statement on [debian-legal, 2026-03](https://lists.debian.org/debian-legal/2026/03/msg00022.html) + project site | **PASS** (explicit, unconditional refusal) |
| **GrapheneOS** | official X post (2026-03-20): "GrapheneOS will remain usable by anyone around the world without requiring personal information, identification or an account… If GrapheneOS devices can't be sold in a region due to their regulations, so be it"; proposes OS child-profile checks instead of per-app ID. Canadian non-profit (GrapheneOS Foundation) | **[PRIMARY]** GrapheneOS official account, 2026-03-20; corroborated by [Privacy Guides](https://www.privacyguides.org/news/2026/03/23/grapheneos-wont-implement-age-verification/) | **PASS** (restores the earlier verdict — the X post IS a primary dev statement; the round-2 downgrade to UNKNOWN was wrong) |
| Devuan, Artix | systemd-free → no `birthDate`/userdb age plumbing (structural immunity) + init-freedom ethos | [structural] | PASS? — confirm a governance statement |
| ~~Omarchy~~ | — | — | **EXCLUDED by project decision** |

### Bucket B — undecided / deliberating (Tier-3 until resolved)
| Distro | Stance | Source | Gate |
|---|---|---|---|
| **Tails** | discussing internally; no decision | **[PRIMARY-ish]** Tails GitLab work item #21457 (per Whonix thread) | UNDECIDED |
| **Debian** | an **unadopted proposal** by one dev for the optional `org.freedesktop.AgeVerification1` D-Bus iface; community-skeptical ("censorship API"); **no GR, no DPL statement** | **[PRIMARY]** [debian-devel](https://lists.debian.org/debian-devel/2026/03/msg00016.html) | UNDECIDED — not a Debian position; systemd `birthDate` rides in via upstream but is inert |
| **Qubes OS** | follows **Fedora's** decision — and Fedora has made none | [PRIMARY] Fedora undecided ([Fedora Discussion](https://discussion.fedoraproject.org/t/regarding-age-verification/184976)) | UNDECIDED (inherits Fedora) |

### Bucket C — reported to comply / silent (Tier-3)
| Distro | Stance | Source | Gate |
|---|---|---|---|
| **Fedora** | **no decision** — active debate (store birth-date file vs group-flags vs manual; whether OSS is even covered) | **[PRIMARY]** [Fedora Discussion](https://discussion.fedoraproject.org/t/regarding-age-verification/184976) | UNDECIDED (pivotal — Qubes + others wait on it) |
| **Ubuntu / Canonical** | official: "no decisions made," under legal review; installer/systemd prototypes are an **external contributor**, not Canonical | **[PRIMARY]** [Ubuntu Discourse](https://discourse.ubuntu.com/t/ubuntus-response-to-californias-digital-age-assurance-act-ab-1043/77948) | UNDECIDED (community has a "must not implement" petition thread — not official) |
| SecureBlue | "reported comply" — but the only trace is a **secondary/circular** report (no SecureBlue issue, FAQ, or statement found); claim is unsubstantiated | [REPORTED] (unconfirmed, likely circular) | UNKNOWN — NEEDS-PRIMARY-SOURCE (do not record as FAIL without a source) |
| Arch, SUSE | publicly silent | [REPORTED] [itsfoss](https://itsfoss.com/news/distros-response-age-verification-laws/) | UNDECIDED |

## Privacy / opsec / throwaway distros (purpose reference; orthogonal to the gate)
Amnesic/throwaway: **Tails**, **Kodachi**. Compartmentalization: **Qubes** (+**Whonix**).
Offensive/intel: **Kali**, **Parrot (Security)**, **BlackArch**, **Pentoo**, **Athena**.
Minimal/DIY: **Arch**, **Alpine**, **Gentoo**. systemd-free (sidestep `birthDate`):
**Devuan**, **Artix**, **Gentoo (OpenRC)**, **Alpine (OpenRC)**. Libre: **Trisquel**, **PureOS**.
*Privacy-focused ≠ gate-pass* — Whonix/Tails were the clearest example (both explored or are weighing an age API).

## Remaining step-1 work
Primary-confirmed **PASS**: **Zorin, System76/Pop!_OS, Parrot, Adenix,
GrapheneOS**; **PASS (hedged)**: **MX, Garuda, Whonix** (each refusing now, but
with a stated "if forced / wait-and-see" caveat). Primary-confirmed
**undecided**: **Fedora, Ubuntu/Canonical, Debian, Tails** (and **Qubes** via
Fedora). 

Round-3 pass (2026-10-04) resolved MX, Garuda, Adenix, and GrapheneOS from
`NEEDS-PRIMARY-SOURCE` — and **restored GrapheneOS to PASS** (the round-2
downgrade to UNKNOWN was wrong: the 2026-03-20 X post is a primary dev
statement). 

Only `NEEDS-PRIMARY-SOURCE` left: **SecureBlue** (the lone "comply" claim is a
circular/secondary report with no locatable primary source — recorded as UNKNOWN,
**not** FAIL). Structural-but-governance-unconfirmed: **Devuan, Artix** (systemd-
free immunity is real; a project governance statement would upgrade them to a
non-hedged PASS). A useful aggregator to watch: the "DoesItAgeVerify" and
"Linux-Age-Verification-Stance" trackers (secondary — always re-confirm against
the project's own channel). Promote/demote the Gate column as each is confirmed,
with date.
