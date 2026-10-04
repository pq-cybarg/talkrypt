# Distro age-verification / ID classification — research log

Working notes for the packaging gate in [`packaging-policy.md`](packaging-policy.md):
a distro is eligible for **first-class** (Tier 1/2) packaging only with a **public
commitment to never implement government-mandated age-verification or
identity-attestation** as a condition of use or distribution.

> **Status of every row below: REPORTED, UNVERIFIED.** The citations are
> **secondary** (news/blogs/forum threads) and this is a **live, fast-moving
> 2025–2026 controversy**. Per the policy, no row becomes a Tier-1 verdict until
> its stance is confirmed from the distro's **primary source** (published policy,
> governance statement, or on-record maintainer position) with that citation
> recorded here. Treat this file as a lead list for that step-1 research, not as
> an assertion of any project's position. Logged 2026-10-04; re-review quarterly.

## Legal context (why this reached the OS)
- **California AB 1043** (Digital Age Assurance) and **Colorado SB26-051** (Age
  Attestation on Computing Devices) push age signalling to the OS; ~9 US states +
  Brazil's ECA Digital in the same wave. **Both CA and CO were amended with
  open-source OS/software exemptions.**
- **systemd** merged a `birthDate` user-record field (PR #40954, ~Mar 2026):
  optional, admin-set only, unset by default, "systemd enforces zero policy." It
  is a potential age *signal*, not verification. See
  [`privacy/age-verification-removal.md`](privacy/age-verification-removal.md).

Sources: [itsfoss](https://itsfoss.com/news/distros-response-age-verification-laws/),
[reclaimthenet](https://reclaimthenet.org/linux-age-verification-pushback),
[falcao.org](https://falcao.org/posts/age-verification-linux-immunity/).

## Target set (project decision, 2026-10-04)
In scope as packaging targets: **all candidates below except Omarchy**
(**Omarchy is deliberately excluded by project decision**). Being in scope does
not grant a Tier — the gate still decides, pending primary-source verification.

## Candidates

### Bucket A — reported refusal (first-class candidates, pending primary source)
| Distro | Reported stance | Secondary source | Gate | Verify |
|---|---|---|---|---|
| Zorin OS | "age verification will not be implemented under any circumstances" | [linuxteck](https://www.linuxteck.com/zorin-os-age-verification/) | PASS? | NEEDS-PRIMARY-SOURCE (find the Zorin forum post) |
| MX Linux | rejects integrating age verification | [Linux Journal](https://www.linuxjournal.com/content/mx-linux-pushes-back-against-age-verification-stand-privacy-and-open-source-principles) | PASS? | NEEDS-PRIMARY-SOURCE |
| Parrot OS | reported independent no-implement determination | [itsfoss](https://itsfoss.com/news/distros-response-age-verification-laws/) | PASS? | NEEDS-PRIMARY-SOURCE |
| Garuda | reported independent no-implement determination | [itsfoss](https://itsfoss.com/news/distros-response-age-verification-laws/) | PASS? | NEEDS-PRIMARY-SOURCE |
| Devuan | systemd-free → no `birthDate` plumbing (structural) + init-freedom ethos | (structural; confirm governance statement) | PASS? | NEEDS-PRIMARY-SOURCE |
| Artix | systemd-free (structural, as Devuan) | (structural) | PASS? | NEEDS-PRIMARY-SOURCE |
| Adenix GNU/Linux | declared it will not implement age checks | [itsfoss](https://itsfoss.com/news/distros-response-age-verification-laws/) | PASS? | NEEDS-PRIMARY-SOURCE |
| ~~Omarchy~~ | (reported refusal) | — | — | **EXCLUDED by project decision** |

### Bucket B — reported *considering* an age API or a comply-faction (Tier-3 until clarified)
Note the counter-intuitive part: some of the most privacy-forward projects are
**not** clean gate-passes right now.
| Distro | Reported stance | Secondary source | Gate |
|---|---|---|---|
| Tails | opened a GitLab issue on the requirement (direction undecided) | [Privacy Guides thread](https://discuss.privacyguides.net/t/age-verification-for-qubes-os-and-whonix-among-other-linux-distributions/35984) | CAUTION |
| Whonix | reportedly discussed adding an age-verification API | [Privacy Guides thread](https://discuss.privacyguides.net/t/age-verification-for-qubes-os-and-whonix-among-other-linux-distributions/35984) | CAUTION |
| Debian | internal discussion incl. a comply-faction; no GR / DPL statement | [Privacy Guides thread](https://discuss.privacyguides.net/t/age-verification-for-qubes-os-and-whonix-among-other-linux-distributions/35984) | CAUTION (conflicting reports; one lists Debian as refusing — resolve via debian-devel + GR tracker) |
| System76 / Pop!_OS | publicly opposes; lobbying Colorado for an open-source exemption — but one source says "chosen to comply" | [itsfoss](https://itsfoss.com/news/distros-response-age-verification-laws/), [Privacy Guides thread](https://discuss.privacyguides.net/t/age-verification-for-qubes-os-and-whonix-among-other-linux-distributions/35984) | CAUTION (reports conflict) |

### Bucket C — silent / undecided (Tier-3)
Arch, SUSE, GrapheneOS (floated, undecided), Qubes OS. ([itsfoss](https://itsfoss.com/news/distros-response-age-verification-laws/))

## Privacy / opsec / throwaway distros (purpose reference, orthogonal to the gate)
Amnesic/throwaway: **Tails**, **Kodachi**. Compartmentalization: **Qubes OS**
(+ **Whonix**). Offensive/intel: **Kali**, **Parrot (Security)**, **BlackArch**,
**Pentoo**, **Athena**. Minimal/DIY: **Arch**, **Alpine**, **Gentoo**.
systemd-free (sidestep `birthDate`): **Devuan**, **Artix**, **Gentoo (OpenRC)**,
**Alpine (OpenRC)**. Libre/anti-telemetry: **Trisquel**, **PureOS**.
*Privacy-focused ≠ gate-pass* — classify each by the gate, not its mission.

## Next step (policy step 1)
For each Bucket-A row, capture the **primary source** (Zorin forum post; MX/Parrot/
Garuda governance or maintainer statement; Debian debian-devel/GR tracker; Tails &
Whonix GitLab issues) and update the Gate column from `PASS?` to a verdict + date.
