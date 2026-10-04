# Removing OS-level age-verification / age-signal plumbing

A defensive guide for users who do not want their operating system to collect,
store, or expose an age/birth-date signal on their own machine. This is about
*your own system* and user autonomy — the same posture as disabling telemetry.
It aligns with talkrypt's anonymity threat model and the packaging gate in
[`../packaging-policy.md`](../packaging-policy.md).

It complements the upstream community effort **Ageless Linux**, which tracks how
distros respond to age-verification mandates and publishes tooling to undo
whatever they implement ([agelesslinux.github.io](https://agelesslinux.github.io/age-reporting/distro-specific.html)).

> **Reality check (2026-10):** no mainstream distro *mandates* age verification,
> and the laws that reached the OS (CA AB 1043, CO SB26-051) were amended with
> open-source exemptions. The one concrete surface that actually shipped is
> systemd's optional `birthDate` field — which is **unset by default, settable
> only by an administrator, and acted on by nothing in systemd itself** ("systemd
> enforces zero policy"). So this guide is mostly *preventive + auditing*, not an
> emergency removal. Verify every command on your own system/version first.

## The one real surface: systemd `birthDate`

systemd PR [#40954](https://github.com/systemd/systemd/pull/40954) (merged ~Mar
2026) added a `birthDate` field to JSON user records. Properties:

- Serialized `YYYY-MM-DD`; lives in the **non-privileged** section of the record
  (readable by the user and by applications), but is **excluded from
  self-modifiable fields** — only root sets it (`homectl --birth-date=`).
- **Optional, unset by default.** systemd does nothing with it; it is at most a
  *data source* an age-querying app could read — i.e. a potential **age-bracket
  fingerprint** in user space, which is the actual privacy concern.
- It remains in mainline (the revert was closed unmerged), so "removal" means one
  of the routes below. Sources:
  [OSTechNix](https://ostechnix.com/systemd-userdb-birthdate-age-verification/),
  [itsfoss](https://itsfoss.com/news/systemd-fork-strips-out-age-verification/).

### 1. Audit — is a birth date set / is the field present?
```sh
# Your own record (works with userdbctl; shows birthDate only if set):
userdbctl user "$(id -un)" 2>/dev/null | grep -i 'birth' || echo "no birthDate on this record"
# homed-managed users:
homectl inspect "$(id -un)" 2>/dev/null | grep -i 'birth' || true
# Is this even a systemd system? (systemd-free distros have no such field.)
[ -d /run/systemd/system ] && echo "systemd init" || echo "NON-systemd init (no birthDate plumbing)"
```
`scripts/privacy/audit-age-signals.sh` wraps this (read-only).

### 2. Keep it unset (simplest, sufficient for most)
Because the field is unset by default and admin-only, the practical defense is:
**do not let an installer/first-run set it, and do not set it yourself.** If some
provisioning set one on a **homed** user, an administrator can overwrite it:
```sh
# Re-assert an EMPTY birth date on a homed-managed user (admin). Confirm the
# switch exists on your systemd version; on non-homed users the field lives in
# userdb drop-ins and this switch does not apply.
sudo homectl update "<user>" --birth-date=""   # verify behaviour on your version
```
If `homectl` does not manage the account (ordinary `/etc/passwd` users), there is
no CLI field to clear — the record simply carries no `birthDate` unless a userdb
drop-in adds one; audit `/etc/userdb` / `/run/userdb` for any that do.

### 3. Strip it at the source (for source-built / patched distros)
Gentoo, Arch (custom `systemd` build), or anyone compiling systemd can drop the
field entirely, using the community forks/reverts as the patch set:
- **"Liberated systemd"** — a fork that removes `birthDate` + the `homectl`
  switch + man pages + tests (12 files / 5 commits)
  ([itsfoss](https://itsfoss.com/news/systemd-fork-strips-out-age-verification/)).
- A **revert-backport** of "add birthDate" + "mark PII fields sensitive" for
  distros that want to carry the patch without a full fork.
Apply as a distro patch (e.g. a Gentoo `/etc/portage/patches/sys-apps/systemd/`
drop-in, or an Arch PKGBUILD `prepare()` patch), then rebuild.

### 4. Structural immunity: systemd-free distros
**Devuan, Artix, Gentoo (OpenRC), Alpine (OpenRC)** have no systemd user-record
layer, so the `birthDate` field does not exist on them at all. If OS-level
age-signalling is in your threat model, a systemd-free base is the cleanest answer.

## General hardening (any distro)
- **Deny the query path.** The privacy risk is a user-space program (including
  browser JS via some bridge) reading an age signal. Prefer apps/stores that do
  not query userdb for age; audit new "age/parental" settings an update adds.
- **Amnesic/throwaway for sensitive sessions.** A live, amnesic system (**Tails**,
  **Kodachi**) carries no persistent user record to stamp with a birth date.
- **Track your distro's stance.** See the classification log
  ([`../distro-age-verification-log.md`](../distro-age-verification-log.md)); watch
  Ageless Linux for per-distro removal scripts as situations evolve.

## Scope / honesty
This removes/avoids *age-signal collection on your own machine*. It is not a way
to defeat a lawful age gate on someone else's service, and it changes nothing
about talkrypt's own crypto. talkrypt is **NOT certified / NOT audited**; these
are user-autonomy notes, not legal advice.
