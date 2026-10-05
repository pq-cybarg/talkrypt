# Packaging recipes for the confirmed-PASS distros

This maps every distro that **passes the packaging gate**
([`packaging-policy.md`](packaging-policy.md); roster in
[`distro-age-verification-log.md`](distro-age-verification-log.md)) to a concrete
recipe: its native package format, the tier it currently sits at, and the exact
build command. It is the operational companion to the policy (which decides
*eligibility*) and the gate log (which records *why* each distro is eligible).

> **Scope.** This is about *first-class packaging endorsement*, not access.
> talkrypt is Apache-2.0 and builds from source (`cargo build --release`)
> everywhere, including distros that don't pass the gate (Tier 3). Shipping a
> *blessed, signed* package is what the gate governs. **NOT certified / NOT
> audited** — see the README banner.

## Tiers (recap)

| Tier | What ships | How we get there |
|---|---|---|
| **Tier 1** | Signed packages built + published by talkrypt CI in the native format | Gate PASS **and** a maintained signed CI pipeline |
| **Tier 2** | A maintained recipe (deb/PKGBUILD/APK) we keep current but don't sign/publish | Gate PASS; recipe exists in-repo |
| **Tier 3** | Source build only (`cargo build`) | Default for everyone |

Today every PASS distro is **Tier 2** (recipe present, not yet a signed
published channel). Promotion to Tier 1 is the signed-CI task tracked at the
bottom. No distro is silently dropped — a gate downgrade moves it to Tier 3.

## The three formats cover the whole PASS set

The confirmed-PASS roster collapses to exactly three packaging ecosystems, each
with one recipe that serves every distro in it:

| Format / recipe | Covers (PASS distros) | Status |
|---|---|---|
| **Debian `.deb`** — `scripts/package.sh` (`build_deb`, portable `ar`+`tar`, no `dpkg-deb` needed) | Zorin, System76/Pop!_OS, Parrot, Adenix, Devuan, **+ hedged:** MX, Whonix/Kicksecure | recipe ✅ |
| **Arch `PKGBUILD`** — [`packaging/arch/PKGBUILD`](../packaging/arch/PKGBUILD) (from-source, `makepkg -si`) | Artix, **+ hedged:** Garuda | recipe ✅ (new) |
| **Android `.apk`** — `android/build-apk.sh` (cargo-ndk `.so` + UniFFI Kotlin + Gradle) | GrapheneOS | recipe ✅ |

macOS (Homebrew, [`packaging/homebrew/talkrypt.rb`](../packaging/homebrew/talkrypt.rb))
and the generic `.tar.gz` / `.dmg` / `.zip` / musl-static artifacts from
`scripts/package.sh` are orthogonal to the Linux gate — they're host-OS
delivery, not distro endorsement.

## Per-distro recipe table

| Distro | Gate verdict | Format | Recipe | Build command |
|---|---|---|---|---|
| **Zorin OS** | PASS | deb (Ubuntu base) | `scripts/package.sh` | `bash scripts/package.sh` → `dist/talkrypt_<ver>_<arch>.deb` |
| **System76 / Pop!_OS** | PASS | deb | `scripts/package.sh` | same as above |
| **Parrot OS** | PASS | deb (Debian base) | `scripts/package.sh` | same |
| **Adenix GNU/Linux** | PASS | deb (Debian base) | `scripts/package.sh` | same |
| **Devuan** | PASS | deb (systemd-free Debian) | `scripts/package.sh` | same (no systemd units shipped, so nothing to adjust) |
| **Artix** | PASS | pacman (Arch, systemd-free) | `packaging/arch/PKGBUILD` | `cd packaging/arch && TALKRYPT_LOCAL_SRC="$(git rev-parse --show-toplevel)" makepkg -si` |
| **GrapheneOS** | PASS | apk (AOSP) | `android/build-apk.sh` | `bash android/build-apk.sh` (see [`android/README.md`](android/README.md)) |
| **MX Linux** | PASS *(hedged)* | deb (Debian base) | `scripts/package.sh` | same as Debian |
| **Garuda** | PASS *(hedged)* | pacman (Arch base) | `packaging/arch/PKGBUILD` | same as Artix |
| **Whonix / Kicksecure** | PASS *(hedged)* | deb (Debian base) | `scripts/package.sh` | same as Debian; transport over Tor is the default feature |

Distros that are **UNDECIDED** (Fedora→Qubes, Ubuntu/Canonical, Debian, Tails,
Arch, SUSE) or **UNKNOWN** (SecureBlue) stay at **Tier 3** (source build) and get
no recipe here until their gate verdict changes — even though some of them share
a format (Fedora would need an `.rpm`, which we deliberately do **not** ship
while the gate is unresolved). The Arch `PKGBUILD` will build on Arch proper, but
we do not publish it for Arch while its gate is UNDECIDED.

## Verifying what you built

Every artifact set is covered by dual checksums and optional PQ signatures:

```sh
bash scripts/package.sh         # builds every available target, writes dist/MANIFEST.txt
bash scripts/verify.sh dist/    # checks SHA-256 AND SHA3-256 for every artifact
# Optional launch-attestation sidecars (ML-DSA-87), when a release key is set:
TALKRYPT_RELEASE_SK=<seed-hex-or-file> bash scripts/package.sh
```

The Arch `PKGBUILD` honors the same `TALKRYPT_RELEASE_SK` env var and writes the
same `<binary>.sig` sidecars into the package, so a pacman install carries the
identical in-process self-attestation as a `.deb` or tarball.

## Promotion to Tier 1 (signed CI) — remaining work

Tier 1 means talkrypt CI builds, signs, and publishes these packages. The pieces
that exist vs. remain:

- ✅ Reproducible build scripts (`package.sh`, `PKGBUILD`, `build-apk.sh`).
- ✅ Dual-checksum manifest (`hash-dist.sh`) + PQ artifact signing (`relsign`, F-8).
- ✅ Gate roster is primary-sourced and closed (only SecureBlue open).
- ⏳ A **real published release key** (`docs/RELEASE_PUBKEY.hex` is a guarded
  placeholder) so sidecar signatures chain to a key downstreams can trust.
- ⏳ A **CI publishing pipeline** (GitHub Actions) that runs these recipes on tag,
  signs, and attaches artifacts to a release channel per format (deb repo /
  AUR push / APK release). Today CI *builds and lints* (`desktop.yml`,
  `android.yml`) but does not *publish* packages.
- ⏳ Per-format channel hosting (an apt repo, an AUR package submission with a
  populated `source`/`sha256sums`, an APK release asset).

Until those land, consumers on a PASS distro use the Tier-2 recipe above to build
locally, and verify with `scripts/verify.sh`.
