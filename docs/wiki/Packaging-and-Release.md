# Packaging & Release

How talkrypt is built, packaged, hashed, and verified for every platform. Full
detail: `docs/PACKAGING.md`, `docs/packaging-policy.md`. Scripts: `scripts/`.

## One command

```sh
bash scripts/release.sh            # desktop + mobile, then one unified set of checksums
bash dist/verify.sh dist           # verify everything (bash)
pwsh  dist/verify.ps1 -Dir dist    # verify everything (PowerShell)
```

`release.sh` runs the desktop and mobile packagers and then hashes the whole
`dist/`. Each step **records** (never hides) any target it can't build on the
current host.

## Scripts

| Script | Builds |
| --- | --- |
| `scripts/package.sh` | Desktop: macOS `.dmg`+`.tar.gz`, Linux `.tar.gz`+`.deb`, Windows `.zip` |
| `scripts/package-mobile.sh` | Android `.apk` (+ iOS `.xcframework` on a Mac with Xcode) |
| `scripts/build-ios.sh` | iOS XCFramework + Swift bindings; `--testflight` to archive + upload |
| `scripts/hash-dist.sh` | SHA-256 **and** SHA3-256 over all of `dist/` + the verifiers |
| `scripts/build-portable.sh` | Bare self-contained per-target `talkrypt` binaries |

## Artifacts

| Platform | Artifact |
| --- | --- |
| macOS | `talkrypt-<v>-macos.dmg` (universal) + per-arch `.tar.gz` |
| Linux glibc | `…-{x86_64,aarch64}-unknown-linux-gnu.tar.gz` + `talkrypt_<v>_{amd64,arm64}.deb` |
| Linux static (musl) | `…-…-linux-musl.tar.gz` + `talkrypt-static_<v>_{amd64,arm64}.deb` |
| Windows | `talkrypt-<v>-x86_64-pc-windows-gnu.zip` |
| Android | `talkrypt-<v>-android-arm64.apk` |
| iOS | `talkrypt-<v>-ios-xcframework.zip` *(on a Mac with Xcode)* |

The glibc `.deb` is the package **`talkrypt`**; the fully-static musl `.deb` is
**`talkrypt-static`** (it Conflicts/Provides `talkrypt`, so install one). Linux
targets cross-compile via [`cross`](https://github.com/cross-rs/cross) (Docker).

## Dual-family integrity (SHA-256 + SHA3-256)

Every release ships **two** independent checksum files — `SHA256SUMS` (SHA-256,
FIPS 180-4, Merkle–Damgård) and `SHA3-256SUMS` (SHA3-256, FIPS 202, Keccak
sponge). **Both must match** for every file: the families are structurally
unrelated, so a cryptanalytic break or deliberate collision in one cannot also
satisfy the other.

`verify.sh` (bash) and `verify.ps1` (PowerShell) check both, print OK/FAIL per
file, and exit non-zero on any mismatch. They auto-detect a SHA3 backend
(`openssl` 3.x / `python3` / `rhash`, or .NET 8's `SHA3_256` on Windows) and fall
back gracefully. `MANIFEST.txt` lists sizes, both digests, and every **skipped**
target with the reason (e.g. "no Xcode → iOS skipped"), never a silent omission.

## Signing (the honest gap)

There is **no trusted code-signing authority**: macOS bundles are *ad-hoc*
signed (Gatekeeper still warns), the `.deb`s and the APK are not authority-signed,
nothing is notarized. Integrity rests on the dual checksums and on building from
source (`SECURITY-AUDIT.md F-8`).

## Packaging political filter

Distributing the **source** is unconditional (Apache-2.0, builds everywhere).
**Endorsing** a downstream channel (a distro repo, a tap, a store) is gated by
`docs/packaging-policy.md`: a Tier-1 channel's host must have publicly committed
to never implement government-mandated age-verification or identity-attestation.
The gate is about *endorsement*, not access — anyone may build and run talkrypt.
