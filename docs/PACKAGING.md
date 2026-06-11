# Desktop packaging

talkrypt's desktop product is the **CLI** (`talkrypt`) and **TUI**
(`talkrypt-tui`), with the key-custody **helper** (`talkrypt-helper`) alongside.
The crypto is pure Rust (RustCrypto: ML-KEM-1024, ML-DSA-87, AES-256-GCM, SHA-3,
Argon2) and the default transport is plain TCP, so the binaries link **no C
libraries** — they build as single, dependency-free executables on every
desktop OS. (`--features tor` pulls Arti and is a separate, heavier build.)

There is no separate desktop GUI: the CLI/TUI *are* the shipped clients, sharing
the same audited core the Android app consumes through `crates/ffi`. A Tauri GUI
on top of the FFI is possible later (see `docs/PLATFORMS.md`) but is not built.

## Scripts

| Script | Output |
| --- | --- |
| `scripts/release.sh` | **Everything**: desktop + mobile, then one unified set of dual-family checksums. The one command to cut a release. |
| `scripts/package.sh` | Desktop **distributables**: macOS `.app` + `.dmg`, Linux `.tar.gz` + `.deb`, Windows `.zip`. |
| `scripts/package-mobile.sh` | Mobile: Android `.apk` (and, on a Mac with Xcode, the iOS `.xcframework`). |
| `scripts/build-ios.sh` | iOS XCFramework + Swift bindings; `--testflight` archives + uploads (needs Xcode app project + Apple account). |
| `scripts/hash-dist.sh` | Hashes **all** of `dist/` with SHA-256 **and** SHA3-256; writes `SHA256SUMS`, `SHA3-256SUMS`, `MANIFEST.txt`, and the `verify.sh` / `verify.ps1` checkers. The single hashing authority. |
| `scripts/build-portable.sh` | Bare, self-contained `talkrypt` binaries per target (hand one to a peer; it just runs). |

```sh
bash scripts/release.sh            # build desktop + mobile, hash everything
bash scripts/package.sh --list     # show desktop targets + which toolchains are present
bash scripts/package.sh            # desktop only
bash scripts/package-mobile.sh     # mobile only (folds into the same checksums)
```

`package.sh` builds the CLI, TUI and helper for each available target, then:

- **macOS** — `lipo`s the two arches into a universal binary, assembles
  `talkrypt.app` (a Terminal launcher over the CLI), ad-hoc-codesigns it, and
  builds `talkrypt-<version>-macos.dmg` (with an `/Applications` symlink).
- **Linux** — a `.tar.gz` of the binaries plus a **`.deb`** built *portably* with
  `ar` + `tar` (no `dpkg-deb` needed), including a `talkrypt.desktop` entry. The
  glibc (gnu) targets produce the `talkrypt` package; the static (musl) targets
  produce a separate `talkrypt-static` package (one fully-static binary, runs on
  any Linux of that arch). Linux targets cross-compile via
  [`cross`](https://github.com/cross-rs/cross) (Docker) when it is installed.
- **Windows** — a `.zip` of the `.exe`s (cross-compiled via `x86_64-pc-windows-gnu`).
- **All** — **two** independent checksum files, `SHA256SUMS` (FIPS 180-4) and
  `SHA3-256SUMS` (FIPS 202 / Keccak), so a weakness in one hash family can't mask
  a tampered artifact; the `verify.sh` / `verify.ps1` checkers; and a
  `MANIFEST.txt` that lists sizes, both digests, and — explicitly — **every
  target it skipped and why** (a missing cross-toolchain is reported, never
  silently dropped).

Artifacts land in `dist/`.

## Targets

`package.sh` knows these triples (install with `rustup target add <triple>`; musl
and the Linux/Windows cross-builds also need the matching linker, easiest via
[`cross`](https://github.com/cross-rs/cross)):

| Triple | Platform | Package |
| --- | --- | --- |
| `aarch64-apple-darwin` | macOS Apple Silicon | universal `.dmg`, `.tar.gz` |
| `x86_64-apple-darwin` | macOS Intel | universal `.dmg`, `.tar.gz` |
| `x86_64-unknown-linux-gnu` | Linux x86_64 (glibc) | `.tar.gz`, `.deb (amd64)` |
| `aarch64-unknown-linux-gnu` | Linux arm64 (glibc) | `.tar.gz`, `.deb (arm64)` |
| `x86_64-unknown-linux-musl` | Linux x86_64 (static) | `.tar.gz`, `talkrypt-static .deb (amd64)` |
| `aarch64-unknown-linux-musl` | Linux arm64 (static) | `.tar.gz`, `talkrypt-static .deb (arm64)` |
| `x86_64-pc-windows-gnu` | Windows x86_64 | `.zip` |

A build host only produces what its toolchain supports; run `package.sh` on (or
cross to) each platform to assemble the full set. The macOS host in this repo
produces both Darwin arches (hence the universal `.dmg`) and cross-compiles the
Windows `.zip` out of the box. The Linux `.deb` is produced wherever a Linux
binary builds — on a Linux host, or via `cross` for the musl targets.

## Mobile

`scripts/package-mobile.sh` builds the mobile artifacts and folds them into the
**same** `SHA256SUMS` / `SHA3-256SUMS` as the desktop set (one manifest covers
every platform).

| Platform | Artifact | Built by | Needs |
| --- | --- | --- | --- |
| Android arm64 | `talkrypt-<version>-android-arm64.apk` | `android/build-apk.sh` | Android SDK + NDK, `cargo-ndk`, JDK |
| iOS (device + sim) | `talkrypt-<version>-ios-xcframework.zip` | `scripts/build-ios.sh` | **full Xcode** + iOS SDK |

- **Android** — the APK bundles the FFI `.so` (cross-compiled to
  `aarch64-linux-android` via `cargo-ndk`) + the uniffi Kotlin bindings,
  assembled by Gradle. It is **debug-signed** (the sideload/P2P/Seeker path,
  not Play Store); `TALKRYPT_TOR=1` compiles the Arti transport in. Install:
  `adb install -r talkrypt-<version>-android-arm64.apk`.
- **iOS** — `build-ios.sh` cross-compiles the FFI to the iOS device + simulator
  targets, generates the uniffi **Swift** bindings, and assembles an
  **XCFramework** (the consumable an iOS app embeds). With `--testflight` and an
  Xcode app project + an Apple Developer account, it archives and uploads via
  `xcrun altool` / fastlane. **This requires full Xcode (the iOS SDK):** a host
  with only the Command Line Tools cannot compile/link for iOS or create an
  XCFramework, so the iOS artifact is reported as *skipped* in `MANIFEST.txt`
  there — never silently omitted. The remaining native-app shell (a thin SwiftUI
  view over the XCFramework) + TestFlight upload are the Apple-account-gated
  steps the script scaffolds but cannot perform without credentials.

## Install

- **macOS** — open `talkrypt-<version>-macos.dmg`, drag `talkrypt.app` to
  Applications. The bundle is **ad-hoc signed, not notarized**, so Gatekeeper
  warns on first launch (right-click → Open). The app opens the CLI in Terminal;
  power users can copy `talkrypt.app/Contents/MacOS/talkrypt-bin` onto `$PATH`.
- **Homebrew** — `packaging/homebrew/talkrypt.rb` is a from-source formula
  (`brew install --build-from-source ./packaging/homebrew/talkrypt.rb`, or via a
  tap once a release URL + sha256 are filled in). It compiles with the system
  Rust toolchain — no prebuilt-binary trust assumptions.
- **Debian/Ubuntu** — `sudo apt install ./talkrypt_<version>_<arch>.deb`
  (installs `talkrypt`, `talkrypt-tui`, `talkrypt-helper` to `/usr/bin` and a
  desktop entry). For the fully-static build, install
  `talkrypt-static_<version>_<arch>.deb` instead (it `Conflicts`/`Provides`
  `talkrypt`, so pick one). The `.deb`s are unsigned; verify against the
  checksums (below).
- **Windows** — unzip and run `talkrypt.exe` from a terminal.
- **Any** — the `scripts/build-portable.sh` binaries are fully self-contained;
  copy one anywhere (USB, AirDrop, the in-app P2P share) and run it.

## Integrity

Every release ships **two** independent checksum files — `SHA256SUMS` (SHA-256,
FIPS 180-4, a Merkle–Damgård construction) and `SHA3-256SUMS` (SHA3-256, FIPS
202, a Keccak sponge). Both must match for every file: the two families are
structurally unrelated, so a cryptanalytic break or a deliberate collision in
one cannot also satisfy the other. Verify before installing.

**One step, both hashes** (ships in `dist/`, cross-platform):

```sh
bash verify.sh                                 # bash: macOS / Linux / *BSD / WSL
```
```powershell
pwsh ./verify.ps1                              # PowerShell: Windows / cross-platform
```

`verify.sh` uses `sha256sum`/`shasum` for SHA-256 and auto-detects a SHA3-256
backend (`openssl` 3.x, `python3`, or `rhash`). `verify.ps1` uses the built-in
`Get-FileHash` for SHA-256 and .NET 8+'s `SHA3_256` (or `python3`/`openssl`) for
SHA3-256. Each prints OK/FAIL per file and exits non-zero on any mismatch.

**By hand**, if you prefer the stock tools:

```sh
shasum -a 256 -c SHA256SUMS        # macOS / BSD          (SHA-256)
sha256sum  -c SHA256SUMS           # Linux                (SHA-256)
openssl dgst -sha3-256 <file>      # compare to SHA3-256SUMS (any OpenSSL 3.x)
```

There is **no trusted code-signing authority** behind these packages: macOS
signing is ad-hoc (`codesign -s -`), the `.deb`s are unsigned, and nothing is
notarized. Integrity rests on the (dual) checksums and on building from source.
This matches the project's honesty posture — see `SECURITY.md` and `README.md`.

## Packaging policy (political filter)

Distributing the *source* is unconditional: talkrypt is Apache-2.0 and builds
everywhere. **Endorsing** a downstream packaging channel (a distro repo, a tap,
a store listing) is gated by `docs/packaging-policy.md` — the Tier-1 gate asks
whether the channel's host has publicly committed to never implement
government-mandated age-verification or identity-attestation mandates. The gate
is about *endorsement*, not access: anyone may build and run the software.

## Reproducibility

Builds are `--release` from a pinned `Cargo.lock` (the Homebrew formula uses
`--locked`). `MANIFEST.txt` records the source git revision and the host triple
so an artifact can be traced to a commit. Pure-Rust, C-free builds make
bit-for-bit reproduction tractable; a fully reproducible-build pipeline (pinned
toolchain + `SOURCE_DATE_EPOCH`) is future work.

## Not certified

These packages carry the same disclaimer as the rest of the project: **NOT
FIPS-validated, NOT CSfC-accredited, NOT NSA-approved, NOT independently
audited.** Experimental, pre-release software. See `docs/COMPLIANCE.md` and
`docs/SECURITY-AUDIT.md` for the self-assessments.
