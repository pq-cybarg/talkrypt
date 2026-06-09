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

## Two scripts

| Script | Output |
| --- | --- |
| `scripts/build-portable.sh` | Bare, self-contained `talkrypt` binaries per target (hand one to a peer; it just runs). |
| `scripts/package.sh` | Real **distributables**: macOS `.app` + `.dmg`, Linux `.tar.gz` + `.deb`, Windows `.zip`, plus `SHA256SUMS` and `MANIFEST.txt`. |

```sh
bash scripts/package.sh --list     # show targets + which toolchains are present
bash scripts/package.sh            # package every target whose toolchain exists
```

`package.sh` builds the CLI, TUI and helper for each available target, then:

- **macOS** — `lipo`s the two arches into a universal binary, assembles
  `talkrypt.app` (a Terminal launcher over the CLI), ad-hoc-codesigns it, and
  builds `talkrypt-<version>-macos.dmg` (with an `/Applications` symlink).
- **Linux** — a `.tar.gz` of the binaries plus a **`.deb`** built *portably* with
  `ar` + `tar` (no `dpkg-deb` needed), including a `talkrypt.desktop` entry.
- **Windows** — a `.zip` of the `.exe`s (cross-compiled via `x86_64-pc-windows-gnu`).
- **All** — `SHA256SUMS` over every artifact and a `MANIFEST.txt` that lists
  sizes, checksums, and — explicitly — **every target it skipped and why** (a
  missing cross-toolchain is reported, never silently dropped).

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
| `x86_64-unknown-linux-musl` | Linux x86_64 (static) | `.tar.gz`, `.deb (amd64)` |
| `aarch64-unknown-linux-musl` | Linux arm64 (static) | `.tar.gz`, `.deb (arm64)` |
| `x86_64-pc-windows-gnu` | Windows x86_64 | `.zip` |

A build host only produces what its toolchain supports; run `package.sh` on (or
cross to) each platform to assemble the full set. The macOS host in this repo
produces both Darwin arches (hence the universal `.dmg`) and cross-compiles the
Windows `.zip` out of the box. The Linux `.deb` is produced wherever a Linux
binary builds — on a Linux host, or via `cross` for the musl targets.

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
  desktop entry). The `.deb` is unsigned; verify against `SHA256SUMS`.
- **Windows** — unzip and run `talkrypt.exe` from a terminal.
- **Any** — the `scripts/build-portable.sh` binaries are fully self-contained;
  copy one anywhere (USB, AirDrop, the in-app P2P share) and run it.

## Integrity

Every release ships `SHA256SUMS`. Verify before installing:

```sh
shasum -a 256 -c SHA256SUMS        # macOS / BSD
sha256sum -c SHA256SUMS            # Linux
```

There is **no trusted code-signing authority** behind these packages: macOS
signing is ad-hoc (`codesign -s -`), the `.deb` is unsigned, and nothing is
notarized. Integrity rests on the checksums and on building from source. This
matches the project's honesty posture — see `SECURITY.md` and `README.md`.

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
