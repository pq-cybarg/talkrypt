# talkrypt 1.0 — platform coverage & release-readiness (ground truth)

> **Honest scope.** This is an evidence-based status of what is *actually built and
> validated* today vs. scaffolded vs. planned — the authoritative reconciliation when
> `ROADMAP.md` / `PLATFORMS.md` / `PACKAGING.md` disagree with the tree. It is not a
> certification or a ship-authorization; the project-wide **NOT FIPS-validated / NOT
> CSfC / NOT NSA-approved / NOT audited** disclaimer applies to every target below.

## The coverage claim, stated honestly

talkrypt covers the **full platform gamut by architecture**: one audited Rust core
(`talkrypt-core` + `talkrypt-crypto`) reached by every client through either a direct
link or the `talkrypt-ffi` (uniffi) boundary, so no platform reimplements crypto or
protocol. That universality is real. What varies per platform is **build + validation
maturity**, in three honest states: **built & validated**, **builds / cross-compiles
(not yet validated on that OS/hardware)**, and **scaffolded / planned (not built)**.

## Status reconciliations (docs that were stale)

- **`ROADMAP.md` header said "Status: PLANNED. Nothing in this document is implemented
  yet."** That is false for its own body: the mobile StrongBox path is hardware-validated,
  `OsKeystore` is implemented on all three desktop OSes, the helper + Windows Named-Pipe
  transport are built. The header is corrected to point here; the body is authoritative.
- **`PLATFORMS.md` / `PACKAGING.md` / wiki said "there is no separate desktop GUI."**
  False: `crates/desktop` (`talkrypt-desktop`) is a real **egui/eframe native GUI** that
  links the core directly, CI-built on every push. The "Tauri later, unbuilt" prose
  predates it.
- **Packaging (RESOLVED):** the egui desktop GUI now ships in the **host-OS** package —
  `scripts/package.sh` builds `talkrypt-desktop` natively for the host and stages it into
  the `.tar.gz`/`.dmg` (GUI libs don't cross-compile, so host-OS only).

## Matrix

| Platform / target | Artifact | Built? | Validation | Evidence |
| --- | --- | --- | --- | --- |
| macOS arm64 | CLI/TUI/helper `.dmg`/`.tar.gz`; egui GUI (sep.) | **Yes** | **HW-validated** (Apple Silicon); Keychain custody live | `dist/…aarch64-apple-darwin…`; `custody-testing-status.md` |
| macOS x86_64 | universal lipo | builds on an Intel/host toolchain | not built in last run | `scripts/package.sh`; `dist/SKIPPED.txt` |
| Linux amd64/arm64 (glibc) | `.tar.gz` + portable `.deb` | recipe built via `cross` | cross-compiles; not validated per-distro | `scripts/package.sh`; Tier-2 recipe |
| Linux amd64/arm64 (musl static) | `talkrypt-static` `.deb` | recipe via `cross` | cross-compiles | `scripts/package.sh`, `build-portable.sh` |
| Linux **armv7** | `.tar.gz` + `.deb (armhf)` + static portable | **packaging target added** (gnueabihf + musleabihf; builds via `cross`) | cross-compiles | `scripts/package.sh`, `build-portable.sh` |
| Windows x86_64 | `.exe` `.zip`; helper Named-Pipe (SDDL ACL) | cross-compiles + clippy-clean | **ACL/CNG/wincred runtime NOT validated** (no Windows host; Wine unfaithful) | `ROADMAP.md`; `custody-testing-status.md` |
| Android arm64 | Kotlin/Gradle **APK** (FFI `.so` via cargo-ndk + uniffi Kotlin) | **Yes** (debug-signed) | **HW-validated on Solana Seeker** (StrongBox → `HARDWARE_BACKED`) | `android/build-apk.sh`; `docs/android/README.md` |
| iOS | FFI **XCFramework** + uniffi Swift | script exists; needs full Xcode | cross-compiles-gated; **no committed app shell** (SE/BLE are reference Swift only) | `scripts/build-ios.sh`; `ios/README.md` |
| Radio/IoT mesh (LoRa) | Rust codecs (Meshtastic/Meshcore/MQTT/frag/pacing) + Android BLE backends | **Yes** (codecs always compiled; frag Kani-proven) | host-tested; **no physical-radio validation evidenced** | `crates/transport/src/mesh/*`; `docs/mesh-lora-backend.md` |
| Browser extensions (#300–304) | — | **Nothing built** | planned | `ROADMAP.md` |
| Web app | — | **Nothing built** (ROADMAP: "no web app today") | planned | `ROADMAP.md` |
| Companion bridges (#431–437) | — | trust model spec'd only | planned | `entropy-companions.md` |

**Desktop custody tiers** (helper): macOS Keychain **HW-validated**; Linux Secret Service
+ TPM 2.0 **validated** (Docker / swtpm); PKCS#11 HSM **validated** (SoftHSM2); macOS
Secure Enclave, Windows TPM/CNG+wincred, SEALSQ PQ chip **compile-checked only** (need
real silicon). See `docs/custody-testing-status.md`.

**Packaging tiers** (`packaging-policy.md`): **Tier 1 (signed, CI-published)** — the signing
machinery is built (ML-DSA + SLH-DSA co-sign, SHA3-384/SHA-384, no repo keys); it goes live
once the maintainer supplies the offline release keys (punch-list #1). **Tier 2** = in-repo recipes
(Debian `.deb`, Arch `PKGBUILD`, Android `.apk`) for the political-filter PASS set;
**Tier 3** = source-build for everyone else (no `.rpm` while Fedora's stance is unresolved).

## 1.0 ship punch-list (drives task #139)

**Blocking a "1.0 shipped" tag:**
1. **⏳ Maintainer generates the offline release keys** (ML-DSA + SLH-DSA seeds) and provides
   them as CI/env secrets (`TALKRYPT_RELEASE_SK*`). The repo holds **no key material**; the
   pubkey is injected at build time and **published with each release** — so this is a
   key-generation action, not a repo commit. The one human gate on the signed tag.
2. **✅ Co-sign + dual-hash (plan 0003)** — ML-DSA-87 + SLH-DSA co-signatures (selectable,
   all-present-must-verify) + SHA3-384/SHA-384; `verify.sh`/`verify.ps1` check all. Dry-run
   validated. (LMS, the CNSA stateful signer, is the deferred offline-only follow-up.)
3. **✅ Desktop GUI packaged** — `talkrypt-desktop` ships in the host-OS package (validated:
   host `.tar.gz` contains it; `.dmg` assembles).
4. **Produce the full artifact set at tag time** — `cross`+`docker` are available and the
   Linux cross→ELF pipeline is validated end-to-end; `release.sh` builds the full set (run
   `cross` with the rustup toolchain active). The remaining per-target builds happen at the
   signed-release run.
5. **✅ armv7 added** — `armv7-unknown-linux-gnueabihf` + `-musleabihf` are first-class in
   `package.sh` (`armhf` `.deb`) and `build-portable.sh`.

**Not blocking the first tag, but honest to record:**
6. iOS app shell + Secure Enclave + a provisioned signed build (needs Xcode + Apple acct).
7. Windows-host validation of the Named-Pipe ACL + CNG/wincred custody.
8. Physical-radio (LoRa) interop validation.
9. Android `armeabi-v7a` ABI (today the APK is `arm64-v8a` only) if 32-bit is in scope.
10. Browser extensions / web app / companion bridges — remain planned.

**Already green (no action for the tag):** workspace tests pass on the post-merge `main`;
the formal-verification suite (11 `formal/` artifacts) is on `main` and CI-green;
dependency advisories cleared (#107/#108/#109/#135/#136); the integrity model (dual-hash +
PQ signature + launch attestation) is built and only awaits real keys (item 1).
