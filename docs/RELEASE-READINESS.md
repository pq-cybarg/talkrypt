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
- **Packaging gap:** the egui desktop GUI is **not yet in the release pipeline** —
  `scripts/package.sh` packages `talkrypt`/`-tui`/`-helper`/`-relsign` only. Tracked in the
  punch-list below.

## Matrix

| Platform / target | Artifact | Built? | Validation | Evidence |
| --- | --- | --- | --- | --- |
| macOS arm64 | CLI/TUI/helper `.dmg`/`.tar.gz`; egui GUI (sep.) | **Yes** | **HW-validated** (Apple Silicon); Keychain custody live | `dist/…aarch64-apple-darwin…`; `custody-testing-status.md` |
| macOS x86_64 | universal lipo | builds on an Intel/host toolchain | not built in last run | `scripts/package.sh`; `dist/SKIPPED.txt` |
| Linux amd64/arm64 (glibc) | `.tar.gz` + portable `.deb` | recipe built via `cross` | cross-compiles; not validated per-distro | `scripts/package.sh`; Tier-2 recipe |
| Linux amd64/arm64 (musl static) | `talkrypt-static` `.deb` | recipe via `cross` | cross-compiles | `scripts/package.sh`, `build-portable.sh` |
| Linux **armv7** | — | **No packaging target** (claimed first-class in policy, absent from scripts) | planned-not-built | punch-list |
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

**Packaging tiers** (`packaging-policy.md`): **Tier 1 (signed, CI-published) = NONE yet**
(`RELEASE_PUBKEY.hex` is a placeholder → signatures inert); **Tier 2** = in-repo recipes
(Debian `.deb`, Arch `PKGBUILD`, Android `.apk`) for the political-filter PASS set;
**Tier 3** = source-build for everyone else (no `.rpm` while Fedora's stance is unresolved).

## 1.0 ship punch-list (drives task #139)

**Blocking a "1.0 shipped" tag:**
1. **Publish real release trust anchors.** Generate the offline release keys and commit
   real `RELEASE_PUBKEY*.hex`, so manifest signatures + launch-attestation sidecars
   actually chain to a trusted key (today they are advisory/inert). (Pairs with plan 0003.)
2. **Co-sign + dual-hash per plan 0003** — LMS + SLH-DSA signatures, SHA3-384 + SHA-384.
3. **Package the egui desktop GUI** — add `talkrypt-desktop` to `scripts/package.sh` so it
   ships in the `.dmg`/`.deb`/`.zip` (or decide, explicitly, that it is source-only for 1.0).
4. **Produce the full desktop artifact set** — run `package.sh` on/through each toolchain
   (the last `dist/` is macOS-arm64-only); the `cross` targets must actually build.
5. **Decide armv7** — either add the target to `package.sh`/`build-portable.sh` or drop the
   "first-class armv7" claim from policy/ROADMAP (don't claim what isn't built).

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
