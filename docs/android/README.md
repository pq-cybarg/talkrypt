# Android key-custody bridge (scaffold)

This directory holds the Android-side **scaffold** for the hardware-keystore
custody tier (roadmap #297 / #409). It is not built by `cargo` — it compiles in
the Android app module (Gradle + NDK) against the uniffi-generated `uniffi.talkrypt`
bindings. The Rust it depends on (`talkrypt_ffi::custody_report` and the
`CustodyTier` enum) is cross-compile-verified for `aarch64-linux-android`.

## What it does

`CustodyBridge.detectTier()` probes the **real** device at runtime:

| Probe result | Reported tier |
|---|---|
| StrongBox-backed key creation succeeds (dedicated secure element) | `HardwareBacked` |
| Key is inside secure hardware (TEE) but not StrongBox | `HardwareBacked` |
| Key lives only in the software Keystore | `OsKeystore` |
| Keystore unavailable / probe failed | `SoftwareSealed` |

`CustodyBridge.parityReport()` feeds that tier through the shared FFI
(`custodyReport`) to produce the same encoded `Capabilities` the desktop helper
emits — so both flow into one #305 PQ + custody-tier parity audit.

**The device never assumes a tier.** A phone without a secure element honestly
reports `OsKeystore`, not `HardwareBacked`. talkrypt's crypto is uniform and
post-quantum regardless of tier; the tier only describes at-rest key protection.

## Why a bridge and not the helper sidecar

Desktop uses a separate helper process over a Unix socket / Named Pipe. Mobile
is **architecturally different**: there is no sidecar — the bridge runs in the
app process and talks to the OS Keystore / StrongBox directly via the Android
framework APIs. Both feed the same custody-tier model.

## Validation

Emulators expose only a *software* Keymaster — they cannot validate StrongBox.
Real-hardware validation targets:

- **Solana Seeker** — Seed Vault secure element → expected `HardwareBacked`.
- **Galaxy A23** — Android Keystore; `HardwareBacked` iff its chipset provides a
  secure element/TEE that backs the probe key, else `OsKeystore`.

## Build outline (when wiring the APK)

```bash
rustup target add aarch64-linux-android armv7-linux-androideabi
cargo install cargo-ndk
cargo ndk -t arm64-v8a -t armeabi-v7a -o app/src/main/jniLibs \
    build -p talkrypt-ffi --release
# generate uniffi Kotlin bindings into the app source (see docs/PLATFORMS.md),
# then drop CustodyBridge.kt into the app module.
```

NOT certified / NOT audited — see the project README.
