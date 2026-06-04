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

### Observed (measured via `adb`)

The Android emulator (`sdk_gphone64_arm64`, API 35) reports:

```
pm has-feature android.hardware.strongbox_keystore  -> false
pm list features | grep keystore                    -> android.hardware.hardware_keystore=300
                                                        android.hardware.keystore.app_attest_key
```

This is the **false-confidence trap made concrete**: the emulator advertises a
*TEE* (`hardware_keystore`), so a naive `isInsideSecureHardware()` check would
map it to `HardwareBacked` — but it's software-emulated. Conclusions baked into
the bridge:

1. **StrongBox** (`strongbox_keystore` feature + `setIsStrongBoxBacked` success)
   is the only "dedicated secure element" signal → strongest `HardwareBacked`.
2. A reported TEE alone is not trustworthy on an emulator. The **definitive**
   hardware proof is **key attestation** — a `KeyGenParameterSpec` attestation
   certificate chain that roots in Google's hardware-attestation root CA
   (which an emulator's software keymaster cannot produce). The bridge should
   verify that chain before claiming `HardwareBacked` for a TEE-only device.
### On-device result — Solana Seeker (real StrongBox)

The APK was built (`android/build-apk.sh`), installed, and **run on the
Seeker**; `adb logcat -s talkrypt` reported:

```
device: Solana Mobile Inc. Seeker | StrongBox feature: true
detected tier: HARDWARE_BACKED | PQ identity: yes (ML-DSA-87)
parity report (8 B): 0100000003000102
```

End-to-end on genuine hardware: `CustodyBridge` created a **StrongBox**-backed
key on the Seeker's secure element → `HARDWARE_BACKED`, and the shared FFI
`custody_report` produced `0100000003000102`, which decodes as `core::Capabilities`:
`01`=PQ-identity true, `00000003`=3 tiers, `00 01 02`=Software < OsKeystore <
HardwareBacked — the **same parity wire the desktop helper emits**. The mobile
bridge and the desktop helper now feed one #305 parity contract, validated on
real StrongBox hardware (not an emulated TEE).

## Build outline (when wiring the APK)

```bash
rustup target add aarch64-linux-android armv7-linux-androideabi
cargo install cargo-ndk
cargo ndk -t arm64-v8a -t armeabi-v7a -o app/src/main/jniLibs \
    build -p talkrypt-ffi --release
# generate uniffi Kotlin bindings into the app source (see docs/PLATFORMS.md),
# then drop CustodyBridge.kt into the app module.
```

**Verified:** `cargo ndk -t arm64-v8a build -p talkrypt-ffi --release` produces
`libtalkrypt_ffi.so` (`ELF 64-bit ARM aarch64`, stripped) using the installed
NDK — the FFI (including `custody_report` + the `CustodyTier` enum) links for
the device. Remaining for an on-device run: the Gradle/Kotlin app module
(generate the uniffi bindings, add `CustodyBridge.kt`, package the APK), then
`adb install` and read the real tier on the Seeker.

NOT certified / NOT audited — see the project README.
