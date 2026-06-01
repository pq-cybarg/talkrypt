# Desktop & mobile (the platform shells)

Every platform is a **thin shell over the same `talkrypt-core`**, reached
through the `talkrypt-ffi` crate (uniffi). The security-critical code is
written once; no platform reimplements crypto or protocol.

```
                       talkrypt-core (Rust, audited once)
                                  │
                          talkrypt-ffi (uniffi)
        ┌──────────────┬──────────┴───────────┬───────────────┐
   Kotlin (Android)  Swift (iOS/macOS)   Python/…        C ABI (desktop)
        │                  │                  │                │
   Android app        (future)          scripting       Tauri/native shell
```

The exported API (`TalkryptClient`): `host(listen, channel)`, `join(uri)`,
`send(text)`, `invite_uri()`, `safety_number()`, `peer_count()`,
`poll_event()`. It is synchronous; UIs poll `poll_event` on a timer. Verified
end to end by the FFI integration test.

## Generating language bindings

```bash
# Build the dynamic library
cargo build -p talkrypt-ffi --release        # -> target/release/libtalkrypt_ffi.{so,dylib}

# Generate bindings (uniffi-bindgen for your target language)
cargo run -p talkrypt-ffi --bin uniffi-bindgen -- \
    generate --library target/release/libtalkrypt_ffi.dylib \
    --language kotlin --out-dir bindings/kotlin
#   --language swift  --out-dir bindings/swift
#   --language python --out-dir bindings/python
```

(uniffi 0.31 generates from the compiled library's embedded metadata — no UDL
file is needed.)

## Android (Solana Seeker, A23, GrapheneOS)

talkrypt-ffi builds a `cdylib`/`staticlib`. Cross-compile for the device ABIs
and drop the Kotlin bindings into an app module:

```bash
rustup target add aarch64-linux-android armv7-linux-androideabi
cargo install cargo-ndk
cargo ndk -t arm64-v8a -t armeabi-v7a -o app/src/main/jniLibs \
    build -p talkrypt-ffi --release
```

- The `.so` per ABI goes in `jniLibs/`; the generated `talkrypt.kt` in the
  app's source. The Kotlin UI calls `TalkryptClient.host(...)` / `.join(...)`.
- **GrapheneOS / Solana Seeker:** the app is a standard sideloadable APK; no
  Google Play Services dependency, no telemetry. Network goes through Tor when
  built with the `tor` feature on the transport (Arti runs in-process — no
  separate Orbot needed).
- **Honest note:** building/running the actual APK requires the Android SDK,
  NDK, and Gradle, plus a device/emulator — that toolchain is outside this
  repo's `cargo` build, so the APK is integration-documented here, not built by
  CI. The Rust side (the hard part) is built and tested.

## Desktop (macOS / Windows 10 / Linux)

Two options, both over the same FFI/core:

1. **Native CLI/TUI** — already shipped (`talkrypt`, `talkrypt-tui`), runs on
   all three OSes today.
2. **Tauri GUI** — a `tauri` app whose Rust backend depends on `talkrypt-ffi`
   (or `talkrypt-core` directly) and exposes commands to a minimal web UI.
   Scaffold with `cargo create-tauri-app`; the backend `#[tauri::command]`s map
   1:1 to the FFI methods. Building the bundle needs the platform's webview
   libs + the Tauri CLI (documented, not in CI).

## Why this shape

A single audited core eliminates the worst risk in cross-platform secure
messengers: divergent, separately-buggy crypto per platform. Here a fix in
`talkrypt-crypto` reaches every platform at once.
