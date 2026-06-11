#!/usr/bin/env bash
# Package the mobile artifacts into dist/ and fold them into the SAME dual-hash
# manifest as the desktop build (one SHA256SUMS / SHA3-256SUMS over everything).
#
#   Android — builds the APK (android/build-apk.sh: FFI .so via cargo-ndk +
#             uniffi Kotlin bindings + Gradle) and copies it in as
#             talkrypt-<version>-android-arm64.apk.
#   iOS     — builds the FFI XCFramework + Swift bindings (scripts/build-ios.sh).
#             Needs full Xcode + iOS SDK; on a host without them it is recorded
#             as SKIPPED (never silently dropped), exactly like a missing desktop
#             cross-toolchain.
#
#   bash scripts/package-mobile.sh                 # Android (+ iOS if Xcode present)
#   TALKRYPT_TOR=1 bash scripts/package-mobile.sh  # APK with the Arti/Tor transport
#
# Run after (or before) scripts/package.sh; hash-dist.sh re-hashes the whole
# dist/, so the final SHA256SUMS/SHA3-256SUMS cover desktop + Android + iOS.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
OUT="dist"; mkdir -p "$OUT"
VERSION="$(grep -m1 '^version' crates/cli/Cargo.toml | sed -E 's/.*"([^"]+)".*/\1/')"
touch "$OUT/SKIPPED.txt"
skip() { echo "$1" >> "$OUT/SKIPPED.txt"; echo "    SKIP: $1"; }

# ---- Android ----
if command -v cargo-ndk >/dev/null 2>&1; then
  echo "==> building Android APK"
  if bash android/build-apk.sh; then
    APK="android/app/build/outputs/apk/debug/app-debug.apk"
    if [[ -f "$APK" ]]; then
      dest="$OUT/talkrypt-$VERSION-android-arm64.apk"
      cp "$APK" "$dest"
      echo "    -> $dest"
    else
      skip "android — build reported success but no APK at $APK"
    fi
  else
    skip "android — build failed (need Android SDK + NDK + JDK; see android/build-apk.sh)"
  fi
else
  skip "android — cargo-ndk not installed (cargo install cargo-ndk; needs Android SDK + NDK + JDK)"
fi

# ---- iOS ----
echo "==> building iOS XCFramework (needs full Xcode)"
if bash scripts/build-ios.sh; then
  : # build-ios.sh writes dist/talkrypt-<version>-ios-xcframework.zip
else
  rc=$?
  if [[ $rc -eq 2 ]]; then
    skip "ios — full Xcode + iOS SDK not present on this host (XCFramework/IPA unbuildable here; see scripts/build-ios.sh)"
  else
    skip "ios — build-ios.sh failed (exit $rc)"
  fi
fi

# ---- one unified set of checksums over desktop + mobile ----
bash "$ROOT/scripts/hash-dist.sh"
echo
echo "==> mobile packaging done; dist/ now hashed (desktop + mobile) — see dist/MANIFEST.txt"
