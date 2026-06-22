#!/usr/bin/env bash
# Build the talkrypt custody-probe APK end to end: the FFI .so (cargo-ndk), the
# uniffi Kotlin bindings (uniffi-bindgen), then the APK (Gradle). Run from
# anywhere; paths are repo-relative.
#
#   bash android/build-apk.sh                       # LAN-only build
#   TALKRYPT_TOR=1 bash android/build-apk.sh         # + Tor (.onion) transport
#   TALKRYPT_NYM=1 bash android/build-apk.sh         # + Nym mixnet (multi-homed)
#   TALKRYPT_TOR=1 TALKRYPT_NYM=1 bash android/build-apk.sh  # both
#   adb install -r android/app/build/outputs/apk/debug/app-debug.apk
#   adb shell am start -n com.talkrypt.app/.MainActivity
#   adb logcat -s talkrypt
#
# Requires: Android SDK + NDK, cargo-ndk, a JDK. NOT certified / NOT audited.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

NDK="${ANDROID_NDK_HOME:-$HOME/Library/Android/sdk/ndk/26.3.11579264}"
SDK="${ANDROID_HOME:-$HOME/Library/Android/sdk}"

# 1. FFI .so for arm64 (real device link via the NDK).
# Set TALKRYPT_TOR=1 to compile the Arti (Tor) transport into the .so, so the
# app's "Route over Tor" toggle works. This pulls the large Arti dependency tree
# and a heavier cross-compile; off by default for a lean, fast build.
# Compose the FFI feature set. Tor (Arti) and Nym (mixnet) are each opt-in and
# heavy; the .so works LAN-only without them. host_nym/join_nym are always
# exported but error unless the .so was built with TALKRYPT_NYM=1.
FEATURES=()
if [ "${TALKRYPT_TOR:-0}" = "1" ]; then
  echo "building FFI with Tor (Arti) — heavier cross-compile…"
  FEATURES+=("tor")
fi
if [ "${TALKRYPT_NYM:-0}" = "1" ]; then
  echo "building FFI with Nym (mixnet) — heavier cross-compile…"
  FEATURES+=("nym")
fi
FEATURE_FLAG=""
if [ ${#FEATURES[@]} -gt 0 ]; then
  FEATURE_FLAG="--features $(IFS=,; echo "${FEATURES[*]}")"
fi
ANDROID_NDK_HOME="$NDK" cargo ndk -t arm64-v8a build -p talkrypt-ffi --release $FEATURE_FLAG
mkdir -p android/app/src/main/jniLibs/arm64-v8a
cp target/aarch64-linux-android/release/libtalkrypt_ffi.so \
   android/app/src/main/jniLibs/arm64-v8a/

# 2. uniffi Kotlin bindings — from the UNSTRIPPED host debug dylib (the release
#    build strips the metadata section uniffi-bindgen needs).
cargo build -p talkrypt-ffi
rm -rf /tmp/tk-bindings && mkdir -p /tmp/tk-bindings
cargo run -q -p talkrypt-ffi --bin uniffi-bindgen -- generate \
    --library target/debug/libtalkrypt_ffi.dylib --language kotlin \
    --out-dir /tmp/tk-bindings --no-format
mkdir -p android/app/src/main/kotlin/uniffi
cp -R /tmp/tk-bindings/uniffi/* android/app/src/main/kotlin/uniffi/

# 3. SDK location + APK.
echo "sdk.dir=$SDK" > android/local.properties
android/gradlew -p android :app:assembleDebug

echo "APK: android/app/build/outputs/apk/debug/app-debug.apk"
