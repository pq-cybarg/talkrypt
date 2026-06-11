#!/usr/bin/env bash
# Build the talkrypt iOS deliverable: the FFI as an **XCFramework** (device +
# simulator slices) plus the uniffi **Swift bindings** — the consumable an iOS
# (SwiftUI) app embeds. Optionally archive + upload to TestFlight when an Xcode
# app project and Apple Developer credentials are present.
#
#   bash scripts/build-ios.sh                 # build the XCFramework + Swift bindings
#   bash scripts/build-ios.sh --testflight    # also archive the app + upload (needs Xcode app project + Apple account)
#
# Hard requirements (this is why it can't run on a CommandLineTools-only host):
#   * Full **Xcode** (the iOS SDK + `xcodebuild -create-xcframework`), not just
#     the Command Line Tools. Check: `xcode-select -p` must point inside Xcode.app.
#   * Rust iOS targets (auto-added below).
# TestFlight additionally requires: an Xcode **app project** (a thin SwiftUI shell
# over this XCFramework — talkrypt's core is all here), an **Apple Developer**
# account + signing/provisioning, and `xcrun altool`/Transporter or fastlane.
# None of those can be fabricated; this script does every step it *can* and
# stops with a precise message at the first thing it genuinely cannot.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
OUT="dist"; mkdir -p "$OUT"
VERSION="$(grep -m1 '^version' crates/cli/Cargo.toml | sed -E 's/.*"([^"]+)".*/\1/')"
LIB="talkrypt_ffi"
WANT_TESTFLIGHT=0; [[ "${1:-}" == "--testflight" ]] && WANT_TESTFLIGHT=1

# 0. Verify full Xcode (not just CommandLineTools) — the iOS SDK lives there.
DEV="$(xcode-select -p 2>/dev/null || true)"
if [[ "$DEV" != *Xcode*.app* ]] || ! xcrun --sdk iphoneos --show-sdk-path >/dev/null 2>&1; then
  echo "build-ios: full Xcode + iOS SDK required (have: ${DEV:-none})." >&2
  echo "  Install Xcode.app, then: sudo xcode-select -s /Applications/Xcode.app/Contents/Developer" >&2
  echo "  (Command Line Tools alone cannot compile/link for iOS or create an XCFramework.)" >&2
  exit 2
fi

# 1. Rust iOS targets: device + both simulator arches.
IOS_DEVICE="aarch64-apple-ios"
IOS_SIM_ARM="aarch64-apple-ios-sim"
IOS_SIM_X86="x86_64-apple-ios"
rustup target add "$IOS_DEVICE" "$IOS_SIM_ARM" "$IOS_SIM_X86" >/dev/null 2>&1 || true

echo "==> building $LIB staticlib for iOS device + simulator"
for t in "$IOS_DEVICE" "$IOS_SIM_ARM" "$IOS_SIM_X86"; do
  cargo build -p talkrypt-ffi --release --target "$t"
done

# 2. Fat simulator lib (arm64-sim + x86_64-sim) — a slice can't hold two arches,
#    so the two simulator arches are lipo'd; the device arch stays separate.
STAGE="$OUT/ios-stage"; rm -rf "$STAGE"; mkdir -p "$STAGE"
SIM_FAT="$STAGE/libsim/lib$LIB.a"; mkdir -p "$STAGE/libsim"
lipo -create -output "$SIM_FAT" \
  "target/$IOS_SIM_ARM/release/lib$LIB.a" \
  "target/$IOS_SIM_X86/release/lib$LIB.a"
DEV_LIB="target/$IOS_DEVICE/release/lib$LIB.a"

# 3. uniffi Swift bindings (from a host build that carries the uniffi metadata).
echo "==> generating Swift bindings (uniffi)"
cargo build -p talkrypt-ffi >/dev/null
HOSTLIB="target/debug/lib$LIB.dylib"
BIND="$STAGE/bindings"; mkdir -p "$BIND"
cargo run -p talkrypt-ffi --bin uniffi-bindgen -- generate \
  --library "$HOSTLIB" --language swift --out-dir "$BIND" --no-format

# Assemble the headers dir each XCFramework slice needs: the generated FFI header
# + a module map named module.modulemap.
HDR="$STAGE/headers"; mkdir -p "$HDR"
cp "$BIND/${LIB}FFI.h" "$HDR/" 2>/dev/null || cp "$BIND"/*FFI.h "$HDR/"
if [[ -f "$BIND/${LIB}FFI.modulemap" ]]; then cp "$BIND/${LIB}FFI.modulemap" "$HDR/module.modulemap"
else cat "$BIND"/*.modulemap > "$HDR/module.modulemap"; fi

# 4. XCFramework: device slice + simulator slice, each with headers.
echo "==> assembling $LIB.xcframework"
XCF="$STAGE/$LIB.xcframework"; rm -rf "$XCF"
xcodebuild -create-xcframework \
  -library "$DEV_LIB"  -headers "$HDR" \
  -library "$SIM_FAT"  -headers "$HDR" \
  -output "$XCF"

# Bundle the XCFramework + the Swift glue (.swift) so an app target can drop both in.
DELIV="$STAGE/talkrypt-ios"; mkdir -p "$DELIV"
cp -R "$XCF" "$DELIV/"
cp "$BIND"/*.swift "$DELIV/"
cp README.md LICENSE "$DELIV/" 2>/dev/null || true
ZIP="$OUT/talkrypt-$VERSION-ios-xcframework.zip"
rm -f "$ZIP"; ( cd "$STAGE" && zip -qr "$ROOT/$ZIP" "talkrypt-ios" )
echo "    -> $ZIP"

# 5. TestFlight (optional) — only with an Xcode app project + Apple credentials.
if [[ "$WANT_TESTFLIGHT" == "1" ]]; then
  APPPROJ="$(ls ios/*.xcodeproj ios/*.xcworkspace 2>/dev/null | head -1 || true)"
  if [[ -z "$APPPROJ" ]]; then
    echo "build-ios: --testflight needs an Xcode app project at ios/ (a SwiftUI shell that embeds $LIB.xcframework)." >&2
    echo "  The XCFramework + Swift bindings above are ready to embed. Then archive + upload:" >&2
    echo "    xcodebuild -scheme talkrypt -archivePath build/talkrypt.xcarchive archive" >&2
    echo "    xcodebuild -exportArchive -archivePath build/talkrypt.xcarchive -exportPath build -exportOptionsPlist ios/ExportOptions.plist" >&2
    echo "    xcrun altool --upload-app -f build/talkrypt.ipa -t ios --apiKey \$ASC_KEY_ID --apiIssuer \$ASC_ISSUER  # App Store Connect API key" >&2
    echo "  (or 'fastlane pilot upload'). Requires an Apple Developer account + signing identity." >&2
    exit 3
  fi
  echo "==> archiving + uploading to TestFlight from $APPPROJ"
  xcodebuild -project "$APPPROJ" -scheme talkrypt -configuration Release \
    -archivePath "$OUT/talkrypt.xcarchive" archive
  xcodebuild -exportArchive -archivePath "$OUT/talkrypt.xcarchive" \
    -exportPath "$OUT/ios-export" -exportOptionsPlist ios/ExportOptions.plist
  IPA="$(ls "$OUT"/ios-export/*.ipa | head -1)"
  cp "$IPA" "$OUT/talkrypt-$VERSION-ios.ipa"
  xcrun altool --upload-app -f "$OUT/talkrypt-$VERSION-ios.ipa" -t ios \
    --apiKey "${ASC_KEY_ID:?set ASC_KEY_ID}" --apiIssuer "${ASC_ISSUER:?set ASC_ISSUER}"
  echo "    uploaded to TestFlight; processing happens on App Store Connect."
fi

rm -rf "$STAGE"
echo "==> iOS XCFramework built. Embed dist/$(basename "$ZIP") in an iOS app target; run with --testflight on a Mac with Xcode + an Apple Developer account to ship to TestFlight."
