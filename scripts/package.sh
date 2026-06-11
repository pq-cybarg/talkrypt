#!/usr/bin/env bash
# Package talkrypt for desktop distribution: real installers/archives, not just
# bare binaries (that's `scripts/build-portable.sh`). For every Rust target whose
# toolchain is present, this builds the CLI + TUI + key-custody helper, then
# assembles platform-native packages:
#
#   macOS    universal .app bundle + .dmg disk image (ad-hoc codesigned)
#   Linux    .tar.gz + a Debian .deb (built portably with `ar`+`tar`,
#            so it needs no dpkg-deb and works on any host)
#   Windows  .zip
#
# It then writes SHA256SUMS over every artifact and a MANIFEST.txt recording
# versions, sizes, checksums, what was built, and — crucially — what was SKIPPED
# and why (no silent truncation: a missing cross-toolchain is reported, never
# hidden). Honors the packaging political filter in docs/packaging-policy.md.
#
#   bash scripts/package.sh                 # package every available target
#   bash scripts/package.sh --list          # show targets + what's installed
#
# Nothing here is signed by a trusted authority or notarized; macOS signing is
# ad-hoc (codesign -s -) so Gatekeeper still warns. NOT certified / NOT audited.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

# The CLI binary is `talkrypt`; the workspace also ships a TUI and a helper.
BINS=(talkrypt:talkrypt-cli talkrypt-tui:talkrypt-tui talkrypt-helper:talkrypt-helper)
VERSION="$(grep -m1 '^version' crates/cli/Cargo.toml | sed -E 's/.*"([^"]+)".*/\1/')"
[[ -z "$VERSION" ]] && VERSION="0.0.0"
GITREV="$(git rev-parse --short HEAD 2>/dev/null || echo unknown)"
STAMP="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

# Targets we know how to package, in priority order. The host target is always
# attempted; others only if their rustup std + linker are present.
TARGETS=(
  aarch64-apple-darwin
  x86_64-apple-darwin
  x86_64-unknown-linux-gnu
  aarch64-unknown-linux-gnu
  x86_64-unknown-linux-musl
  aarch64-unknown-linux-musl
  x86_64-pc-windows-gnu
)

have_target() { rustup target list --installed 2>/dev/null | grep -qx "$1"; }

if [[ "${1:-}" == "--list" ]]; then
  echo "talkrypt $VERSION ($GITREV) — packaging targets:"
  for t in "${TARGETS[@]}"; do
    if have_target "$t"; then echo "  [installed] $t"; else echo "  [missing]   $t   ->  rustup target add $t"; fi
  done
  exit 0
fi

OUT="dist"
STAGE="$OUT/stage"
rm -rf "$STAGE"; mkdir -p "$OUT" "$STAGE"
ARTIFACTS=(); SKIPPED=()

# Build every workspace binary for $1 (target triple). On success sets the global
# REL to the release dir and returns 0; on failure records a skip reason and
# returns 1. Called directly (NOT in a subshell) so SKIPPED accumulates.
build_target() {
  local t="$1"
  REL=""
  if ! have_target "$t"; then SKIPPED+=("$t — rustup target not installed (rustup target add $t)"); return 1; fi
  # Linux targets cross-compile cleanly via `cross` (Docker) when present, which
  # supplies the right linker/sysroot; otherwise fall back to plain cargo (works
  # natively, and for Windows via mingw / macOS arches on a mac host).
  local builder="cargo"
  if [[ "$t" == *linux* && "${USE_CROSS:-auto}" != "no" ]] && command -v cross >/dev/null 2>&1; then
    builder="cross"
  fi
  echo "==> building binaries for $t (via $builder)"
  for entry in "${BINS[@]}"; do
    local crate="${entry#*:}"
    if ! "$builder" build --release -p "$crate" --target "$t" >/dev/null 2>&1; then
      SKIPPED+=("$t — '$crate' failed to build ($builder; cross linker/toolchain missing?)")
      return 1
    fi
  done
  REL="target/$t/release"
  return 0
}

# Assemble a per-target archive (.tar.gz for Unix, .zip for Windows) with all
# binaries + docs, into dist/. Echoes nothing; appends to ARTIFACTS.
archive_target() {
  local t="$1" reldir="$2" ext="" pkgdir
  [[ "$t" == *windows* ]] && ext=".exe"
  pkgdir="$STAGE/talkrypt-$VERSION-$t"
  mkdir -p "$pkgdir"
  for entry in "${BINS[@]}"; do
    local name="${entry%%:*}"
    cp "$reldir/$name$ext" "$pkgdir/" 2>/dev/null || true
    strip "$pkgdir/$name$ext" 2>/dev/null || true
  done
  cp README.md LICENSE "$pkgdir/" 2>/dev/null || true
  cat > "$pkgdir/USAGE.txt" <<EOF
talkrypt $VERSION ($GITREV) — post-quantum E2E encrypted chat
  talkrypt host                 create a chat, print a talkrypt:// invite + QR
  talkrypt join <uri>           join from an invite
  talkrypt link-offer/-accept   link a second device to your account
  talkrypt registry             host a username directory
  talkrypt version              build banner + honesty disclaimer
Run 'talkrypt --help' for all flags. NOT certified / NOT audited.
EOF
  local archive
  if [[ "$t" == *windows* ]]; then
    archive="$OUT/talkrypt-$VERSION-$t.zip"
    ( cd "$STAGE" && zip -qr "$ROOT/$archive" "talkrypt-$VERSION-$t" )
  else
    archive="$OUT/talkrypt-$VERSION-$t.tar.gz"
    tar -czf "$archive" -C "$STAGE" "talkrypt-$VERSION-$t"
  fi
  ARTIFACTS+=("$archive")
  echo "    -> $archive"
}

# ---- build each target, collect release dirs ----
declare -A RELDIR
for t in "${TARGETS[@]}"; do
  if build_target "$t"; then
    RELDIR["$t"]="$REL"
    archive_target "$t" "$REL"
  fi
done

# ---- macOS: universal binary -> .app -> .dmg ----
mac_arm="${RELDIR[aarch64-apple-darwin]:-}"
mac_x86="${RELDIR[x86_64-apple-darwin]:-}"
if [[ -n "$mac_arm" || -n "$mac_x86" ]] && command -v lipo >/dev/null 2>&1; then
  echo "==> assembling macOS .app + .dmg"
  uni="$STAGE/talkrypt-universal"
  if [[ -n "$mac_arm" && -n "$mac_x86" ]]; then
    lipo -create -output "$uni" "$mac_arm/talkrypt" "$mac_x86/talkrypt"
  else
    cp "${mac_arm:-$mac_x86}/talkrypt" "$uni"   # single-arch fallback
  fi
  strip "$uni" 2>/dev/null || true
  app="$STAGE/talkrypt.app"
  mkdir -p "$app/Contents/MacOS" "$app/Contents/Resources"
  cp "$uni" "$app/Contents/MacOS/talkrypt-bin"
  # Launcher opens Terminal on the CLI (the shipped product is the CLI/TUI).
  cat > "$app/Contents/MacOS/talkrypt" <<'EOF'
#!/bin/bash
DIR="$(cd "$(dirname "$0")" && pwd)"
open -a Terminal "$DIR/talkrypt-bin"
EOF
  chmod +x "$app/Contents/MacOS/talkrypt" "$app/Contents/MacOS/talkrypt-bin"
  cat > "$app/Contents/Info.plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>CFBundleName</key><string>talkrypt</string>
  <key>CFBundleDisplayName</key><string>talkrypt</string>
  <key>CFBundleIdentifier</key><string>com.talkrypt.app</string>
  <key>CFBundleVersion</key><string>$VERSION</string>
  <key>CFBundleShortVersionString</key><string>$VERSION</string>
  <key>CFBundleExecutable</key><string>talkrypt</string>
  <key>CFBundlePackageType</key><string>APPL</string>
  <key>LSMinimumSystemVersion</key><string>11.0</string>
</dict></plist>
EOF
  # Ad-hoc sign so the bundle is at least internally consistent (NOT notarized).
  command -v codesign >/dev/null 2>&1 && codesign --force --deep -s - "$app" 2>/dev/null || true
  if command -v hdiutil >/dev/null 2>&1; then
    dmg="$OUT/talkrypt-$VERSION-macos.dmg"
    rm -f "$dmg"
    dmgsrc="$STAGE/dmgsrc"; mkdir -p "$dmgsrc"
    cp -R "$app" "$dmgsrc/"
    ln -sf /Applications "$dmgsrc/Applications"
    hdiutil create -quiet -volname "talkrypt $VERSION" -srcfolder "$dmgsrc" \
      -ov -format UDZO "$dmg"
    ARTIFACTS+=("$dmg")
    echo "    -> $dmg"
  fi
fi

# ---- Linux: portable .deb (ar + tar; no dpkg-deb needed) ----
# Two .deb flavors per arch, so both coexist as installable packages (they share
# /usr/bin paths, so each Conflicts/Provides the other — install one):
#   gnu  -> `talkrypt`        (dynamically linked against glibc; the Debian-native build)
#   musl -> `talkrypt-static` (one fully-static binary, no libc dep — runs anywhere)
# `arch` is the dpkg architecture (amd64/arm64); a static binary still targets an
# arch, so the field is the same — only the Package name and filename differ,
# which is why the gnu/musl builds no longer collide on one filename.
build_deb() {
  local t="$1" reldir="$2" arch pkg variant_desc
  case "$t" in
    x86_64-*) arch="amd64" ;;
    aarch64-*) arch="arm64" ;;
    *) return 0 ;;
  esac
  if [[ "$t" == *musl* ]]; then
    pkg="talkrypt-static"
    variant_desc=$' This is the fully-static (musl) build: one self-contained binary with no\n libc or other shared-library dependency, so it runs on any Linux of this\n architecture regardless of distro or glibc version.'
  else
    pkg="talkrypt"
    variant_desc=""
  fi
  command -v ar >/dev/null 2>&1 || { SKIPPED+=(".deb($pkg/$arch) — 'ar' not found"); return 0; }
  echo "==> building .deb ($pkg, $arch) from $t"
  local d="$STAGE/deb-$pkg-$arch"
  rm -rf "$d"; mkdir -p "$d/usr/bin" "$d/usr/share/doc/$pkg" "$d/usr/share/applications" "$d/DEBIAN"
  for entry in "${BINS[@]}"; do
    local name="${entry%%:*}"
    cp "$reldir/$name" "$d/usr/bin/" 2>/dev/null || true
    strip "$d/usr/bin/$name" 2>/dev/null || true
  done
  cp README.md LICENSE "$d/usr/share/doc/$pkg/" 2>/dev/null || true
  cat > "$d/usr/share/applications/talkrypt.desktop" <<EOF
[Desktop Entry]
Name=talkrypt
Comment=Post-quantum end-to-end encrypted chat (CLI)
Exec=x-terminal-emulator -e talkrypt
Terminal=true
Type=Application
Categories=Network;InstantMessaging;Security;
EOF
  local instsize
  instsize=$(du -sk "$d/usr" | cut -f1)
  cat > "$d/DEBIAN/control" <<EOF
Package: $pkg
Version: $VERSION
Architecture: $arch
Maintainer: talkrypt <resistant@tuta.com>
Installed-Size: $instsize
Section: net
Priority: optional
Conflicts: $([[ "$pkg" == talkrypt ]] && echo talkrypt-static || echo talkrypt)
Provides: talkrypt
Description: Post-quantum end-to-end encrypted chat (CLI/TUI)
 talkrypt is a minimalist, forward-secret, post-quantum end-to-end encrypted
 chat (ML-KEM-1024, ML-DSA-87, AES-256-GCM) over Tor. Pure-Rust crypto; no C
 dependencies. NOT FIPS-validated, NOT audited, NOT authorized for classified
 use. Experimental, pre-release software.$variant_desc
EOF
  # Assemble the .deb (an `ar` archive: debian-binary, control.tar.gz, data.tar.gz).
  local deb="$OUT/${pkg}_${VERSION}_${arch}.deb"
  local tmp="$STAGE/debtmp-$pkg-$arch"; rm -rf "$tmp"; mkdir -p "$tmp"
  echo "2.0" > "$tmp/debian-binary"
  tar -czf "$tmp/control.tar.gz" -C "$d/DEBIAN" .
  tar -czf "$tmp/data.tar.gz" -C "$d" usr
  rm -f "$ROOT/$deb"
  ( cd "$tmp" && ar rc "$ROOT/$deb" debian-binary control.tar.gz data.tar.gz )
  ARTIFACTS+=("$deb")
  echo "    -> $deb"
}
# Build a .deb for every Linux target produced: gnu -> `talkrypt`,
# musl -> `talkrypt-static` (distinct package + filename, so they don't collide).
# musl binaries also ship as fully-static .tar.gz above.
for t in x86_64-unknown-linux-gnu aarch64-unknown-linux-gnu x86_64-unknown-linux-musl aarch64-unknown-linux-musl; do
  [[ -n "${RELDIR[$t]:-}" ]] && build_deb "$t" "${RELDIR[$t]}"
done

# ---- checksums (SHA-256 + SHA3-256) + manifest ----
# Hashing is owned by scripts/hash-dist.sh (the single authority over the whole
# dist/, so desktop + mobile share one set of sums). Record what we skipped so
# hash-dist.sh folds it into MANIFEST.txt, then hand off.
: > "$OUT/SKIPPED.txt"
for s in "${SKIPPED[@]}"; do echo "$s" >> "$OUT/SKIPPED.txt"; done

if [[ ${#ARTIFACTS[@]} -eq 0 ]]; then
  echo "Nothing packaged — see --list and install a target."
  exit 1
fi

bash "$ROOT/scripts/hash-dist.sh"
echo
echo "==> packaged ${#ARTIFACTS[@]} desktop artifact(s) into $OUT/"
cat "$OUT/MANIFEST.txt"
exit 0
