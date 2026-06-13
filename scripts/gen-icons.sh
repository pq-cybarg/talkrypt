#!/usr/bin/env bash
# Regenerate the raster app icons from assets/talkrypt-logo.svg:
#   * assets/icons/talkrypt.icns      — macOS .app bundle icon
#   * assets/icons/talkrypt-512.png   — Linux hicolor icon (+ 256/128)
#
# Needs rsvg-convert (librsvg) to rasterize the SVG; macOS .icns additionally
# needs iconutil (ships with macOS). Run when the logo changes; the outputs are
# committed so package.sh needs no renderer at build time.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SVG="$ROOT/assets/talkrypt-logo.svg"
OUT="$ROOT/assets/icons"
mkdir -p "$OUT"
command -v rsvg-convert >/dev/null || { echo "need rsvg-convert (brew install librsvg)"; exit 1; }

png() { rsvg-convert -w "$1" -h "$1" "$SVG" -o "$2"; }

# Linux PNGs.
for s in 128 256 512; do png "$s" "$OUT/talkrypt-$s.png"; done
echo "  -> assets/icons/talkrypt-{128,256,512}.png"

# macOS .icns via an .iconset (each size + @2x retina variant).
if command -v iconutil >/dev/null 2>&1; then
  ISET="$OUT/talkrypt.iconset"; rm -rf "$ISET"; mkdir -p "$ISET"
  for s in 16 32 128 256 512; do
    png "$s"            "$ISET/icon_${s}x${s}.png"
    png "$((s*2))"      "$ISET/icon_${s}x${s}@2x.png"
  done
  iconutil -c icns "$ISET" -o "$OUT/talkrypt.icns"
  rm -rf "$ISET"
  echo "  -> assets/icons/talkrypt.icns"
else
  echo "  (iconutil not found — skipped .icns; run on macOS to produce it)"
fi
