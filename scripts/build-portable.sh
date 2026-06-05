#!/usr/bin/env bash
# Build portable talkrypt CLI binaries for peer-to-peer distribution.
#
# talkrypt's crypto is pure-Rust (RustCrypto: ML-KEM, ML-DSA, AES, SHA-3,
# Argon2) and the default transport is plain TCP, so the CLI links no C
# libraries — it builds as a single, fully-static, dependency-free binary on
# musl. That binary "just runs" on any matching machine, which is exactly what
# you want when handing the app to someone in person (alongside `Share app` on
# mobile and `link-offer`/QR for pairing).
#
#   bash scripts/build-portable.sh                # build every installed target
#   bash scripts/build-portable.sh --list         # show targets + install hints
#
# Targets (install the rustup target first; musl also needs a musl toolchain or
# the `cross` tool):
#   x86_64-unknown-linux-musl     fully static Linux x86_64
#   aarch64-unknown-linux-musl    fully static Linux arm64
#   x86_64-apple-darwin           macOS Intel
#   aarch64-apple-darwin          macOS Apple Silicon
#   x86_64-pc-windows-gnu         Windows x86_64 (.exe)
#
# Output: dist/talkrypt-<target>[.exe], stripped, plus a universal macOS binary
# (talkrypt-macos-universal) when both darwin arches are present.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

TARGETS=(
  x86_64-unknown-linux-musl
  aarch64-unknown-linux-musl
  x86_64-apple-darwin
  aarch64-apple-darwin
  x86_64-pc-windows-gnu
)

if [[ "${1:-}" == "--list" ]]; then
  echo "Portable targets (install with: rustup target add <target>):"
  for t in "${TARGETS[@]}"; do
    if rustup target list --installed 2>/dev/null | grep -qx "$t"; then
      echo "  [installed] $t"
    else
      echo "  [missing]   $t   ->  rustup target add $t"
    fi
  done
  echo
  echo "musl cross-builds are easiest with 'cross' (https://github.com/cross-rs/cross):"
  echo "  cargo install cross && CROSS=1 bash scripts/build-portable.sh"
  exit 0
fi

mkdir -p dist
BUILDER="cargo"
if [[ "${CROSS:-}" == "1" ]] && command -v cross >/dev/null 2>&1; then
  BUILDER="cross"
fi

built=()
for t in "${TARGETS[@]}"; do
  # With plain cargo, only build targets whose rustup target is installed.
  if [[ "$BUILDER" == "cargo" ]] && ! rustup target list --installed 2>/dev/null | grep -qx "$t"; then
    echo "skip $t (target not installed; 'rustup target add $t' or use CROSS=1)"
    continue
  fi
  echo "==> building $t with $BUILDER"
  if ! $BUILDER build --release -p talkrypt-cli --target "$t"; then
    echo "!! build failed for $t (toolchain/linker missing?) — skipping"
    continue
  fi
  ext=""
  [[ "$t" == *windows* ]] && ext=".exe"
  src="target/$t/release/talkrypt$ext"
  dst="dist/talkrypt-$t$ext"
  cp "$src" "$dst"
  # Best-effort strip (skip for cross-arch where host strip can't process it).
  strip "$dst" 2>/dev/null || true
  built+=("$dst")
  echo "    -> $dst"
done

# macOS universal binary when both arches were built.
if [[ -f dist/talkrypt-x86_64-apple-darwin && -f dist/talkrypt-aarch64-apple-darwin ]] \
   && command -v lipo >/dev/null 2>&1; then
  lipo -create -output dist/talkrypt-macos-universal \
    dist/talkrypt-x86_64-apple-darwin dist/talkrypt-aarch64-apple-darwin
  built+=("dist/talkrypt-macos-universal")
  echo "==> universal macOS binary: dist/talkrypt-macos-universal"
fi

echo
if [[ ${#built[@]} -eq 0 ]]; then
  echo "No binaries built. Run with --list to see targets, or install one:"
  echo "  rustup target add x86_64-unknown-linux-musl"
  exit 1
fi
echo "Built ${#built[@]} portable binary(ies):"
for b in "${built[@]}"; do
  sz=$(du -h "$b" | cut -f1)
  echo "  $b  ($sz)"
done
echo
echo "These are self-contained. Hand one to a peer (USB, AirDrop, the in-app"
echo "P2P share, or any channel) and it runs with no install or dependencies."
