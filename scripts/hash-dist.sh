#!/usr/bin/env bash
# Hash EVERY release artifact in dist/ with two independent families — SHA-256
# (FIPS 180-4) and SHA3-256 (FIPS 202 / Keccak) — and write SHA256SUMS,
# SHA3-256SUMS, MANIFEST.txt, and the verify.sh / verify.ps1 checkers.
#
# This is the single hashing authority for the whole release: the desktop
# packager (package.sh) and the mobile packager (package-mobile.sh) each drop
# their artifacts into dist/ and then call this, so one set of checksums covers
# desktop + Android + iOS together. Idempotent — safe to re-run after adding
# more artifacts.
#
#   bash scripts/hash-dist.sh
#
# Two unrelated hash families mean a cryptanalytic break or deliberate collision
# in one cannot also satisfy the other.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
OUT="dist"
[[ -d "$OUT" ]] || { echo "no $OUT/ — build something first (package.sh / package-mobile.sh)"; exit 1; }

VERSION="$(grep -m1 '^version' crates/cli/Cargo.toml | sed -E 's/.*"([^"]+)".*/\1/')"
[[ -z "$VERSION" ]] && VERSION="0.0.0"
GITREV="$(git rev-parse --short HEAD 2>/dev/null || echo unknown)"
STAMP="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

# Release artifact extensions (everything a user downloads). Excludes the sums,
# manifest, verifier scripts, and the stage/ scratch dir.
shopt -s nullglob
ARTIFACTS=()
for f in "$OUT"/*.tar.gz "$OUT"/*.zip "$OUT"/*.dmg "$OUT"/*.deb "$OUT"/*.apk "$OUT"/*.aab "$OUT"/*.ipa "$OUT"/*.xcframework.zip; do
  ARTIFACTS+=("$(basename "$f")")
done
shopt -u nullglob
[[ ${#ARTIFACTS[@]} -eq 0 ]] && { echo "no release artifacts in $OUT/"; exit 1; }

# --- SHA-256 ---
sha256_hex() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | cut -d' ' -f1
  else shasum -a 256 "$1" | cut -d' ' -f1; fi
}

# --- SHA3-256: openssl 3.x (LibreSSL lacks SHA3) -> python3 hashlib -> rhash ---
SHA3_BACKEND=""
if command -v openssl >/dev/null 2>&1 && echo | openssl dgst -sha3-256 >/dev/null 2>&1; then SHA3_BACKEND="openssl"
elif command -v python3 >/dev/null 2>&1 && python3 -c "import hashlib;hashlib.sha3_256" >/dev/null 2>&1; then SHA3_BACKEND="python"
elif command -v rhash >/dev/null 2>&1; then SHA3_BACKEND="rhash"; fi
sha3_256_hex() {
  case "$SHA3_BACKEND" in
    openssl) openssl dgst -sha3-256 "$1" | sed -E 's/^.*= *//' ;;
    python)  python3 - "$1" <<'PY'
import hashlib,sys
print(hashlib.sha3_256(open(sys.argv[1],'rb').read()).hexdigest())
PY
      ;;
    rhash)   rhash --sha3-256 --simple "$1" | cut -d' ' -f1 ;;
    *)       return 1 ;;
  esac
}

cd "$OUT"
rm -f SHA256SUMS SHA3-256SUMS
for a in "${ARTIFACTS[@]}"; do
  printf "%s  %s\n" "$(sha256_hex "$a")" "$a" >> SHA256SUMS
  [[ -n "$SHA3_BACKEND" ]] && printf "%s  %s\n" "$(sha3_256_hex "$a")" "$a" >> SHA3-256SUMS
done
cp "$ROOT/scripts/verify.sh" "$ROOT/scripts/verify.ps1" . 2>/dev/null || true

{
  echo "talkrypt $VERSION  ($GITREV)  hashed $STAMP"
  echo "host: $(rustc -vV 2>/dev/null | sed -n 's/^host: //p')"
  echo "hashes: SHA-256 (SHA256SUMS) + SHA3-256 (SHA3-256SUMS); verify with verify.sh / verify.ps1"
  echo
  echo "ARTIFACTS:"
  for a in "${ARTIFACTS[@]}"; do
    sz=$(du -h "$a" | cut -f1)
    printf "  %s  (%s)\n" "$a" "$sz"
    printf "      sha256:   %s\n" "$(sha256_hex "$a")"
    [[ -n "$SHA3_BACKEND" ]] && printf "      sha3-256: %s\n" "$(sha3_256_hex "$a")"
  done
  if [[ -s SKIPPED.txt ]]; then
    echo
    echo "SKIPPED (not silently — install the toolchain to include these):"
    sed 's/^/  - /' SKIPPED.txt
  fi
  [[ -z "$SHA3_BACKEND" ]] && { echo; echo "WARNING: no SHA3 backend (install openssl 3.x / python3 / rhash) — SHA3-256SUMS not written."; }
  echo
  echo "Packaging endorsement is gated by docs/packaging-policy.md (the political"
  echo "filter). The software itself is Apache-2.0 and buildable everywhere."
  echo "NOT FIPS-validated · NOT CSfC-accredited · NOT NSA-approved · NOT audited."
} > MANIFEST.txt

echo "==> hashed ${#ARTIFACTS[@]} artifact(s) in $OUT/ (SHA-256 + SHA3-256); wrote SHA256SUMS, SHA3-256SUMS, MANIFEST.txt"
