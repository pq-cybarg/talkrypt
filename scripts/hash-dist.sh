#!/usr/bin/env bash
# Hash EVERY release artifact in dist/ with two independent families — SHA-384
# (FIPS 180-4) and SHA3-384 (FIPS 202 / Keccak) — and write SHA384SUMS,
# SHA3-384SUMS, MANIFEST.txt, and the verify.sh / verify.ps1 checkers.
#
# This is the single hashing authority for the whole release: the desktop
# packager (package.sh) and the mobile packager (package-mobile.sh) each drop
# their artifacts into dist/ and then call this, so one set of checksums covers
# desktop + Android + iOS together. Idempotent — safe to re-run after adding
# more artifacts.
#
#   bash scripts/hash-dist.sh
#
# Two unrelated 384-bit hash families — the CNSA-aligned SHA-384 and the FIPS 202
# SHA3-384 that talkrypt's own crypto uses — mean a cryptanalytic break or
# deliberate collision in one cannot also satisfy the other.
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

# --- SHA-384 (FIPS 180-4) ---
sha384_hex() {
  if command -v sha384sum >/dev/null 2>&1; then sha384sum "$1" | cut -d' ' -f1
  else shasum -a 384 "$1" | cut -d' ' -f1; fi
}

# --- SHA3-384 (FIPS 202): openssl 3.x (LibreSSL lacks SHA3) -> python3 hashlib -> rhash ---
SHA3_BACKEND=""
if command -v openssl >/dev/null 2>&1 && echo | openssl dgst -sha3-384 >/dev/null 2>&1; then SHA3_BACKEND="openssl"
elif command -v python3 >/dev/null 2>&1 && python3 -c "import hashlib;hashlib.sha3_384" >/dev/null 2>&1; then SHA3_BACKEND="python"
elif command -v rhash >/dev/null 2>&1; then SHA3_BACKEND="rhash"; fi
sha3_384_hex() {
  case "$SHA3_BACKEND" in
    openssl) openssl dgst -sha3-384 "$1" | sed -E 's/^.*= *//' ;;
    python)  python3 - "$1" <<'PY'
import hashlib,sys
print(hashlib.sha3_384(open(sys.argv[1],'rb').read()).hexdigest())
PY
      ;;
    rhash)   rhash --sha3-384 --simple "$1" | cut -d' ' -f1 ;;
    *)       return 1 ;;
  esac
}

cd "$OUT"
rm -f SHA384SUMS SHA3-384SUMS
for a in "${ARTIFACTS[@]}"; do
  printf "%s  %s\n" "$(sha384_hex "$a")" "$a" >> SHA384SUMS
  [[ -n "$SHA3_BACKEND" ]] && printf "%s  %s\n" "$(sha3_384_hex "$a")" "$a" >> SHA3-384SUMS
done
cp "$ROOT/scripts/verify.sh" "$ROOT/scripts/verify.ps1" . 2>/dev/null || true

{
  echo "talkrypt $VERSION  ($GITREV)  hashed $STAMP"
  echo "host: $(rustc -vV 2>/dev/null | sed -n 's/^host: //p')"
  echo "hashes: SHA-384 (SHA384SUMS) + SHA3-384 (SHA3-384SUMS); verify with verify.sh / verify.ps1"
  echo
  echo "ARTIFACTS:"
  for a in "${ARTIFACTS[@]}"; do
    sz=$(du -h "$a" | cut -f1)
    printf "  %s  (%s)\n" "$a" "$sz"
    printf "      sha-384:   %s\n" "$(sha384_hex "$a")"
    [[ -n "$SHA3_BACKEND" ]] && printf "      sha3-384:  %s\n" "$(sha3_384_hex "$a")"
  done
  if [[ -s SKIPPED.txt ]]; then
    echo
    echo "SKIPPED (not silently — install the toolchain to include these):"
    sed 's/^/  - /' SKIPPED.txt
  fi
  [[ -z "$SHA3_BACKEND" ]] && { echo; echo "WARNING: no SHA3 backend (install openssl 3.x / python3 / rhash) — SHA3-384SUMS not written."; }
  echo
  echo "Packaging endorsement is gated by docs/packaging-policy.md (the political"
  echo "filter). The software itself is Apache-2.0 and buildable everywhere."
  echo "NOT FIPS-validated · NOT CSfC-accredited · NOT NSA-approved · NOT audited."
} > MANIFEST.txt

# --- PQ release co-signatures (SECURITY-AUDIT F-8) -----------------------------
# Sign SHA384SUMS with each scheme whose signing SECRET is provided in the env — a
# SELECTABLE co-signature set; the verifier requires every signature PRESENT to
# verify. The git repo holds NO keys: each pubkey is DERIVED from its secret here
# and PUBLISHED into dist/ (and injected into binaries at build time), so the
# posted build carries the pubkey while the source tree stores nothing.
#   ML-DSA-87 (general)              : TALKRYPT_RELEASE_SK      -> SHA384SUMS.sig,     RELEASE_PUBKEY.hex
#   SLH-DSA   (FIPS 205, stateless)  : TALKRYPT_RELEASE_SK_SLH  -> SHA384SUMS.slh.sig, RELEASE_PUBKEY_SLH.hex
# LMS (SP 800-208 — the CNSA-designated STATEFUL signer) is an OFFLINE-only
# follow-up: a stateful one-time-key MUST NOT run in CI (index reuse is
# catastrophic). See docs/plans/0003-release-cosigning.md.
RELSIGN="$ROOT/target/release/talkrypt-relsign"
[[ -x "$RELSIGN" ]] || RELSIGN="$ROOT/target/debug/talkrypt-relsign"
if [[ ! -x "$RELSIGN" ]]; then
  ( cd "$ROOT" && cargo build -q -p talkrypt-relsign ) && RELSIGN="$ROOT/target/debug/talkrypt-relsign"
fi

# sign_one <algo-flag> <secret> <expected-sig-file> <pubkey-file> <label>
sign_one() {
  local algo="$1" sk="$2" sig="$3" pub="$4" label="$5"
  [[ -z "$sk" ]] && return 0
  if [[ ! -x "$RELSIGN" ]]; then
    echo "WARNING: $label secret set but talkrypt-relsign unavailable — $sig NOT written."
    return 0
  fi
  "$RELSIGN" --algo "$algo" sign SHA384SUMS "$sk" >/dev/null   # writes $sig
  {
    echo "# talkrypt release public key ($label) — PUBLISHED WITH THIS RELEASE."
    echo "# Pin the copy you obtained OUT OF BAND; a mirror could swap both file + key."
    "$RELSIGN" --algo "$algo" pubkey "$sk"
  } > "$pub"
  echo "==> signed SHA384SUMS -> $sig ($label); published $pub"
}

if [[ -n "${TALKRYPT_RELEASE_SK:-}${TALKRYPT_RELEASE_SK_SLH:-}" ]]; then
  sign_one ml-dsa  "${TALKRYPT_RELEASE_SK:-}"     SHA384SUMS.sig     RELEASE_PUBKEY.hex     "ML-DSA-87"
  sign_one slh-dsa "${TALKRYPT_RELEASE_SK_SLH:-}" SHA384SUMS.slh.sig RELEASE_PUBKEY_SLH.hex "SLH-DSA-SHA2-256s"
else
  echo "note: no TALKRYPT_RELEASE_SK* set — release is checksum-only (unsigned). See docs/PACKAGING.md."
fi

echo "==> hashed ${#ARTIFACTS[@]} artifact(s) in $OUT/ (SHA-384 + SHA3-384); wrote SHA384SUMS, SHA3-384SUMS, MANIFEST.txt"
