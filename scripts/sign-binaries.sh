#!/usr/bin/env bash
# Sign shipped executables for talkrypt's LAUNCH-TIME self-attestation
# (permissive-security hardening). For each binary, writes a detached
# `<binary>.sig` sidecar (ML-DSA-87, hex) that `talkrypt_crypto::harden` reads at
# startup and verifies against the embedded release public key
# (docs/RELEASE_PUBKEY.hex) when `TALKRYPT_HARDEN` is set. See
# docs/custody-options.md and docs/hardware-backed-sealing.md.
#
# This is SEPARATE from the release-manifest signature (hash-dist.sh signs
# SHA256SUMS). This one lets a running binary attest its OWN integrity in-process,
# post-quantum, independent of the OS code-signature stack.
#
#   TALKRYPT_RELEASE_SK=<seed-hex-or-file> bash scripts/sign-binaries.sh <path>...
#
# Each <path> may be an executable file or a directory (every regular, executable
# file in it is signed, skipping existing *.sig). No-ops with a clear notice if
# TALKRYPT_RELEASE_SK is unset — packaging stays reproducible and unsigned rather
# than failing.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"

if [[ $# -lt 1 ]]; then
  echo "usage: TALKRYPT_RELEASE_SK=<seed> bash scripts/sign-binaries.sh <file|dir>..." >&2
  exit 2
fi

if [[ -z "${TALKRYPT_RELEASE_SK:-}" ]]; then
  echo "note: TALKRYPT_RELEASE_SK unset — launch-attestation sidecars NOT written" \
       "(binaries ship unsigned; hardening self-attestation stays env-only). See docs/PACKAGING.md."
  exit 0
fi

RELSIGN="$ROOT/target/release/talkrypt-relsign"
[[ -x "$RELSIGN" ]] || RELSIGN="$ROOT/target/debug/talkrypt-relsign"
if [[ ! -x "$RELSIGN" ]]; then
  ( cd "$ROOT" && cargo build -q -p talkrypt-relsign )
  RELSIGN="$ROOT/target/debug/talkrypt-relsign"
fi

sign_one() {
  local f="$1"
  # relsign writes <f>.sig next to the file.
  "$RELSIGN" sign "$f" "$TALKRYPT_RELEASE_SK" >/dev/null
  echo "  signed $(basename "$f") -> $(basename "$f").sig"
}

count=0
for path in "$@"; do
  if [[ -f "$path" ]]; then
    sign_one "$path"; count=$((count + 1))
  elif [[ -d "$path" ]]; then
    while IFS= read -r -d '' f; do
      case "$f" in *.sig) continue;; esac
      sign_one "$f"; count=$((count + 1))
    done < <(find "$path" -type f -perm -u+x -print0)
  else
    echo "  skip (not found): $path" >&2
  fi
done
echo "==> wrote $count launch-attestation sidecar signature(s) (ML-DSA-87)"
