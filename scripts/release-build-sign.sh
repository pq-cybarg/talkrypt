#!/usr/bin/env bash
# Build (or skip) + co-sign + verify a talkrypt release, using EXISTING release
# keys. The repo holds NO keys: the signing seeds live OUTSIDE the tree in a
# gitignored keys dir, and only their PUBLIC halves are published into dist/.
#
#   bash scripts/release-build-sign.sh                 # build everything, then sign + verify
#   bash scripts/release-build-sign.sh --skip-build    # sign the EXISTING dist/ (no rebuild)
#   bash scripts/release-build-sign.sh --mobile        # also run the Android/iOS packager
#   bash scripts/release-build-sign.sh --attest        # also write per-binary launch-attestation sigs
#
# Keys (generate them first with scripts/release-keygen-build-sign.sh):
#   $TALKRYPT_KEYS_DIR/ml-dsa.seed   (ML-DSA-87   release secret, 64 hex)
#   $TALKRYPT_KEYS_DIR/slh-dsa.seed  (SLH-DSA-256s release secret, 64 hex)
#   TALKRYPT_KEYS_DIR defaults to <repo>/.release-keys (gitignored, chmod 700).
#
# This script NEVER prints the seeds and NEVER writes them into dist/. It exports
# them to the child hash-dist.sh only as env vars (TALKRYPT_RELEASE_SK*), exactly
# as a CI secret would. The output is a dist/ that `verify.sh` passes against BOTH
# SHA-384 and SHA3-384 and EVERY co-signature present (ML-DSA-87 + SLH-DSA).
#
# NOT FIPS-validated · NOT CSfC-accredited · NOT NSA-approved · NOT audited.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

SKIP_BUILD=0; DO_MOBILE=0; DO_ATTEST=0
for a in "$@"; do
  case "$a" in
    --skip-build) SKIP_BUILD=1 ;;
    --mobile)     DO_MOBILE=1 ;;
    --attest)     DO_ATTEST=1 ;;
    -h|--help)    sed -n '2,20p' "$0"; exit 0 ;;
    *) echo "unknown arg: $a" >&2; exit 2 ;;
  esac
done
# Allow the env to force a build-skip too (handy in CI re-sign jobs).
[[ "${TALKRYPT_SKIP_BUILD:-}" == "1" ]] && SKIP_BUILD=1

KEYS_DIR="${TALKRYPT_KEYS_DIR:-$ROOT/.release-keys}"
ML_SEED="$KEYS_DIR/ml-dsa.seed"
SLH_SEED="$KEYS_DIR/slh-dsa.seed"
if [[ ! -f "$ML_SEED" || ! -f "$SLH_SEED" ]]; then
  echo "release-build-sign: no release keys in $KEYS_DIR" >&2
  echo "  generate them first:  bash scripts/release-keygen-build-sign.sh" >&2
  echo "  (or point TALKRYPT_KEYS_DIR at a dir holding ml-dsa.seed + slh-dsa.seed)" >&2
  exit 1
fi

# Use the rustup toolchain if present: Homebrew's rustc only ships the host arch's
# std, so cross-target builds (x86_64-apple-darwin, the linux/windows targets) fail
# with "can't find crate for core" under it. rustup's toolchain carries every
# installed target's std; prepend its bin so `cargo`/`cross` resolve to it.
if [[ -x "$HOME/.cargo/bin/cargo" ]]; then
  export PATH="$HOME/.cargo/bin:$PATH"
fi

# Export the signing secrets to the child packagers EXACTLY like a CI secret would.
# They are read by hash-dist.sh / sign-binaries.sh and never touch disk here.
TALKRYPT_RELEASE_SK="$(grep -vE '^[[:space:]]*#' "$ML_SEED"  | tr -d '[:space:]')"
TALKRYPT_RELEASE_SK_SLH="$(grep -vE '^[[:space:]]*#' "$SLH_SEED" | tr -d '[:space:]')"
export TALKRYPT_RELEASE_SK TALKRYPT_RELEASE_SK_SLH

if [[ "$SKIP_BUILD" -eq 0 ]]; then
  echo "### build (desktop) ###"
  bash "$ROOT/scripts/package.sh"
  if [[ "$DO_MOBILE" -eq 1 ]]; then
    echo "### build (mobile) ###"
    bash "$ROOT/scripts/package-mobile.sh" || echo "  (mobile packager reported skips — see dist/SKIPPED.txt)"
  fi
else
  echo "### --skip-build: signing the existing dist/ ###"
  [[ -d "$ROOT/dist" ]] || { echo "no dist/ to sign — drop --skip-build to build first" >&2; exit 1; }
fi

# Re-hash + co-sign the current dist/ (idempotent). hash-dist.sh signs SHA384SUMS
# with each scheme whose secret is in the env and PUBLISHES the derived pubkeys.
echo "### hash + co-sign (ML-DSA-87 + SLH-DSA) + publish pubkeys ###"
bash "$ROOT/scripts/hash-dist.sh"

if [[ "$DO_ATTEST" -eq 1 ]]; then
  echo "### per-binary launch-attestation sidecars (ML-DSA-87) ###"
  # Sign the staged executables under dist/stage, if the packager kept them.
  if [[ -d "$ROOT/dist/stage" ]]; then
    bash "$ROOT/scripts/sign-binaries.sh" "$ROOT/dist/stage" || true
  fi
fi

# Self-contained verify: drop the relsign verifier next to the artifacts so
# verify.sh can check the PQ co-signatures, then run it.
RELSIGN="$ROOT/target/release/talkrypt-relsign"
[[ -x "$RELSIGN" ]] || RELSIGN="$ROOT/target/debug/talkrypt-relsign"
[[ -x "$RELSIGN" ]] && cp "$RELSIGN" "$ROOT/dist/talkrypt-relsign"

echo "### verify (both hashes + every co-signature) ###"
bash "$ROOT/dist/verify.sh" "$ROOT/dist"

echo
echo "release signed + verified in dist/  (version $(grep -m1 '^version' crates/cli/Cargo.toml | sed -E 's/.*"([^"]+)".*/\1/'))"
echo "deploy a DRAFT release with:  bash scripts/release-deploy.sh"
