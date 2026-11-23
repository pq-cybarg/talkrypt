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
# Prefer SEALED keys (.seed.enc) — co-signed via `talkrypt-keyvault`, whose passphrase
# is read from the operator's terminal (/dev/tty): the plaintext seed never leaves the
# vault and no secret is exported to the environment. Fall back to legacy plaintext
# seeds (.seed), co-signed by hash-dist.sh via env vars.
ML_ENC="$KEYS_DIR/ml-dsa.seed.enc"; SLH_ENC="$KEYS_DIR/slh-dsa.seed.enc"
ML_SEED="$KEYS_DIR/ml-dsa.seed";    SLH_SEED="$KEYS_DIR/slh-dsa.seed"
if [[ -f "$ML_ENC" || -f "$SLH_ENC" ]]; then
  SEALED=1
elif [[ -f "$ML_SEED" && -f "$SLH_SEED" ]]; then
  SEALED=0
else
  echo "release-build-sign: no release keys in $KEYS_DIR" >&2
  echo "  generate them first:  bash scripts/release-keygen-build-sign.sh" >&2
  echo "  (sealed *.seed.enc via talkrypt-keyvault, or legacy ml-dsa.seed + slh-dsa.seed)" >&2
  exit 1
fi

# Use the rustup toolchain if present: Homebrew's rustc only ships the host arch's
# std, so cross-target builds (x86_64-apple-darwin, the linux/windows targets) fail
# with "can't find crate for core" under it. rustup's toolchain carries every
# installed target's std; prepend its bin so `cargo`/`cross` resolve to it.
if [[ -x "$HOME/.cargo/bin/cargo" ]]; then
  export PATH="$HOME/.cargo/bin:$PATH"
fi

# LEGACY plaintext keys only: export the secrets to hash-dist.sh EXACTLY like a CI
# secret. SEALED keys export NOTHING — the keyvault holds the passphrase + seed
# in-process and signs below.
if [[ "$SEALED" -eq 0 ]]; then
  TALKRYPT_RELEASE_SK="$(grep -vE '^[[:space:]]*#' "$ML_SEED"  | tr -d '[:space:]')"
  TALKRYPT_RELEASE_SK_SLH="$(grep -vE '^[[:space:]]*#' "$SLH_SEED" | tr -d '[:space:]')"
  export TALKRYPT_RELEASE_SK TALKRYPT_RELEASE_SK_SLH
fi

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

# Re-hash the current dist/ (idempotent). With LEGACY plaintext keys, hash-dist.sh
# ALSO co-signs SHA384SUMS from the env secrets and publishes the pubkeys. With SEALED
# keys the env is empty, so hash-dist.sh only hashes and the keyvault co-signs next.
echo "### hash (SHA-384 + SHA3-384)${SEALED:+ }$([[ $SEALED -eq 0 ]] && echo '+ co-sign (legacy seeds)') ###"
bash "$ROOT/scripts/hash-dist.sh"

if [[ "$SEALED" -eq 1 ]]; then
  echo "### co-sign SHA384SUMS via talkrypt-keyvault (enter the key passphrase at the prompt) ###"
  VAULT="$ROOT/target/release/talkrypt-keyvault"
  [[ -x "$VAULT" ]] || VAULT="$ROOT/target/debug/talkrypt-keyvault"
  if [[ ! -x "$VAULT" ]]; then
    ( cd "$ROOT" && cargo build -q --release -p talkrypt-keyvault ) && VAULT="$ROOT/target/release/talkrypt-keyvault"
  fi
  RS="$ROOT/target/release/talkrypt-relsign"; [[ -x "$RS" ]] || RS="$ROOT/target/debug/talkrypt-relsign"
  [[ -x "$RS" ]] || { ( cd "$ROOT" && cargo build -q -p talkrypt-relsign ); RS="$ROOT/target/debug/talkrypt-relsign"; }

  # Co-sign SHA384SUMS with each sealed key present (the vault reads the passphrase from
  # your terminal), and PUBLISH the public key (derived from the sealed header — needs
  # NO passphrase). Writes dist/SHA384SUMS[.slh].sig + dist/RELEASE_PUBKEY*.hex.
  sign_sealed() {
    local algo="$1" enc="$2" pub="$3" label="$4"
    [[ -f "$enc" ]] || return 0
    "$VAULT" --algo "$algo" sign "$ROOT/dist/SHA384SUMS" "$enc"
    {
      echo "# talkrypt release public key ($label) — PUBLISHED WITH THIS RELEASE."
      echo "# Pin the copy you obtained OUT OF BAND; a mirror could swap both file + key."
      "$RS" --algo "$algo" pubkey "$enc"
    } > "$ROOT/dist/$pub"
    echo "==> keyvault-signed SHA384SUMS ($label); published dist/$pub"
  }
  sign_sealed ml-dsa  "$ML_ENC"  RELEASE_PUBKEY.hex     "ML-DSA-87"
  sign_sealed slh-dsa "$SLH_ENC" RELEASE_PUBKEY_SLH.hex "SLH-DSA-SHA2-256s"
fi

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
