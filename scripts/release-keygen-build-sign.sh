#!/usr/bin/env bash
# GENERATE the canonical release signing keys, then build (or skip) + co-sign +
# verify. Use this ONCE to mint a release identity; thereafter use
# scripts/release-build-sign.sh (same flags) which reuses these keys.
#
#   bash scripts/release-keygen-build-sign.sh                # keygen, build all, sign, verify
#   bash scripts/release-keygen-build-sign.sh --skip-build   # keygen + sign the existing dist/
#   bash scripts/release-keygen-build-sign.sh --force        # OVERWRITE existing keys (danger)
#   (all other flags — --mobile, --attest — pass through to release-build-sign.sh)
#
# Keys are written to $TALKRYPT_KEYS_DIR (default <repo>/.release-keys), which is
# gitignored and created chmod 700; each seed file is chmod 600. The repo tracks
# NOTHING here — only the PUBLIC keys get published (into dist/ by hash-dist.sh).
#
# >>> BACK UP THE TWO SEED FILES OFFLINE. <<< They ARE the release identity: lose
# them and you can never sign an update under the same key; leak them and anyone
# can forge a "signed" release. Treat them like an offline root key.
#
# NOT FIPS-validated · NOT CSfC-accredited · NOT NSA-approved · NOT audited.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

FORCE=0; PASS=()
for a in "$@"; do
  case "$a" in
    --force) FORCE=1 ;;
    -h|--help) sed -n '2,19p' "$0"; exit 0 ;;
    *) PASS+=("$a") ;;    # forward --skip-build / --mobile / --attest
  esac
done

KEYS_DIR="${TALKRYPT_KEYS_DIR:-$ROOT/.release-keys}"
ML_ENC="$KEYS_DIR/ml-dsa.seed.enc"
SLH_ENC="$KEYS_DIR/slh-dsa.seed.enc"

mkdir -p "$KEYS_DIR"; chmod 700 "$KEYS_DIR"

if [[ ( -f "$ML_ENC" || -f "$SLH_ENC" ) && "$FORCE" -ne 1 ]]; then
  echo "release-keygen: keys already exist in $KEYS_DIR" >&2
  echo "  refusing to overwrite a release identity. To sign with them:" >&2
  echo "      bash scripts/release-build-sign.sh ${PASS[*]:-}" >&2
  echo "  to DELIBERATELY mint a new identity (old signatures stop verifying):" >&2
  echo "      bash scripts/release-keygen-build-sign.sh --force ${PASS[*]:-}" >&2
  exit 1
fi
# `--force`: drop the old sealed keys so the vault (which refuses to clobber --out) can mint anew.
[[ "$FORCE" -eq 1 ]] && rm -f "$ML_ENC" "$SLH_ENC"

# Build the vault if needed (rustup toolchain so it builds anywhere).
[[ -x "$HOME/.cargo/bin/cargo" ]] && export PATH="$HOME/.cargo/bin:$PATH"
VAULT="$ROOT/target/release/talkrypt-keyvault"
[[ -x "$VAULT" ]] || { cargo build -q --release -p talkrypt-keyvault; VAULT="$ROOT/target/release/talkrypt-keyvault"; }

# The keyvault mints each key IN-PROCESS: it reads a NEW passphrase from YOUR terminal
# (/dev/tty, not this script's stdin), seals the seed with Argon2id + AES-256-GCM to the
# .seed.enc, prints the public address + pubkey, and shows the 24-word QRL mnemonic ON
# SCREEN for your offline backup. The plaintext seed never leaves the vault, never
# touches this script, and never hits the environment.
echo "### minting SEALED release keys in $KEYS_DIR (choose a passphrase when prompted) ###"
"$VAULT" --algo ml-dsa  keygen --out "$ML_ENC"  || { echo "ml-dsa keygen failed" >&2; exit 1; }
"$VAULT" --algo slh-dsa keygen --out "$SLH_ENC" || { echo "slh-dsa keygen failed" >&2; exit 1; }
echo
echo ">>> BACK UP the 24-word mnemonics shown above (on screen only) AND remember the"
echo "    passphrase. The sealed $KEYS_DIR/*.seed.enc + passphrase sign releases; the"
echo "    mnemonic is your offline recovery if the sealed file is lost. <<<"
echo

# Hand off to build+sign. Pass PASS ONLY if non-empty: `"${PASS[@]:-}"` on an empty
# array expands to a single empty-string arg, which the child's strict arg loop
# rejected as `unknown arg:`. Guarding on length avoids that AND the set -u unbound
# error on old bash.
if [[ ${#PASS[@]} -gt 0 ]]; then
  exec bash "$ROOT/scripts/release-build-sign.sh" "${PASS[@]}"
else
  exec bash "$ROOT/scripts/release-build-sign.sh"
fi
