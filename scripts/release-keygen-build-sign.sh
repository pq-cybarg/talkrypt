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
ML_SEED="$KEYS_DIR/ml-dsa.seed"
SLH_SEED="$KEYS_DIR/slh-dsa.seed"

mkdir -p "$KEYS_DIR"; chmod 700 "$KEYS_DIR"

if [[ ( -f "$ML_SEED" || -f "$SLH_SEED" ) && "$FORCE" -ne 1 ]]; then
  echo "release-keygen: keys already exist in $KEYS_DIR" >&2
  echo "  refusing to overwrite a release identity. To sign with them:" >&2
  echo "      bash scripts/release-build-sign.sh ${PASS[*]:-}" >&2
  echo "  to DELIBERATELY mint a new identity (old signatures stop verifying):" >&2
  echo "      bash scripts/release-keygen-build-sign.sh --force ${PASS[*]:-}" >&2
  exit 1
fi

# Build the signer if needed (rustup toolchain so it builds anywhere).
[[ -x "$HOME/.cargo/bin/cargo" ]] && export PATH="$HOME/.cargo/bin:$PATH"
RELSIGN="$ROOT/target/release/talkrypt-relsign"
[[ -x "$RELSIGN" ]] || { cargo build -q --release -p talkrypt-relsign; RELSIGN="$ROOT/target/release/talkrypt-relsign"; }

# keygen prints "SEED <hex>" / "PUBKEY <hex>" on stdout. Capture the SEED into a
# 0600 file; show only the PUBKEY (public) to the operator.
mint() {  # <algo> <seed-file> <label>
  local algo="$1" out="$2" label="$3" line seed pub
  line="$("$RELSIGN" --algo "$algo" keygen 2>/dev/null)"
  seed="$(printf '%s\n' "$line" | awk '/^SEED/   {print $2}')"
  pub="$( printf '%s\n' "$line" | awk '/^PUBKEY/ {print $2}')"
  [[ -n "$seed" && -n "$pub" ]] || { echo "keygen ($label) produced no key" >&2; exit 1; }
  ( umask 077; printf '# %s release signing SEED (SECRET — back up OFFLINE, never commit)\n%s\n' "$label" "$seed" > "$out" )
  chmod 600 "$out"
  echo "  $label  pubkey: $pub"
  echo "           seed  : $out  (chmod 600, gitignored)"
}

echo "### minting release keys in $KEYS_DIR ###"
mint ml-dsa  "$ML_SEED"  "ML-DSA-87"
mint slh-dsa "$SLH_SEED" "SLH-DSA-SHA2-256s"
echo
echo ">>> BACK UP $KEYS_DIR OFFLINE NOW. These seeds are the release identity. <<<"
echo

exec bash "$ROOT/scripts/release-build-sign.sh" "${PASS[@]:-}"
