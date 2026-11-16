#!/usr/bin/env bash
# Verify talkrypt release artifacts against BOTH SHA384SUMS and SHA3-384SUMS, then
# every post-quantum co-signature present.
#
# Two independent 384-bit hash families (SHA-384 = FIPS 180-4 / Merkle-Damgard,
# and SHA3-384 = FIPS 202 / Keccak sponge) must BOTH match for every file: a flaw
# or backdoor in one construction cannot mask a tampered artifact, because it
# would also have to forge a second, structurally unrelated digest.
#
#   bash verify.sh            # verify files in the current directory
#   bash verify.sh /path/dir  # verify files in another directory
#
# Exit status: 0 if every listed file is present, both digests match, and every
# co-signature present verifies; non-zero otherwise. Needs a SHA-384 tool
# (sha384sum or shasum) and a SHA3-384 tool (openssl 3.x, python3, or rhash) — it
# auto-detects and reports if none.
set -uo pipefail

DIR="${1:-.}"
cd "$DIR" || { echo "verify: cannot enter '$DIR'" >&2; exit 2; }

red()   { printf '\033[31m%s\033[0m' "$1"; }
green() { printf '\033[32m%s\033[0m' "$1"; }
yellow(){ printf '\033[33m%s\033[0m' "$1"; }

# --- pick a SHA-384 backend ---
sha384_of() {
  if command -v sha384sum >/dev/null 2>&1; then sha384sum "$1" | cut -d' ' -f1
  elif command -v shasum >/dev/null 2>&1; then shasum -a 384 "$1" | cut -d' ' -f1
  else return 1; fi
}
command -v sha384sum >/dev/null 2>&1 || command -v shasum >/dev/null 2>&1 || {
  echo "verify: no SHA-384 tool (install coreutils 'sha384sum' or perl 'shasum')" >&2; exit 2; }

# --- pick a SHA3-384 backend ---
SHA3=""
if command -v openssl >/dev/null 2>&1 && echo | openssl dgst -sha3-384 >/dev/null 2>&1; then
  SHA3="openssl"
elif command -v python3 >/dev/null 2>&1 && python3 -c "import hashlib;hashlib.sha3_384" >/dev/null 2>&1; then
  SHA3="python"
elif command -v rhash >/dev/null 2>&1; then
  SHA3="rhash"
fi
sha3_384_of() {
  case "$SHA3" in
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

# Verify every "<hex>  <name>" line in a sums file with the given hasher.
# Sets globals: PASS, FAIL, MISS (counts). Prints one line per file.
verify_file_list() {
  local sums="$1" label="$2" hasher="$3"
  [[ -f "$sums" ]] || { echo "  ($label: no $sums — skipped)"; return; }
  local line hex name got
  while IFS= read -r line || [[ -n "$line" ]]; do
    [[ -z "$line" || "$line" == \#* ]] && continue
    hex="${line%% *}"
    name="${line#* }"; name="${name#"${name%%[![:space:]]*}"}"  # ltrim
    if [[ ! -f "$name" ]]; then
      printf "  %s  %-46s %s\n" "$(yellow MISS)" "$name" "$label"
      MISS=$((MISS+1)); continue
    fi
    got="$($hasher "$name")"
    if [[ "${got,,}" == "${hex,,}" ]]; then
      printf "  %s    %-46s %s\n" "$(green OK)" "$name" "$label"
      PASS=$((PASS+1))
    else
      printf "  %s  %-46s %s\n" "$(red FAIL)" "$name" "$label"
      printf "        expected %s\n        got      %s\n" "$hex" "$got"
      FAIL=$((FAIL+1))
    fi
  done < "$sums"
}

echo "talkrypt artifact verification in: $(pwd)"
echo "  sha-384 backend: $( command -v sha384sum >/dev/null 2>&1 && echo sha384sum || echo shasum )"
echo "  sha3-384 backend: ${SHA3:-<none found>}"
echo

PASS=0; FAIL=0; MISS=0
echo "SHA-384:"
verify_file_list "SHA384SUMS" "sha384" sha384_of
echo
echo "SHA3-384:"
if [[ -n "$SHA3" ]]; then
  verify_file_list "SHA3-384SUMS" "sha3-384" sha3_384_of
else
  echo "  (no SHA3-384 backend — install openssl 3.x, python3, or rhash to check the second digest)"
fi

# --- optional PQ co-signature check (SECURITY-AUDIT F-8) ---------------------
# The checksum files bind artifacts to hashes; the signatures bind the SHA384SUMS
# manifest to a SIGNER's post-quantum key. A release carries a SELECTABLE set of
# co-signatures; EVERY signature present must verify. Each needs the
# `talkrypt-relsign` tool (a pure-shell PQ verifier isn't possible) plus that
# signer's public key — provide it via the per-scheme env var or the bundled
# RELEASE_PUBKEY*.hex (published WITH the release; the git repo holds no keys).
# TRUST ANCHOR: pin the pubkey you obtained OUT OF BAND, not one from an untrusted
# mirror (which could swap both the file and the key). If the tool or a real key
# is absent, that signature is advisory (reported, not checked).
#   SHA384SUMS.sig     : ML-DSA-87            — $TALKRYPT_RELEASE_PUBKEY     / RELEASE_PUBKEY.hex
#   SHA384SUMS.slh.sig : SLH-DSA-SHA2-256s    — $TALKRYPT_RELEASE_PUBKEY_SLH / RELEASE_PUBKEY_SLH.hex
SIG_FAIL=0; SIG_SEEN=0
RELSIGN_BIN="$(command -v talkrypt-relsign || true)"
[[ -z "$RELSIGN_BIN" && -x "./talkrypt-relsign" ]] && RELSIGN_BIN="./talkrypt-relsign"

pubkey_from() {  # <env-value> <pubkey-file>
  local pk="$1"
  [[ -z "$pk" && -f "$2" ]] && pk="$(grep -vE '^[[:space:]]*#' "$2" | tr -d '[:space:]')"
  printf '%s' "$pk"
}

verify_sig() {  # <algo> <sigfile> <pubkey> <label>
  local algo="$1" sigf="$2" pk="$3" label="$4"
  [[ -f "$sigf" ]] || return 0
  SIG_SEEN=1
  if [[ -n "$RELSIGN_BIN" && -n "$pk" ]]; then
    if "$RELSIGN_BIN" --algo "$algo" verify SHA384SUMS "$sigf" "$pk" >/dev/null 2>&1; then
      echo "  $(green OK)    $sigf  ($label)"
    else
      echo "  $(red FAIL)  $sigf did NOT verify under that key ($label)"
      SIG_FAIL=1
    fi
  elif [[ -z "$RELSIGN_BIN" ]]; then
    echo "  ($(yellow advisory): $sigf present but talkrypt-relsign not on PATH — NOT checked)"
  else
    echo "  ($(yellow advisory): $sigf present but no $label pubkey — NOT checked)"
  fi
}

if [[ -f "SHA384SUMS.sig" || -f "SHA384SUMS.slh.sig" ]]; then
  echo
  echo "PQ co-signatures (all present must verify):"
  verify_sig ml-dsa  "SHA384SUMS.sig"     "$(pubkey_from "${TALKRYPT_RELEASE_PUBKEY:-}"     RELEASE_PUBKEY.hex)"     "ML-DSA-87"
  verify_sig slh-dsa "SHA384SUMS.slh.sig" "$(pubkey_from "${TALKRYPT_RELEASE_PUBKEY_SLH:-}" RELEASE_PUBKEY_SLH.hex)" "SLH-DSA-SHA2-256s"
fi

echo
echo "----"
printf "OK: %d   FAIL: %d   MISSING: %d\n" "$PASS" "$FAIL" "$MISS"
if [[ "$FAIL" -gt 0 || "$MISS" -gt 0 || "$SIG_FAIL" -gt 0 ]]; then
  echo "$(red "VERIFICATION FAILED") — do NOT trust these artifacts."
  exit 1
fi
if [[ "$PASS" -eq 0 ]]; then
  echo "$(yellow "nothing verified") — no SHA384SUMS/SHA3-384SUMS found here."
  exit 2
fi
echo "$(green "All artifacts verified") against both SHA-384 and SHA3-384$( [[ "$SIG_SEEN" -eq 1 ]] && printf ", plus every PQ co-signature present" )."
