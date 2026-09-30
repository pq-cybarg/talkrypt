#!/usr/bin/env bash
# Verify talkrypt release artifacts against BOTH SHA256SUMS and SHA3-256SUMS.
#
# Two independent hash families (SHA-256 = FIPS 180-4 / Merkle–Damgård, and
# SHA3-256 = FIPS 202 / Keccak sponge) must BOTH match for every file: a flaw
# or backdoor in one construction cannot mask a tampered artifact, because it
# would also have to forge a second, structurally unrelated digest.
#
#   bash verify.sh            # verify files in the current directory
#   bash verify.sh /path/dir  # verify files in another directory
#
# Exit status: 0 if every listed file is present and both digests match;
# non-zero otherwise. Needs a SHA-256 tool (sha256sum or shasum) and a SHA3-256
# tool (openssl 3.x, python3, or rhash) — it auto-detects and reports if none.
set -uo pipefail

DIR="${1:-.}"
cd "$DIR" || { echo "verify: cannot enter '$DIR'" >&2; exit 2; }

red()   { printf '\033[31m%s\033[0m' "$1"; }
green() { printf '\033[32m%s\033[0m' "$1"; }
yellow(){ printf '\033[33m%s\033[0m' "$1"; }

# --- pick a SHA-256 backend ---
sha256_of() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | cut -d' ' -f1
  elif command -v shasum >/dev/null 2>&1; then shasum -a 256 "$1" | cut -d' ' -f1
  else return 1; fi
}
command -v sha256sum >/dev/null 2>&1 || command -v shasum >/dev/null 2>&1 || {
  echo "verify: no SHA-256 tool (install coreutils 'sha256sum' or perl 'shasum')" >&2; exit 2; }

# --- pick a SHA3-256 backend ---
SHA3=""
if command -v openssl >/dev/null 2>&1 && echo | openssl dgst -sha3-256 >/dev/null 2>&1; then
  SHA3="openssl"
elif command -v python3 >/dev/null 2>&1 && python3 -c "import hashlib;hashlib.sha3_256" >/dev/null 2>&1; then
  SHA3="python"
elif command -v rhash >/dev/null 2>&1; then
  SHA3="rhash"
fi
sha3_256_of() {
  case "$SHA3" in
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
echo "  sha-256 backend: $( command -v sha256sum >/dev/null 2>&1 && echo sha256sum || echo shasum )"
echo "  sha3-256 backend: ${SHA3:-<none found>}"
echo

PASS=0; FAIL=0; MISS=0
echo "SHA-256:"
verify_file_list "SHA256SUMS" "sha256" sha256_of
echo
echo "SHA3-256:"
if [[ -n "$SHA3" ]]; then
  verify_file_list "SHA3-256SUMS" "sha3-256" sha3_256_of
else
  echo "  (no SHA3-256 backend — install openssl 3.x, python3, or rhash to check the second digest)"
fi

# --- optional PQ signature check (SECURITY-AUDIT F-8) ---
# The checksum files above bind artifacts to hashes; the signature binds the hash
# manifest to a SIGNER's ML-DSA-87 key. The signer may be the project (its release
# key) OR any user who signed their own copy — the mechanism is identical; you just
# verify against whichever public key you trust for the source you got this from.
# Checking needs the `talkrypt-relsign` tool (a pure-shell ML-DSA verifier isn't
# possible) plus that signer's public key: provide it via $TALKRYPT_RELEASE_PUBKEY
# or a RELEASE_PUBKEY.hex file (which may carry `#` comment lines — only the hex is
# used). Trust anchor: a copy you obtained out of band, NOT one bundled by an
# untrusted mirror. If the tool or a real key is absent, this step is advisory.
SIG_FAIL=0
if [[ -f "SHA256SUMS.sig" ]]; then
  RELSIGN_BIN="$(command -v talkrypt-relsign || true)"
  [[ -z "$RELSIGN_BIN" && -x "./talkrypt-relsign" ]] && RELSIGN_BIN="./talkrypt-relsign"
  PUBKEY="${TALKRYPT_RELEASE_PUBKEY:-}"
  # Comment-aware: strip `#` lines + whitespace so a placeholder/annotated key file
  # yields an empty (→ advisory) rather than a garbage pubkey.
  [[ -z "$PUBKEY" && -f "RELEASE_PUBKEY.hex" ]] && PUBKEY="$(grep -vE '^[[:space:]]*#' RELEASE_PUBKEY.hex | tr -d '[:space:]')"
  echo
  echo "PQ signature (ML-DSA-87):"
  if [[ -n "$RELSIGN_BIN" && -n "$PUBKEY" ]]; then
    if "$RELSIGN_BIN" verify SHA256SUMS SHA256SUMS.sig "$PUBKEY" >/dev/null 2>&1; then
      echo "  $(green OK)    SHA256SUMS is signed by the trusted key"
    else
      echo "  $(red FAIL)  SHA256SUMS signature did NOT verify under that key"
      SIG_FAIL=1
    fi
  elif [[ -z "$RELSIGN_BIN" ]]; then
    echo "  ($(yellow advisory): SHA256SUMS.sig present but talkrypt-relsign not on PATH — signature NOT checked)"
  else
    echo "  ($(yellow advisory): SHA256SUMS.sig present but no signer pubkey — set TALKRYPT_RELEASE_PUBKEY — signature NOT checked)"
  fi
fi

echo
echo "----"
printf "OK: %d   FAIL: %d   MISSING: %d\n" "$PASS" "$FAIL" "$MISS"
if [[ "$FAIL" -gt 0 || "$MISS" -gt 0 || "$SIG_FAIL" -gt 0 ]]; then
  echo "$(red "VERIFICATION FAILED") — do NOT trust these artifacts."
  exit 1
fi
if [[ "$PASS" -eq 0 ]]; then
  echo "$(yellow "nothing verified") — no SHA256SUMS/SHA3-256SUMS found here."
  exit 2
fi
echo "$(green "All artifacts verified") against both SHA-256 and SHA3-256."
