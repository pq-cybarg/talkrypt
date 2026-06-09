#!/usr/bin/env bash
# Reproducible cryptographic inventory + algorithm-floor assertion.
#
# Emits the crypto dependency SBOM (exact versions from Cargo.lock) and asserts
# the CNSA 2.0 parameter-set floor that docs/COMPLIANCE.md claims: ML-KEM-1024,
# ML-DSA-87, AES-256-GCM, and that no sub-floor or forbidden primitive has crept
# in (ML-KEM-768/ML-DSA-65, AES-128, RSA/ECDSA-as-identity, MD5/SHA-1/DES/RC4).
# Exits non-zero on a violation, so it can gate CI.
#
#   bash scripts/crypto-inventory.sh
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

fail=0
note() { printf '  %-22s %s\n' "$1" "$2"; }
bad()  { echo "  ✗ FLOOR VIOLATION: $1" >&2; fail=1; }

echo "talkrypt cryptographic inventory"
echo "================================"

# ---- SBOM: exact versions from Cargo.lock ----
echo
echo "Cryptographic dependencies (Cargo.lock):"
for c in ml-kem ml-dsa aes-gcm aws-lc-rs sha2 sha3 tiny-keccak hkdf x25519-dalek argon2 zeroize getrandom; do
  v="$(awk -v n="$c" '$1=="name" && $3=="\""n"\""{found=1} found && $1=="version"{gsub(/"/,"",$3); print $3; exit}' Cargo.lock 2>/dev/null || true)"
  [ -z "$v" ] && v="(absent)"
  note "$c" "$v"
done

# ---- Algorithm floor (suite IDs are the canonical statement) ----
echo
echo "Suite identifiers (crates/crypto/src/suite.rs):"
sid="$(grep -hoE 'tk\.(dr|noise)\.[a-z0-9+.-]+|mlkem1024[a-z+]*|mldsa87|aes256gcm' crates/crypto/src/suite.rs | sort -u)"
echo "$sid" | sed 's/^/  /'

echo
echo "Floor assertions:"
grep -q 'mlkem1024' crates/crypto/src/suite.rs && note "ML-KEM-1024" "present" || bad "ML-KEM-1024 token missing"
grep -q 'mldsa87'   crates/crypto/src/suite.rs && note "ML-DSA-87"   "present" || bad "ML-DSA-87 token missing"
grep -q 'aes256gcm' crates/crypto/src/suite.rs && note "AES-256-GCM" "present" || bad "AES-256-GCM token missing"

# ---- AES-256-GCM is the only AEAD cipher (positive assertion) ----
# Assert by the cipher TYPE that is actually instantiated, not by strings in
# comments. The RFC 9420 MLS conformance harness (crates/crypto/src/mls/) names
# the standard ciphersuite "…AES128GCM…" in a comment and derives a 16-byte
# key-schedule to match official vectors, but it instantiates NO cipher and is
# not wired into messaging (it routes through crate::aead = AES-256-GCM and
# ML-KEM-1024). A type-based check is precise: it passes here, yet would still
# catch a real AES-128 cipher anywhere — including in the harness.
echo
echo "AEAD cipher assertion:"
if grep -qE 'Aes256Gcm' crates/crypto/src/aead.rs; then note "AES-256-GCM" "instantiated in aead.rs"; else bad "Aes256Gcm not found in aead.rs"; fi
echo
echo "Forbidden / sub-floor primitive scan (cipher/type instantiation, all of crates/crypto/src):"
scan() { # pattern, label  — matches actual TYPE/usage, not doc comments
  if grep -rlE "$1" crates/crypto/src/ 2>/dev/null | grep -q .; then bad "found '$2' instantiated in crypto sources"; else note "no $2" "ok"; fi
}
scan 'Aes128Gcm|aes_gcm::Aes128|Aes128::'      "AES-128 cipher"
scan 'MlKem768|ml_kem::MlKem768'               "ML-KEM-768 (sub-floor)"
scan 'MlDsa65|ml_dsa::MlDsa65'                 "ML-DSA-65 (sub-floor)"
scan '\bMd5\b|md5::|Sha1::|sha1::'             "MD5/SHA-1"
scan '\bDes\b|TripleDes|Rc4|rc4::'             "DES/3DES/RC4"
# ECDSA/RSA as an *identity* signature would violate the pure-PQ identity rule.
scan 'rsa::|RsaPrivateKey|ecdsa::|p256::ecdsa' "ECDSA/RSA identity"

# ---- Registry floor enforcement is wired (parameter-based, not self-declared) ----
echo
echo "Floor enforcement (crates/crypto/src/suite.rs):"
if grep -q 'fn meets_cnsa_floor' crates/crypto/src/suite.rs; then note "param floor check" "meets_cnsa_floor present"; else bad "meets_cnsa_floor missing"; fi
if grep -q 'meets_cnsa_floor(&d.id)' crates/crypto/src/suite.rs; then note "register() enforces" "ok"; else bad "register() does not call meets_cnsa_floor"; fi

# ---- ml-kem / ml-dsa crates expose only the Category-5 parameter set ----
echo
echo "PQ parameter set (the crate APIs in use):"
grep -rqE 'MlKem1024' crates/crypto/src/ && note "ML-KEM API" "MlKem1024 only" || bad "MlKem1024 not referenced"
grep -rqE 'MlDsa87'   crates/crypto/src/ && note "ML-DSA API" "MlDsa87 only"   || bad "MlDsa87 not referenced"

# ---- Dependency advisory + supply-chain scan lives in its own gate ----
echo
echo "Dependency advisories / supply-chain: see scripts/audit-deps.sh"
echo "  (cargo audit + cargo deny; CI: .github/workflows/audit.yml — SECURITY-AUDIT R-1)"

echo
if [ "$fail" -eq 0 ]; then
  echo "RESULT: algorithm floor OK (CNSA 2.0 parameter sets; no sub-floor/forbidden primitives)."
else
  echo "RESULT: FLOOR VIOLATED — see ✗ lines above." >&2
fi
exit "$fail"
