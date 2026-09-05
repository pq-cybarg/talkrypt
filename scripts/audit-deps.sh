#!/usr/bin/env bash
# Dependency-advisory + supply-chain scan (SECURITY-AUDIT R-1 / F-2).
#
# Runs cargo-audit (RustSec vulnerability DB) and cargo-deny (advisories +
# licenses + banned crates + source policy from deny.toml). Exits non-zero on a
# vulnerability, a disallowed license, or an unexpected dependency source — so it
# gates CI and should be run before every release. Run it anywhere with network
# access to the advisory DB.
#
#   bash scripts/audit-deps.sh
#
# Install the tools once: cargo install cargo-audit cargo-deny
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

rc=0
have() { command -v "$1" >/dev/null 2>&1; }

echo "== cargo audit (RustSec advisory DB) =="
if have cargo-audit; then
  # Fail on vulnerabilities (default). Unmaintained-crate notices print as
  # warnings but do NOT fail the gate (they are not vulnerabilities). The ignore
  # list below MUST mirror deny.toml [advisories].ignore (cargo-audit reads CLI
  # flags, cargo-deny reads deny.toml) — each entry is justified there:
  #   RUSTSEC-2023-0071  rsa (Marvin) — vendored + blinded; tor-only; absent by default.
  #   RUSTSEC-2026-01xx / -2025-0141  Nym-feature-only advisories in the nym-sdk
  #     transitive tree (libcrux-*, quick-xml, rustls-webpki via nym's rustls 0.21,
  #     bincode). Absent from default AND tor builds; do NOT touch talkrypt's
  #     content crypto (RustCrypto ML-KEM/ML-DSA). quinn-proto's advisory was
  #     FIXED by upgrade (0.11.15), not ignored. See deny.toml for full rationale.
  AUDIT_IGNORES=(
    RUSTSEC-2023-0071
    RUSTSEC-2026-0124 RUSTSEC-2026-0125 RUSTSEC-2026-0126
    RUSTSEC-2026-0207 RUSTSEC-2026-0208            # libcrux-sha3 (nym; fix blocked by nym's pin)
    RUSTSEC-2026-0209 RUSTSEC-2026-0211            # libcrux-aesgcm (nym's AEAD, not ours; no upstream fix)
    RUSTSEC-2026-0212                              # libcrux-secrets (nym; fix blocked by nym's pin)
    RUSTSEC-2026-0194 RUSTSEC-2026-0195
    RUSTSEC-2026-0098 RUSTSEC-2026-0099 RUSTSEC-2026-0104
    RUSTSEC-2025-0141
    RUSTSEC-2026-0258                              # h2 0.3.27 (nym-only; tendermint-rpc→reqwest 0.11); 0.4 path FIXED by upgrade to 0.4.19
  )
  # NB RUSTSEC-2026-0204 (crossbeam-epoch) is FIXED by upgrade to 0.9.20, not ignored.
  # NB RUSTSEC-2026-0257 (webbrowser BROWSER arg-injection) was FIXED by upgrade to 1.2.4, not ignored.
  # NB RUSTSEC-2026-0258 (h2) 0.4 path was FIXED by upgrade to 0.4.19; only the nym-only 0.3.27 path is ignored above.
  IGNORE_FLAGS=()
  for id in "${AUDIT_IGNORES[@]}"; do IGNORE_FLAGS+=(--ignore "$id"); done
  cargo audit "${IGNORE_FLAGS[@]}" || rc=1
else
  echo "  cargo-audit not installed — 'cargo install cargo-audit'"; rc=2
fi

echo
echo "== cargo deny (advisories + licenses + bans + sources) =="
if have cargo-deny; then
  cargo deny check || rc=1
else
  echo "  cargo-deny not installed — 'cargo install cargo-deny'"; rc=2
fi

echo
case "$rc" in
  0) echo "RESULT: dependency audit clean." ;;
  2) echo "RESULT: tools missing — install cargo-audit + cargo-deny, then re-run." >&2 ;;
  *) echo "RESULT: dependency audit FOUND ISSUES — see output above." >&2 ;;
esac
exit "$rc"
