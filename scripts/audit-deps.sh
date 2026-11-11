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
  # warnings but do NOT fail the gate (they are not vulnerabilities), so they are
  # NOT listed here — only in deny.toml (cargo-deny errors on them).
  #
  # >>> The ONLY vulnerability ignore is the Arti-pinned bundled-SQLite advisory. <<<
  # Every other RustSec vulnerability that once rode the nym/tor trees was FIXED,
  # not ignored — the whole nym cosmos/credential EC stack (crypto-bigint 0.5.5 /
  # RUSTSEC-2026-0387), the old nym reqwest-0.11 TLS cluster (rustls 0.21,
  # rustls-webpki 0.101, h2 0.3), and the libcrux PQ crates were all migrated to
  # modern released versions via the vendored patches in third-party/. See each
  # crate's TALKRYPT-PATCH.md and deny.toml for the full record.
  AUDIT_IGNORES=(
    RUSTSEC-2026-0459  # libsqlite3-sys 0.37.0 bundled SQLite < 3.54.0 — FIXED LOCALLY:
                       # third-party/libsqlite3-sys swaps the bundled amalgamation
                       # 3.51.3 -> PATCHED 3.54.1 (version stays 0.37.0 for the
                       # `links=sqlite3` single-copy shared by Arti + nym). Advisory
                       # matches by version only; this records the fix. tor/nym-only.
  )
  # NB RUSTSEC-2026-0387 (crypto-bigint 0.5.5) was FIXED by migrating the nym cosmos
  # EC stack to k256/p256/p384 0.14 + ecdsa 0.17 + bip32 0.6 (third-party/), not ignored.
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
