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
  # warnings but do NOT fail the gate (they are not vulnerabilities). One
  # advisory is ignored because it is fixed by a local source patch, not
  # accepted as-is — see deny.toml + third-party/rsa/TALKRYPT-PATCH.md:
  #   RUSTSEC-2023-0071  rsa (Marvin) — vendored + blinded; tor-only; absent by default.
  cargo audit --ignore RUSTSEC-2023-0071 || rc=1
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
