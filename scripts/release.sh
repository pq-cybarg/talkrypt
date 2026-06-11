#!/usr/bin/env bash
# One-shot release: build every desktop target AND the mobile artifacts, then
# emit one set of dual-family checksums (SHA-256 + SHA3-256) over all of them,
# plus the verify.sh / verify.ps1 checkers.
#
#   bash scripts/release.sh
#
# Equivalent to: package.sh (desktop) then package-mobile.sh (Android + iOS),
# with hash-dist.sh producing the unified SHA256SUMS / SHA3-256SUMS / MANIFEST.
# Each step records — never hides — any target it could not build on this host.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
echo "### desktop ###"
bash "$ROOT/scripts/package.sh"
echo
echo "### mobile ###"
bash "$ROOT/scripts/package-mobile.sh"
echo
echo "### release complete — dist/ ###"
ls -1 "$ROOT/dist"/*.{tar.gz,zip,dmg,deb,apk,ipa,xcframework.zip} 2>/dev/null || true
echo
echo "verify with:  bash dist/verify.sh dist   (or: pwsh dist/verify.ps1 -Dir dist)"
