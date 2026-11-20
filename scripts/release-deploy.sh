#!/usr/bin/env bash
# Deploy the MOST RECENT signed build (dist/) as a GitHub release. DRAFT by
# default — nothing goes public, and the git tag ref is not created until a draft
# is published, so this is fully reversible.
#
#   bash scripts/release-deploy.sh                    # verify dist/, create a DRAFT release
#   bash scripts/release-deploy.sh --tag v1.0.0       # override the tag (default: v<version>)
#   bash scripts/release-deploy.sh --publish          # make it PUBLIC (explicit; outward + hard to undo)
#   bash scripts/release-deploy.sh --repo owner/name  # override the target repo
#
# It re-verifies dist/ (both hashes + every PQ co-signature) and REFUSES to deploy
# if verification fails. It uploads ONLY public artifacts + checksums + signatures
# + published pubkeys + the verify scripts; it will not upload anything that looks
# like a secret (seed/key), as a belt-and-suspenders guard on top of .gitignore.
#
# NOT FIPS-validated · NOT CSfC-accredited · NOT NSA-approved · NOT audited.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
DIST="$ROOT/dist"

REPO="pq-cybarg/talkrypt"
DRAFT=1
TAG=""
for ((i=1; i<=$#; i++)); do
  a="${!i}"
  case "$a" in
    --publish) DRAFT=0 ;;
    --tag)  i=$((i+1)); TAG="${!i}" ;;
    --repo) i=$((i+1)); REPO="${!i}" ;;
    -h|--help) sed -n '2,18p' "$0"; exit 0 ;;
    *) echo "unknown arg: $a" >&2; exit 2 ;;
  esac
done

[[ -d "$DIST" ]] || { echo "no dist/ — build + sign first (scripts/release-build-sign.sh)" >&2; exit 1; }
command -v gh >/dev/null 2>&1 || { echo "need the GitHub CLI 'gh' on PATH" >&2; exit 1; }

VERSION="$(grep -m1 '^version' crates/cli/Cargo.toml | sed -E 's/.*"([^"]+)".*/\1/')"
[[ -z "$TAG" ]] && TAG="v$VERSION"

# Re-verify before shipping anything. The verifier needs the relsign tool next to
# the artifacts to check PQ co-signatures.
RELSIGN="$ROOT/target/release/talkrypt-relsign"
[[ -x "$RELSIGN" ]] || RELSIGN="$ROOT/target/debug/talkrypt-relsign"
[[ -x "$RELSIGN" ]] && cp "$RELSIGN" "$DIST/talkrypt-relsign"
echo "### re-verifying dist/ before deploy ###"
bash "$DIST/verify.sh" "$DIST" || { echo "verification FAILED — refusing to deploy" >&2; exit 1; }

# Collect PUBLIC assets only. Artifacts + the two sums + every signature + the
# published pubkeys + verifiers + manifest. Never seeds / loose host binaries.
shopt -s nullglob
ASSETS=()
for f in "$DIST"/*.tar.gz "$DIST"/*.zip "$DIST"/*.dmg "$DIST"/*.deb "$DIST"/*.apk "$DIST"/*.aab "$DIST"/*.ipa "$DIST"/*.xcframework.zip \
         "$DIST"/SHA384SUMS "$DIST"/SHA3-384SUMS "$DIST"/SHA384SUMS.sig "$DIST"/SHA384SUMS.slh.sig \
         "$DIST"/RELEASE_PUBKEY.hex "$DIST"/RELEASE_PUBKEY_SLH.hex \
         "$DIST"/verify.sh "$DIST"/verify.ps1 "$DIST"/MANIFEST.txt; do
  [[ -f "$f" ]] && ASSETS+=("$f")
done
shopt -u nullglob

# Belt-and-suspenders: drop anything that smells like a secret.
SAFE=()
for f in "${ASSETS[@]}"; do
  case "$(basename "$f")" in
    *.seed|*.key|*.secret|*seed*|ml-dsa.*|slh-dsa.*) echo "  !! skipping suspected secret: $(basename "$f")" >&2 ;;
    *) SAFE+=("$f") ;;
  esac
done
[[ ${#SAFE[@]} -gt 0 ]] || { echo "no publishable assets found in dist/" >&2; exit 1; }

echo "### ${DRAFT:+DRAFT }release $TAG -> $REPO  (${#SAFE[@]} assets) ###"
for f in "${SAFE[@]}"; do echo "    + $(basename "$f")"; done

NOTES="$(cat <<EOF
talkrypt $VERSION — post-quantum, Tor/Nym/mesh end-to-end encrypted chat.

Verify before trusting:
  bash verify.sh .        # checks SHA-384 + SHA3-384 AND both PQ co-signatures

Co-signed with ML-DSA-87 (FIPS 204) + SLH-DSA-SHA2-256s (FIPS 205); dual
SHA-384 (FIPS 180-4) + SHA3-384 (FIPS 202) checksums. Pin the published
RELEASE_PUBKEY*.hex out of band.

NOT FIPS-validated · NOT CSfC-accredited · NOT NSA-approved · NOT audited.
"CNSA-aligned" denotes algorithm choice only.
EOF
)"

ARGS=( release create "$TAG" --repo "$REPO" --title "talkrypt $VERSION" --notes "$NOTES" )
[[ "$DRAFT" -eq 1 ]] && ARGS+=( --draft )

# gh uses the HTTPS API (not the ssh remote), but keep the ssh override harmless.
GIT_SSH_COMMAND=/usr/bin/ssh gh "${ARGS[@]}" "${SAFE[@]}"

echo
if [[ "$DRAFT" -eq 1 ]]; then
  echo "DRAFT created (not public, no tag ref yet). Review it, then publish with:"
  echo "    gh release edit $TAG --repo $REPO --draft=false"
else
  echo "PUBLISHED $TAG to $REPO."
fi
