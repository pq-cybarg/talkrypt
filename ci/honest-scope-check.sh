#!/usr/bin/env bash
# Honest-scope gate for the talkrypt 2.0 branch (docs/2.0/CHARTER.md §2).
#
# This is the AUTOMATED half of the honest-scope invariant; a human reviewer is the
# other half. It enforces two things on the 2.0 research branch:
#
#   1. No unhedged GUARANTEE-language. A covert / undetectable / unbreakable /
#      certified property may only appear as a GOAL UNDER EVALUATION — i.e. on a line
#      that also carries a hedge ("goal", "under evaluation", "not a guarantee",
#      "unverified", "not broken", a forbidding "must not / no ... guarantee", etc.)
#      or the explicit `honest-scope-ok` inline escape. An assertion like "is
#      undetectable" or "FIPS-validated" with no hedge fails the build.
#
#   2. Gate-ledger consistency. A component assessment record (docs/2.0/components/
#      <slug>.md) may declare `mainline-eligible: true` ONLY when all three gate
#      fields — fv / security-eval / pentest — are `status: pass` with a non-empty
#      `evidence:` link (CHARTER.md §1). A component cannot mark itself ready without
#      the evidence.
#
# Run: bash ci/honest-scope-check.sh   (gates the 2.0 workflow; exits non-zero on a
# violation). It only scans `docs/2.0/**` (+ future 2.0 crates); mainline is governed
# by its own no-certification rules.
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
rc=0
red() { printf '  \033[31m\xe2\x9c\x97\033[0m %s\n' "$1"; }
grn() { printf '  \033[32m\xe2\x9c\x93\033[0m %s\n' "$1"; }

# Files in scope: everything under docs/2.0/ (and, as 2.0 code lands, add its crate
# globs here). Use git to list tracked files so untracked scratch is ignored.
mapfile -t FILES < <(git ls-files 'docs/2.0/*' 'docs/2.0/**' 2>/dev/null | sort -u)

# A GUARANTEE-claim: strong "it IS X" adjectives + cannot/impossible phrasings +
# certification words. NB "covert channel" (the feature name) and "low-observability"
# / "undetected" (premise descriptors) are intentionally NOT triggers — only words
# that read as an asserted absolute property are.
TRIGGER='undetectable|unobservable|untraceable|unbreakable|uncrackable|impossible to (detect|break|trace|read)|cannot be (detected|broken|traced|read)|provably (covert|secure|anonymous|private)|guaranteed (covert|undetectable|secure|anonymous|private)|\bcertified\b|\baccredited\b|nsa-?approved|fips-?validated|csfc-?accredited'
# A HEDGE neutralizes a trigger on the same line (goal-wording, forbidding-wording,
# or the explicit escape). Keep this list in sync with CHARTER.md §2.
HEDGE='honest-scope-ok|goal|under evaluation|not a guarantee|not guaranteed|unverified|not broken|aspiration|no claim|makes no claim|assert[s]? no|may not|must not|never|not certified|not audited|not accredited|forbidden|forbidding'

echo "== honest-scope: unhedged guarantee-language =="
scan_hits=0
for f in "${FILES[@]}"; do
  [ -f "$f" ] || continue
  while IFS=: read -r ln text; do
    printf '%s' "$text" | grep -qiE "$HEDGE" && continue
    red "$f:$ln  unhedged guarantee-language: $(printf '%s' "$text" | sed 's/^[[:space:]]*//' | cut -c1-80)"
    scan_hits=1; rc=1
  done < <(grep -niE "$TRIGGER" "$f" 2>/dev/null)
done
[ "$scan_hits" -eq 0 ] && grn "no unhedged covert/undetectable/certification guarantees in docs/2.0"

echo "== honest-scope: component gate ledger =="
ledger_hits=0
while IFS= read -r f; do
  [ -f "$f" ] || continue
  case "$f" in */TEMPLATE.md) continue;; esac
  grep -Eqi '^[[:space:]]*mainline-eligible:[[:space:]]*true' "$f" || continue
  # Extract the YAML-ish front-matter block (between the first two `---` lines) and
  # check each gate's status + evidence.
  fm="$(awk 'NR==1&&/^---/{f=1;next} f&&/^---/{exit} f{print}' "$f")"
  for g in "fv" "security-eval" "pentest"; do
    # The two indented lines following `<gate>:` carry its status/evidence.
    block="$(printf '%s\n' "$fm" | awk -v k="$g:" '$0 ~ "^[[:space:]]*"k {g=1;next} g&&/^[[:space:]]{2}[a-z]/{exit} g{print}')"
    st="$(printf '%s\n' "$block" | grep -E '^[[:space:]]*status:' | head -1 | sed -E 's/.*status:[[:space:]]*//; s/[[:space:]]*$//')"
    ev="$(printf '%s\n' "$block" | grep -E '^[[:space:]]*evidence:' | head -1 | sed -E 's/.*evidence:[[:space:]]*//; s/^"//; s/"$//; s/[[:space:]]*$//')"
    if [ "$st" != "pass" ]; then
      red "$f  mainline-eligible:true but gate '$g' is '${st:-unset}' (must be 'pass')"; ledger_hits=1; rc=1
    elif [ -z "$ev" ]; then
      red "$f  mainline-eligible:true but gate '$g' has no evidence link"; ledger_hits=1; rc=1
    fi
  done
done < <(git ls-files 'docs/2.0/components/*.md' 2>/dev/null)
[ "$ledger_hits" -eq 0 ] && grn "no component claims mainline-eligibility without all three gates pass+evidenced"

echo
if [ "$rc" -eq 0 ]; then echo "RESULT: honest-scope gate clean."; else echo "RESULT: honest-scope gate FOUND VIOLATIONS — see above." >&2; fi
exit "$rc"
