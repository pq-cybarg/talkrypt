#!/usr/bin/env bash
# Install talkrypt's tracked git hooks into .git/hooks (git doesn't run hooks from
# a tracked dir, so we link them in). Idempotent; preserves the existing ghid
# pre-push lock. Run once after cloning.
#
#   bash scripts/install-hooks.sh
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SRC="$ROOT/scripts/hooks"
DST="$ROOT/.git/hooks"
[[ -d "$DST" ]] || { echo "not a git repo (no .git/hooks)"; exit 1; }

for hook in "$SRC"/*; do
  name="$(basename "$hook")"
  chmod +x "$hook"
  ln -sf "../../scripts/hooks/$name" "$DST/$name"
  echo "installed hook: $name -> scripts/hooks/$name"
done
echo "done. (the existing pre-push ghid identity lock is left untouched unless tracked here)"
