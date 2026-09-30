#!/bin/bash
# Aeneas -> F* pipeline (best-effort; exact flags depend on the charon/aeneas versions).
set -uxo pipefail
eval "$(opam env)" 2>/dev/null || true
cd /home/fv

# Locate the built binaries (Charon's Makefile builds into charon/bin or charon/target;
# Aeneas into aeneas/bin). Search rather than hard-code a path that drifts across versions.
CHARON="$(find /home/fv/charon -type f -name charon -perm -u+x 2>/dev/null | grep -E '/(bin|release)/charon$' | head -1)"
[ -z "${CHARON:-}" ] && CHARON="$(find /home/fv/charon -type f -name charon -perm -u+x 2>/dev/null | head -1)"
AENEAS="$(find /home/fv/aeneas -type f -name aeneas -perm -u+x 2>/dev/null | head -1)"
FSTAR=/home/fv/fstar/bin/fstar.exe
echo "CHARON=$CHARON"
echo "AENEAS=$AENEAS"

echo "== 1. Charon: Rust -> LLBC =="
"${CHARON:-charon}" version || echo "(charon build status above)"
# Charon operates on a crate; wrap the single file in a throwaway crate.
# --preset=aeneas is REQUIRED or Aeneas rejects the LLBC.
mkdir -p /tmp/crate/src && cp aeneas_decode.rs /tmp/crate/src/lib.rs
printf '[package]\nname="decode"\nversion="0.0.0"\nedition="2021"\n[lib]\npath="src/lib.rs"\n' > /tmp/crate/Cargo.toml
( cd /tmp/crate && "${CHARON}" cargo --preset aeneas ) || echo "CHARON_STEP_STATUS=$?"

echo "== 2. Aeneas: LLBC -> F* (recursive form, F*-verifiable) =="
# -loops-to-rec  : emit loops as recursive `Tot` functions (the form Aeneas's own F* CI
#                  verifies) instead of the default loop/control_flow combinator, whose
#                  primitives this Aeneas build does not ship in Primitives.fst.
# -decreases-clauses : emit a Decode.Clauses.Template.fst with the termination measure as
#                  `admit ()` for us to fill (the sound termination-proof obligation).
# -split-files   : one module per concern (Types / Clauses / FunsExternal / Funs).
LLBC="$(find /tmp/crate -name '*.llbc' 2>/dev/null | head -1)"
echo "LLBC=$LLBC"
[ -n "${LLBC:-}" ] && "${AENEAS}" -backend fstar -loops-to-rec -decreases-clauses -split-files \
    "$LLBC" -dest /tmp/out || echo "AENEAS_STEP_STATUS=$?"

echo "== 3. F*: fill the termination measure, then verify the whole auto-translated model =="
# --already_cached 'Prims FStar LowStar Steel' tells F* to TRUST the prebuilt ulib.checked
# instead of rechecking (and erroring on) its own standard library — the flag Aeneas's own
# backends/fstar/Makefile uses. F* is pinned to v2026.04.17 (matches Aeneas main's era).
AC="Prims FStar LowStar Steel"
FAIL=0
if ls /tmp/out/Decode.Funs.fst >/dev/null 2>&1; then
  cd /tmp/out
  # Fill the decreases measure Aeneas left as `admit ()`. The loop increments `i` toward `n`
  # (i := i+1 each iteration, guard i < n), so `n - i` strictly decreases and is a nat under
  # the guard. This is the ONLY human-supplied step, and F* then PROVES it discharges the
  # decreases obligation (nothing is admitted).
  sed -e 's/module Decode.Clauses.Template/module Decode.Clauses/' \
      -e 's/admit ()/if i <= n then n - i else 0/' \
      Decode.Clauses.Template.fst > Decode.Clauses.fst
  for m in Primitives.fst Decode.Types.fst Decode.Clauses.fst Decode.FunsExternal.fsti Decode.Funs.fst; do
    echo "---- verifying $m ----"
    if "$FSTAR" --already_cached "$AC" --cache_checked_modules --include . "$m" 2>&1 \
         | grep -viE 'spurious|suppressing|Unable to load' | grep -E 'Verified|Error|error'; then :; fi
    "$FSTAR" --already_cached "$AC" --cache_checked_modules --include . "$m" >/dev/null 2>&1 || FAIL=1
  done
  if [ "$FAIL" = 0 ]; then
    echo "RESULT: PROVEN — Charon->Aeneas->F* auto-translation of the decoder verified (Tot, all VCs discharged)."
  else
    echo "RESULT: a module failed to verify (FAIL=$FAIL)."
  fi
else
  echo "(no Decode.Funs.fst generated)"
fi
echo "== pipeline complete =="
