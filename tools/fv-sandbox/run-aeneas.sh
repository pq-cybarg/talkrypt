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

echo "== 2. Aeneas: LLBC -> F* =="
LLBC="$(find /tmp/crate -name '*.llbc' 2>/dev/null | head -1)"
echo "LLBC=$LLBC"
[ -n "${LLBC:-}" ] && "${AENEAS}" -backend fstar "$LLBC" -dest /tmp/out || echo "AENEAS_STEP_STATUS=$?"

echo "== 3. F*: type-check Aeneas's runtime + the generated model =="
# F* is pinned to v2026.04.17 (matches Aeneas main's flake era; it ships FStar.Mul, so no
# shim is needed). The key flag is `--already_cached 'Prims FStar LowStar Steel'`, which
# tells F* to TRUST the prebuilt ulib.checked instead of rechecking (and erroring on) its
# own standard library. This is exactly what Aeneas's own backends/fstar/Makefile does
# (minus --cmi, which this F* release predates).
AC="Prims FStar LowStar Steel"
if ls /tmp/out/Decode.fst >/dev/null 2>&1; then
  cd /tmp/out
  # Aeneas's runtime support library — verifies clean:
  "$FSTAR" --already_cached "$AC" --cache_checked_modules --include . Primitives.fst \
    || echo "FSTAR_PRIM_STATUS=$?"
  # The generated model. NOTE (honest): this Aeneas `main` build emits references to the
  # `control_flow` and `loop` primitives but does NOT define them in its own Primitives.fst
  # (backends/fstar/ ships only Primitives.fst, defining neither). So Decode.fst does not
  # type-check out of the box here — an Aeneas-internal coherence gap in this Charon-pin /
  # Aeneas-main / F*-release triple, NOT a decoder problem. We deliberately do NOT hand-roll
  # a total `loop`: a sound `loop` for a general Rust loop needs the Div effect, so a
  # `Tot loop` stub would be verifier-passes-but-UNSOUND. The totality property is instead
  # machine-checked (soundly, with an explicit `decreases`) in formal/DecodeTotality.fst.
  "$FSTAR" --already_cached "$AC" --cache_checked_modules --include . Decode.fst \
    || echo "FSTAR_DECODE_STATUS=$? (expected: missing Aeneas primitives control_flow/loop — see generated/README.md)"
else
  echo "(no Decode.fst generated)"
fi
echo "== pipeline attempt complete =="
