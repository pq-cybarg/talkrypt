#!/bin/bash
# Aeneas -> F* pipeline (best-effort; exact flags depend on the charon/aeneas versions).
set -uxo pipefail
eval "$(opam env)" 2>/dev/null || true
cd /home/fv
echo "== 1. Charon: Rust -> LLBC =="
./charon/target/release/charon --version || echo "(charon build status above)"
# Charon operates on a crate; wrap the single file in a throwaway crate.
mkdir -p /tmp/crate/src && cp aeneas_decode.rs /tmp/crate/src/lib.rs
printf '[package]\nname="decode"\nversion="0.0.0"\nedition="2021"\n[lib]\npath="src/lib.rs"\n' > /tmp/crate/Cargo.toml
( cd /tmp/crate && /home/fv/charon/target/release/charon cargo ) || echo "CHARON_STEP_STATUS=$?"
echo "== 2. Aeneas: LLBC -> F* =="
ls /tmp/crate/*.llbc 2>/dev/null && \
  /home/fv/aeneas/bin/aeneas -backend fstar /tmp/crate/decode.llbc -dest /tmp/out || echo "AENEAS_STEP_STATUS=$?"
echo "== 3. F*: verify the generated model =="
ls /tmp/out/*.fst 2>/dev/null && \
  /home/fv/fstar/bin/fstar.exe /tmp/out/*.fst || echo "FSTAR_STEP_STATUS=$?"
echo "== pipeline attempt complete =="
