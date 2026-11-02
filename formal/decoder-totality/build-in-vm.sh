#!/usr/bin/env bash
# =============================================================================
#  Aeneas -> F* totality proof for talkrypt's nested-heap decoders.
#
#  >>> RUN THIS INSIDE A THROWAWAY VM ONLY. <<<
#  A source build of Charon + Aeneas executes hundreds of third-party build
#  scripts and needs a pinned nightly (rustc-dev) + an OCaml/dune toolchain.
#  Per docs/fv-heap-decoder-spike.md and the project opsec posture, never run it
#  on the opsec-sensitive host. The CVE gate it depends on is already cleared
#  host-safely by `cargo update` (see README.md); this script only does the part
#  that must be isolated: the build + extraction + proof.
#
#  Prereqs in the VM: git, a C toolchain, opam (OCaml >= 5), z3, fstar.exe on
#  PATH (same as `formal/Makefile`), and rustup (the nightly is pinned by
#  Charon's rust-toolchain file).
# =============================================================================
set -euo pipefail

TALKRYPT_ROOT="${TALKRYPT_ROOT:?set TALKRYPT_ROOT to the talkrypt checkout path}"
WORK="${WORK:-$PWD/aeneas-fv-work}"
mkdir -p "$WORK"; cd "$WORK"

echo "== 1. Charon (clear CVEs, then build) =="
[ -d charon ] || git clone https://github.com/AeneasVerif/charon.git charon
cd charon/charon
cargo update                      # clears the networking-stack CVEs (README.md)
cargo audit || { echo "audit must be vuln-clean (exit 0) before building"; exit 1; }
cd ..
cargo build --release             # builds charon + charon-driver (pinned nightly)
make build-dev-rustc || true      # Charon's own bootstrap target, if present
CHARON_BIN="$PWD/bin/charon"
cd "$WORK"

echo "== 2. Aeneas (OCaml backend) =="
[ -d aeneas ] || git clone https://github.com/AeneasVerif/aeneas.git aeneas
cd aeneas
opam install --deps-only -y . || true
make                              # builds the aeneas binary
AENEAS_BIN="$PWD/bin/aeneas"
cd "$WORK"

echo "== 3. Extract the decoder crate -> LLBC =="
# Charon runs as a rustc wrapper over the crate holding the decoders. We extract
# talkrypt-core (narrow it with --include once the paths are confirmed in the VM).
cd "$TALKRYPT_ROOT"
"$CHARON_BIN" --dest "$WORK/llbc" \
  --start-from 'crate::linkage::LinkageProof::decode' \
  --start-from 'crate::linkage::LinkagePayload::decode' \
  --start-from 'crate::presence::NamePresence::decode' \
  -- -p talkrypt-core
# NOTE: confirm the exact --start-from paths + any --opaque for crypto leaves in
# the VM (charon --help). The goal is the decode closure + IdentityChain/SignedCert.

echo "== 4. Aeneas: LLBC -> F* =="
"$AENEAS_BIN" -backend fstar -dest "$WORK/fstar-out" "$WORK/llbc/talkrypt_core.llbc"

echo "== 5. Prove totality =="
# Aeneas-emitted F* models the decoders as pure Option-returning functions (heap
# gone). Totality = every emitted `decode` terminates and returns (no `_ ->
# False` admits). Add thm_decode_total lemmas, then check with fstar.exe exactly
# like formal/Makefile does for GroupAuth.fst:
cp "$WORK"/fstar-out/*.fst "$TALKRYPT_ROOT/formal/decoder-totality/" 2>/dev/null || true
cd "$TALKRYPT_ROOT/formal"
# add the generated .fst to the Makefile `fstar` target, then:
make fstar

echo "== Done. Review formal/decoder-totality/*.fst, add thm_decode_total, commit."
echo "   Then flip linkage.rs:301 'diagnosed, not landed' -> 'landed (Aeneas->F*)'."
