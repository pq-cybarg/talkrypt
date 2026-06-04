#!/usr/bin/env bash
# Faithfully test the TPM HardwareBacked custody tier against swtpm (a spec-
# faithful software TPM 2.0) in a container. Run from the repo root:
#
#   docker run --rm -v "$PWD:/work" -w /work \
#     -v "$HOME/.cargo/registry:/usr/local/cargo/registry" \
#     -e CARGO_TARGET_DIR=/cargo-target rust:1-bookworm \
#     bash docs/linux-tpm-test.sh
#
# Mounting the host cargo registry lets deps resolve offline.
set -euo pipefail

export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq tpm2-tools swtpm swtpm-tools libtss2-tcti-swtpm0 >/dev/null

# A software TPM 2.0 on a TCP socket, auto-started (startup-clear).
SWTPM_DIR="$(mktemp -d)"
swtpm socket --tpm2 --tpmstate dir="$SWTPM_DIR" \
  --ctrl type=tcp,port=2322 --server type=tcp,port=2321 \
  --flags not-need-init,startup-clear --daemon
sleep 1

# Point tpm2-tools (and the helper's shelled tpm2_* calls, via env inheritance)
# at swtpm.
export TPM2TOOLS_TCTI="swtpm:host=localhost,port=2321"
tpm2_startup -c 2>/dev/null || true   # idempotent; startup-clear already ran it

cargo test -p talkrypt-helper --features tpm --test tpm -- --nocapture
