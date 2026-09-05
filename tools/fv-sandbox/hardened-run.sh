#!/usr/bin/env bash
# Run the FV sandbox with a hardened, ephemeral, AIRGAPPED profile.
# NIST SP 800-190 / CIS Docker Benchmark aligned. The build (Dockerfile) fetched every
# tool; this run needs NO network and drops every privilege. Nothing persists (--rm).
#
# Usage:  ./hardened-run.sh                      # verify the baked-in decoder
#         ./hardened-run.sh /home/fv/other.rs    # verify a different baked-in harness
set -euo pipefail

IMAGE="talkrypt-fv-sandbox:latest"

# Build once (network only here). Rebuild is cheap after the first time (layer cache).
docker build --platform=linux/amd64 -t "$IMAGE" "$(dirname "$0")"

# Hardened, one-time, throwaway run:
#   --rm                       ephemeral: container + its writable layer are destroyed
#   --network=none             AIRGAPPED: no egress/ingress during verification
#   --cap-drop=ALL             drop every Linux capability
#   --security-opt no-new-privileges  cannot gain privileges via setuid, etc.
#   --security-opt seccomp=...  keep the default seccomp filter (deny dangerous syscalls)
#   --read-only                immutable root filesystem
#   --tmpfs ...                the only writable areas: /tmp and Verus's scratch, in RAM,
#                              noexec/nosuid, size-capped
#   --user 10001:10001         non-root
#   --memory / --pids-limit / --cpus   resource caps (anti-DoS / fork-bomb)
#   --hostname / no bind mounts / no env secrets
exec docker run \
    --rm \
    --network=none \
    --cap-drop=ALL \
    --security-opt=no-new-privileges \
    --security-opt=seccomp=default \
    --read-only \
    --tmpfs /tmp:rw,noexec,nosuid,size=256m \
    --tmpfs /home/fv/.verus-scratch:rw,noexec,nosuid,size=256m \
    --user 10001:10001 \
    --memory=4g \
    --memory-swap=4g \
    --pids-limit=512 \
    --cpus=2 \
    --hostname fv-sandbox \
    --platform=linux/amd64 \
    "$IMAGE" "$@"
