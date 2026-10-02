#!/usr/bin/env bash
# Wire up the emulator<->real-hardware round-robin test bridge (see
# docs/testing/emulator-hardware-bridge.md).
#
# For each real USB device serial, adb-forward a distinct Mac-local port to the
# device's talkrypt LAN port, then launch the round-robin relay on 9779. Android
# EMULATORS then reach the relay (and thus the real devices) via their NAT alias
# 10.0.2.2:9779 — no per-emulator forward needed for the outbound direction.
#
#   bash scripts/test/hw-bridge.sh <device-serial>[,<serial>...] [talkrypt-port]
#
# Example (two real phones on talkrypt LAN port 9779):
#   bash scripts/test/hw-bridge.sh SM02G4061972692,ZY227KJ4 9779
#
# Then on an emulator, join/host pointing at 10.0.2.2:9779.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"

SERIALS="${1:-}"
TK_PORT="${2:-9779}"
LISTEN_PORT="${3:-9779}"
[[ -z "$SERIALS" ]] && { echo "usage: hw-bridge.sh <serial>[,<serial>...] [tk-port] [listen-port]" >&2; exit 2; }

command -v adb >/dev/null || { echo "adb not found (install platform-tools)" >&2; exit 2; }

backends=()
base=19001
IFS=',' read -r -a arr <<< "$SERIALS"
for s in "${arr[@]}"; do
  local_port=$base; base=$((base + 1))
  echo "==> adb -s $s forward tcp:$local_port tcp:$TK_PORT"
  adb -s "$s" forward "tcp:$local_port" "tcp:$TK_PORT"
  backends+=("127.0.0.1:$local_port")
done

joined=$(IFS=,; echo "${backends[*]}")
echo "==> backends: $joined"
echo "==> emulators reach these via 10.0.2.2:$LISTEN_PORT"
exec python3 "$ROOT/scripts/test/roundrobin-bridge.py" \
  --listen "127.0.0.1:$LISTEN_PORT" --backends "$joined"
