#!/usr/bin/env bash
# Two-emulator bilateral LAN test for talkrypt.
#
# WHY A BRIDGE: Android emulators are NAT-isolated — every instance sees itself
# as 10.0.2.15 and the host (Mac) loopback as 10.0.2.2, but they cannot reach
# each other directly. So the host emulator binds 0.0.0.0:9779 and advertises
# the host-loopback alias 10.0.2.2:9779 (the app does this automatically when it
# detects it's on an emulator — see MainActivity.lanAdvertise). We bridge the
# host emulator's listener onto the Mac with `adb forward tcp:9779 tcp:9779`, so
# the joiner emulator dialing 10.0.2.2:9779 → Mac:9779 → host emulator:9779.
#
#   joiner(10.0.2.2:9779) ─► Mac:9779 ─[adb forward]─► hostEmu:9779
#
# Usage: scripts/test-lan-bilateral.sh <host-emulator> <joiner-emulator>
#   e.g. scripts/test-lan-bilateral.sh emulator-5554 emulator-5556
set -uo pipefail

HOST_EMU="${1:-emulator-5554}"
JOIN_EMU="${2:-emulator-5556}"
PKG="com.talkrypt.app"
PORT=9779
TMP="/tmp/tk-lan"
mkdir -p "$TMP"

say() { printf '\n\033[1;36m== %s\033[0m\n' "$*"; }
fail() { printf '\033[1;31mFAIL: %s\033[0m\n' "$*"; exit 1; }

# Dump the foreground UI of a device and echo any talkrypt:// URI found in it.
dump_invite() {
  local d="$1"
  adb -s "$d" shell uiautomator dump /sdcard/tk.xml >/dev/null 2>&1
  adb -s "$d" pull /sdcard/tk.xml "$TMP/$d.xml" >/dev/null 2>&1
  grep -oE 'talkrypt://[a-z2-7]+' "$TMP/$d.xml" 2>/dev/null | head -1
}

# Tap a node by its visible text using the uiautomator dump bounds.
tap_text() {
  local d="$1" needle="$2"
  adb -s "$d" shell uiautomator dump /sdcard/tk.xml >/dev/null 2>&1
  adb -s "$d" pull /sdcard/tk.xml "$TMP/$d.xml" >/dev/null 2>&1
  local bounds
  bounds=$(grep -oE "text=\"[^\"]*$needle[^\"]*\"[^>]*bounds=\"[0-9,\[\]]+\"" "$TMP/$d.xml" | grep -oE 'bounds="[0-9,\[\]]+"' | head -1)
  [ -z "$bounds" ] && return 1
  local nums; nums=$(echo "$bounds" | grep -oE '[0-9]+')
  local x1 y1 x2 y2; read -r x1 y1 x2 y2 <<< "$(echo $nums)"
  adb -s "$d" shell input tap $(( (x1+x2)/2 )) $(( (y1+y2)/2 ))
}

say "1) bridge $HOST_EMU listener onto the Mac (adb forward tcp:$PORT)"
adb -s "$HOST_EMU" forward --remove tcp:$PORT 2>/dev/null
adb -s "$HOST_EMU" forward tcp:$PORT tcp:$PORT || fail "adb forward"
adb -s "$HOST_EMU" forward --list | grep ":$PORT"

say "2) launch app fresh on both"
for d in "$HOST_EMU" "$JOIN_EMU"; do
  adb -s "$d" shell am force-stop "$PKG"
  adb -s "$d" shell am start -n "$PKG/.MainActivity" >/dev/null
done
sleep 4

echo "(host/join steps are driven interactively below — see comments)"
