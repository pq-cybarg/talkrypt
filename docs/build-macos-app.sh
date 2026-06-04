#!/usr/bin/env bash
# Build the release binaries and assemble a talkrypt.app bundle (a Terminal-
# launching wrapper around the CLI/TUI/helper), then install it to /Applications.
#
#   bash docs/build-macos-app.sh
#
# The bundle just launches Terminal with the bundled binaries on PATH — talkrypt
# is a terminal app, not a GUI. NOT certified / NOT audited (see README).
set -euo pipefail
cd "$(dirname "$0")/.."

cargo build --release -p talkrypt-cli -p talkrypt-tui -p talkrypt-helper

APP="/Applications/talkrypt.app"
mkdir -p "$APP/Contents/MacOS" 2>/dev/null || APP="$HOME/Applications/talkrypt.app"
mkdir -p "$APP/Contents/MacOS"

cat > "$APP/Contents/Info.plist" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>CFBundleName</key><string>talkrypt</string>
	<key>CFBundleDisplayName</key><string>talkrypt</string>
	<key>CFBundleIdentifier</key><string>com.talkrypt.app</string>
	<key>CFBundleVersion</key><string>0.1.0</string>
	<key>CFBundleShortVersionString</key><string>0.1.0</string>
	<key>CFBundlePackageType</key><string>APPL</string>
	<key>CFBundleExecutable</key><string>talkrypt-launch</string>
	<key>LSMinimumSystemVersion</key><string>11.0</string>
	<key>NSHighResolutionCapable</key><true/>
</dict>
</plist>
PLIST

cat > "$APP/Contents/MacOS/talkrypt-launch" <<'LAUNCH'
#!/bin/bash
DIR="$(cd "$(dirname "$0")" && pwd)"
/usr/bin/osascript <<OSA
tell application "Terminal"
  activate
  do script "export PATH=\"$DIR:\$PATH\"; clear; talkrypt version; echo; echo 'talkrypt is ready (binaries bundled in this app). Examples:'; echo '  talkrypt host --channel #general'; echo '  talkrypt host --posture hybrid'; echo '  talkrypt join <talkrypt://invite>'; echo '  talkrypt-tui host --listen 127.0.0.1:9000'; echo"
end tell
OSA
LAUNCH

cp target/release/talkrypt target/release/talkrypt-tui target/release/talkrypt-helper "$APP/Contents/MacOS/"
chmod +x "$APP/Contents/MacOS/"*

# Register with LaunchServices so it appears in Spotlight/Launchpad.
/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister -f "$APP" 2>/dev/null || true
echo "Installed $APP"
