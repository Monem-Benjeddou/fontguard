#!/bin/sh
# Build Fontguard.app (macOS 15+, needs the Xcode Command Line Tools for swiftc).
#   FONTGUARD_HOME  folder holding fontguard.py   (default: ~/.fontguard)
#   APP_DIR         where to put the app          (default: ~/Applications)
# Rebuilding changes the ad-hoc signature, so macOS may ask for Full Disk Access again.
set -e
cd "$(dirname "$0")"
FG_HOME="${FONTGUARD_HOME:-$HOME/.fontguard}"
# /Applications when writable: the Full Disk Access picker in System Settings shows it by default.
APP_DIR="${APP_DIR:-$([ -w /Applications ] && echo /Applications || echo "$HOME/Applications")}"
APP="$APP_DIR/Fontguard.app"
rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS"
swiftc -swift-version 5 -parse-as-library -O -target "$(uname -m)-apple-macos15.0" Fontguard.swift -o "$APP/Contents/MacOS/Fontguard"
cat > "$APP/Contents/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleIdentifier</key><string>com.fontguard.app</string>
  <key>CFBundleName</key><string>Fontguard</string>
  <key>CFBundleExecutable</key><string>Fontguard</string>
  <key>CFBundlePackageType</key><string>APPL</string>
  <key>CFBundleShortVersionString</key><string>1.0</string>
  <key>LSMinimumSystemVersion</key><string>15.0</string>
  <key>LSUIElement</key><true/>
  <key>FGHome</key><string>$FG_HOME</string>
</dict>
</plist>
PLIST
# Login agent, registered by the app through SMAppService (it appears under Login Items).
mkdir -p "$APP/Contents/Library/LaunchAgents"
cat > "$APP/Contents/Library/LaunchAgents/com.fontguard.agent.plist" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>com.fontguard.agent</string>
  <key>BundleProgram</key><string>Contents/MacOS/Fontguard</string>
  <key>EnvironmentVariables</key><dict><key>FONTGUARD_BACKGROUND</key><string>1</string></dict>
  <key>RunAtLoad</key><true/>
  <!-- restart after a crash, but respect Quit from the menu -->
  <key>KeepAlive</key><dict><key>SuccessfulExit</key><false/></dict>
  <key>ThrottleInterval</key><integer>30</integer>
  <key>ProcessType</key><string>Background</string>
  <key>LowPriorityIO</key><true/>
  <key>Nice</key><integer>10</integer>
</dict>
</plist>
PLIST
# Sign with a stable local identity when one exists (install.sh creates "Fontguard Local Signing"), so
# a Full Disk Access grant survives rebuilds. Ad-hoc signing ties the grant to the exact binary instead.
IDENTITY="${SIGN_IDENTITY:-Fontguard Local Signing}"
if security find-identity -v -p codesigning 2>/dev/null | grep -q "\"$IDENTITY\""; then
  codesign --force --sign "$IDENTITY" "$APP"
else
  codesign --force --sign - "$APP"
  echo "note: signed ad-hoc; Full Disk Access must be granted again after every rebuild"
fi
echo "built $APP (uses $FG_HOME)"
