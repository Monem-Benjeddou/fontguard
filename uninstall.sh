#!/bin/sh
# Remove fontguard. Quarantined files are kept unless you pass --purge.
FG="${FONTGUARD_HOME:-$HOME/.fontguard}"
APP_DIR="${APP_DIR:-$([ -d /Applications/Fontguard.app ] && echo /Applications || echo "$HOME/Applications")}"
LABEL=com.fontguard.agent

BIN="$APP_DIR/Fontguard.app/Contents/MacOS/Fontguard"
[ -x "$BIN" ] && "$BIN" --unregister-login >/dev/null 2>&1
launchctl bootout "gui/$(id -u)/$LABEL" 2>/dev/null
rm -f "$HOME/Library/LaunchAgents/$LABEL.plist"   # installs older than 1.1 kept a plist here
pkill -x Fontguard 2>/dev/null
pkill -f "fontguard.py watch" 2>/dev/null
rm -rf "$APP_DIR/Fontguard.app"

if [ "$(git config --global core.hooksPath)" = "$FG/hooks" ]; then
  prev="$(cat "$FG/previous-hooks-path" 2>/dev/null)"
  if [ -n "$prev" ]; then git config --global core.hooksPath "$prev"; else git config --global --unset core.hooksPath; fi
fi

if [ "$1" = "--purge" ]; then
  rm -rf "$FG"
  echo "fontguard removed, including its quarantine."
else
  rm -rf "$FG/hooks" "$FG/fontguard.py" "$FG/status.json" "$FG/previous-hooks-path"
  echo "fontguard removed. Quarantined files are still in $FG/quarantine (use --purge to delete them)."
fi
