#!/bin/sh
# Install fontguard:
#   1. the scanner and git hooks in ~/.fontguard (existing hooks keep running after ours)
#   2. on macOS, the Fontguard app (real-time watcher) and a login agent that starts it
#   3. the permissions helper
# Usage: ./install.sh [--hooks-only]
set -e
SRC="$(cd "$(dirname "$0")" && pwd)"
FG="${FONTGUARD_HOME:-$HOME/.fontguard}"
APP_DIR="${APP_DIR:-$HOME/Applications}"
LABEL=com.fontguard.agent
PY=/usr/bin/python3
[ -x "$PY" ] || PY=python3

echo "Installing fontguard into $FG"
mkdir -p "$FG/hooks"
cp "$SRC/fontguard.py" "$FG/fontguard.py"
for h in pre-commit pre-push post-checkout post-merge; do
  cp "$SRC/hooks/fontguard-hook" "$FG/hooks/$h"
  chmod +x "$FG/hooks/$h"
done

# Keep hooks that were already configured: ours run first, then theirs.
prev="$(git config --global core.hooksPath 2>/dev/null || true)"
if [ -n "$prev" ] && [ "$prev" != "$FG/hooks" ]; then
  echo "$prev" > "$FG/previous-hooks-path"
  echo "  existing hooks in $prev will still run after fontguard's"
fi
git config --global core.hooksPath "$FG/hooks"
"$PY" "$FG/fontguard.py" selftest

if [ "$1" = "--hooks-only" ] || [ "$(uname)" != "Darwin" ]; then
  echo "Done: git hooks are active. Run 'python3 $FG/fontguard.py scan <folder>' to scan."
  exit 0
fi

if ! command -v swiftc >/dev/null 2>&1; then
  echo "swiftc not found. Install the Xcode Command Line Tools (xcode-select --install) and re-run"
  echo "to get the real-time app. Git hooks are already active."
  exit 0
fi

mkdir -p "$APP_DIR"
FONTGUARD_HOME="$FG" APP_DIR="$APP_DIR" sh "$SRC/app/build.sh"

# Older installs started the app from a plist in ~/Library/LaunchAgents; the app now registers its own
# login item (visible in System Settings > Login Items). Stop the old one so two copies never fight.
launchctl bootout "gui/$(id -u)/$LABEL" 2>/dev/null || true
rm -f "$HOME/Library/LaunchAgents/$LABEL.plist"
pkill -x Fontguard 2>/dev/null || true
status="$("$APP_DIR/Fontguard.app/Contents/MacOS/Fontguard" --register-login 2>/dev/null || true)"
case "$status" in
  enabled) echo "Fontguard is running in the background and starts at login." ;;
  requiresApproval) echo "Fontguard needs your approval: System Settings > General > Login Items > allow Fontguard." ;;
  *) echo "Could not register the login item (status: ${status:-unknown}). Open Fontguard from $APP_DIR once; it registers itself." ;;
esac
echo

FONTGUARD_HOME="$FG" APP_DIR="$APP_DIR" sh "$SRC/setup-permissions.sh"
