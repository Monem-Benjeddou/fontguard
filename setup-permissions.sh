#!/bin/sh
# Walks you through the permissions Fontguard needs, and checks each one took effect.
# Safe to re-run at any time.
FG="${FONTGUARD_HOME:-$HOME/.fontguard}"
APP_DIR="${APP_DIR:-$([ -d /Applications/Fontguard.app ] && echo /Applications || echo "$HOME/Applications")}"
APP="$APP_DIR/Fontguard.app"
LABEL=com.fontguard.agent
ok()   { printf '  \033[32m✓\033[0m %s\n' "$1"; }
warn() { printf '  \033[33m!\033[0m %s\n' "$1"; }

echo "1/4  Turn off auto-run tasks in your editors"
echo "     (the worm's main trick is a task that runs when you open a folder)"
/usr/bin/python3 - <<'PY'
import os, re, shutil
base = os.path.expanduser("~/Library/Application Support")
found = False
for app in ["Code", "Code - Insiders", "Cursor", "Windsurf", "VSCodium"]:
    path = os.path.join(base, app, "User", "settings.json")
    if not os.path.isdir(os.path.dirname(path)):
        continue
    found = True
    text = open(path, encoding="utf-8").read() if os.path.exists(path) else "{}"
    if re.search(r'"task\.allowAutomaticTasks"\s*:\s*"off"', text):
        print(f"  \033[32m✓\033[0m {app}: already off")
        continue
    if os.path.exists(path):
        shutil.copy(path, path + ".fontguard-backup")
    if '"task.allowAutomaticTasks"' in text:
        text = re.sub(r'("task\.allowAutomaticTasks"\s*:\s*)("[^"]*"|true|false)', r'\1"off"', text)
    elif (i := text.find("{")) >= 0:
        rest = text[i + 1:]
        comma = "" if re.fullmatch(r"\s*}\s*", rest) else ","  # no dangling comma when the file was just {}
        text = text[:i + 1] + f'\n    "task.allowAutomaticTasks": "off"{comma}' + rest
    else:
        text = '{\n    "task.allowAutomaticTasks": "off"\n}\n'
    open(path, "w", encoding="utf-8").write(text)
    print(f"  \033[32m✓\033[0m {app}: auto-run tasks turned off (backup: settings.json.fontguard-backup)")
if not found:
    print("  no VS Code-family editor found")
PY

echo
echo "2/4  Start at login"
if [ ! -x "$APP/Contents/MacOS/Fontguard" ]; then
  warn "Fontguard.app not found at $APP (run ./install.sh)"
else
  status="$("$APP/Contents/MacOS/Fontguard" --register-login 2>/dev/null || true)"
  case "$status" in
    enabled) ok "Fontguard is in Login Items and starts at login" ;;
    requiresApproval)
      open "x-apple.systempreferences:com.apple.LoginItems-Settings.extension"
      echo "     System Settings is open. Under 'Allow in the Background', switch Fontguard on."
      printf '     Press Return when done: '; read -r _
      status="$("$APP/Contents/MacOS/Fontguard" --register-login 2>/dev/null || true)"
      if [ "$status" = "enabled" ]; then ok "login item enabled"; else warn "still $status; re-run this script later"; fi ;;
    *) warn "could not register the login item (status: ${status:-unknown})" ;;
  esac
fi

echo
echo "3/4  Full Disk Access for Fontguard"
echo "     (without it, macOS hides Downloads, Desktop and Documents from the real-time watcher)"
granted() { grep -q '"fullDiskAccess": true' "$FG/status.json" 2>/dev/null; }
restart() { launchctl kickstart -k "gui/$(id -u)/$LABEL" 2>/dev/null || open -g "$APP" --args --background; sleep 4; }
if [ ! -d "$APP" ]; then
  warn "Fontguard.app not found at $APP. Git hooks still protect you; run ./install.sh to add the app."
elif granted; then
  ok "already granted"
else
  open "x-apple.systempreferences:com.apple.preference.security?Privacy_AllFiles"
  open -R "$APP"
  echo "     System Settings and Finder are open. Drag Fontguard from Finder into the"
  echo "     Full Disk Access list (or click + and pick it), then switch it on."
  while :; do
    printf '     Press Return when done, or type s then Return to skip: '
    read -r answer
    if [ "$answer" = "s" ]; then warn "skipped. Re-run this script any time."; break; fi
    restart
    if granted; then ok "Full Disk Access is on"; break; fi
    warn "not detected yet. Check that the switch next to Fontguard is on."
  done
fi

echo
echo "4/4  Notifications"
osascript -e 'display notification "Fontguard will tell you when it blocks something." with title "Fontguard"' 2>/dev/null
echo "     A test notification was sent. If none appeared, allow notifications for"
echo "     Script Editor in System Settings → Notifications (Fontguard sends them through it)."

echo
echo "Status"
if [ "$(git config --global core.hooksPath)" = "$FG/hooks" ]; then ok "git hooks active"; else warn "git hooks not active (run ./install.sh)"; fi
if pgrep -xq Fontguard; then ok "real-time watcher running"; else warn "real-time watcher not running"; fi
if granted; then ok "Full Disk Access"; else warn "Full Disk Access missing"; fi
echo "Open Fontguard from $(dirname "$APP") to see what it has caught."
