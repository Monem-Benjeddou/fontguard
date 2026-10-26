# Changelog

## 1.1.1

Catches the October 2026 variant, which slipped past 1.1.0:

- A `.vscode/tasks.json` that starts with a UTF-8 byte-order mark is now parsed. The worm adds the BOM so the file fails to parse, then puts `node` in `command` and the fake font in `args`.
- A `tasks.json` that still won't parse is flagged if it has a `folderOpen` task that mentions a font file.
- A JS/TS file that starts with 150+ blank characters is flagged. The worm now ships whole-file payloads (`api.js`) that begin with hundreds of tabs.
- Added the C2 servers seen in September and October: 193.247.144.38, 194.11.226.41, 166.88.134.75, 91.218.183.174.
- The process rules now stop the Python stager (`Request._V=` / `Request._target=`), and any `security find-generic-password` call for a browser's Safe Storage key. That call is how the stealer gets at saved browser passwords.

## 1.1.0

- Starts at login through a login item the app registers itself (`SMAppService`). It appears under System Settings › General › Login Items, and the Overview shows whether it is enabled, with a button to fix it.
- Only one copy runs: opening the app again hands over to the running one and shows its window.
- Fixed a CPU spin (about half a core) after the watcher restarted or was paused.
- Restarting the watcher no longer stops watchers you started by hand; the crash restart can no longer loop.
- One notification per burst of catches instead of one per file.
- `post-checkout` and `post-merge` scan only the files the checkout or pull brought in. A fresh clone is still scanned in full.
- Loader processes are stopped by the same tested rules as `procs`, not a broad pattern that could hit your own shell.
- Quarantine paths are stored relative to `/`, so Restore works for files outside the home folder.
- Scans skip `~/Library` by full path instead of any folder named `Library`.
- Task rule also matches `node.exe`, `bun` and `deno run`.
- Log lines are written by a single writer; `setup-permissions.sh` no longer leaves a dangling comma in an empty `settings.json`.
- Tests for clone and pull quarantine paths.

## 1.0.0

First release.

- Technique-based detection: fake font files run by `folderOpen` tasks, payloads hidden after blank space in JS/TS files, auto-run workspace settings, the `~/.node_modules` loader, known C2 addresses and campaign markers.
- Git hooks: block infected commits and pushes, quarantine on clone, checkout and pull. Existing hooks keep running.
- macOS app: real-time watcher on FSEvents, menu-bar status, scan, quarantine (restore and delete), activity history. Starts in the background at login.
- `install.sh`, `uninstall.sh`, and `setup-permissions.sh`, a guided permissions helper that checks each step took effect.
- Scans skip app bundles, system folders and the quarantine itself.
