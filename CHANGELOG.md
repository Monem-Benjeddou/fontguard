# Changelog

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
