# fontguard

Detects and blocks the git worm that spreads through VS Code auto-run tasks and
poisoned config files, on macOS (real-time app + git hooks) and Linux (git hooks).

The worm commits a hidden `.vscode/tasks.json` task that runs when you open the
folder. The task runs `node ./public/fonts/<something>.woff2`, a "font" that is
really obfuscated JavaScript. It also appends payloads to `eslint.config.js`,
`vite.config.js`, `postcss.config.js`, `tailwind.config.js` and source files,
after hundreds of blank characters so no editor shows them. Those run on
`npm run dev`, on `npm run build`, or whenever your editor's ESLint loads the
config. Once running, it steals credentials and uses your GitHub token to
force-push the same infection into every repo you can write to. It keeps the
original commit message and date, so the change is easy to miss.

## What it catches

Filenames, extensions and strings change between waves, so fontguard looks for
the technique rather than a fixed signature:

| Check | Why it works |
|---|---|
| A `folderOpen` task that runs `node` on a non-script file, or downloads or decodes code | Legitimate auto-run tasks run scripts or `npm`, not fonts |
| A font-named file (`.woff2`, `.ttf`, `.lfk`…) that is plain text | Real fonts are binary and always contain NUL bytes |
| Code after a long run of blank space on the same line in JS/TS | The trick that hides payloads off-screen |
| A committed `.vscode/settings.json` that turns automatic tasks on | Re-enables the trigger for that workspace |
| The `~/.node_modules/.npm-ws*` loader, known C2 addresses and campaign markers | Second stage and confirmation |

## How it protects you

| Where | What happens |
|---|---|
| Real-time watcher (macOS app) | A file is moved to quarantine the moment it lands on disk, however it arrives: clone, zip, copy or AirDrop. If the loader lands, its running process is stopped too |
| `git clone`, `checkout`, `pull` | Infected files are moved to quarantine before an editor can open them |
| `git commit`, `git push` | Blocked if they would spread the worm |
| `fontguard.py scan <folder>` | Report only. Add `--quarantine` to move what it finds |
| `fontguard.py procs` | Report running processes that behave like the worm. Read-only |

Quarantine means moving the file to `~/.fontguard/quarantine/`, never deleting
it. App bundles and system folders are never scanned, so a false alarm can't
break an installed app.

## Install

```sh
git clone https://github.com/Monem-Benjeddou/fontguard.git
cd fontguard
./install.sh
```

The installer:
- copies the scanner and git hooks to `~/.fontguard`
- keeps any hooks you already had: they still run after fontguard's
- on macOS, builds `Fontguard.app` into `/Applications` (or `~/Applications` if that isn't writable) and registers it as a login item, so it runs in the background from the next login and appears under System Settings › General › Login Items. This needs the Xcode Command Line Tools: `xcode-select --install`
- runs the permissions helper

Linux, or hooks only: `./install.sh --hooks-only`

Requirements: Python 3.9+, git. On macOS, macOS 15 or later is required for the app.

## Permissions

`./setup-permissions.sh` walks you through each permission and checks that it
took effect. Run it again at any time.

1. **Auto-run tasks off** in VS Code, Cursor, Windsurf and VSCodium (`"task.allowAutomaticTasks": "off"`). It backs up your settings first.
2. **Start at login.** macOS may ask you to allow Fontguard under Login Items; the helper opens that pane and confirms.
3. **Full Disk Access for Fontguard.** Without it, macOS hides Downloads, Desktop and Documents from the watcher. The helper opens the right Settings pane and shows the app in Finder, so you can drag it into the list. It then restarts the app and confirms the grant.
4. **Notifications,** so you hear about every catch.

Access is granted to Fontguard.app alone, not to Python or your terminal.

The app is signed ad-hoc, so macOS ties the grant to the exact build: after an
upgrade, remove the old "Fontguard" entry from the Full Disk Access list and
add the new one. To make grants survive upgrades, create a local signing
identity once; `build.sh` uses it automatically when it exists:

```sh
openssl req -x509 -newkey rsa:2048 -sha256 -days 3650 -nodes -keyout key.pem -out cert.pem \
  -subj "/CN=Fontguard Local Signing" -addext "extendedKeyUsage=critical,codeSigning" -addext "keyUsage=critical,digitalSignature"
openssl pkcs12 -export -out id.p12 -inkey key.pem -in cert.pem -passout pass:x -name "Fontguard Local Signing" \
  -certpbe PBE-SHA1-3DES -keypbe PBE-SHA1-3DES -macalg sha1
security import id.p12 -k ~/Library/Keychains/login.keychain-db -P x -T /usr/bin/codesign && rm key.pem cert.pem id.p12
```

If `security find-identity -v -p codesigning` doesn't list it afterwards, open Keychain Access, double-click the certificate, and set Code Signing to Always Trust.

## Using the app

Open **Fontguard** from `/Applications`, or click the shield in the menu bar.

- **Overview:** status, the protection switch, what's covered, recent catches.
- **Scan:** drop a folder or choose one, then quarantine what it finds.
- **Quarantine:** one row per incident. You can restore false alarms or delete for good.
- **Activity:** a searchable history.

## If you were infected

fontguard stops new infections. It can't undo what already ran. Do this from
another device:

1. Change your GitHub password, sign out all sessions, and revoke every personal access token, OAuth app (including GitHub CLI and Git Credential Manager) and SSH key. Until then, the worm can re-push.
2. Turn on branch protection that blocks force pushes on your main branches, and tell the owners of repos your token could write to.
3. Restore infected files from the last clean commit and push normally. Don't force-push.
4. Treat secrets on the machine as stolen: browser passwords, `.env` files, API keys and cloud credentials.
5. A clean reinstall of the OS is the only way to be sure.

## Indicators

- `.vscode/tasks.json` with `"runOn": "folderOpen"` running `node ./public/fonts/fa-solid-400.woff2` and similar
- `.vscode/settings.json` with `"task.allowAutomaticTasks": true`
- `.gitignore` entries `branch_structure.json`, `temp_auto_push.bat`, `temp_interactive_push.bat`
- `import { createRequire } from 'module'` added to ESM config files
- `global['!']`, `global['_V']`, `global.i="A8-…"`, `_$_1e42`
- `~/.node_modules/.npm-ws-runner.js`, `.npm-ws.json`, `.npm-ws.pid`
- C2: `95.135.181.151`, `166.88.54.158`
- Force pushes that keep the old author date, made from a machine you don't own

## Uninstall

```sh
./uninstall.sh            # keeps the quarantine
./uninstall.sh --purge    # deletes it too
```

Your previous git hooks setting is restored.

## Development

```sh
python3 fontguard.py selftest
python3 -m unittest discover -s tests -v
shellcheck -s sh install.sh uninstall.sh setup-permissions.sh app/build.sh hooks/fontguard-hook
pipx run ruff==0.17.1 check fontguard.py tests/
```

CI runs all of the above on macOS and Linux, builds the app, and scans the repo with fontguard itself.

## Limits

fontguard is a focused tool for one malware family, not an antivirus. It
can't stop changes made directly on GitHub with a stolen token; only revoking
the token does that. It runs with your user's rights, so malware that is
already running as you could disable it. Repos that set their own
`core.hooksPath` (Husky, Lefthook) bypass the global git hooks; on macOS the
real-time watcher still covers them. New variants that drop all of these
techniques would need new rules. Please report them (see
[SECURITY.md](SECURITY.md)).

## License

MIT
