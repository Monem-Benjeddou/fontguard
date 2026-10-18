"""Tests for fontguard. Standard library only: python3 -m unittest discover -s tests -v"""
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
import fontguard  # noqa: E402


class DetectionRules(unittest.TestCase):
    def test_selftest(self):
        # The built-in self-test holds the rule fixtures shared with the app's "Run Self-test".
        self.assertEqual(fontguard.selftest(), 0)

    def test_scan_skips_quarantine_and_app_bundles(self):
        tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmp)
        payload = b"\t\t\tglobal['!'] = '8-&&';var a=1;"
        for rel in ["repo/public/fonts/fa-solid.lfk", "Some.app/Contents/fonts/fa-solid.lfk"]:
            os.makedirs(os.path.join(tmp, os.path.dirname(rel)))
            with open(os.path.join(tmp, rel), "wb") as f:
                f.write(payload)
        out = subprocess.run([sys.executable, os.path.join(ROOT, "fontguard.py"), "scan", tmp],
                             capture_output=True, text=True, check=False)
        self.assertEqual(out.returncode, 1)
        self.assertIn("repo/public/fonts/fa-solid.lfk", out.stderr)
        self.assertNotIn("Some.app", out.stderr, "app bundles must never be scanned or moved")


class HookInstall(unittest.TestCase):
    """install.sh in a throwaway HOME: chaining, blocking, uninstall."""

    def setUp(self):
        self.home = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.home)
        self.env = dict(os.environ, HOME=self.home, GIT_CONFIG_NOSYSTEM="1")
        prev = os.path.join(self.home, "prevhooks")
        os.makedirs(prev)
        self.write_hook(os.path.join(prev, "pre-commit"), "prev-ran")
        self.git("config", "--global", "core.hooksPath", prev)
        self.git("config", "--global", "user.name", "t")
        self.git("config", "--global", "user.email", "t@example.com")
        self.prev = prev

    def write_hook(self, path, marker):
        with open(path, "w") as f:
            f.write(f'#!/bin/sh\ntouch "$HOME/{marker}"\n')
        os.chmod(path, 0o755)

    def git(self, *args, cwd=None):
        return subprocess.run(["git", *args], cwd=cwd, env=self.env, capture_output=True, text=True, check=False)

    def sh(self, script, *args):
        cmd = ["sh", os.path.join(ROOT, script), *args]
        return subprocess.run(cmd, env=self.env, capture_output=True, text=True, check=False)

    def test_install_chain_block_uninstall(self):
        r = self.sh("install.sh", "--hooks-only")
        self.assertEqual(r.returncode, 0, r.stderr)
        fg_hooks = os.path.join(self.home, ".fontguard", "hooks")
        self.assertEqual(self.git("config", "--global", "core.hooksPath").stdout.strip(), fg_hooks)

        repo = os.path.join(self.home, "repo")
        self.git("init", "-q", "-b", "main", repo)
        self.write_hook(os.path.join(repo, ".git", "hooks", "pre-commit"), "local-ran")
        with open(os.path.join(repo, "a.txt"), "w") as f:
            f.write("ok\n")
        self.git("add", "a.txt", cwd=repo)
        self.assertEqual(self.git("commit", "-q", "-m", "clean", cwd=repo).returncode, 0)
        self.assertTrue(os.path.exists(os.path.join(self.home, "prev-ran")), "previous global hook must still run")
        self.assertTrue(os.path.exists(os.path.join(self.home, "local-ran")), "repo's own .git/hooks must still run")

        with open(os.path.join(repo, "eslint.config.js"), "w") as f:
            f.write("export default {};" + " " * 200 + "global['r']=require;eval(x)")
        self.git("add", "eslint.config.js", cwd=repo)
        self.assertNotEqual(self.git("commit", "-q", "-m", "bad", cwd=repo).returncode, 0, "infected commit must be blocked")

        self.assertEqual(self.sh("uninstall.sh").returncode, 0)
        self.assertEqual(self.git("config", "--global", "core.hooksPath").stdout.strip(), self.prev)

    def test_clone_quarantines_payload(self):
        self.assertEqual(self.sh("install.sh", "--hooks-only").returncode, 0)
        src = os.path.join(self.home, "infected")
        self.git("init", "-q", "-b", "main", src)
        os.makedirs(os.path.join(src, "public", "fonts"))
        with open(os.path.join(src, "public", "fonts", "fa-solid-400.woff2"), "w") as f:
            f.write("\t\t\tglobal['!'] = '8-&&';var a=1;")
        with open(os.path.join(src, "README.md"), "w") as f:
            f.write("hello\n")
        self.git("add", "-A", cwd=src)
        self.assertEqual(self.git("-c", "core.hooksPath=/dev/null", "commit", "-q", "-m", "bad", cwd=src).returncode, 0)

        clone = os.path.join(self.home, "clone")
        self.assertEqual(self.git("clone", "-q", src, clone).returncode, 0)
        self.assertFalse(os.path.exists(os.path.join(clone, "public", "fonts", "fa-solid-400.woff2")),
                         "payload must be moved out before an editor can run it")
        self.assertTrue(os.path.exists(os.path.join(clone, "README.md")), "clean files must stay")
        quarantined = [f for _, _, fs in os.walk(os.path.join(self.home, ".fontguard", "quarantine")) for f in fs]
        self.assertIn("fa-solid-400.woff2", quarantined)

    def test_pull_quarantines_only_what_arrived(self):
        self.assertEqual(self.sh("install.sh", "--hooks-only").returncode, 0)
        src = os.path.join(self.home, "upstream")
        self.git("init", "-q", "-b", "main", src)
        with open(os.path.join(src, "README.md"), "w") as f:
            f.write("hello\n")
        self.git("add", "-A", cwd=src)
        self.git("commit", "-q", "-m", "clean", cwd=src)
        clone = os.path.join(self.home, "work")
        self.assertEqual(self.git("clone", "-q", src, clone).returncode, 0)

        # The worm lands upstream after the clone; a plain pull must still catch it.
        with open(os.path.join(src, "vite.config.js"), "w") as f:
            f.write("export default {};" + " " * 200 + "global['r']=require;eval(x)")
        self.git("add", "-A", cwd=src)
        self.assertEqual(self.git("-c", "core.hooksPath=/dev/null", "commit", "-q", "-m", "bad", cwd=src).returncode, 0)
        self.assertEqual(self.git("pull", "-q", "--ff-only", cwd=clone).returncode, 0)
        self.assertFalse(os.path.exists(os.path.join(clone, "vite.config.js")), "pulled payload must be quarantined")
        self.assertTrue(os.path.exists(os.path.join(clone, "README.md")))


if __name__ == "__main__":
    unittest.main()
