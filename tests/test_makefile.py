"""make check-history: the deny-list history scan fails when there is no main branch."""
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


@unittest.skipUnless(shutil.which("make") and shutil.which("git"), "needs make and git")
class TestCheckHistory(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, True)
        shutil.copy(ROOT / "Makefile", self.tmp / "Makefile")
        (self.tmp / "deny.txt").write_text("never-in-this-repo-7f3a\n")
        git = ["git", "-C", str(self.tmp), "-c", "user.name=t", "-c", "user.email=t@example.test"]
        subprocess.run(git[:3] + ["init", "-q", "-b", "work"], check=True)
        subprocess.run(git + ["add", "Makefile"], check=True)
        subprocess.run(git + ["commit", "-qm", "x"], check=True)
        self.git = git

    def run_make(self):
        return subprocess.run(["make", "-s", "-C", str(self.tmp), "check-history", "DENYLIST=deny.txt"],
                              capture_output=True, text=True)

    def test_no_main_exits_2(self):
        r = self.run_make()
        self.assertEqual(r.returncode, 2, r.stdout + r.stderr)
        self.assertIn("no main branch", r.stdout)
        self.assertNotIn("deny-list hits", r.stdout)

    def test_main_clean_exits_0(self):
        subprocess.run(self.git + ["branch", "main"], check=True)
        r = self.run_make()
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("deny-list hits (tree + git log -p main): 0", r.stdout)
