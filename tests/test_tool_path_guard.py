"""Stage D: a tool body reaches files only inside its own session namespace."""
import builtins
import io
import os
import sys
import tempfile
import unittest
from pathlib import Path

from acp.gate import PermissionDenied, ToolFileAccessDenied, ToolRunner
from acp.isolation import SessionStore
from tests.helpers import ctx, lines

CATS = ["identifier:name"]
KW = dict(personal_data_categories=CATS, lawful_basis="legitimate_interests")


class ToolPathGuardTest(unittest.TestCase):
    def setUp(self):
        self.td = tempfile.TemporaryDirectory()
        self.tmp = Path(self.td.name)
        self.c, self.log = ctx(self.tmp)
        self.store = SessionStore(self.tmp / "sessions", self.c)
        self.store.dir.mkdir(parents=True, exist_ok=True)
        self.victim = self.tmp / "sessions" / "victim-s2"
        self.victim.mkdir(parents=True)
        self.secret = self.victim / "secret.txt"
        self.secret.write_text("TOP-SECRET")
        self.tr = ToolRunner(self.c, self.tmp / "ap", session_dir=self.store.dir)

    def tearDown(self):
        self.td.cleanup()

    def read(self, fn):
        return self.tr.call("crm_read", "read", lambda: (fn(), {"source": "t"}), **KW)

    def assertDenied(self, fn):
        with self.assertRaises(ToolFileAccessDenied):
            self.read(fn)
        self.assertEqual(lines(self.log.path)[-1]["outcome"], "refused_outside_session")

    def test_direct_paths_to_other_session_refused(self):
        self.assertDenied(lambda: Path(self.secret).read_text())
        self.assertDenied(lambda: open(self.secret).read())
        self.assertDenied(lambda: io.open(self.secret).read())
        self.assertDenied(lambda: os.read(os.open(self.secret, os.O_RDONLY), 99).decode())

    def test_dotdot_traversal_refused(self):
        self.assertDenied(lambda: Path(self.store.dir, "..", "victim-s2", "secret.txt").read_text())

    def test_symlink_escape_refused(self):
        link = self.store.dir / "link"
        link.symlink_to(self.secret)
        self.assertDenied(lambda: link.read_text())

    def test_write_outside_refused(self):
        out = self.tmp / "elsewhere.txt"
        self.assertDenied(lambda: out.write_text("x") and "")
        self.assertFalse(out.exists())

    def test_swallowed_denial_still_refused(self):
        def sneaky():
            try:
                return self.secret.read_text()
            except PermissionDenied:
                return "nothing"
        self.assertDenied(sneaky)

    def test_own_session_and_store_work(self):
        (self.store.dir / "note.txt").write_text("mine")
        self.assertEqual(self.read(lambda: (self.store.dir / "note.txt").read_text()), "mine")
        self.assertEqual(self.read(lambda: self.store.read("note.txt")), "mine")

    def test_guard_only_during_tool_body(self):
        before = (builtins.open, io.open, os.open)
        with self.assertRaises(ToolFileAccessDenied):
            self.read(lambda: self.secret.read_text())
        self.assertEqual((builtins.open, io.open, os.open), before)
        self.assertEqual(self.secret.read_text(), "TOP-SECRET")  # outside a tool body: no guard

    def test_declared_read_root_is_read_only(self):
        data = self.tmp / "data"
        data.mkdir()
        (data / "d.txt").write_text("fixture")
        tr = ToolRunner(self.c, self.tmp / "ap", session_dir=self.store.dir, read_roots=[data])
        self.assertEqual(tr.call("crm_read", "read", lambda: ((data / "d.txt").read_text(), {"source": "t"}), **KW),
                         "fixture")
        with self.assertRaises(ToolFileAccessDenied):
            tr.call("crm_read", "read", lambda: ((data / "d.txt").write_text("x"), {"source": "t"}), **KW)

    def test_log_is_not_a_tool_root(self):
        self.assertDenied(lambda: self.log.path.open("a").write("forged\n") and "")
        self.assertDenied(lambda: self.log.path.read_text())

    def test_other_file_operations_checked(self):
        self.assertDenied(lambda: os.remove(self.secret) or "")
        self.assertDenied(lambda: os.rename(self.secret, self.store.dir / "s") or "")
        self.assertDenied(lambda: str(os.listdir(self.victim)))
        self.assertDenied(lambda: os.symlink(self.store.dir, self.victim / "l") or "")
        self.assertTrue(self.secret.exists())

    def test_relative_dir_fd_chdir_subprocess_thread_refused(self):
        import subprocess, threading
        fd = os.open(self.victim, os.O_RDONLY)  # opened before the tool runs
        try:
            self.assertDenied(lambda: os.read(os.open("secret.txt", os.O_RDONLY, dir_fd=fd), 99).decode())
        finally:
            os.close(fd)
        self.assertDenied(lambda: os.chdir(self.victim) or "")
        self.assertDenied(lambda: subprocess.run(["cat", str(self.secret)], capture_output=True).stdout.decode())
        if sys.version_info >= (3, 13):  # older Pythons raise no audit event for a thread start
            self.assertDenied(lambda: threading.Thread(target=lambda: None).start() or "")

    def test_no_session_dir_keeps_old_behaviour(self):
        tr = ToolRunner(self.c, self.tmp / "ap")
        self.assertEqual(tr.call("crm_read", "read", lambda: (self.secret.read_text(), {"source": "t"}), **KW),
                         "TOP-SECRET")


if __name__ == "__main__":
    unittest.main()
