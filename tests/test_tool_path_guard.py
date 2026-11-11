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


def _child_read(path, q):  # spawn target: must be importable by the child
    q.put(open(path).read())


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
        self.assertDenied(lambda: threading.Thread(target=lambda: None).start() or "")  # every Python version

    def test_thread_started_by_tool_cannot_read_outside(self):
        import _thread, threading
        from concurrent.futures import ThreadPoolExecutor
        got = []
        self.assertDenied(lambda: threading.Thread(target=lambda: got.append(self.secret.read_text())).start() or "")
        self.assertDenied(lambda: _thread.start_new_thread(lambda: got.append(self.secret.read_text()), ()) and "")
        self.assertDenied(lambda: _thread.start_new(lambda: got.append(self.secret.read_text()), ()) and "")
        self.assertDenied(lambda: ThreadPoolExecutor(1).submit(self.secret.read_text).result())
        self.assertDenied(lambda: threading.Timer(0, lambda: got.append(self.secret.read_text())).start() or "")
        self.assertEqual(got, [])
        t = threading.Thread(target=lambda: got.append("outside a tool body"))  # no guard outside a tool body
        t.start()
        t.join()
        self.assertEqual(got, ["outside a tool body"])

    def test_sqlite_outside_session_refused(self):
        import sqlite3
        outside = self.tmp / "outside.db"
        self.assertDenied(lambda: sqlite3.connect(outside) and "")
        self.assertDenied(lambda: sqlite3.connect(str(self.secret)).execute("select 1").fetchall() and "")
        self.assertDenied(lambda: sqlite3.connect(f"file:{outside}?mode=rwc", uri=True) and "")
        self.assertDenied(lambda: sqlite3.connect("rel.db") and "")
        self.assertDenied(lambda: sqlite3.connect(":memory:").execute(f"ATTACH DATABASE '{outside}' AS a") and "")
        self.assertDenied(lambda: sqlite3.connect("").execute("ATTACH DATABASE ? AS a", (str(outside),)) and "")
        self.assertDenied(lambda: sqlite3.connect(self.store.dir / "own.db").execute(f"VACUUM INTO '{outside}'") and "")
        self.assertDenied(lambda: os.symlink(outside, self.store.dir / "own.db-journal") or "")  # link to outside
        (self.store.dir / "sub").mkdir()
        self.assertDenied(lambda: os.symlink("../x", self.store.dir / "sub" / "own.db-journal") or "")  # moved later
        self.assertDenied(lambda: os.symlink(self.store.dir / "x", self.store.dir / "y") or "")  # any link, even inside
        (self.store.dir / "own2.db-wal").symlink_to(outside)  # planted before the tool runs
        self.assertDenied(lambda: sqlite3.connect(self.store.dir / "own2.db") and "")

        class Quiet(sqlite3.Connection):
            def set_authorizer(self, *a):
                pass
        self.assertDenied(lambda: sqlite3.connect("", factory=Quiet).execute(f"ATTACH DATABASE '{outside}' AS a") and "")
        self.assertFalse(outside.exists())
        self.assertEqual(self.secret.read_text(), "TOP-SECRET")

        def use():  # the session's own files and in-memory databases still work
            c = sqlite3.connect(self.store.dir / "own.db")
            c.execute("create table t(x)")
            c.execute("insert into t values (1)")
            c.commit()
            m = sqlite3.connect(":memory:")
            m.execute(f"ATTACH DATABASE '{self.store.dir / 'two.db'}' AS b")
            return str(c.execute("select x from t").fetchall() + m.execute("select 2").fetchall())
        self.assertEqual(self.read(use), "[(1,), (2,)]")

    def test_sys_path_change_inside_tool_does_not_open_outside(self):
        for entry in (str(self.secret), str(self.victim)):
            sys.path.append(entry)
            try:
                self.assertDenied(lambda: open(self.secret).read())
                self.assertDenied(lambda: str(os.listdir(self.victim)))
            finally:
                sys.path.remove(entry)

    def test_no_session_dir_keeps_old_behaviour(self):
        tr = ToolRunner(self.c, self.tmp / "ap")
        self.assertEqual(tr.call("crm_read", "read", lambda: (self.secret.read_text(), {"source": "t"}), **KW),
                         "TOP-SECRET")

    # C13 escapes: each of these passed through the per-event guard of db42c16.
    def test_spawned_process_cannot_read_outside(self):
        import multiprocessing
        mp = multiprocessing.get_context("spawn")
        q = mp.Queue()

        def body():
            p = mp.Process(target=_child_read, args=(str(self.secret), q))
            p.start()
            p.join(30)
            return q.get(timeout=5)
        self.assertDenied(body)
        self.assertTrue(q.empty())

    def test_mkfifo_outside_refused(self):
        out = self.tmp / "x.fifo"
        self.assertDenied(lambda: os.mkfifo(out) or "")
        self.assertFalse(out.exists())

    def test_unix_socket_bind_outside_refused(self):
        import socket
        out = self.tmp / "x.sock"
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            self.assertDenied(lambda: s.bind(str(out)) or "")
        finally:
            s.close()
        self.assertFalse(out.exists())

    def test_readline_import_refused(self):
        saved = sys.modules.pop("readline", None)
        try:
            self.assertDenied(lambda: __import__("readline") and "")
        finally:
            sys.modules.pop("readline", None)
            if saved is not None:
                sys.modules["readline"] = saved

    def test_readline_history_write_outside_refused(self):
        import readline
        out = self.tmp / "x.hist"
        self.assertDenied(lambda: readline.write_history_file(str(out)) or "")
        self.assertFalse(out.exists())

    @unittest.skipUnless(hasattr(os, "chflags"), "no chflags")
    def test_chflags_outside_refused(self):
        import stat
        before = os.stat(self.secret).st_flags
        self.assertDenied(lambda: os.chflags(self.secret, stat.UF_NODUMP) or "")
        self.assertEqual(os.stat(self.secret).st_flags, before)

    def test_unnamed_audit_event_with_outside_path_refused(self):
        self.assertDenied(lambda: sys.audit("acp.test.unknown", str(self.secret)) or "")

    def test_reimport_of_wrapped_native_module_refused(self):
        saved = sys.modules["_posixsubprocess"]

        def body():
            del sys.modules["_posixsubprocess"]
            return __import__("_posixsubprocess") and ""
        try:
            self.assertDenied(body)
        finally:
            sys.modules["_posixsubprocess"] = saved


if __name__ == "__main__":
    unittest.main()
