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


def _guard_asking():
    f = sys._getframe(2)
    while f is not None and f.f_code.co_filename in (os.__file__, "<frozen os>"):
        f = f.f_back
    return f is not None and f.f_code.co_filename.endswith(os.path.join("acp", "gate.py"))


def _read_close(f):
    with f:
        return f.read()


def _liar(inside, outside):
    """A path object that shows the guard one path and the OS another (TOCTOU)."""
    class Liar:
        def __fspath__(self):
            return str(inside if _guard_asking() else outside)
    return Liar()


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


    def test_pathlike_toctou_fileio_refused(self):
        ok = self.store.dir / "ok.txt"
        ok.write_text("fine")
        got = []
        self.assertDenied(lambda: got.append(io.FileIO(_liar(ok, self.secret)).read()) or "")
        self.assertEqual(got, [])
        out = self.tmp / "x-out.txt"
        self.assertDenied(lambda: io.FileIO(_liar(self.store.dir / "w.txt", out), "w").write(b"x") and "")
        self.assertFalse(out.exists())

    def test_pathlike_toctou_mkfifo_refused(self):
        import stat
        out = self.tmp / "x.fifo"
        self.assertDenied(lambda: os.mkfifo(_liar(self.store.dir / "f", out)) or "")
        self.assertFalse(out.exists())
        out2 = self.tmp / "x.node"
        self.assertDenied(lambda: os.mknod(_liar(self.store.dir / "n", out2), stat.S_IFIFO | 0o600) or "")
        self.assertFalse(out2.exists())

    def test_pathlib_subclass_fspath_refused(self):
        ok = self.store.dir / "ok.txt"
        ok.write_text("fine")
        secret = self.secret

        class Lying(type(Path())):
            def __fspath__(self):
                return str(ok if _guard_asking() else secret)
        for opener in (open, io.FileIO):
            got = []
            self.assertDenied(lambda: got.append(opener(Lying(ok)).read()) or "")
            self.assertEqual(got, [])


    def test_pathlib_gc_mutation_refused(self):
        # Even an exact stdlib Path can change its cached text in a gc callback after C converted it; the hook
        # now refuses non-str paths at native calls and the open wrapper converts a Path once before the call.
        import gc
        ok = self.store.dir / "ok.txt"
        ok.write_text("fine")
        seen = []
        for opener in (io.FileIO, open):
            for n in range(1, 12):
                p = Path(ok)
                str(p)
                p._str = str(self.secret)
                calls = [0]

                def cb(phase, info, p=p, calls=calls, n=n):
                    if phase == "start":
                        calls[0] += 1
                        if calls[0] == n:
                            p._str = str(ok)
                gc.callbacks.append(cb)
                old = gc.get_threshold()
                gc.set_threshold(1)
                try:
                    seen.append(self.read(lambda: _read_close(opener(p))))
                except ToolFileAccessDenied:
                    pass
                finally:
                    gc.set_threshold(*old)
                    gc.callbacks.remove(cb)
        self.assertNotIn("TOP-SECRET", [x.decode() if isinstance(x, bytes) else x for x in seen])

    def test_lying_path_shapes_refused(self):
        ok = self.store.dir / "ok.txt"
        ok.write_text("fine")

        class S(str):
            def __fspath__(self):
                return str(self)

        class B(bytes):
            pass

        class Entry:  # os.DirEntry look-alike
            path = str(ok)

            def __fspath__(self):
                return self.path

        class Fd(int):
            def __index__(self):
                return int(self)
        with os.scandir(self.store.dir) as it:
            real_entry = next(e for e in it if e.name == "ok.txt")
        for shape in (S(str(ok)), B(os.fsencode(ok)), Entry(), real_entry):
            self.assertDenied(lambda shape=shape: open(shape).read())
            self.assertDenied(lambda shape=shape: io.FileIO(shape).read() and "")
        fd = os.open(ok, os.O_RDONLY)
        try:
            for shape in (Fd(fd), True):
                self.assertDenied(lambda shape=shape: open(shape, closefd=False).read())
        finally:
            os.close(fd)

    def test_stdlib_paths_still_work(self):
        """Positive control: ordinary file work inside the session still succeeds under the guard."""
        d = self.store.dir

        def use():
            (d / "a.txt").write_text("one")
            os.rename(d / "a.txt", d / "b.txt")
            with open(d / "b.txt") as f:
                text = f.read()
            os.mkdir(d / "sub")
            os.remove(d / "b.txt")
            return text + str(sorted(os.listdir(d / "sub")))
        self.assertEqual(self.read(use), "one[]")

    def test_deferred_signal_handler_refused(self):
        import signal
        import time
        got = []

        def handler(*_):
            got.append(open(self.secret).read())

        def body():
            signal.signal(signal.SIGALRM, handler)
            signal.setitimer(signal.ITIMER_REAL, 0.05)
            return "ok"
        try:
            self.assertDenied(body)
            time.sleep(0.2)
        finally:
            signal.setitimer(signal.ITIMER_REAL, 0)
            signal.signal(signal.SIGALRM, signal.SIG_DFL)
        self.assertEqual(got, [])

    def test_returned_object_del_refused(self):
        import gc
        got, secret = [], self.secret

        class Later:
            def __del__(self):
                try:
                    got.append(open(secret).read())
                except Exception:
                    pass
        self.assertDenied(Later)
        gc.collect()
        self.assertEqual(got, [])

    def test_finalizer_chain_refused(self):
        import gc
        got, secret, left = [], self.secret, [50]

        class Chain:  # each __del__ leaves a new cycle: the window cannot outwait it
            def __init__(self):
                self.me = self

            def __del__(self):
                if left[0] > 0:
                    left[0] -= 1
                    Chain()
                else:
                    try:
                        got.append(open(secret).read())
                    except Exception:
                        pass

        def body():
            Chain()
            return "ok"
        self.assertDenied(body)
        for _ in range(60):
            gc.collect()
        self.assertEqual(got, [])

    def test_atexit_thread_finalize_refused(self):
        import atexit
        import threading
        import weakref
        got = []

        def f(*_):
            got.append(open(self.secret).read())

        class Obj:
            pass
        keep = Obj()
        try:
            self.assertDenied(lambda: atexit.register(f) and None)
            self.assertDenied(lambda: threading.Thread(target=f).start())
            self.assertDenied(lambda: weakref.finalize(keep, f) and None)
            self.assertDenied(lambda: threading.settrace(f))
        finally:
            atexit.unregister(f)
            threading.settrace(None)
        del keep
        self.assertEqual(got, [])


if __name__ == "__main__":
    unittest.main()
