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


    def test_register_at_fork_refused(self):
        out, secret, armed = self.tmp / "child.txt", self.secret, [True]

        def leak():  # runs in the child of a later host fork
            if armed[0]:
                try:
                    out.write_text(open(secret).read())
                except Exception:
                    pass
        try:
            with self.assertRaises(ToolFileAccessDenied):
                self.read(lambda: os.register_at_fork(after_in_child=leak))
        finally:
            pid = os.fork()
            if pid == 0:
                os._exit(0)
            os.waitpid(pid, 0)
            armed[0] = False
        self.assertFalse(out.exists())

    def test_asyncgen_hooks_restored(self):
        before = tuple(sys.get_asyncgen_hooks())
        got, secret = [], self.secret

        def hook(agen):
            got.append(open(secret).read())

        async def agen():
            yield 1
        try:
            try:
                self.read(lambda: sys.set_asyncgen_hooks(firstiter=hook, finalizer=hook))
            except ToolFileAccessDenied:
                pass
            after = tuple(sys.get_asyncgen_hooks())
            a = agen()
            try:
                a.asend(None).send(None)
            except StopIteration:
                pass
        finally:
            sys.set_asyncgen_hooks(firstiter=before[0], finalizer=before[1])
        self.assertTrue(all(x is y for x, y in zip(after, before)))
        self.assertEqual(got, [])

    def test_logging_root_handler_restored(self):
        import logging
        got, secret, armed = [], self.secret, [True]
        level = logging.root.level

        class Leak(logging.Handler):
            def emit(self, record):
                pass

            def close(self):  # logging.shutdown calls it at host exit
                if armed[0]:
                    got.append(open(secret).read())
                super().close()

        def body():
            logging.root.addHandler(Leak())
            logging.root.setLevel(1)
        try:
            try:
                self.read(body)
            except ToolFileAccessDenied:
                pass
            left = [h for h in logging.root.handlers if isinstance(h, Leak)]
            logging.shutdown([r for r in list(logging._handlerList) if isinstance(r(), Leak)])
            self.assertEqual(logging.root.level, level)
        finally:
            armed[0] = False
            for h in logging.root.handlers[:]:
                if isinstance(h, Leak):
                    logging.root.removeHandler(h)
            logging.root.setLevel(level)
        self.assertEqual((left, got), ([], []))

    def test_sys_path_environ_restored(self):
        import subprocess
        path, env, cache = list(sys.path), dict(os.environ), dict(sys.path_importer_cache)

        def body():
            sys.path.insert(0, str(self.store.dir))
            sys.path_importer_cache[str(self.store.dir)] = None
            os.environ["ACP_LEAK"] = "1"
            os.environ["HOME"] = str(self.store.dir)
            os.putenv("ACP_RAW", "1")
        try:
            self.read(body)
            self.assertEqual(sys.path, path)
            self.assertEqual(dict(os.environ), env)
            self.assertEqual(sys.path_importer_cache.keys(), cache.keys())
            for k in ("ACP_LEAK", "ACP_RAW"):
                self.assertEqual(subprocess.run(["/usr/bin/printenv", k], capture_output=True).returncode, 1)
            self.assertEqual(subprocess.run(["/usr/bin/printenv", "HOME"], capture_output=True,
                                            text=True).stdout.strip(), env["HOME"])
        finally:
            sys.path[:] = path
            for k in ("ACP_LEAK", "ACP_RAW"):
                os.environ.pop(k, None)
                os.unsetenv(k)
            os.environ["HOME"] = env["HOME"]

    def test_every_snapshot_row_restored(self):
        import copyreg
        import gc
        import logging
        import threading

        def f(*_):
            return None

        class Finder:
            def find_spec(self, *_):
                return None

        class Key:
            pass
        sets = [lambda: sys.set_asyncgen_hooks(firstiter=f, finalizer=f),
                lambda: setattr(sys, "excepthook", f), lambda: setattr(sys, "unraisablehook", f),
                lambda: setattr(sys, "displayhook", f), lambda: setattr(sys, "breakpointhook", f),
                lambda: setattr(threading, "excepthook", f),
                lambda: sys.meta_path.insert(0, Finder()), lambda: sys.path_hooks.append(f),
                lambda: sys.path_importer_cache.__setitem__("/acp-row", None), lambda: sys.path.append("/acp-row"),
                lambda: os.environ.__setitem__("ACP_ROW", "1"), lambda: setattr(os, "environ", {}),
                lambda: sys.setprofile(f), lambda: sys.settrace(f),
                lambda: setattr(threading, "_profile_hook", f), lambda: setattr(threading, "_trace_hook", f),
                lambda: logging.root.addHandler(logging.NullHandler()), lambda: logging.root.setLevel(1),
                lambda: gc.callbacks.append(f), lambda: copyreg.dispatch_table.__setitem__(Key, f)]

        def state():
            held = lambda v: (v, dict(v) if isinstance(v, dict) else list(v))  # noqa: E731
            return {"asyncgen": tuple(sys.get_asyncgen_hooks()), "excepthook": sys.excepthook,
                    "unraisablehook": sys.unraisablehook, "displayhook": sys.displayhook,
                    "breakpointhook": sys.breakpointhook, "threading.excepthook": threading.excepthook,
                    "meta_path": held(sys.meta_path), "path_hooks": held(sys.path_hooks),
                    "path_importer_cache": held(sys.path_importer_cache), "path": held(sys.path),
                    "environ": (os.environ, dict(os.environ)), "profile": (sys.getprofile(), sys.gettrace()),
                    "threading.hooks": (threading._profile_hook, threading._trace_hook),
                    "root.handlers": held(logging.root.handlers), "root.level": logging.root.level,
                    "gc.callbacks": held(gc.callbacks), "dispatch_table": held(copyreg.dispatch_table)}

        def same(a, b):
            if isinstance(a, tuple):
                return len(a) == len(b) and all(same(x, y) for x, y in zip(a, b))
            if isinstance(a, list):
                return len(a) == len(b) and all(x is y or x == y for x, y in zip(a, b))
            if isinstance(a, dict) and not isinstance(a, type(os.environ)):
                return a.keys() == b.keys() and all(a[k] is b[k] or a[k] == b[k] for k in a)
            return a is b or (type(a) in (int, str) and a == b)

        def body():
            for s in sets:
                try:
                    s()
                except Exception:
                    pass
        before = state()
        try:
            try:
                self.read(body)
            except ToolFileAccessDenied:
                pass
            after = state()
        finally:  # put the host back by hand if the gate did not
            sys.set_asyncgen_hooks(firstiter=before["asyncgen"][0], finalizer=before["asyncgen"][1])
            for k, o, a in (("excepthook", sys, "excepthook"), ("unraisablehook", sys, "unraisablehook"),
                            ("displayhook", sys, "displayhook"), ("breakpointhook", sys, "breakpointhook"),
                            ("threading.excepthook", threading, "excepthook")):
                setattr(o, a, before[k])
            for k, o, a in (("meta_path", sys, "meta_path"), ("path_hooks", sys, "path_hooks"),
                            ("path_importer_cache", sys, "path_importer_cache"), ("path", sys, "path"),
                            ("root.handlers", logging.root, "handlers"), ("gc.callbacks", gc, "callbacks"),
                            ("dispatch_table", copyreg, "dispatch_table")):
                v, items = before[k]
                setattr(o, a, v)
                if isinstance(v, dict):
                    v.clear()
                    v.update(items)
                else:
                    v[:] = items
            os.environ = before["environ"][0]
            os.environ.pop("ACP_ROW", None)
            sys.setprofile(before["profile"][0])
            sys.settrace(before["profile"][1])
            threading._profile_hook, threading._trace_hook = before["threading.hooks"]
            logging.root.setLevel(before["root.level"])
        self.assertEqual([k for k in before if not same(before[k], after[k])], [])

    def call(self, body):
        try:
            self.read(body)
        except ToolFileAccessDenied:
            pass

    def test_root_filters_restored(self):
        import logging
        filters = list(logging.root.filters)
        try:
            self.call(lambda: logging.root.addFilter(lambda r: False))
            self.assertEqual(logging.root.filters, filters)
        finally:
            logging.root.filters[:] = filters

    def test_record_factory_restored(self):
        import logging
        factory = logging.getLogRecordFactory()
        try:
            self.call(lambda: logging.setLogRecordFactory(lambda *a, **k: None))
            self.assertIs(logging.getLogRecordFactory(), factory)
        finally:
            logging.setLogRecordFactory(factory)

    def test_std_streams_restored(self):
        import io
        streams = (sys.stdin, sys.stdout, sys.stderr)

        def body():
            sys.stdin, sys.stdout, sys.stderr = io.StringIO(), io.StringIO(), io.StringIO()
        try:
            self.call(body)
            self.assertEqual([a is b for a, b in zip((sys.stdin, sys.stdout, sys.stderr), streams)], [True] * 3)
        finally:
            sys.stdin, sys.stdout, sys.stderr = streams

    def test_pathfinder_attrs_restored(self):
        import importlib.machinery as m
        before = {c: dict(vars(c)) for c in (m.PathFinder, m.FileFinder)}

        def body():
            m.PathFinder.find_spec = classmethod(lambda cls, *a, **k: None)
            m.FileFinder.find_spec = lambda self, *a, **k: None
            m.FileFinder.acp_planted = staticmethod(lambda: None)
        try:
            self.call(body)
            for c, d in before.items():
                self.assertEqual(sorted(k for k in set(vars(c)) | set(d) if vars(c).get(k) is not d.get(k)), [])
        finally:
            for c, d in before.items():
                for k in [k for k in vars(c) if k not in d]:
                    delattr(c, k)
                for k, v in d.items():
                    if vars(c).get(k) is not v:
                        setattr(c, k, v)

    def test_original_std_streams_restored(self):  # P1
        import io
        streams = (sys.__stdin__, sys.__stdout__, sys.__stderr__)

        def body():
            sys.__stdin__, sys.__stdout__, sys.__stderr__ = io.StringIO(), io.StringIO(), io.StringIO()
        try:
            self.call(body)
            self.assertEqual([a is b for a, b in zip((sys.__stdin__, sys.__stdout__, sys.__stderr__), streams)],
                             [True] * 3)
        finally:
            sys.__stdin__, sys.__stdout__, sys.__stderr__ = streams

    def test_root_logger_binding_refused_and_restored(self):  # P3
        import logging
        root, manager = logging.root, logging.Logger.manager
        held = (logging.root, logging.Logger.root, logging.Logger.manager, manager.root)
        fake = logging.RootLogger(logging.WARNING)

        def body():
            logging.root = logging.Logger.root = manager.root = fake
            logging.Logger.manager = logging.Manager(fake)
        try:
            with self.assertRaises(ToolFileAccessDenied):
                self.read(body)
            now = (logging.root, logging.Logger.root, logging.Logger.manager, manager.root)
            self.assertEqual([a is b for a, b in zip(now, held)], [True] * 4)
        finally:
            logging.root = logging.Logger.root = manager.root = root
            logging.Logger.manager = manager

    def _swap_class(self, mod, cls, name, value):  # a module whose class was swapped: (refused, true value after)
        import types
        md = types.ModuleType.__dict__["__dict__"].__get__(mod)
        orig = md[name]

        def body():
            setattr(mod, name, value)
            mod.__class__ = cls(orig)
        try:
            with self.assertRaises(ToolFileAccessDenied) as cm:
                self.read(body)
            return orig, type(mod), md[name], str(cm.exception)
        finally:
            object.__dict__["__class__"].__set__(mod, types.ModuleType)
            md[name] = orig

    def test_module_class_swap_raising_setattr(self):  # P8
        import types

        def cls(orig):
            class Raise(types.ModuleType):
                def __setattr__(self, n, v):
                    raise AttributeError(n)
            return Raise
        orig, t, now, _ = self._swap_class(sys, cls, "excepthook", lambda *a: None)
        self.assertIs(t, types.ModuleType)
        self.assertIs(now, orig)

    def _lying(self, name):
        import types

        def cls(orig):
            class Lie(types.ModuleType):
                def __getattribute__(self, n):
                    return orig if n == name else super().__getattribute__(n)
            return Lie
        return cls

    def test_sys_class_swap_lying_refused(self):  # P9
        import types
        orig, t, now, msg = self._swap_class(sys, self._lying("excepthook"), "excepthook", lambda *a: None)
        self.assertEqual((t, now is orig, "type(sys)" in msg), (types.ModuleType, True, True))

    def test_logging_class_swap_lying_refused(self):  # P10
        import logging
        import types
        orig, t, now, msg = self._swap_class(logging, self._lying("_logRecordFactory"), "_logRecordFactory",
                                             lambda *a, **k: None)
        self.assertEqual((t, now is orig, "type(logging)" in msg), (types.ModuleType, True, True))

    def test_builtin_frozen_importer_attrs_restored(self):  # P12
        import importlib.machinery as m
        before = {c: dict(vars(c)) for c in (m.BuiltinImporter, m.FrozenImporter)}

        def body():
            m.BuiltinImporter.find_spec = classmethod(lambda cls, *a, **k: None)
            m.FrozenImporter.acp_planted = staticmethod(lambda: None)
        try:
            with self.assertRaises(ToolFileAccessDenied):
                self.read(body)
            for c, d in before.items():
                self.assertEqual(sorted(k for k in set(vars(c)) | set(d) if vars(c).get(k) is not d.get(k)), [])
        finally:
            for c, d in before.items():
                for k in [k for k in vars(c) if k not in d]:
                    delattr(c, k)
                for k, v in d.items():
                    if vars(c).get(k) is not v:
                        setattr(c, k, v)

    def test_logging_disable_restored(self):  # P13
        import logging
        before, log = logging.root.manager.disable, logging.getLogger("acp.test.disable")

        def body():
            logging.disable(logging.CRITICAL)
            log.isEnabledFor(logging.WARNING)  # fills the logger's cache with the disabled answer
        try:
            self.call(body)
            self.assertEqual((logging.root.manager.disable, log.isEnabledFor(logging.WARNING)), (before, True))
        finally:
            logging.disable(before)

    def test_print_logging_import_still_work(self):  # control: ordinary use is neither refused nor undone
        import contextlib
        import io
        import logging
        buf = io.StringIO()

        def body():
            import json
            print("hello", file=buf)
            logging.getLogger("acp.test.control").warning("hello")
            return json.dumps([1])
        with contextlib.redirect_stderr(io.StringIO()):
            out = self.read(body)
        self.assertEqual((out[0] if isinstance(out, tuple) else out, buf.getvalue()), ("[1]", "hello\n"))

    # fix12i: the checks look nothing up through module state at call time; every module and logger class is put
    # back; the restore loop is capped.
    def _in_time(self, fn, seconds=20):  # (finished, exception) with a deadline: a hung restore loop fails the test
        import threading
        box = {}

        def run():
            try:
                fn()
            except BaseException as e:
                box["e"] = e
        t = threading.Thread(target=run, daemon=True)
        t.start()
        t.join(seconds)
        return not t.is_alive(), box.get("e"), t

    def test_posixpath_class_swap_then_cross_session_read_refused(self):  # C20 (a)
        import posixpath
        import types
        sess = str(self.store.dir)

        class Lie(types.ModuleType):
            def __getattribute__(self, n):
                if n == "realpath":
                    return lambda p, *a, **k: sess + "/x"
                return types.ModuleType.__getattribute__(self, n)

        def body():
            posixpath.__class__ = Lie
            return "ok"
        try:
            with self.assertRaises(ToolFileAccessDenied):
                self.read(body)
            self.assertIs(type(posixpath), types.ModuleType)
            self.assertDenied(lambda: open(self.secret).read())
        finally:
            object.__setattr__(posixpath, "__class__", types.ModuleType)

    def test_any_module_or_logger_class_swap_restored_and_refused(self):  # C20 (b)
        import builtins
        import importlib
        import json
        import logging
        import types
        lg = logging.getLogger("acp.x")

        class Mod(types.ModuleType):
            pass

        class Lg(logging.Logger):
            pass
        for name, o, cls in (("builtins", builtins, Mod), ("importlib", importlib, Mod), ("json", json, Mod),
                             ("logger acp.x", lg, Lg)):
            t = type(o)
            try:
                with self.assertRaises(ToolFileAccessDenied) as cm:
                    self.read(lambda: (object.__setattr__(o, "__class__", cls), "ok")[1])
                self.assertIn(f"type({name})", str(cm.exception))
                self.assertIs(type(o), t)
            finally:
                object.__setattr__(o, "__class__", t)

    def test_noop_setter_property_hits_restore_cap(self):  # C20 (c)
        import logging
        cls = type(logging.root)
        box = {}

        def body():
            cls.level = property(lambda s: 99, lambda s, v: None)
            return "ok"
        try:
            done, e, _ = self._in_time(lambda: box.setdefault("r", self.read(body)))
            self.assertTrue(done, "restore loop did not stop")
            self.assertIsInstance(e, ToolFileAccessDenied)
            self.assertIn("(not restored)", str(e))
        finally:
            if "level" in vars(cls):
                del cls.level


    # fix12j: modules and loggers first made during the call are class-checked too
    def _fresh(self, mod, logger):
        import logging
        sys.modules.pop(mod, None)
        logging.root.manager.loggerDict.pop(logger, None)

    def test_module_imported_in_body_class_swap_restored_and_refused(self):  # C21 (15)
        import types
        self._fresh("colorsys", "")
        box = {}

        class Mod(types.ModuleType):
            pass

        def body():
            import colorsys
            box["m"] = colorsys
            object.__setattr__(colorsys, "__class__", Mod)
            return "ok"
        try:
            with self.assertRaises(ToolFileAccessDenied) as cm:
                self.read(body)
            self.assertIn("type(colorsys)", str(cm.exception))
            self.assertIs(type(box["m"]), types.ModuleType)
        finally:
            if "m" in box:
                object.__setattr__(box["m"], "__class__", types.ModuleType)

    def test_logger_made_in_body_class_swap_restored_and_refused(self):  # C21 (16)
        import logging
        self._fresh("colorsys", "jc21.new.child")
        box = {}

        class Lg(logging.Logger):
            pass

        def body():
            lg = box["l"] = logging.getLogger("jc21.new.child")
            object.__setattr__(lg, "__class__", Lg)
            return "ok"
        try:
            with self.assertRaises(ToolFileAccessDenied) as cm:
                self.read(body)
            self.assertIn("type(logger jc21.new.child)", str(cm.exception))
            self.assertIs(type(box["l"]), logging.Logger)
        finally:
            if "l" in box:
                object.__setattr__(box["l"], "__class__", logging.Logger)
            for n in ("jc21.new.child", "jc21.new", "jc21"):
                logging.root.manager.loggerDict.pop(n, None)

    def test_new_import_and_new_logger_still_work(self):  # control
        import contextlib
        import io
        import logging
        self._fresh("colorsys", "acp.fix12j.new.child")

        def body():
            import colorsys
            logging.getLogger("acp.fix12j.new.child").warning("hi")
            return str(colorsys.rgb_to_hsv(0, 0, 0))
        with contextlib.redirect_stderr(io.StringIO()):
            out = self.read(body)
        self.assertEqual(out[0] if isinstance(out, tuple) else out, "(0.0, 0.0, 0)")
        logging.root.manager.loggerDict.pop("acp.fix12j.new.child", None)
        logging.root.manager.loggerDict.pop("acp.fix12j.new", None)
        logging.root.manager.loggerDict.pop("acp.fix12j", None)

    # fix12k: a placeholder or lazy-module class passes only when its contents are real (C22)
    def _drop_loggers(self, *names):
        import logging
        for n in names:
            logging.root.manager.loggerDict.pop(n, None)

    def test_existing_logger_swapped_to_placeholder_restored_and_refused(self):  # C22 (a)
        import logging
        self._drop_loggers("jc22.old")
        lg = logging.getLogger("jc22.old")

        def body():
            object.__setattr__(lg, "__class__", logging.PlaceHolder)
            return "ok"
        try:
            with self.assertRaises(ToolFileAccessDenied) as cm:
                self.read(body)
            self.assertIn("type(logger jc22.old)", str(cm.exception))
            self.assertIs(type(lg), logging.Logger)
        finally:
            object.__setattr__(lg, "__class__", logging.Logger)
            self._drop_loggers("jc22.old", "jc22")

    def test_new_logger_swapped_to_placeholder_restored_and_refused(self):  # C22 (b)
        import logging
        self._drop_loggers("jc22.new", "jc22")
        box = {}

        def body():
            lg = box["l"] = logging.getLogger("jc22.new")
            object.__setattr__(lg, "__class__", logging.PlaceHolder)
            return "ok"
        try:
            with self.assertRaises(ToolFileAccessDenied) as cm:
                self.read(body)
            self.assertIn("type(logger jc22.new)", str(cm.exception))
            self.assertIs(type(box["l"]), logging.Logger)
        finally:
            if "l" in box:
                object.__setattr__(box["l"], "__class__", logging.Logger)
            self._drop_loggers("jc22.new", "jc22")

    def test_placeholder_with_foreign_loggermap_key_refused(self):  # C22 (c)
        import logging
        self._drop_loggers("jc22.ph.child", "jc22.ph", "jc22")
        reads = []

        class Evil:
            @property
            def parent(self):
                reads.append(1)
                return logging.root

        def body():
            logging.getLogger("jc22.ph.child")
            logging.root.manager.loggerDict["jc22.ph"].loggerMap[Evil()] = None
            return "ok"
        try:
            with self.assertRaises(ToolFileAccessDenied) as cm:
                self.read(body)
            self.assertIn("type(logger jc22.ph)", str(cm.exception))
            ph = logging.root.manager.loggerDict["jc22.ph"]
            self.assertIs(type(ph), logging.PlaceHolder)
            self.assertFalse([k for k in ph.loggerMap if type(k) is Evil])
            logging.getLogger("jc22.ph")  # logging fixes up the children: no foreign code runs
            self.assertEqual(reads, [])
        finally:
            self._drop_loggers("jc22.ph.child", "jc22.ph", "jc22")

    def test_new_module_swapped_to_lazy_module_restored_and_refused(self):  # C22 (d)
        import importlib.util
        import types
        self._fresh("colorsys", "")
        box = {}

        def body():
            import colorsys
            box["m"] = colorsys
            object.__setattr__(colorsys, "__class__", importlib.util._LazyModule)
            return "ok"
        try:
            with self.assertRaises(ToolFileAccessDenied) as cm:
                self.read(body)
            self.assertIn("type(colorsys)", str(cm.exception))
            self.assertIs(type(box["m"]), types.ModuleType)
        finally:
            if "m" in box:
                object.__setattr__(box["m"], "__class__", types.ModuleType)

    def test_real_lazy_import_still_works(self):  # control
        import importlib.util
        self._fresh("colorsys", "")
        box = {}

        def body():
            spec = importlib.util.find_spec("colorsys")
            loader = importlib.util.LazyLoader(spec.loader)
            spec.loader = loader
            m = box["m"] = importlib.util.module_from_spec(spec)
            sys.modules["colorsys"] = m
            loader.exec_module(m)
            return "ok"
        out = self.read(body)
        self.assertEqual(out[0] if isinstance(out, tuple) else out, "ok")
        self.assertIs(type(box["m"]), importlib.util._LazyModule)
        self.assertEqual(box["m"].rgb_to_hsv(0, 0, 0), (0.0, 0.0, 0))
        sys.modules.pop("colorsys", None)

    def test_getlogger_placeholders_still_work(self):  # control
        import logging
        self._drop_loggers("jc22ok.b.c", "jc22ok.b.d", "jc22ok.b", "jc22ok")

        def body():
            logging.getLogger("jc22ok.b.c")
            logging.getLogger("jc22ok.b.d")
            return "ok"
        out = self.read(body)
        self.assertEqual(out[0] if isinstance(out, tuple) else out, "ok")
        self.assertIs(type(logging.root.manager.loggerDict["jc22ok.b"]), logging.PlaceHolder)
        self._drop_loggers("jc22ok.b.c", "jc22ok.b.d", "jc22ok.b", "jc22ok")

if __name__ == "__main__":
    unittest.main()
