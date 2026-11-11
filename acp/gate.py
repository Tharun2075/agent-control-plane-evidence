"""B1d: tool runner with permission check and approval gate.

Every tool call goes through ToolRunner.call(). It
1. refuses a tool the manifest does not allow (logged, outcome refused_not_permitted);
   It also refuses (logged) once current_task.expires has passed, and treats a
   missing delegated_authority as no authority (fail closed). This is authorise(),
   the one check SessionStore (write, read, handoff) also calls;
2. for a tool the manifest marks outbound or irreversible, computes
   action_sha256 over (agent, session, tool, action, payload) and looks for an
   approval record approvals/<first 16 hex>.json whose action_sha256 matches.
   No record: the call is blocked and logged (outcome blocked_pending_approval).
   A changed payload changes the digest, so an approval cannot be reused for a
   different message or recipient;
   An approval is single-use: before the tool runs, the call claims it by
   creating approvals/<name>.claimed with O_CREAT|O_EXCL, an atomic step even
   across processes. Only the call that creates the marker runs the tool; a
   second caller is refused and logged. The record is then marked consumed with
   the log record and outcome (ok or error) of the call that used it, so a tool
   that raises does not leave a reusable approval;
3. checks URLs by parsed, normalised parts, not by raw string (see check_url);
   a tool that reports a final URL after redirects has that URL checked too;
4. runs the tool and logs the result with its provenance and decision mode.
"""
from __future__ import annotations

import atexit
import codecs
import copyreg
import faulthandler
import gc
import hashlib
import hmac
import json
import logging
import os
import pathlib
import re
import secrets
import signal
import sys
import threading
import types
import weakref
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable
from urllib.parse import unquote, urlsplit, urlunsplit

from .agent import AgentContext
from .canon import canonical, digest
from .log import _WRITING as _LOG_WRITING
from .manifest import tool_spec


def _parse(ts: str) -> datetime:
    if not isinstance(ts, str):  # e.g. an int: invalid, so callers fail closed and log it
        raise ValueError(f"expires must be an ISO 8601 string, not {type(ts).__name__}")
    dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
    if dt.tzinfo is None:  # a naive time means whatever the host TZ says: refuse, do not guess
        raise ValueError(f"expires {ts!r} has no UTC offset")
    return dt.astimezone(timezone.utc)


class PermissionDenied(Exception):
    def __init__(self, message: str, outcome: str = "refused_not_permitted"):
        super().__init__(message)
        self.outcome = outcome


class ToolFileAccessDenied(PermissionDenied):
    """A tool body opened a file outside its own session namespace."""

    def __init__(self, path: str):
        super().__init__(f"tool file access outside session: {path}", "refused_outside_session")
        self.path = path


# Path guard: while a tool body runs, every file open on this thread (builtins.open,
# io.open, os.open, pathlib, open_code) is checked by an audit hook. Allowed: anything
# under the session dir; reads under declared read roots and the Python install; writes
# under declared write roots and the hash-chained log. Everything else raises.
# Deny by default: any other audit event not on the short safe list is refused when a str/bytes/path
# argument is relative or resolves outside the allowed dirs (checked as a write). Native calls that touch
# files or start processes without an audit event (_posixsubprocess.fork_exec, os.mkfifo, os.mknod,
# readline history files, dbm) are wrapped or refused at import.
# One rule for process-global hooks a tool body could leave behind: irreversible ones are REFUSED while the
# body runs (signal handlers and timers, atexit, thread starts, weakref.finalize, sys.addaudithook,
# os.register_at_fork, codecs.register/register_error, faulthandler.enable/register/dump_traceback_later);
# the rest are SNAPSHOT before the body and RESTORED after it (the _RESTORED table below: interpreter hooks,
# import finders and path state, sys.path, os.environ, std streams, profile/trace, the root logger's handlers,
# filters and level, the root logger binding and logging.disable, the log record factory, gc.callbacks, copyreg;
# a module or logger whose class was swapped is put back and the call refused). The result
# leaves as JSON data only and the body's objects are collected inside the window, so __del__ runs guarded.
# Scope: the guard lives in the gate process and binds tool code that does not tamper with the gate
# (its globals, the hook, a removed sqlite authorizer, the wrapped functions) or with shared interpreter
# state outside the restored list (ctypes, object-graph walking, sys.modules, builtins, patched modules,
# objects reachable from restored state that are mutated in place, attributes not on that list).
# Metadata calls (os.stat, os.access, os.path.exists) raise no audit event, and file descriptors the host
# already holds are not tracked. An OS sandbox per tool is the next step.
_GUARD = threading.local()
_PY_ROOTS = tuple({Path(p).resolve() for p in (sys.prefix, sys.base_prefix, sys.exec_prefix, sys.base_exec_prefix)}
                  | {Path(__file__).resolve().parent})
_WRITE_FLAGS = os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND


def _under(p: Path, roots) -> bool:
    return any(p == r or r in p.parents for r in roots)


# Audit events the guard checks. Path events: (event -> (path arg indexes, writes?, dir_fd arg indexes)).
_PATH_EVENTS = {
    "os.remove": ((0,), True, (1,)), "os.rmdir": ((0,), True, (1,)), "os.mkdir": ((0,), True, (2,)),
    "os.rename": ((0, 1), True, (2, 3)), "os.link": ((0, 1), True, (2, 3)), "os.symlink": ((1,), True, (2,)),
    "os.chmod": ((0,), True, (2,)), "os.chown": ((0,), True, (3,)), "os.truncate": ((0,), True, ()),
    "os.utime": ((0,), True, (3,)), "os.listdir": ((0,), False, ()), "os.scandir": ((0,), False, ()),
    # Events with a non-path string argument (a glob pattern, a mode name): only the path positions are checked.
    "pathlib.Path.glob": ((0,), False, ()), "pathlib.Path.rglob": ((0,), False, ()),
    "shutil.copyfile": ((1,), True, ()), "shutil.copymode": ((1,), True, ()), "shutil.copystat": ((1,), True, ()),
    "shutil.copytree": ((1,), True, ()), "shutil.move": ((0, 1), True, ()), "shutil.rmtree": ((0,), True, (1,)),
}
# Events a tool body may not raise at all: new processes, threads the guard cannot follow, cwd changes, native code,
# and code the host would run after the body returns (trace/profile functions, audit and async-generator hooks).
# Python < 3.13 raises no audit event for a thread start; there the thread-start functions are wrapped below.
_DENY_EVENTS = {"os.chdir", "os.system", "os.exec", "os.posix_spawn", "os.spawn", "os.fork", "os.forkpty",
                "subprocess.Popen", "_thread.start_new_thread", "_thread.start_joinable_thread", "ctypes.dlopen",
                "ctypes.dlsym", "sqlite3.enable_load_extension", "sqlite3.load_extension", "sys.setprofile",
                "sys.settrace", "sys.addaudithook", "sys.set_asyncgen_hooks_firstiter",
                "sys.set_asyncgen_hooks_finalizer", "sys.monitoring.register_callback"}
# Events whose arguments are code, names, data or network addresses, never file paths: they pass.
# Every event not handled by name in _open_hook and not listed here is checked argument by argument.
_SAFE_EVENTS = {"import", "exec", "compile", "code.__new__", "function.__new__", "marshal.loads", "marshal.dumps",
                "marshal.load", "pickle.find_class", "object.__getattr__", "object.__setattr__",
                "object.__delattr__", "sys._getframe", "array.__new__",
                "fcntl.fcntl", "fcntl.ioctl", "fcntl.flock", "fcntl.lockf", "socket.__new__", "builtins.input",
                "builtins.input/result", "socket.getaddrinfo", "socket.gethostbyname", "socket.gethostbyname_ex",
                "socket.gethostbyaddr", "socket.getnameinfo", "socket.getservbyname", "socket.getservbyport",
                "http.client.connect", "http.client.send", "urllib.Request", "smtplib.connect", "smtplib.send",
                "os.putenv", "os.unsetenv"}
# Socket events (sock, address): a str/bytes/path address is an AF_UNIX file path, whatever the socket claims.
_SOCKET_EVENTS = {"socket.bind", "socket.connect", "socket.sendto", "socket.sendmsg"}
# Modules that create or read files in C without an audit event: their import is refused in a tool body,
# and if one was imported before, its file functions are wrapped (see _guard_native).
_NATIVE_FILE_MODULES = {"readline": ("read_history_file", "write_history_file", "append_history_file",
                                     "read_init_file"),
                        "_dbm": ("open",), "dbm.ndbm": ("open",), "_gdbm": ("open",), "dbm.gnu": ("open",)}
# C modules a tool body may not load: file access without an audit event, or a fresh copy that would lack
# the wrappers installed below. Refused by name at import and at _imp.create_builtin/create_dynamic.
_NATIVE_GUARDED = {"readline", "_dbm", "_gdbm", "_posixsubprocess", "posix", "nt", "_thread", "_imp", "_signal",
                   "atexit"}
_SQLITE_MEMORY = ("", ":memory:")
_SQLITE_SIDE = ("", "-journal", "-wal", "-shm")  # SQLite opens these beside the database without an audit event


def _deny(what: str):
    _GUARD.denied = what
    raise ToolFileAccessDenied(what)


# Path arguments: only types whose text cannot change between the check and the use. Native calls (the open
# event, the os.* path events, sqlite, sockets, any other event) take an exact str or bytes, or an exact int where
# a file descriptor is allowed: a str/bytes subclass, an object with __fspath__ (a pathlib subclass, a DirEntry
# look-alike) or even a stdlib Path (its cached text can be changed by a gc callback after C converted it) could
# show the guard one path and the OS another. The wrappers below (builtins.open, io.open, os path functions) turn
# an exact stdlib pathlib path into its string once before the native call, so the string checked is the one opened.
_PATHLIB_TYPES = (pathlib.PurePath, pathlib.PurePosixPath, pathlib.PureWindowsPath, pathlib.Path, pathlib.PosixPath,
                  pathlib.WindowsPath)


def _plain(x, pathlib_ok=False, fd_ok=False):
    """x as an exact str/bytes (or exact int fd when fd_ok); an exact stdlib pathlib path converted once when
    pathlib_ok; any other type is refused."""
    t = type(x)
    if t is str or t is bytes or (fd_ok and t is int):
        return x
    if pathlib_ok and t in _PATHLIB_TYPES:
        s = os.fspath(x)
        if type(s) is str:
            return s
    _deny(f"path argument of type {t.__name__}: pass a str, bytes or stdlib pathlib path")


def _outside(g, path, writes: bool):
    """The resolved path if the guard refuses it, else None."""
    if isinstance(path, int):  # an fd that was already checked when it was opened
        return None
    raw = os.fsdecode(path if path is not None else ".")
    target = os.path.realpath(raw)  # symlinks and '..' resolved before the check
    p = Path(target)
    session, reads, writes_ok = g
    if _under(p, (session,)) or (_under(p, writes_ok) if writes else _under(p, reads + _PY_ROOTS)):
        return None
    if not writes and raw in _SYS_PATH:  # the import system lists sys.path entries; names only
        return None
    return target


def _check_path(g, path, writes: bool):
    target = _outside(g, path, writes)
    if target is not None:
        _deny(target)


def _sqlite_file(db) -> str:
    """Refusal reason for a sqlite database name, or '' when it is a plain absolute path or in-memory."""
    if db is None:
        return "sqlite database given as an expression"
    name = os.fsdecode(db)
    if name in _SQLITE_MEMORY:
        return ""
    if name.lower().startswith("file:"):
        return f"sqlite URI {name!r}"
    if not os.path.isabs(name):
        return f"relative sqlite path {name!r}"
    return ""


def _sqlite_authorizer(g):
    import sqlite3

    def authorize(action, arg1, arg2, db_name, trigger):
        # ATTACH and VACUUM INTO both reach SQLite as an attach of a new file.
        if action != sqlite3.SQLITE_ATTACH or (arg1 is not None and os.fsdecode(arg1) in _SQLITE_MEMORY):
            return sqlite3.SQLITE_OK
        why = _sqlite_file(arg1) or next(filter(None, (_outside(g, os.fsdecode(arg1) + x, True) for x in _SQLITE_SIDE)), None)
        if not why:
            return sqlite3.SQLITE_OK
        if getattr(_GUARD, "allow", None) is not None:
            _GUARD.denied = why  # the tool body cannot hide the refusal by catching the sqlite error
        return sqlite3.SQLITE_DENY
    return authorize


def _open_hook(event, args):
    g = getattr(_GUARD, "allow", None)
    if g is None or getattr(_LOG_WRITING, "on", False):
        return
    if event in ("os.putenv", "os.unsetenv"):  # raw environment edits: the key is put back after the call
        k = args[0]
        if type(k) not in (str, bytes):  # only exact str/bytes keys: the put-back never runs tool code
            _deny(f"{event} key of type {type(k).__name__}")
        _GUARD.env_raw.add(os.fsencode(k))
        return
    if event == "open":
        path, mode, flags = args
        if path is None:
            return
        path = _plain(path, fd_ok=True)
        if type(path) is not int and not os.path.isabs(os.fsdecode(path)):
            _deny(f"relative path {os.fsdecode(path)!r}")  # dir_fd is not in the event: refuse relative opens
        writes = bool(mode and any(c in mode for c in "wax+")) or bool(flags and flags & _WRITE_FLAGS)
        _check_path(g, path, writes)
    elif event in _PATH_EVENTS:
        idx, writes, fds = _PATH_EVENTS[event]
        if any(i < len(args) and args[i] not in (None, -1) for i in fds):
            _deny(f"{event} with dir_fd")
        for i in idx:  # os.* events come from C: exact types; pathlib/shutil events are Python-level notices
            _check_path(g, _plain(args[i], pathlib_ok=not event.startswith("os."), fd_ok=True), writes)
        if event == "os.symlink":  # C code (SQLite side files) follows links unseen, and a link can be re-pointed
            _deny("symlink inside a tool body " + os.fsdecode(args[1]))
    elif event == "sqlite3.connect":
        db = args[0] if args else None
        db = db if db is None else _plain(db)
        why = _sqlite_file(db)
        if why:
            _deny(why)
        if os.fsdecode(db) not in _SQLITE_MEMORY:
            for side in _SQLITE_SIDE:
                _check_path(g, os.fsdecode(db) + side, True)
    elif event == "sqlite3.connect/handle":
        # The connection is not ready inside this event; the authorizer goes on at the next profile event
        # on this thread (the return from connect), before any statement can run.
        _GUARD.sqlite_pending = getattr(_GUARD, "sqlite_pending", []) + [(args[0], _sqlite_authorizer(g))]
        if sys.getprofile() is not _sqlite_profile:
            _GUARD.sqlite_prev_profile = sys.getprofile()
            _set_profile(_sqlite_profile)
    elif event in _DENY_EVENTS:
        if not (event == "sys.setprofile" and getattr(_GUARD, "internal", False)):  # the gate's own sqlite hook
            _deny(event)
    elif event in _SOCKET_EVENTS:
        addr = args[1]
        if addr is not None and not isinstance(addr, tuple):  # inet addresses are tuples; anything else is a file path
            if type(addr) not in (str, bytes):  # exact types: the C code parses the same immutable value we check
                _deny(f"{event} with a non-str/bytes address")
            _check_arg(g, event, addr)  # bind creates the socket file
    elif event == "import":
        _check_module(g, args[0] if args else "")  # first load only: re-import of a loaded module raises no event
    elif event not in _SAFE_EVENTS:  # deny by default: any other event with an outside path argument is refused
        _check_args(g, event, args)


def _check_args(g, event, args):
    for a in args:
        if isinstance(a, (tuple, list)):
            _check_args(g, event, a)
        elif isinstance(a, (str, bytes, os.PathLike)):
            _check_arg(g, event, a)


def _check_arg(g, event, a):
    try:
        raw = os.fsdecode(_plain(a))
    except (TypeError, ValueError):
        _deny(f"{event} with an undecodable argument")
    if "\0" in raw or not os.path.isabs(raw):
        _deny(f"{event} with non-absolute argument {raw!r}")
    _check_path(g, raw, True)  # an unknown event may write: fail closed


def _sqlite_profile(frame, event, arg):
    import sqlite3
    waiting = []
    for conn, auth in getattr(_GUARD, "sqlite_pending", []):
        try:
            sqlite3.Connection.set_authorizer(conn, auth)  # base method: a Connection subclass cannot skip it
        except Exception:  # still inside connect: try again; _run_guarded refuses if it never goes on
            waiting.append((conn, auth))
    _GUARD.sqlite_pending = waiting
    if not waiting:
        _set_profile(getattr(_GUARD, "sqlite_prev_profile", None))


def _set_profile(fn):
    _GUARD.internal = True
    try:
        sys.setprofile(fn)
    finally:
        _GUARD.internal = False


def _guard_call(fn, what, check=None):
    """Wrap a native call that raises no audit event: refused (or its path checked) inside a tool body."""
    def guarded(*a, **kw):
        g = getattr(_GUARD, "allow", None)
        if g is not None and not getattr(_LOG_WRITING, "on", False):
            if check is None:
                _deny(what)
            check(g, *a, **kw)
        return fn(*a, **kw)
    guarded._acp_guard = True
    return guarded


def _guard_thread_start(start):
    return _guard_call(start, "thread start")


def _check_module(g, name):
    if type(name) is not str:
        _deny("import with a non-str module name")
    if name.rpartition(".")[2] in _NATIVE_GUARDED:  # the C init symbol is PyInit_<last name part>
        _deny(f"loading {name}: native file or process access without an audit event")


def _guard_create(fn):
    """_imp.create_builtin/create_dynamic inside a tool body: check the name, then load from a fresh spec built
    from the values checked, so a spec whose attributes change between reads cannot slip a guarded module in."""
    def guarded(spec, *a):
        g = getattr(_GUARD, "allow", None)
        if g is None or getattr(_LOG_WRITING, "on", False):
            return fn(spec, *a)
        name, origin = getattr(spec, "name", None), getattr(spec, "origin", None)
        _check_module(g, name)
        if origin is not None and (type(origin) is not str or not _under(Path(os.path.realpath(origin)), _PY_ROOTS)):
            _deny(f"native module load from outside the Python install: {origin!r}")
        return fn(importlib.machinery.ModuleSpec(name, None, origin=origin), *a)
    guarded._acp_guard = True
    return guarded


def _check_node(g, path, *a, dir_fd=None, **kw):
    if dir_fd is not None or type(path) is int:
        _deny("mkfifo/mknod with dir_fd")
    _check_arg(g, "mkfifo/mknod", path)


def _guard_paths(fn, n):
    """Wrap a path function: inside a tool body its first n path arguments become plain str/bytes before the call,
    so the audit hook and any check see the exact string the OS gets."""
    def guarded(*a, **kw):
        if getattr(_GUARD, "allow", None) is not None and not getattr(_LOG_WRITING, "on", False):
            a = tuple(_plain(x, True, True) if i < n else x for i, x in enumerate(a))
            for k in ("file", "path", "src", "dst", "database"):
                if k in kw:
                    kw[k] = _plain(kw[k], True, True)
        return fn(*a, **kw)
    guarded._acp_guard = True
    return guarded


def _wrap(mod, name, what, check=None):
    fn = getattr(mod, name, None)
    if fn is not None and not getattr(fn, "_acp_guard", False):
        setattr(mod, name, _guard_call(fn, what, check))


def _guard_native():
    """Wrap the file functions of C modules that were imported before a tool body ran (their import is refused)."""
    for mod_name, names in _NATIVE_FILE_MODULES.items():
        mod = sys.modules.get(mod_name)
        for name in names if mod is not None else ():
            _wrap(mod, name, f"{mod_name}.{name}: file access in C without an audit event")


if sys.version_info < (3, 13):  # no audit event for a thread start: refuse it at the start functions
    import _thread
    for _name in ("start_new_thread", "start_new", "start_joinable_thread"):  # every alias of the start function
        if hasattr(_thread, _name):
            setattr(_thread, _name, _guard_thread_start(getattr(_thread, _name)))
    threading._start_new_thread = _guard_thread_start(threading._start_new_thread)

# Process starts that raise no audit event (_posixsubprocess.fork_exec backs subprocess and multiprocessing
# spawn/forkserver) and file nodes created in C without one (mkfifo, mknod): refused or checked at the call.
import _imp  # noqa: E402
import _posixsubprocess  # noqa: E402
import multiprocessing.process  # noqa: E402
import importlib.machinery  # noqa: E402
_imp.create_builtin = _guard_create(_imp.create_builtin)
_imp.create_dynamic = _guard_create(_imp.create_dynamic)
_wrap(_posixsubprocess, "fork_exec", "process start")
_wrap(multiprocessing.process.BaseProcess, "start", "process start")
for _mod in {os, sys.modules[os.name]}:
    for _name in ("fork", "forkpty", "posix_spawn", "posix_spawnp"):
        _wrap(_mod, _name, "process start")
    for _name in ("mkfifo", "mknod"):
        _wrap(_mod, _name, None, _check_node)
        setattr(_mod, _name, _guard_paths(getattr(_mod, _name), 1))  # convert first, then _check_node checks it
for _name, _n in (("open", 1), ("remove", 1), ("unlink", 1), ("rmdir", 1), ("mkdir", 1), ("chmod", 1),
                  ("chown", 1), ("lchown", 1), ("truncate", 1), ("utime", 1), ("listdir", 1), ("scandir", 1),
                  ("rename", 2), ("replace", 2), ("link", 2), ("symlink", 2)):
    if hasattr(os, _name):
        setattr(os, _name, _guard_paths(getattr(os, _name), _n))
import builtins  # noqa: E402
import io  # noqa: E402
import sqlite3  # noqa: E402
builtins.open = io.open = _guard_paths(io.open, 1)  # pathlib's Path.open calls io.open
sqlite3.connect = _guard_paths(sqlite3.connect, 1)
_guard_native()
# Code the host would run after the body returns, with no audit event: signal handlers and timers, exit
# functions, finalizers, trace/profile functions for new threads. Refused inside a tool body.
import _signal  # noqa: E402
for _mod in (signal, _signal):
    for _name in ("signal", "setitimer", "alarm", "set_wakeup_fd"):
        _wrap(_mod, _name, f"deferred code: signal.{_name}")
_wrap(atexit, "register", "deferred code: atexit.register")
_wrap(threading, "_register_atexit", "deferred code: threading._register_atexit")
for _name in ("setprofile", "settrace", "setprofile_all_threads", "settrace_all_threads"):
    _wrap(threading, _name, f"deferred code: threading.{_name}")
_wrap(weakref.finalize, "__init__", "deferred code: weakref.finalize")
for _mod in {os, sys.modules[os.name]}:
    _wrap(_mod, "register_at_fork", "deferred code: os.register_at_fork")
import _codecs  # noqa: E402
for _mod in (codecs, _codecs):
    for _name in ("register", "register_error"):
        _wrap(_mod, _name, f"deferred code: codecs.{_name}")
for _name in ("enable", "register", "dump_traceback_later"):
    _wrap(faulthandler, _name, f"deferred code: faulthandler.{_name}")


_MODULE_DICT = types.ModuleType.__dict__["__dict__"].__get__  # a module's own dict, read past type(o)
_SET_CLASS = object.__dict__["__class__"].__set__


def _attr(o, a):  # an attribute: the same object is put back; a module's is read and written in its own dict
    if type(o) is types.ModuleType:
        d = _MODULE_DICT(o)
        get, put = (lambda: d.get(a)), (lambda v: d.__setitem__(a, v))
    else:
        get, put = (lambda: getattr(o, a, None)), (lambda v: setattr(o, a, v))

    def restore(v):
        if get() is v:
            return False
        put(v)
        return True
    return get, restore


def _class_of(o):  # an object's class (a swapped one can lie about every attribute): it is put back first
    t = type(o)

    def restore(_):
        if type(o) is t:
            return False
        _SET_CLASS(o, t)
        return True
    return lambda: t, restore


def _held(o, a):  # a list or dict attribute: the same object is put back, holding the same items
    get, put = _attr(o, a)

    def snap():
        v = get()
        return v, dict(v) if type(v) is dict else list(v)

    def restore(snap):
        v, items = snap
        changed = put(v)
        same = len(v) == len(items) and all(  # identity in order only: no tool __eq__ or __hash__ runs
            x is y for x, y in zip(v, items))
        if type(v) is dict:
            same = same and all(x is y for x, y in zip(v.values(), items.values()))
        if same:
            return changed
        if type(v) is dict:
            v.clear()
            v.update(items)
        else:
            v[:] = items
        return True
    return snap, restore


def _quiet(fn, *a):  # the gate's own call to a setter the audit hook refuses; no tool object is compared or dropped here
    on = getattr(_LOG_WRITING, "on", False)
    _LOG_WRITING.on = True
    try:
        fn(*a)
    finally:
        _LOG_WRITING.on = on


def _pair(get, put):  # a getter/setter pair of two hooks
    def restore(v):
        cur = tuple(get())  # held until the guard is back on, so a dropped hook's __del__ runs guarded
        if all(x is y for x, y in zip(cur, v)):
            return False
        _quiet(put, *v)
        return True
    return lambda: tuple(get()), restore


def _env_snap():
    _GUARD.env_raw = set()
    return os.environ, os.environ._data, dict(os.environ._data)


def _env_restore(snap):  # os.environ and the process environment (raw os.putenv keys come from the audit hook)
    env, held, data = snap
    changed = _attr(os, "environ")[1](env) | _attr(env, "_data")[1](held)
    raw, _GUARD.env_raw = _GUARD.env_raw, set()  # exact bytes only (the audit hook refuses other key types)
    if not raw and len(held) == len(data) and all(  # identity in order only: no tool __eq__ or __hash__ runs
            a is b and x is y for (a, x), (b, y) in zip(zip(held.keys(), held.values()), data.items())):
        return changed
    gone = [k for k in list(held.keys()) + list(raw) if type(k) is bytes and k not in data]
    held.clear()  # planted keys of any type go with the clear
    held.update(data)
    for k in gone:
        _quiet(os.unsetenv, k)
    for k, v in data.items():
        _quiet(os.putenv, k, v)
    return True


def _class_dict(cls):  # a class's own attributes (import finders): changed or added keys are put back
    def restore(snap):
        cur, changed = vars(cls), False
        for k in [k for k in cur if k not in snap]:
            delattr(cls, k)
            changed = True
        for k, v in snap.items():
            if cur.get(k) is not v:
                setattr(cls, k, v)
                changed = True
        return changed
    return lambda: dict(vars(cls)), restore


def _disable_restore(v):  # logging.disable: the level is put back and the loggers' cached checks dropped
    m = logging.root.manager
    if type(m.disable) is int and m.disable == v:
        return False
    m.disable = v
    m._clear_cache()
    return True


def _level_restore(v):
    cur = logging.root.level
    if type(cur) is int and cur == v:
        return False
    logging.root.setLevel(v)
    return True


# Process-global state the host uses after a tool body returns: snapshot before the call, restored after it, even
# when the body raises. One row per channel: (name, snapshot, restore -> changed, a change refuses the call).
# Code hooks refuse the call; data a tool may legitimately touch (imports, environment, log level) is only put back.
_RESTORED = (  # the class rows come first, so every later row reads and writes through the real class
    *((f"type({n})", *_class_of(o), True) for n, o in (("sys", sys), ("logging", logging), ("threading", threading),
                                                         ("os", os), ("gc", gc), ("copyreg", copyreg))),
    *((f"type({n})", *_class_of(o), True) for n, o in (("logging.root", logging.root),
                                                         ("logging.root.manager", logging.root.manager),
                                                         ("os.environ", os.environ))),
    ("sys.asyncgen_hooks", *_pair(sys.get_asyncgen_hooks, lambda f, g: sys.set_asyncgen_hooks(f, g)), True),
    *((f"sys.{a}", *_attr(sys, a), True) for a in ("excepthook", "unraisablehook", "displayhook", "breakpointhook")),
    ("threading.excepthook", *_attr(threading, "excepthook"), True),
    ("sys.profile/trace", *_pair(lambda: (sys.getprofile(), sys.gettrace()),
                                 lambda f, g: (sys.setprofile(f), sys.settrace(g))), True),
    ("threading.profile/trace", *_pair(lambda: (threading._profile_hook, threading._trace_hook),
                                       lambda f, g: (setattr(threading, "_profile_hook", f),
                                                     setattr(threading, "_trace_hook", g))), True),
    ("sys.meta_path", *_held(sys, "meta_path"), True),
    ("sys.path_hooks", *_held(sys, "path_hooks"), True),
    ("gc.callbacks", *_held(gc, "callbacks"), True),
    ("copyreg.dispatch_table", *_held(copyreg, "dispatch_table"), True),
    *((f"importlib.machinery.{c.__name__}", *_class_dict(c), True) for c in (importlib.machinery.PathFinder,
                                                                          importlib.machinery.FileFinder)),
    *((f"importlib.machinery.{c.__name__}", *_class_dict(c), True) for c in (importlib.machinery.BuiltinImporter,
                                                                          importlib.machinery.FrozenImporter)),
    *((n, *_attr(o, "root"), True) for n, o in (("logging.root", logging), ("logging.Logger.root", logging.Logger),
                                                ("logging.root.manager.root", logging.root.manager))),
    ("logging.Logger.manager", *_attr(logging.Logger, "manager"), True),
    ("logging.root.handlers", *_held(logging.root, "handlers"), True),
    ("logging.root.filters", *_held(logging.root, "filters"), True),
    ("logging record factory", *_attr(logging, "_logRecordFactory"), True),
    ("logging handler list", *_held(logging, "_handlerList"), False),  # logging.shutdown closes these at exit
    ("logging.root.level", lambda: logging.root.level, _level_restore, False),
    ("logging.root.manager.disable", lambda: logging.root.manager.disable, _disable_restore, False),
    ("sys.path_importer_cache", *_held(sys, "path_importer_cache"), False),
    ("sys.path", *_held(sys, "path"), False),
    *((f"sys.{a}", *_attr(sys, a), False) for a in ("stdin", "stdout", "stderr")),
    *((f"sys.{a}", *_attr(sys, a), False) for a in ("__stdin__", "__stdout__", "__stderr__")),
    ("os.environ", _env_snap, _env_restore, False),
)


def _restore(snaps):
    """Put every _RESTORED row back; return (names of changed code hooks, whether anything changed)."""
    code, moved = [], False
    for (name, _, restore, refuse), snap in zip(_RESTORED, snaps):  # runs inside the window, guard on
        try:
            if restore(snap):
                moved = True
                if refuse:
                    code.append(name)
        except BaseException:  # a planted object broke the restore: fail closed, refuse the call, go on
            code.append(name + " (not restored)")
    return code, moved


def _plain_result(out):
    """The result leaves the tool body as JSON data only: no object of the body outlives the guard window."""
    try:
        return json.loads(json.dumps(out))
    except (TypeError, ValueError, RecursionError):
        _deny(f"non-JSON tool result ({type(out).__name__})")


def _plain_error(e):
    """A fresh copy of the body's exception with JSON-only args: no traceback, frame or object of the body."""
    cls = type(e)
    try:
        mod, name = type.__dict__["__module__"].__get__(cls), type.__dict__["__qualname__"].__get__(cls)
        known = isinstance(mod, str) and isinstance(name, str) and (
            (mod == "builtins" and vars(builtins).get(name) is cls)
            or (mod.startswith("acp.") and getattr(sys.modules.get(mod), name, None) is cls))
        args, attrs = json.loads(json.dumps(e.args)), json.loads(json.dumps(vars(e)))
        msg = json.loads(json.dumps(str(e)))
    except Exception:
        known, msg = False, cls.__name__
    if not known:
        return RuntimeError(f"tool error: {msg}")
    err = cls.__new__(cls, *args)
    err.args = tuple(args)
    vars(err).update(attrs)
    return err


_SYS_PATH = tuple(sys.path)  # snapshot at install: a tool body that edits sys.path gains nothing
sys.addaudithook(_open_hook)


class ApprovalRequired(Exception):
    def __init__(self, action_sha256: str):
        super().__init__(f"approval required for action {action_sha256}")
        self.action_sha256 = action_sha256


class Rejected(Exception):
    pass


def authorise(ctx: AgentContext, tool: str, base: dict, detail: dict) -> None:
    """The one authority check for every agent action (ToolRunner.call and
    SessionStore write/read/handoff). Refuses, with a log record built from
    base + detail, once current_task.expires has passed (or is missing or
    invalid), and any tool not in both allowed_tools and delegated_authority.
    A missing delegated_authority counts as no authority (fail closed)."""
    allowed = ctx.manifest["permissions"].get("allowed_tools", [])
    authority = ctx.manifest["current_task"].get("delegated_authority")
    if authority is None:  # fail closed: no stated authority means none
        authority = []
    expires = ctx.manifest["current_task"].get("expires")
    now = ctx.log.clock.current()
    try:
        expired = not expires or now >= _parse(expires)
    except ValueError:
        ctx.record(**base, outcome="refused_authority_expired",
                   detail={**detail, "gate": "refused", "expires": expires, "reason": "invalid expires"})
        raise PermissionDenied(f"{ctx.agent_id} authority has invalid expires ({expires!r})",
                               "refused_authority_expired")
    if expired:
        ctx.record(**base, outcome="refused_authority_expired",
                   detail={**detail, "gate": "refused", "expires": expires})
        raise PermissionDenied(f"{ctx.agent_id} authority expired or has no expiry ({expires})",
                               "refused_authority_expired")
    if tool not in allowed or tool not in authority:
        ctx.record(**base, outcome="refused_not_permitted", detail={**detail, "gate": "refused"})
        raise PermissionDenied(f"{ctx.agent_id} may not use {tool}")


def recipient_expired(recipient: AgentContext, now) -> bool:
    """True when the recipient's current_task.expires has passed, is missing
    or is invalid (fail closed). Used by SessionStore.handoff so a valid
    session cannot push data into an expired session's store."""
    expires = recipient.manifest["current_task"].get("expires")
    try:
        return not expires or now >= _parse(expires)
    except ValueError:
        return True


def decided_in_log(log_path: Path, action_sha256: str) -> bool:
    """True when the hash-chained log already holds a human decision (approved
    or rejected) for this action. The approvals directory alone can be reset
    (claim marker deleted, file rewritten); the log record of the first use
    cannot be removed without verify() failing."""
    try:
        raw = Path(log_path).read_bytes().splitlines()
    except FileNotFoundError:
        return False
    for line in raw:
        d = (json.loads(line).get("detail") or {}) if line.strip() else {}
        if d.get("action_sha256") == action_sha256 and d.get("gate") in ("approved", "rejected"):
            return True
    return False


def action_digest(ctx: AgentContext, tool: str, action: str, payload) -> str:
    return digest(
        {"agent": ctx.agent_id, "session": ctx.session_id, "tool": tool, "action": action, "payload": payload}
    )


def approval_path(approvals_dir: Path, action_sha256: str) -> Path:
    return Path(approvals_dir) / (action_sha256.split(":", 1)[1][:16] + ".json")


# Approval records are signed with HMAC-SHA256. The key is made fresh in this
# process's memory and never written to disk, so no tool, session store or
# approvals-dir write can read it; a file written without it is refused.
_APPROVAL_KEY = secrets.token_bytes(32)
_SIGNED_FIELDS = ("action_sha256", "approver", "decision", "note", "simulated", "at")


def approval_mac(rec: dict, key: bytes | None = None) -> str:
    body = canonical({k: rec.get(k) for k in _SIGNED_FIELDS})
    return "hmac-sha256:" + hmac.new(key or _APPROVAL_KEY, body, hashlib.sha256).hexdigest()


def approval_mac_ok(rec: dict) -> bool:
    mac = rec.get("mac")
    return isinstance(mac, str) and hmac.compare_digest(mac, approval_mac(rec))


def write_approval(
    approvals_dir: Path,
    action_sha256: str,
    *,
    approver: str,
    decision: str = "approve",
    note: str = "",
    simulated: bool = False,
    at: str = "",
) -> Path:
    if decision not in ("approve", "reject"):
        raise ValueError("decision must be approve or reject")
    p = approval_path(approvals_dir, action_sha256)
    p.parent.mkdir(parents=True, exist_ok=True)
    rec = {
        "action_sha256": action_sha256,
        "approver": approver,
        "decision": decision,
        "note": note,
        "simulated": simulated,
        "at": at,
    }
    rec["mac"] = approval_mac(rec)
    p.write_bytes(canonical(rec) + b"\n")
    return p


DEFAULT_PORTS = {"http": 80, "https": 443}


class UrlRefused(ValueError):
    pass


def _segments(path: str, fold: bool = False) -> list[str]:
    """Path -> whole segments, empty segments dropped; lower-cased when fold."""
    return [x.lower() if fold else x for x in path.split("/") if x]


def normalise_url(url: str) -> tuple[str, str, int, str, str]:
    """(scheme, host, port, decoded path, decoded query). Raises UrlRefused for
    anything the gate and the fetcher could read differently, so the gate never
    judges a rewritten URL while the tool fetches the raw one: non-http(s)
    scheme, userinfo, no host, bad port, backslash or control characters,
    encoded '/', '\\' or '.', ';' path parameters, '.' or '..' segments, or a
    path still percent-encoded after one decode (double encoding)."""
    if "\\" in url or any(ord(c) < 0x20 for c in url):
        raise UrlRefused("backslash or control character in URL")
    try:
        u = urlsplit(url)
        port = u.port
    except ValueError as e:
        raise UrlRefused(f"unparseable URL ({e})")
    scheme = u.scheme.lower()
    if scheme not in DEFAULT_PORTS:
        raise UrlRefused(f"scheme {scheme or '(none)'} is not http or https")
    if "@" in u.netloc:
        raise UrlRefused("userinfo in URL")
    host = (u.hostname or "").rstrip(".")
    if not host:
        raise UrlRefused("no host")
    raw = u.path.lower()
    if any(e in raw for e in ("%2f", "%5c", "%2e")) or ";" in raw:
        raise UrlRefused("encoded separator or ';' parameter in path")
    path = unquote(u.path)
    if "%" in path or "\\" in path or any(ord(c) < 0x20 for c in path):
        raise UrlRefused("encoded or unsafe characters left in path after one decode")
    if any(x in (".", "..") for x in path.split("/")):
        raise UrlRefused("dot segment in path")
    return scheme, host, port or DEFAULT_PORTS[scheme], path, unquote(u.query)


def normalised_url_string(url: str) -> str:
    """normalise_url() as one URL string (default port dropped, path and query
    decoded), for the log: it shows the target the gate judged."""
    scheme, host, port, path, query = normalise_url(url)
    netloc = host if port == DEFAULT_PORTS[scheme] else f"{host}:{port}"
    return urlunsplit((scheme, netloc, path, query, ""))


_URLISH = re.compile(r"^(?:[A-Za-z][A-Za-z0-9+.-]*:)?//\S*$")


def url_values(payload) -> list[tuple[str, str]]:
    """Every top-level string value of a dict payload that is a whole URL
    (scheme://... or //host...), whatever its key: a tool may fetch from
    "uri", "href" or "endpoint" as readily as from "url"."""
    if not isinstance(payload, dict):
        return []
    return [(k, v.strip()) for k, v in payload.items() if isinstance(v, str) and _URLISH.match(v.strip())]


def _has_run(segs: list[str], run: list[str]) -> bool:
    n = len(run)
    return n > 0 and any(segs[i:i + n] == run for i in range(len(segs) - n + 1))


def check_url(url: str, allowed_prefixes, blocked_patterns) -> tuple[str, list | str] | None:
    """None if the URL may be used, else (reason, matched). Blocked patterns
    match whole path segments anywhere in the path; an allowed prefix must have
    the same scheme, host and port and its path segments (case-sensitive)
    must lead the URL's."""
    if not url:
        return None
    try:
        scheme, host, port, path, query = normalise_url(url)
    except UrlRefused as e:
        return str(e), "unsafe URL"
    # Blocked: whole segments, case-folded, anywhere in the path; plus the old
    # substring rule on the decoded, case-folded path and query, so the list
    # never blocks less than it did.
    low = (path + "?" + query).lower()
    blocked = [b for b in blocked_patterns or []
               if _has_run(_segments(path, True), _segments(unquote(b), True)) or unquote(b).lower() in low]
    if blocked:
        return "blocked pattern", blocked
    if allowed_prefixes is not None:
        segs = _segments(path)
        for x in allowed_prefixes:
            try:
                xs, xh, xp, xpath, _ = normalise_url(x)
            except UrlRefused:
                continue
            xsegs = _segments(xpath)
            if (xs, xh, xp) == (scheme, host, port) and segs[:len(xsegs)] == xsegs:
                return None
        return "outside allowed_url_prefixes", "not in allowed_url_prefixes"
    return None


class ToolRunner:
    def __init__(self, ctx: AgentContext, approvals_dir: Path, session_dir: Path | None = None,
                 read_roots=(), write_roots=()):
        """With session_dir set, tool bodies may open files only inside it (plus declared
        read-only data roots and write-only stub roots); see the path guard above."""
        self.ctx = ctx
        self.approvals_dir = Path(approvals_dir)
        self.session_dir = Path(session_dir).resolve() if session_dir else None
        self.read_roots = tuple(Path(r).resolve() for r in read_roots)  # the log itself is never a root:
        self.write_roots = tuple(Path(r).resolve() for r in write_roots)  # only ChainLog.append may write it

    def _run_guarded(self, fn):
        if self.session_dir is None:
            return fn()
        _guard_native()
        prev = getattr(_GUARD, "allow", None)
        gc.collect()  # host garbage dies outside the window
        snaps = [snap() for _, snap, _, _ in _RESTORED]
        _GUARD.allow, _GUARD.denied = (self.session_dir, self.read_roots, self.write_roots), None
        out = err = None
        try:
            try:
                out = _plain_result(fn())
            except BaseException as e:  # a refusal caused it (e.g. sqlite "not authorized"): report the refusal
                try:
                    err = None if _GUARD.denied else _plain_error(e)
                except BaseException:
                    err = RuntimeError("tool error")
        finally:
            try:
                changed = []
                rounds, found = 0, 1
                while found:  # the body's objects die inside the window: their __del__ runs guarded;
                    rounds += 1  # the window stays shut until no garbage is left (a chain only hangs, like a busy loop)
                    found = gc.collect()
                    step, moved = _restore(snaps)
                    changed += step
                    found = found or moved
                if rounds > 4:  # finalizers kept making garbage
                    changed.append("finalizer chain")
                if changed and not _GUARD.denied:
                    _GUARD.denied = "deferred code: " + ", ".join(dict.fromkeys(changed))
            finally:
                _GUARD.allow = prev
            if getattr(_GUARD, "sqlite_pending", None):  # fail closed: a connection ran without its authorizer
                _GUARD.sqlite_pending = []
                _GUARD.denied = _GUARD.denied or "sqlite authorizer not installed"
        if _GUARD.denied:  # the tool swallowed the denial: still refuse its result
            raise ToolFileAccessDenied(_GUARD.denied)
        if err is not None:
            raise err from None
        return out

    def requires_approval(self, tool: str) -> bool:
        spec = tool_spec(self.ctx.manifest, tool) or {}
        triggers = set(self.ctx.manifest["permissions"].get("approval_required_for", []))
        return bool(
            ("outbound" in triggers and spec.get("outbound"))
            or ("irreversible" in triggers and spec.get("irreversible"))
            or tool in triggers
        )

    def call(
        self,
        tool: str,
        action: str,
        fn: Callable[[], tuple],
        *,
        payload=None,
        personal_data_categories=None,
        lawful_basis: str = "not_applicable",
        recipients=(),
        detail: dict | None = None,
    ):
        """fn() returns (value, provenance_or_None[, overrides]). overrides may set
        personal_data_categories, lawful_basis and detail from what the tool found."""
        ctx = self.ctx
        base = dict(
            operation="execute_tool",
            tool=tool,
            action=action,
            personal_data_categories=personal_data_categories,
            lawful_basis=lawful_basis,
            recipients=recipients,
        )
        detail = dict(detail or {})
        authorise(ctx, tool, base, detail)
        now = ctx.log.clock.current()

        url = payload.get("url", "") if isinstance(payload, dict) else ""
        perms = ctx.manifest["permissions"]
        prefixes, patterns = perms.get("allowed_url_prefixes"), perms.get("blocked_url_patterns", [])
        bad = check_url(url, prefixes, patterns)
        for k, v in url_values(payload):  # a tool may read the URL from any key, so check them all
            if bad:
                break
            if v != url:
                bad = check_url(v, prefixes, patterns)
                if bad:
                    url = v
        if bad:
            ctx.record(**base, outcome="refused_purpose_limitation",
                       detail={**detail, "gate": "refused", "url": url, "matched": bad[1]})
            raise PermissionDenied(f"{url} refused: {bad[0]} {bad[1]}")
        if url:  # log the decoded target next to the raw URL, only when they differ
            norm = normalised_url_string(url)
            if norm != url:
                detail["normalised_url"] = norm

        decision_mode, approval_ref = "automated", None
        if self.requires_approval(tool):
            a = action_digest(ctx, tool, action, payload)
            p = approval_path(self.approvals_dir, a)
            appr = json.loads(p.read_bytes()) if p.exists() else None
            claim = p.with_name(p.name + ".claimed")
            reason = None
            if not appr or appr.get("action_sha256") != a:
                reason = "no approval record"
            elif not approval_mac_ok(appr):
                reason = "approval MAC invalid"
            elif appr.get("consumed") or claim.exists() or decided_in_log(ctx.log.path, a):
                reason = "approval already used"
            elif appr["decision"] == "approve":
                try:  # atomic claim: exactly one caller creates the marker
                    fd = os.open(claim, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o644)
                except FileExistsError:
                    reason = "approval already used"
                else:
                    with os.fdopen(fd, "wb") as f:
                        f.write(canonical({"action_sha256": a, "claimed_at": now.isoformat()}) + b"\n")
            if reason:
                ctx.record(
                    **base,
                    outcome="blocked_pending_approval",
                    detail={**detail, "gate": "blocked", "action_sha256": a, "reason": reason},
                )
                raise ApprovalRequired(a)
            approval_ref = p.name
            detail.update(gate="approved" if appr["decision"] == "approve" else "rejected",
                          action_sha256=a, approver=appr["approver"], approval_simulated=appr["simulated"])
            if appr["decision"] != "approve":
                ctx.record(**base, outcome="rejected_by_human", decision_mode="human_rejected",
                           approval_ref=approval_ref, detail=detail)
                raise Rejected(a)
            decision_mode = "human_approved"
        def consume(rec):  # one approval, one action, whatever the outcome
            appr["consumed"] = True
            appr["consumed_by"] = {"log_seq": rec["seq"], "log_hash": rec["hash"], "outcome": rec["outcome"]}
            tmp = p.with_name(p.name + ".tmp")
            tmp.write_bytes(canonical(appr) + b"\n")
            os.replace(tmp, p)

        try:
            out = self._run_guarded(fn)
            value, provenance = out[0], out[1]
            if len(out) > 2:  # tool reports what it actually found (e.g. special category data)
                ov = out[2]
                base["personal_data_categories"] = ov.get("personal_data_categories", base["personal_data_categories"])
                base["lawful_basis"] = ov.get("lawful_basis", base["lawful_basis"])
                detail.update(ov.get("detail", {}))
        except Exception as e:  # logged, then re-raised
            outcome = e.outcome if isinstance(e, ToolFileAccessDenied) else "error"
            rec = ctx.record(**base, outcome=outcome, decision_mode=decision_mode, approval_ref=approval_ref,
                             detail={**detail, "error": type(e).__name__})
            if approval_ref:
                consume(rec)
            raise
        final_url = detail.get("final_url")
        bad = check_url(final_url, prefixes, patterns) if final_url and final_url != url else None
        if bad:  # the tool followed a redirect out of purpose: discard the result
            rec = ctx.record(**base, outcome="refused_purpose_limitation", decision_mode=decision_mode,
                             approval_ref=approval_ref,
                             detail={**detail, "gate": "refused", "url": url, "matched": bad[1]})
            if approval_ref:
                consume(rec)
            raise PermissionDenied(f"final URL {final_url} refused: {bad[0]} {bad[1]}")
        rec = ctx.record(**base, outcome="ok", decision_mode=decision_mode, approval_ref=approval_ref,
                         provenance=provenance, detail=detail)
        if approval_ref:
            consume(rec)
        return value
