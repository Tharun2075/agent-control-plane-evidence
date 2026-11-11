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

import hashlib
import hmac
import json
import os
import re
import secrets
import sys
import threading
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
# Scope: the guard lives in the gate process and binds tool code that does not tamper with the gate
# (its globals, the hook, a removed sqlite authorizer). os.stat, os.path.exists and os.lstat raise no
# audit event, so a tool body can learn whether a path outside the session exists and its size and
# times; it cannot read, write, list or remove it. An OS sandbox per tool is the next step.
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
}
# Events a tool body may not raise at all: new processes, threads the guard cannot follow, cwd changes, native code.
# Python < 3.13 raises no audit event for a thread start; there the thread-start functions are wrapped below.
_DENY_EVENTS = {"os.chdir", "os.system", "os.exec", "os.posix_spawn", "os.spawn", "os.fork", "os.forkpty",
                "subprocess.Popen", "_thread.start_new_thread", "_thread.start_joinable_thread", "ctypes.dlopen",
                "ctypes.dlsym", "sqlite3.enable_load_extension", "sqlite3.load_extension"}
_SQLITE_MEMORY = ("", ":memory:")
_SQLITE_SIDE = ("", "-journal", "-wal", "-shm")  # SQLite opens these beside the database without an audit event


def _deny(what: str):
    _GUARD.denied = what
    raise ToolFileAccessDenied(what)


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
    if event == "open":
        path, mode, flags = args
        if path is None:
            return
        if not isinstance(path, int) and not os.path.isabs(os.fsdecode(path)):
            _deny(f"relative path {os.fsdecode(path)!r}")  # dir_fd is not in the event: refuse relative opens
        writes = bool(mode and any(c in mode for c in "wax+")) or bool(flags and flags & _WRITE_FLAGS)
        _check_path(g, path, writes)
    elif event in _PATH_EVENTS:
        idx, writes, fds = _PATH_EVENTS[event]
        if any(i < len(args) and args[i] not in (None, -1) for i in fds):
            _deny(f"{event} with dir_fd")
        for i in idx:
            _check_path(g, args[i], writes)
        if event == "os.symlink":  # the link target too: SQLite side files and other C code follow links unseen
            if not os.path.isabs(os.fsdecode(args[0])):  # a relative target changes meaning when the link is moved
                _deny("relative symlink target " + os.fsdecode(args[0]))
            _check_path(g, os.fsdecode(args[0]), True)
    elif event == "sqlite3.connect":
        db = args[0] if args else None
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
            sys.setprofile(_sqlite_profile)
    elif event in _DENY_EVENTS:
        _deny(event)


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
        sys.setprofile(getattr(_GUARD, "sqlite_prev_profile", None))


def _guard_thread_start(start):
    def guarded(*a, **kw):
        if getattr(_GUARD, "allow", None) is not None and not getattr(_LOG_WRITING, "on", False):
            _deny("thread start")
        return start(*a, **kw)
    return guarded


if sys.version_info < (3, 13):  # no audit event for a thread start: refuse it at the start functions
    import _thread
    for _name in ("start_new_thread", "start_new", "start_joinable_thread"):  # every alias of the start function
        if hasattr(_thread, _name):
            setattr(_thread, _name, _guard_thread_start(getattr(_thread, _name)))
    threading._start_new_thread = _guard_thread_start(threading._start_new_thread)

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
        prev = getattr(_GUARD, "allow", None)
        _GUARD.allow, _GUARD.denied = (self.session_dir, self.read_roots, self.write_roots), None
        try:
            out = fn()
        except Exception:
            if not _GUARD.denied:
                raise
            out = None  # a refusal caused this error (e.g. sqlite "not authorized"): report the refusal
        finally:
            _GUARD.allow = prev
            if getattr(_GUARD, "sqlite_pending", None):  # fail closed: a connection ran without its authorizer
                _GUARD.sqlite_pending = []
                _GUARD.denied = _GUARD.denied or "sqlite authorizer not installed"
        if _GUARD.denied:  # the tool swallowed the denial: still refuse its result
            raise ToolFileAccessDenied(_GUARD.denied)
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
