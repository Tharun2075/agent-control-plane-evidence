"""B1e: per-session scratch namespace.

Each session gets <root>/<session id>/. read() resolves the path (following
symlinks and '..') and refuses, with a log record, any path outside the
session's own directory. Data moves between sessions only through handoff(),
which copies one file and logs the recipient agent on the sender's log.

Limit: this is an in-process check, not an OS sandbox. A tool that opens files
itself bypasses it; production use needs OS-level isolation (separate user,
container or sandbox profile) with this layer kept for the audit record.
"""
from __future__ import annotations

import os
from pathlib import Path

from .agent import AgentContext
from .canon import sha256_hex


class IsolationError(Exception):
    pass


class SessionStore:
    def __init__(self, root: Path, ctx: AgentContext):
        self.root = Path(root).resolve()
        self.ctx = ctx
        self.dir = self.root / ctx.session_id
        self.dir.mkdir(parents=True, exist_ok=True)

    def _rel(self, p: Path) -> str:
        return os.path.relpath(p, self.root)

    def _inside(self, p: Path) -> bool:
        d = self.dir.resolve()
        return p == d or d in p.parents

    def write(self, name: str, text: str, *, personal_data_categories=None, lawful_basis="not_applicable",
              derived_from: str | None = None, detail: dict | None = None) -> Path:
        p = (self.dir / name).resolve()
        if not self._inside(p):
            self.ctx.record(operation="execute_tool", tool="session_store", action="write",
                            outcome="refused_outside_session",
                            personal_data_categories=personal_data_categories, lawful_basis=lawful_basis,
                            detail={"requested": self._rel(p)})
            raise IsolationError(name)
        data = text.encode("utf-8")
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(data)
        self.ctx.record(operation="execute_tool", tool="session_store", action="write", outcome="ok",
                        personal_data_categories=personal_data_categories, lawful_basis=lawful_basis,
                        provenance={"content_sha256": "sha256:" + sha256_hex(data), "derived_from": derived_from},
                        detail={**(detail or {}), "path": self._rel(p)})
        return p

    def read(self, path, *, personal_data_categories=None, lawful_basis="not_applicable",
             detail: dict | None = None) -> str:
        p = Path(path)
        if not p.is_absolute():
            p = self.dir / p
        p = p.resolve()
        if not self._inside(p):
            self.ctx.record(operation="execute_tool", tool="session_store", action="read",
                            outcome="refused_outside_session",
                            personal_data_categories=personal_data_categories, lawful_basis=lawful_basis,
                            detail={**(detail or {}), "requested": self._rel(p),
                                    "session_dir": self._rel(self.dir)})
            raise IsolationError(f"{self._rel(p)} is outside session {self.ctx.session_id}")
        data = p.read_bytes()
        self.ctx.record(operation="execute_tool", tool="session_store", action="read", outcome="ok",
                        personal_data_categories=personal_data_categories, lawful_basis=lawful_basis,
                        provenance={"content_sha256": "sha256:" + sha256_hex(data), "source": self._rel(p)},
                        detail=detail or {})
        return data.decode("utf-8")

    def handoff(self, name: str, to: "SessionStore", *, personal_data_categories=None,
                lawful_basis="not_applicable", detail: dict | None = None) -> Path:
        src = (self.dir / name).resolve()
        dst = to.dir / name
        bad = None
        if not self._inside(src):
            bad = "source outside sender session"
        elif dst.is_symlink():
            bad = "destination is a symlink"
        elif not to._inside(dst.resolve()):
            bad = "destination outside recipient session"
        if bad:
            self.ctx.record(operation="invoke_agent", tool=None, action="handoff",
                            outcome="refused_outside_session",
                            personal_data_categories=personal_data_categories, lawful_basis=lawful_basis,
                            recipients=[], detail={**(detail or {}), "reason": bad, "requested": name,
                                                   "to_session": to.ctx.session_id})
            raise IsolationError(f"handoff refused: {bad}")
        data = src.read_bytes()
        # O_NOFOLLOW: refuse if a symlink appears at dst between the check and the write.
        fd = os.open(dst, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(data)
        self.ctx.record(operation="invoke_agent", tool=None, action="handoff", outcome="ok",
                        personal_data_categories=personal_data_categories, lawful_basis=lawful_basis,
                        recipients=[f"agent:{to.ctx.agent_id}"],
                        provenance={"content_sha256": "sha256:" + sha256_hex(data), "source": self._rel(src)},
                        detail={**(detail or {}), "to_session": to.ctx.session_id, "path": self._rel(dst)})
        return dst
