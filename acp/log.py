"""B1b: append-only, hash-chained JSONL action log.

Each line is the canonical JSON of one record. record.hash is the SHA-256 of
the canonical JSON of the record without its "hash" field; that body includes
prev_hash, the hash of the previous record (64 zeros for the first). This is
the linear hash chain used by tamper-evident logs (Schneier and Kelsey 1999;
the same idea underlies the RFC 6962 / RFC 9162 transparency-log Merkle tree,
which adds efficient inclusion proofs we do not need at this size).

A sidecar file <log>.head holds {count, last_hash}. It lets verify() detect a
deleted tail record. Rewriting the whole chain AND the head file is not
detectable locally: anchor the head hash somewhere the writer cannot change
(a git commit pushed elsewhere, an RFC 3161 timestamp, a regulator's copy).
"""
from __future__ import annotations

import json
import os
import sys
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path

from .canon import canonical, sha256_hex

try:
    import fcntl
except ImportError:  # not POSIX: in-process lock only
    fcntl = None

GENESIS = "0" * 64
# UK GDPR Article 6(1)(a)-(f)
LAWFUL_BASES = (
    "consent",
    "contract",
    "legal_obligation",
    "vital_interests",
    "public_task",
    "legitimate_interests",
)
# "not_applicable" is allowed only when no personal data is touched.
LAWFUL_TAGS = LAWFUL_BASES + ("unclear", "not_applicable")
DECISION_MODES = ("automated", "human_approved", "human_rejected")
REQUIRED = (
    "gen_ai.agent.id",
    "agent_manifest_sha256",
    "gen_ai.conversation.id",
    "step",
    "gen_ai.operation.name",
    "gen_ai.tool.name",
    "action",
    "personal_data_categories",
    "lawful_basis",
    "decision_mode",
    "approval_ref",
    "outcome",
    "recipients",
    "provenance",
    "detail",
)


class ChainError(Exception):
    pass


class WallClock:
    def now(self) -> str:
        return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")

    def current(self) -> datetime:
        return datetime.now(timezone.utc)


class FixedStepClock:
    """Deterministic clock: start time plus one step per call. Used for the
    committed reference runs so their hash chains reproduce byte for byte."""

    def __init__(self, start: str = "2026-11-10T09:00:00Z", step_seconds: int = 1):
        self.t = datetime.strptime(start, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
        self.step = timedelta(seconds=step_seconds)

    def current(self) -> datetime:
        """Time of the next record, without advancing the clock."""
        return self.t

    def now(self) -> str:
        s = self.t.strftime("%Y-%m-%dT%H:%M:%S.000000Z")
        self.t += self.step
        return s


def record_hash(body: dict) -> str:
    return sha256_hex(canonical(body))


def check_fields(fields: dict) -> None:
    missing = [k for k in REQUIRED if k not in fields]
    if missing:
        raise ChainError(f"record missing fields: {missing}")
    cats = fields["personal_data_categories"]
    if not isinstance(cats, list) or not cats:
        raise ChainError("personal_data_categories must be a non-empty list (use ['none'])")
    lb = fields["lawful_basis"]
    if lb not in LAWFUL_TAGS:
        raise ChainError(f"lawful_basis {lb!r} not in {LAWFUL_TAGS}")
    if cats == ["none"] and lb != "not_applicable":
        raise ChainError("no personal data touched: lawful_basis must be 'not_applicable'")
    if cats != ["none"] and lb == "not_applicable":
        raise ChainError("personal data touched: lawful_basis must be an Art 6 basis or 'unclear'")
    if fields["decision_mode"] not in DECISION_MODES:
        raise ChainError(f"decision_mode {fields['decision_mode']!r} not in {DECISION_MODES}")


class ChainLog:
    def __init__(self, path, clock=None, durable: bool = True):
        self.path = Path(path)
        self.head_path = self.path.with_name(self.path.name + ".head")
        self.clock = clock or WallClock()
        self.durable = durable
        self.append_ns: list[int] = []
        self.seq = 0
        self.last_hash = GENESIS
        self.size = 0
        # One writer at a time: a thread lock inside this process, plus flock on
        # the log file across processes (two ChainLogs on one path).
        self._lock = threading.Lock()
        if self.path.exists() and self.path.stat().st_size:
            # Read the chain under the same locks as append, and take the size
            # from the locked fd, so seq, last_hash and size describe one state.
            with self._lock, open(self.path, "ab") as f:
                if fcntl:
                    fcntl.flock(f.fileno(), fcntl.LOCK_EX)
                self._resync(f.fileno())

    def _resync(self, fd: int) -> None:
        """Caller holds self._lock and the flock on fd."""
        res = verify(self.path)
        if not res.ok:
            raise ChainError("refusing to append to a log that fails verify: " + "; ".join(res.errors))
        self.seq, self.last_hash, self.size = res.records, res.last_hash, os.fstat(fd).st_size

    def append(self, **fields) -> dict:
        check_fields(fields)
        t0 = time.perf_counter_ns()
        with self._lock, open(self.path, "ab") as f:
            if fcntl:
                fcntl.flock(f.fileno(), fcntl.LOCK_EX)
            if os.fstat(f.fileno()).st_size != self.size:  # another writer appended: catch up first
                self._resync(f.fileno())
            rec = {"seq": self.seq, "ts": self.clock.now(), **fields, "prev_hash": self.last_hash}
            rec["hash"] = record_hash(rec)
            line = canonical(rec) + b"\n"
            f.write(line)
            f.flush()
            if self.durable:
                if sys.platform == "darwin" and fcntl:  # macOS fsync() does not flush the drive cache
                    fcntl.fcntl(f.fileno(), fcntl.F_FULLFSYNC)
                else:
                    os.fsync(f.fileno())
            tmp = self.head_path.with_name(self.head_path.name + ".tmp")
            tmp.write_bytes(canonical({"count": self.seq + 1, "last_hash": rec["hash"]}) + b"\n")
            os.replace(tmp, self.head_path)
            self.append_ns.append(time.perf_counter_ns() - t0)
            self.seq += 1
            self.last_hash = rec["hash"]
            self.size += len(line)
            return rec  # flock is released when the file closes


@dataclass
class VerifyResult:
    ok: bool
    records: int
    last_hash: str
    errors: list[str] = field(default_factory=list)


def verify(path, require_head: bool = True) -> VerifyResult:
    path = Path(path)
    errors: list[str] = []
    prev = GENESIS
    n = 0
    for i, raw in enumerate(path.read_bytes().splitlines()):
        try:
            rec = json.loads(raw)
        except ValueError:
            errors.append(f"line {i + 1}: not valid JSON")
            continue
        if rec.get("seq") != i:
            errors.append(f"line {i + 1}: seq {rec.get('seq')} != {i} (record deleted, inserted or reordered)")
        if rec.get("prev_hash") != prev:
            errors.append(f"line {i + 1}: prev_hash does not match previous record (chain broken)")
        body = {k: v for k, v in rec.items() if k != "hash"}
        if record_hash(body) != rec.get("hash"):
            errors.append(f"line {i + 1}: hash mismatch (record edited)")
        prev = rec.get("hash", "")
        n += 1
    head_path = path.with_name(path.name + ".head")
    if head_path.exists():
        head = json.loads(head_path.read_bytes())
        if head.get("count") != n or head.get("last_hash") != prev:
            errors.append(
                f"head mismatch: head says {head.get('count')} records, log has {n} "
                "(tail deleted or records appended outside the logger)"
            )
    elif require_head:
        errors.append("head file missing")
    return VerifyResult(ok=not errors, records=n, last_hash=prev, errors=errors)


def read_records(path) -> list[dict]:
    return [json.loads(line) for line in Path(path).read_bytes().splitlines() if line.strip()]
