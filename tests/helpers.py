import json
from pathlib import Path

from acp.agent import AgentContext
from acp.log import ChainLog, FixedStepClock
from acp.manifest import bind_session, load

ROOT = Path(__file__).resolve().parent.parent


def ctx(tmp: Path, name="outreach-agent", sid="test-s1", log=None, **kw):
    log = log or ChainLog(tmp / "log.jsonl", clock=FixedStepClock(), durable=False)
    kw.setdefault("expires", "2026-11-10T23:59:59Z")
    m = bind_session(load(ROOT / "manifests" / f"{name}.json"), session_id=sid, task="unit test", **kw)
    return AgentContext(log, m, sid), log


def lines(p: Path):
    return [json.loads(x) for x in p.read_bytes().splitlines()]
