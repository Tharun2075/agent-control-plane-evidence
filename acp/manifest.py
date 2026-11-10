"""B1a: six-part agent identity manifest.

The six parts follow the ICO call for evidence on agentic AI (Transparency and
Accountability themes): owner and purpose; capabilities and tools; permissions
and approval thresholds; deployment context; relationships to other agents;
current task, session and delegated authority.

Agent and tool field names reuse the OpenTelemetry GenAI semantic conventions
(gen_ai.agent.id, gen_ai.agent.name, gen_ai.agent.version,
gen_ai.agent.description, gen_ai.tool.name, gen_ai.tool.type,
gen_ai.tool.description, gen_ai.provider.name, gen_ai.conversation.id) so the
same identifiers can be attached to OpenTelemetry spans.

Cut-list decision: no Ed25519 signature (Python's standard library has no
Ed25519). A manifest is identified by the SHA-256 digest of its canonical JSON;
every log record carries that digest.
"""
from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

from .canon import digest

SCHEMA_ID = "acp-agent-manifest/0.1"
SIX_PARTS = (
    "owner_and_purpose",
    "capabilities",
    "permissions",
    "deployment_context",
    "relationships",
    "current_task",
)
ID_FIELDS = ("gen_ai.agent.id", "gen_ai.agent.name", "gen_ai.agent.version")


def load(path) -> dict:
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def manifest_digest(m: dict) -> str:
    return digest(m)


def validate(m: dict) -> list[str]:
    """Minimal structural check (stdlib only; schema/agent-manifest.schema.json
    is the full JSON Schema for use with any validator)."""
    errors: list[str] = []
    if m.get("schema") != SCHEMA_ID:
        errors.append(f"schema must be {SCHEMA_ID!r}")
    for k in ID_FIELDS:
        if not isinstance(m.get(k), str) or not m.get(k):
            errors.append(f"missing {k}")
    for part in SIX_PARTS:
        if not isinstance(m.get(part), dict):
            errors.append(f"missing part {part}")
    caps = m.get("capabilities", {})
    tools = caps.get("tools", []) if isinstance(caps, dict) else []
    names = set()
    for t in tools:
        for k in ("gen_ai.tool.name", "gen_ai.tool.type", "outbound", "irreversible"):
            if k not in t:
                errors.append(f"tool missing {k}: {t}")
        names.add(t.get("gen_ai.tool.name"))
    perms = m.get("permissions", {})
    for name in perms.get("allowed_tools", []) if isinstance(perms, dict) else []:
        if name not in names:
            errors.append(f"allowed tool {name!r} not declared in capabilities")
    return errors


def bind_session(
    template: dict,
    *,
    session_id: str,
    task: str,
    delegated_by: str | None = None,
    delegated_authority: list[str] | None = None,
    expires: str | None = None,
) -> dict:
    """Fill part 6 (current task / session / delegated authority).

    Fails closed: expires is required; a delegated session (delegated_by set)
    needs an explicit delegated_authority, a delegator listed in
    relationships.accepts_delegation_from, and authority within allowed_tools.
    Only a non-delegated session with no delegated_authority gets allowed_tools.

    The digest of the bound manifest changes per session, so a log record's
    agent_manifest_sha256 pins both who the agent is and what it was allowed
    to do in that session.
    """
    m = copy.deepcopy(template)
    allowed = list(m["permissions"].get("allowed_tools", []))
    if expires is None:
        raise ValueError("expires is required: delegated authority must end")
    if delegated_by is not None:
        # Fail closed: a delegation must name its authority explicitly and come
        # from an agent this manifest accepts delegation from.
        if delegated_by not in m["relationships"].get("accepts_delegation_from", []):
            raise ValueError(f"{m['gen_ai.agent.id']} does not accept delegation from {delegated_by!r}")
        if delegated_authority is None:
            raise ValueError("a delegation must state delegated_authority explicitly")
    authority = allowed if delegated_authority is None else list(delegated_authority)
    extra = [t for t in authority if t not in allowed]
    if extra:
        raise ValueError(f"delegated_authority {extra} exceeds the agent's allowed_tools")
    m["current_task"] = {
        "gen_ai.conversation.id": session_id,
        "task": task,
        "delegated_by": delegated_by,
        "delegated_authority": authority,
        "expires": expires,
    }
    errs = validate(m)
    if errs:
        raise ValueError("invalid manifest: " + "; ".join(errs))
    return m


def tool_spec(m: dict, name: str) -> dict | None:
    for t in m["capabilities"].get("tools", []):
        if t.get("gen_ai.tool.name") == name:
            return t
    return None


def write(m: dict, path: Path) -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(m, indent=2, sort_keys=True, ensure_ascii=False) + "\n", encoding="utf-8")
    return manifest_digest(m)
