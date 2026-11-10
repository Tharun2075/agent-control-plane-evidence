"""Agent context: binds a manifest and a session to a ChainLog so every record
carries the agent identity digest, session id and a per-agent step counter."""
from __future__ import annotations

from .log import ChainLog
from .manifest import manifest_digest

NONE = ["none"]


class AgentContext:
    def __init__(self, log: ChainLog, manifest: dict, session_id: str):
        self.log = log
        self.manifest = manifest
        self.agent_id = manifest["gen_ai.agent.id"]
        self.digest = manifest_digest(manifest)
        self.session_id = session_id
        self.step = 0

    def record(
        self,
        *,
        operation: str,
        action: str,
        outcome: str,
        tool: str | None = None,
        personal_data_categories=None,
        lawful_basis: str = "not_applicable",
        decision_mode: str = "automated",
        approval_ref: str | None = None,
        recipients=(),
        provenance: dict | None = None,
        detail: dict | None = None,
    ) -> dict:
        self.step += 1
        return self.log.append(
            **{
                "gen_ai.agent.id": self.agent_id,
                "agent_manifest_sha256": self.digest,
                "gen_ai.conversation.id": self.session_id,
                "step": self.step,
                "gen_ai.operation.name": operation,
                "gen_ai.tool.name": tool,
                "action": action,
                "personal_data_categories": list(personal_data_categories or NONE),
                "lawful_basis": lawful_basis,
                "decision_mode": decision_mode,
                "approval_ref": approval_ref,
                "outcome": outcome,
                "recipients": list(recipients),
                "provenance": provenance,
                "detail": detail or {},
            }
        )
