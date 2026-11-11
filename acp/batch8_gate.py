"""Batch 8: the two halves of the batch 6 gate rule as separate arms, and the arm list.

Stdlib only; frozen by repeats/batch8/PROTOCOL.md (its SHA-256 is pre-registered there).
`bench_gate.review` approves iff (1) the tool's action word is in the user task and (2) every
target argument is in the user task. Arm "allowlist" checks only (2); arm "approval" checks
only (1). Their conjunction is `bench_gate.review` (tested in tests/test_batch8.py).
"""

from __future__ import annotations

from acp import bench_gate
from acp.bench_gate import GATED, _words

# Control arms (gate on side-effect tools) and AgentDojo defence arms (no gate).
GATE_ARMS = ("allowlist", "approval")
DEFENCE_ARMS = ("tool_filter", "spotlighting", "repeat_user_prompt")
ARMS = GATE_ARMS + DEFENCE_ARMS


def review_allowlist(suite: str, tool: str, args: dict, user_prompt: str) -> tuple[bool, str]:
    """Condition (2) only: every target argument appears literally in the user task (fix 12 B:
    including the task target of a tool with no recipient, `bench_gate.TASK_TARGETS`)."""
    return bench_gate.check_targets(suite, tool, args, user_prompt)


def review_approval(suite: str, tool: str, args: dict, user_prompt: str) -> tuple[bool, str]:
    """Condition (1) only: one of the tool's action words is a word of the user task."""
    words = GATED[suite][tool]
    if words:
        uw = _words(user_prompt)
        if not any(w2.startswith(w) for w in words for w2 in uw):
            return False, "action not in user task"
    return True, "approved"


REVIEWS = {"gated": bench_gate.review, "allowlist": review_allowlist, "approval": review_approval}
