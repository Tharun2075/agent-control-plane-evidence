"""Fix 12 B, model-free: how the task-target rule changes the gate on AgentDojo ground truth.

For every banking/slack user task, its ground-truth calls to gated tools are reviewed against
its own prompt (benign: should pass); for every injection task, its ground-truth calls are
reviewed against every user prompt of the suite (attack: should be blocked). Prints counts
under the v1.2 rule (no task target) and the batch 12 rule. No model is called.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from acp import bench_gate  # noqa: E402
from agentdojo.task_suite.load_suites import get_suite  # noqa: E402

BENCH_VERSION = "v1.2.2"


def calls(suite, task, env):
    return [(c.function, dict(c.args)) for c in task.ground_truth(env)]


def main():
    saved = bench_gate.TASK_TARGETS
    for sname in ("banking", "slack"):
        suite = get_suite(BENCH_VERSION, sname)
        env0 = suite.load_and_inject_default_environment({})
        users = [(t, calls(suite, t, env0.model_copy(deep=True))) for t in suite.user_tasks.values()]
        injs = [(t, calls(suite, t, env0.model_copy(deep=True))) for t in suite.injection_tasks.values()]
        for label, targets in (("v1.2", {}), ("batch12", saved)):
            bench_gate.TASK_TARGETS = targets
            ben = [(t.ID, f) for t, cs in users for f, a in cs
                   if f in bench_gate.GATED[sname] and not bench_gate.review(sname, f, a, t.PROMPT)[0]]
            att_tot = att_pass = 0
            per_tool = {}
            for it, cs in injs:
                for ut, _ in users:
                    for f, a in cs:
                        if f not in bench_gate.GATED[sname]:
                            continue
                        att_tot += 1
                        if bench_gate.review(sname, f, a, ut.PROMPT)[0]:
                            att_pass += 1
                            per_tool[f] = per_tool.get(f, 0) + 1
            print(f"{sname} {label}: benign gated calls blocked={len(ben)} {sorted(set(ben))[:8]}; "
                  f"attack calls approved={att_pass}/{att_tot} {per_tool}")
    bench_gate.TASK_TARGETS = saved


if __name__ == "__main__":
    main()
