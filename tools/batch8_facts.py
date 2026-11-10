"""Write repeats/batch8/task_facts.json: the AgentDojo task facts the R5 failure analysis needs.

  python3 tools/batch8_facts.py      # needs agentdojo (same pinned version as the runner); no model calls

Per suite: the user task prompts, the target markers of each injection task (bench_gate.target_markers
of its ground-truth calls, as the runner computes them), the argument names of each gated tool and
the injection tasks AgentDojo scores from the call trace (security_from_traces).
The summary (tools/batch8_summary.py) reads only this file, so it runs without AgentDojo.
Email addresses in prompts and markers are replaced by the same hash tag (email-<sha256[:10]>),
so marker-in-prompt tests give the same answer and the file passes the public-safe check.
"""
import hashlib
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from acp import bench_gate  # noqa: E402
from agentdojo.task_suite.load_suites import get_suite  # noqa: E402

BENCH_VERSION = "v1.2.2"
OUT = ROOT / "repeats" / "batch8" / "task_facts.json"
EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")


def redact(s: str) -> str:
    return EMAIL.sub(lambda m: "email-" + hashlib.sha256(m.group().lower().encode()).hexdigest()[:10], s)


def facts(sname: str) -> dict:
    suite = get_suite(BENCH_VERSION, sname)
    env0 = suite.load_and_inject_default_environment({})
    its = {}
    for name, it in sorted(suite.injection_tasks.items()):
        calls = [(c.function, dict(c.args)) for c in it.ground_truth(env0)]
        its[name] = [redact(m) for m in bench_gate.target_markers(calls, sname)]
    tools = {f.name: sorted(f.parameters.model_json_schema().get("properties", {}))
             for f in suite.tools if f.name in bench_gate.GATED[sname]}
    # Injection tasks whose security is scored from the call trace (blocked calls count too).
    traced = sorted(n for n, it in suite.injection_tasks.items() if "security_from_traces" in type(it).__dict__)
    return {"user_tasks": {n: redact(t.PROMPT) for n, t in sorted(suite.user_tasks.items())},
            "injection_markers": its, "gated_tool_args": dict(sorted(tools.items())),
            "trace_scored": traced}


def main() -> int:
    data = {"bench": f"agentdojo-{BENCH_VERSION}", "suites": {s: facts(s) for s in ("banking", "slack")}}
    OUT.write_text(json.dumps(data, indent=1, sort_keys=True) + "\n")
    print("wrote", OUT.relative_to(ROOT))
    return 0


if __name__ == "__main__":
    sys.exit(main())
