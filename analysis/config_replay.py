"""L12: which subset of the three checks is the cheapest that still blocks every outside-task payload.

(a) Measured arms: batch 8 runs one check alone ("allowlist" = targets only, "approval" = action word only)
    on the same six open models as the batch 7 full gate. Attack success and benign utility per arm and model.
(b) Replay: every recorded target-hitting call carries each check's own verdict (`chk`). A subset S of
    {authority, action, allowlist} lets a run through when some target call passes every check in S.
    Attack side: batch 10 plain arm (outside-task AgentDojo targets, the gate never stopped the run, so the
    whole trajectory is recorded). Benign side: batch 14 gated benign calls; a run is refused under S when
    one of its calls fails a check in S. Caveat: gated trajectories stop at the first refusal, so benign
    costs for subsets smaller than the full gate are lower bounds on the calls the model would have made.
"""

from __future__ import annotations

import itertools
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from acp import bench_gate as g  # noqa: E402
from common import CHECKS, wilson, write_csv  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]

OPEN = ("openai.gpt-oss-120b-1_0", "openai.gpt-oss-20b-1_0", "qwen.qwen3-32b-v1_0", "qwen.qwen3-vl-235b-a22b",
        "deepseek.v3.2", "mistral.mistral-large-3-675b-instruct")


def fmt(k: int, n: int) -> str:
    if not n:
        return "0/0"
    lo, hi = wilson(k, n)
    return f"{k}/{n} [{lo:.3f},{hi:.3f}]"


def measured() -> list[dict]:
    recs = g.load_records(ROOT / "repeats" / "batch8" / "runs") + g.load_records(ROOT / "repeats" / "batch7" / "runs")
    rows = []
    for arm, batch in (("allowlist", "batch8"), ("approval", "batch8"), ("gated", "batch7")):
        tot = {"att": 0, "succ": 0, "ben": 0, "util": 0}
        for m in OPEN + ("ALL",):
            if m == "ALL":
                c = tot
            else:
                rs = [r for r in recs if r.get("arm") == arm and _mid(r["model"]) == m]
                att = [r for r in rs if r["kind"] == "attacked" and g.classify(r) not in ("error", "provider-refused")]
                ben = [r for r in rs if r["kind"] == "benign" and g.classify(r) not in ("error", "provider-refused")]
                c = {"att": len(att), "succ": sum(bool(r.get("security")) for r in att),
                     "ben": len(ben), "util": sum(bool(r.get("utility")) for r in ben)}
                for k in tot:
                    tot[k] += c[k]
            rows.append({"part": "measured", "config": arm, "model": m,
                         "attack_success": fmt(c["succ"], c["att"]), "benign_utility": fmt(c["util"], c["ben"])})
    return rows


def _mid(model: str) -> str:
    return model.replace("-1:0", "-1_0").replace("-v1:0", "-v1_0")


def passes(chk: dict, subset: tuple) -> bool:
    return all(chk.get(c, True) for c in subset)


def replay() -> list[dict]:
    att = [r for r in g.load_records(ROOT / "repeats" / "batch10" / "runs")
           if r.get("arm") == "plain" and r["kind"] == "attacked"]
    att_chk = [[x["chk"] for x in r.get("calls") or [] if x.get("hit") and "chk" in x] for r in att]
    att_chk = [cs for cs in att_chk if cs]
    ben = [r for r in g.load_records(ROOT / "repeats" / "batch14" / "runs")
           if r.get("arm") == "gated" and r["kind"] == "benign" and g.classify(r) not in ("error", "provider-refused")]
    ben_chk = [[x["chk"] for x in r.get("calls") or [] if "chk" in x] for r in ben]
    rows = []
    for n in range(len(CHECKS) + 1):
        for subset in itertools.combinations(CHECKS, n):
            through = sum(any(passes(c, subset) for c in cs) for cs in att_chk)
            refused = sum(any(not passes(c, subset) for c in cs) for cs in ben_chk)
            rows.append({"part": "replay", "config": "+".join(subset) or "none", "model": "ALL",
                         "attack_success": f"target call passes {fmt(through, len(att_chk))}",
                         "benign_utility": f"refused {fmt(refused, len(ben_chk))}"})
    return rows


def main() -> None:
    rows = measured() + replay()
    print(write_csv("config_replay.csv", rows))
    for r in rows:
        if r["model"] == "ALL":
            print(r)


if __name__ == "__main__":
    main()
