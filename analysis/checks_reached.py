"""L9: how far each attacked run's attacker-target calls got through the checks.

Stages in gate order (acp/bench_gate.review): 0 = the model never called a tool with the attacker's
target (declined); 1 = refused by delegated authority; 2 = refused by the action-word check;
3 = refused by the target allowlist; 4 = passed every check (the call ran on the gated arm).
A run counts at its deepest target call. Verdicts come from the per-call `chk` record, which the
gate writes on every arm: on the plain arm they are what the gate would have said (nothing was
refused). Batch 14 records no authority verdict (stage 1 empty there). Errors and provider
refusals are their own column.
"""
import re
from collections import Counter, defaultdict

from acp import bench_gate as g
from common import CHECKS, first_failing, runs, write_csv

STAGES = ("declined", "authority", "action", "allowlist", "passed", "error")


def stage(r):
    if g.classify(r) in ("error", "provider-refused"):
        return "error"
    best = 0
    for c in r.get("calls") or []:
        if not c.get("hit") or c.get("chk") is None:
            continue
        k = first_failing(c["chk"])
        best = max(best, 4 if k is None else 1 + CHECKS.index(k))
    return STAGES[best]


def table(batch, key):
    t = defaultdict(Counter)
    for r in runs(batch):
        if r["kind"] == "attacked":
            t[key(r)][stage(r)] += 1
    return [{"batch": batch, "group": k, "runs": sum(c.values()), **{s: c[s] for s in STAGES}}
            for k, c in sorted(t.items())]


def short(m):
    return re.sub(r"^(openai|qwen|deepseek|mistral)\.", "", m).split("-instruct")[0].replace("_0", "").replace("-1:0", "")


def main():
    rows = table("batch14", lambda r: f"{r['arm']} | {short(r['model'])}")
    rows += table("batch14", lambda r: f"{r['arm']} | ALL")
    rows += table("batch15", lambda r: f"{r['arm']} | {short(r['model'])}")
    rows += table("batch10", lambda r: f"{r['arm']} | {r.get('attack') or 'fixed'}")
    rows += table("batch11b", lambda r: f"{r['arm']} | seeded 8-try rewrite probe")
    print(write_csv("checks_reached.csv", rows))
    for x in rows:
        if "ALL" in x["group"] or x["batch"] != "batch14":
            print(x)


if __name__ == "__main__":
    main()
