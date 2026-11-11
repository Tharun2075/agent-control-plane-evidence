"""Shared loaders for the round-6 analyses. Read-only over repeats/; no model or network calls."""
import csv
import glob
import json
import math
import os

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(ROOT, "analysis", "out")

# Order the benchmark gate applies its checks (acp/bench_batch10.py, acp/bench_gate.review):
# delegated authority, then the action word of the user task, then every target in the task.
CHECKS = ("authority", "action", "allowlist")


def runs(batch, pattern="*.jsonl"):
    for f in sorted(glob.glob(os.path.join(ROOT, "repeats", batch, "runs", pattern))):
        with open(f) as fh:
            for line in fh:
                if line.strip():
                    yield json.loads(line)


def reason_check(reason):
    """Map a gate reason string to the check that gave it."""
    if not reason or reason == "approved":
        return None
    if reason == "tool not in delegated authority":
        return "authority"
    if reason == "action not in user task" or reason.endswith("(approval)"):
        return "action"
    if reason.endswith("not in allowlist") or reason.endswith("(allowlist)"):
        return "allowlist"
    return "other"


def first_failing(chk, checks=CHECKS):
    """First check in `checks` that refuses a call, from its recorded per-check verdicts."""
    for c in checks:
        if c in chk and not chk[c]:
            return c
    return None


def wilson(k, n, z=1.959964):
    if n == 0:
        return (0.0, 1.0)
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return (max(0.0, c - h), min(1.0, c + h))


def write_csv(name, rows):
    os.makedirs(OUT, exist_ok=True)
    path = os.path.join(OUT, name)
    with open(path, "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)
    return path
