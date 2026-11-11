"""Batch 13 driver (repeats/batch13/PROTOCOL.md): runs the 18 files rep by rep under the USD 32 cap.

Order: rep 1, 2, 3; inside a rep haiku, sonnet, opus; plain then gated. Each file gets
--budget-usd = min(its share, what is left of the cap minus the in-flight reserve). A rep starts
only if the projected cost of a whole rep still fits; otherwise it and later reps are not run
(whole reps only). The API key goes into the child's environment only; it is never printed.
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

from bench_batch13 import BASE, MODELS, REPS  # noqa: E402

CAP = 32.0
RESERVE = 0.5  # runs already in flight when a file hits its share (4 workers x opus ~USD 0.1)
SHARE = {"claude-haiku-5-5": 0.15, "claude-sonnet-5-5": 2.0, "claude-opus-5-5": 3.8}
REP0_COST = 10.129  # batch 6 Claude B1, six files, list price
ARMS = ["plain", "gated"]


def spent(path: Path) -> float:
    if not path.exists():
        return 0.0
    return sum(json.loads(x).get("cost_usd", 0) for x in path.read_text().splitlines())


def run_file(rep: int) -> dict:
    return {(m, arm): BASE / "runs" / f"r{rep}" / f"{m}__{arm}__B1.jsonl" for m in MODELS for arm in ARMS}


def total_spent() -> float:
    return sum(spent(p) for r in REPS for p in run_file(r).values())


def rep_projection(done_reps: list[int]) -> float:
    """Cost of one whole rep: mean of the batch 13 reps done so far, else batch 6; plus 5 %."""
    full = [sum(spent(p) for p in run_file(r).values()) for r in done_reps]
    return (sum(full) / len(full) if full else REP0_COST) * 1.05


def child_env() -> dict:
    key = subprocess.run(["/Users/thar/.workflow/bin/secret-get", "ico-evidence-api", "ico-evidence"],
                         capture_output=True, text=True, check=True).stdout.strip()
    if not key:
        raise SystemExit("no key from secret-get")
    env = {k: v for k, v in os.environ.items() if k not in ("CLAUDE_CODE_OAUTH_TOKEN", "ANTHROPIC_API_KEY")}
    env["ANTHROPIC_API_KEY"] = key
    return env


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--python", default=sys.executable)
    p.add_argument("--reps", default="1,2,3")
    a = p.parse_args(argv)
    env = child_env()
    out_dir = BASE / "logs" / "out"
    out_dir.mkdir(parents=True, exist_ok=True)
    done_reps: list[int] = []
    for rep in [int(x) for x in a.reps.split(",")]:
        left = CAP - total_spent()
        need = rep_projection(done_reps) - sum(spent(f) for f in run_file(rep).values())
        if need > left - RESERVE:
            print(f"REP-CUT r{rep}: projected ${need:.2f} > left ${left - RESERVE:.2f}; r{rep}+ not run", flush=True)
            break
        for (m, arm), f in run_file(rep).items():
            left = CAP - total_spent() - RESERVE
            budget = round(min(SHARE[m], spent(f) + left), 3)
            print(f"START r{rep} {m} {arm} budget=${budget:.3f} total=${total_spent():.3f}", flush=True)
            with (out_dir / f"r{rep}__{m}__{arm}.out").open("a") as log:
                rc = subprocess.run([a.python, str(ROOT / "tools" / "bench_batch13.py"), "--rep", str(rep),
                                     "--model", m, "--arm", arm, "--budget-usd", str(budget)],
                                    env=env, stdout=log, stderr=subprocess.STDOUT, cwd=ROOT).returncode
            print(f"END r{rep} {m} {arm} rc={rc} file=${spent(f):.3f} total=${total_spent():.3f}", flush=True)
        done_reps.append(rep)
    print(f"BATCH13-END total=${total_spent():.3f}", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
