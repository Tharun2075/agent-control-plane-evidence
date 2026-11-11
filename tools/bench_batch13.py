"""Batch 13 runner (repeats/batch13/PROTOCOL.md): sampled repeats of the batch 6 Claude B1 runs.

Same tasks, arms, attack, pipeline and gate as batch 6 (tools/bench_agentdojo.py, unchanged);
only the output folder changes (one per rep) and each record carries its rep. Claude 5.5 takes no
temperature, so every rep uses the provider's default sampling, as batch 6 (rep 0) did.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import bench_agentdojo as B  # noqa: E402

BASE = ROOT / "repeats" / "batch13"
MODELS = ["claude-haiku-5-5", "claude-sonnet-5-5", "claude-opus-5-5"]
REPS = [1, 2, 3]
SAMPLING = "provider-default"


def configure(rep: int) -> None:
    """Point the batch 6 runner at this rep's folders and tag its records."""
    B.RUN_DIR = BASE / "runs" / f"r{rep}"
    B.LOG_DIR = BASE / "logs" / f"r{rep}"
    inner = getattr(B.run_one, "__wrapped__", B.run_one)

    def run_one(j, a, client, chain, lock):
        rec = inner(j, a, client, chain, lock)
        rec.update(batch=13, rep=rep, sampling=SAMPLING)
        return rec

    run_one.__wrapped__ = inner
    B.run_one = run_one


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--rep", type=int, required=True, choices=REPS)
    p.add_argument("--model", required=True, choices=MODELS)
    a, rest = p.parse_known_args(argv)
    for flag in ("--provider", "--set"):
        if any(r == flag or r.startswith(flag + "=") for r in rest):
            p.error(f"{flag} is fixed by the protocol (anthropic, B1)")
    configure(a.rep)
    return B.main(["--model", a.model, "--provider", "anthropic", "--set", "B1", *rest])


if __name__ == "__main__":
    sys.exit(main())
