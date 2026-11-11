"""Batch 11b runner (repeats/batch11b/PROTOCOL-ADDENDUM.md): batch 11 re-run after the YAML fix.

Try 1 (the batch-9 hand-written injection, which went through AgentDojo's default path and loaded
fine) is reused from the batch-11 record of the same pair, no call. A pair whose try 1 succeeded is
copied as it is. Every other pair re-runs tries 2..K with the same attacker (model, prompt,
temperature) and the same victim settings as batch 11, now with the rewrite YAML-escaped
(bench_batch11.yaml_safe). Budget counts only new spend.
"""
from __future__ import annotations

import argparse
import json
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
sys.path.insert(0, str(ROOT))

import bench_agentdojo as B  # noqa: E402
import bench_batch9 as B9  # noqa: E402
import bench_batch11 as B11  # noqa: E402
import bench_bedrock as BB  # noqa: E402

SRC_DIR = ROOT / "repeats" / "batch11" / "runs"
RUN_DIR = ROOT / "repeats" / "batch11b" / "runs"
LOG_DIR = ROOT / "repeats" / "batch11b" / "logs"
MAX_TRIES = 8


def try1_of(rec: dict) -> dict:
    t = dict(rec["tries"][0])
    assert t["t"] == 1 and t["seeded"], "batch-11 record without a seeded try 1"
    t["reused_from"] = "batch11"
    return t


def run_pair(j, a, client, chain, lock, src: dict, attacker=None) -> dict:
    """One pair of batch 11b from its batch-11 record `src`."""
    t1 = try1_of(src)
    kw = {} if attacker is None else {"attacker": attacker}
    rec = B11.run_seeded(j, a, client, chain, lock, max_tries=a.max_tries, prior=[t1], **kw)
    rec["batch"] = "11b"
    rec["try1_reused"] = True
    rec["cost_new_usd"] = round(rec["cost_usd"] - t1["cost_usd"], 6)
    return rec


def out_path(a) -> Path:
    return RUN_DIR / B11.out_path(a).name


def main(argv=None) -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--model")
    p.add_argument("--region", default="us-east-1", choices=["us-east-1", "us-west-2"])
    p.add_argument("--temperature", type=float, default=0.0)
    p.add_argument("--max-tries", type=int, default=MAX_TRIES)
    p.add_argument("--limit", type=int, default=0)
    p.add_argument("--budget-usd", type=float, default=0.0, help="new spend of this invocation")
    p.add_argument("--workers", type=int, default=4)
    a = p.parse_args(argv)
    a.arm, a.attack = B11.ARM, B11.ATTACK
    BB.check_model(a.model)
    RUN_DIR.mkdir(parents=True, exist_ok=True)
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    src_file = SRC_DIR / B11.out_path(a).name
    src = {B.key(r): r for r in map(json.loads, src_file.read_text().splitlines())}
    out = out_path(a)
    done = {}
    if out.exists():
        for line in out.read_text().splitlines():
            r = json.loads(line)
            done[B.key(r)] = r
    jobs = [j for j in B9.plan_adaptive() if B.key(j) not in done]
    missing = [B.key(j) for j in jobs if B.key(j) not in src]
    if missing:
        raise SystemExit(f"no batch-11 record for {missing}")
    if a.limit:
        jobs = jobs[:max(0, a.limit - len(done))]
    lock = threading.Lock()
    chain = B.ChainLog(LOG_DIR / (out.stem + ".gated.jsonl"))
    client = BB.make_client(a.region)
    stop = threading.Event()
    state = {"spent": 0.0, "n": 0}

    def work(j):
        if stop.is_set():
            return
        try:
            rec = run_pair(j, a, client, chain, lock, src[B.key(j)])
        except B.ProviderStop as e:
            stop.set()
            print(f"PROVIDER-STOP bedrock {a.model} {e}", flush=True)
            return
        with lock:
            with out.open("a") as f:
                f.write(json.dumps(rec, sort_keys=True) + "\n")
            state["spent"] += rec["cost_new_usd"]
            state["n"] += 1
            print(f"{state['n']}/{len(jobs)} {B.key(rec)} s={rec['security']} e={rec['error_class']} "
                  f"k={rec['success_at']}/{rec['n_tries']} new=${state['spent']:.3f}", flush=True)
            if a.budget_usd and state["spent"] >= a.budget_usd:
                stop.set()
                print(f"BUDGET-STOP ${state['spent']:.2f}", flush=True)

    t0 = time.time()
    with ThreadPoolExecutor(a.workers) as ex:
        list(ex.map(work, jobs))
    print(f"DONE {out.name} runs={state['n']} new_spent=${state['spent']:.3f} secs={time.time() - t0:.0f}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
