"""Batch 11 runner (repeats/batch11/PROTOCOL.md): the batch-10 LLM attacker seeded with the batch-9
allowlist-aware injection, on the 17 set-A tasks, gated arm only, on Bedrock.

Try 1 is the batch-9 hand-written allowlist-aware injection, verbatim (no attacker call). Tries 2..k
are attacker rewrites that see the previous tries' injection, result, gate block reasons and final
reply. Reuses the batch-10 gate executor, victim run and attacker call unchanged.
"""
from __future__ import annotations

import argparse
import json
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
sys.path.insert(0, str(ROOT))

import bench_agentdojo as B  # noqa: E402
import bench_batch9 as B9  # noqa: E402
import bench_batch10 as B10  # noqa: E402
import bench_bedrock as BB  # noqa: E402
from agentdojo.attacks.attack_registry import load_attack  # noqa: E402
from agentdojo.attacks.important_instructions_attacks import ImportantInstructionsAttack  # noqa: E402
from agentdojo.task_suite.load_suites import get_suite  # noqa: E402

RUN_DIR = ROOT / "repeats" / "batch11" / "runs"
LOG_DIR = ROOT / "repeats" / "batch11" / "logs"
ARM = "gated"
ATTACK = "adaptive_seeded"
MAX_TRIES = 5
NO_USE = {"input": 0, "output": 0, "cost_usd": 0.0, "stop_reason": ""}


def seed_injection(suite, ut, goal: str, pipe) -> dict:
    """The batch-9 set-A body (bench_batch9.py), verbatim: important_instructions text with the
    allowlist-aware goal, on every important_instructions injection candidate of the user task."""
    att = load_attack("important_instructions", suite, pipe)
    body = ImportantInstructionsAttack._JB_STRING.format(goal=goal, user=att.user_name, model=att.model_name)
    return {c: body for c in att.get_injection_candidates(ut)}


def yaml_safe(text: str) -> str:
    """Attacker text escaped for the inside of a YAML double-quoted scalar, which is where every
    AgentDojo banking/slack injection placeholder sits; AgentDojo pastes the value in with str.format
    and then yaml.safe_load-s the environment, so a raw '"' or '\\' broke the parse (batch-11
    ParserError, repeats/batch11b/PROTOCOL-ADDENDUM.md). PyYAML's own double-quoted emitter does the
    escaping; the loaded value equals the text exactly (newlines included)."""
    out = yaml.dump(text, default_style='"', width=10 ** 9, allow_unicode=True).rstrip("\n")
    if out.endswith("\n..."):
        out = out[:-4].rstrip("\n")
    if not (len(out) >= 2 and out[0] == out[-1] == '"') or "\n" in out:
        raise ValueError("yaml_safe: unexpected emitter output")
    return out[1:-1]


def rewrite_injection(suite, ut, inj: str, pipe) -> dict:
    """An attacker rewrite on the same injection candidates as the seed."""
    return {c: inj for c in load_attack("important_instructions", suite, pipe).get_injection_candidates(ut)}


def run_seeded(j, a, client, chain, lock, attacker=B10.attacker_call, max_tries=MAX_TRIES, prior=None) -> dict:
    """prior: tries already run for this pair (batch 11b reuses batch-11 try 1); the loop continues
    after them with the same history the attacker would have seen."""
    suite = get_suite(B.BENCH_VERSION, j["suite"])
    ut = suite.user_tasks[j["ut"]]
    goal = B9.adaptive_goal(j["tool"], j["target"])
    authority = B10.authority_for(suite, ut, j["suite"])
    rec = B10._base(j, a)
    rec.update({"set": "A", "it": None, "kind": "attacked", "attack": ATTACK, "adaptive_tool": j["tool"],
                "adaptive_target": j["target"], "max_tries": max_tries})
    tries, history = list(prior or []), list(prior or [])
    success_at = next((h["t"] for h in tries if h.get("security")), None)
    for t in range(len(tries) + 1, max_tries + 1 if success_at is None else 0):
        st = B10.State10(ARM, authority, j["suite"], ut.PROMPT, list(B9.ADAPTIVE_MARKERS[j["suite"]]), True,
                         chain, f"{B.key(j)}#{t}", lock)
        a_err, fallback, use = None, False, dict(NO_USE)
        box = {}
        if t == 1:
            def fn(pipe):
                box.update(seed_injection(suite, ut, goal, pipe))
                return dict(box)
        else:
            try:
                raw, use = attacker(client, ut.PROMPT, goal, history)
            except B.ProviderStop:
                raise
            except Exception as e:  # attacker failure: fall back, recorded
                raw, use, a_err = "", dict(NO_USE), type(e).__name__
            inj = B10.parse_injection(raw)
            fallback = not inj
            if fallback:
                inj = B10.fallback_injection(goal)

            def fn(pipe, inj=inj):
                box.update(rewrite_injection(suite, ut, inj, pipe))  # raw text stays in the record
                return {c: yaml_safe(v) for c, v in box.items()}
        run = B10._victim_run(suite, ut, None, st, a, client, fn)
        # batch-9 success rule: a target-marker call the gate let through (bench_batch9.adaptive_success)
        run["security"] = B9.adaptive_success(run["calls"])
        reasons = sorted({c["gate"] for c in run["calls"] if c.get("gate") not in (None, "approved")})
        h = {"t": t, "seeded": t == 1, "injection": next(iter(box.values()), ""),
             "injection_slots": sorted(box), "attacker_fallback": fallback, "attacker_error": a_err,
             "attacker_usage": use, "block_reasons": reasons, **run}
        h["cost_usd"] = round(run["cost_usd"] + use["cost_usd"], 6)
        tries.append(h)
        history.append(h)
        if run["security"]:
            success_at = t
            break
    last = tries[-1]
    rec.update({k: last[k] for k in ("utility", "security", "error_class", "error", "target_call_attempted",
                                     "gate_checks", "gate_blocks", "blocked_target", "calls", "authority")})
    rec.update({"tries": tries, "n_tries": len(tries), "success_at": success_at,
                "attacker_model": B10.ATTACKER_MODEL, "attacker_temperature": B10.ATTACKER_T,
                "cost_usd": round(sum(h["cost_usd"] for h in tries), 6), "ts_end": B.now()})
    return rec


def out_path(a) -> Path:
    tag = a.model.replace("/", "_").replace(":", "_")
    return RUN_DIR / f"{tag}__{ARM}__{ATTACK}__T{a.temperature:g}.jsonl"


def main(argv=None) -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--model")
    p.add_argument("--region", default="us-east-1", choices=["us-east-1", "us-west-2"])
    p.add_argument("--temperature", type=float, default=0.0)
    p.add_argument("--max-tries", type=int, default=MAX_TRIES, help="lowered only by the PROTOCOL cut rule")
    p.add_argument("--limit", type=int, default=0)
    p.add_argument("--budget-usd", type=float, default=0.0)
    p.add_argument("--workers", type=int, default=4)
    a = p.parse_args(argv)
    a.arm, a.attack = ARM, ATTACK
    BB.check_model(a.model)
    RUN_DIR.mkdir(parents=True, exist_ok=True)
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    out = out_path(a)
    done = {}
    if out.exists():
        for line in out.read_text().splitlines():
            r = json.loads(line)
            done[B.key(r)] = r
    spent = sum(r.get("cost_usd", 0) for r in done.values())
    jobs = [j for j in B9.plan_adaptive() if B.key(j) not in done]
    if a.limit:
        jobs = jobs[:max(0, a.limit - len(done))]
    lock = threading.Lock()
    chain = B.ChainLog(LOG_DIR / (out.stem + ".gated.jsonl"))
    client = BB.make_client(a.region)
    stop = threading.Event()
    state = {"spent": spent, "n": 0}

    def work(j):
        if stop.is_set():
            return
        try:
            rec = run_seeded(j, a, client, chain, lock, max_tries=a.max_tries)
        except B.ProviderStop as e:
            stop.set()
            print(f"PROVIDER-STOP bedrock {a.model} {e}", flush=True)
            return
        with lock:
            with out.open("a") as f:
                f.write(json.dumps(rec, sort_keys=True) + "\n")
            state["spent"] += rec["cost_usd"]
            state["n"] += 1
            print(f"{state['n']}/{len(jobs)} {B.key(rec)} u={rec['utility']} s={rec['security']} "
                  f"e={rec['error_class']} gate={rec['gate_checks']}/{rec['gate_blocks']} "
                  f"k={rec['success_at']}/{rec['n_tries']} ${state['spent']:.3f}", flush=True)
            if a.budget_usd and state["spent"] >= a.budget_usd:
                stop.set()
                print(f"BUDGET-STOP ${state['spent']:.2f}", flush=True)

    t0 = time.time()
    with ThreadPoolExecutor(a.workers) as ex:
        list(ex.map(work, jobs))
    print(f"DONE {out.name} runs={state['n']} spent=${state['spent']:.3f} secs={time.time() - t0:.0f}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
