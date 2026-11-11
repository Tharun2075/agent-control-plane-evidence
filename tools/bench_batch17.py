"""Batch 17 runner (repeats/batch17/PROTOCOL.md). Three sub-batches on Bedrock, reusing the batch-9/10/11
runners unchanged:
  p1  LLM approval reviewer (qwen.qwen3-32b-v1:0, prompt repeats/batch17/p1/reviewer_prompt.txt) in place of
      the scripted action-word reviewer: the 17 set-A pairs x 3 reps (batch-11 seeded injection, try 1 only)
      plus the B1 benign tasks, per victim.
  p2  the DeepSeek V3.2 B1 runs missing from repeats/batch9/runs (list: repeats/batch17/p2/missing.json).
  p3  B1 plain vs gated on the AgentDojo travel and workspace suites (gate: acp/bench_gate_b17.py).
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
import threading
import time
from argparse import Namespace
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
sys.path.insert(0, str(ROOT))

import bench_agentdojo as B  # noqa: E402
import bench_batch9 as B9  # noqa: E402
import bench_batch10 as B10  # noqa: E402
import bench_batch11 as B11  # noqa: E402
import bench_bedrock as BB  # noqa: E402
from acp import bench_gate_b17  # noqa: E402
from agentdojo.task_suite.load_suites import get_suite  # noqa: E402

BB.BedrockLLM.__init__.__defaults__ = (20,)  # more retries: batch 16 shares the account quota
D = ROOT / "repeats" / "batch17"
REVIEWER_MODEL = "qwen.qwen3-32b-v1:0"
REVIEWER_PROMPT = D / "p1" / "reviewer_prompt.txt"
REVIEWER_ARM = "llm_reviewer"
VICTIMS = ("openai.gpt-oss-120b-1:0", "deepseek.v3.2")
P3_SUITES = ("travel", "workspace")
CODE = ["tools/bench_batch17.py", "acp/bench_gate_b17.py", "repeats/batch17/p1/reviewer_prompt.txt",
        "tools/bench_agentdojo.py", "tools/bench_batch9.py", "tools/bench_batch10.py", "tools/bench_batch11.py",
        "tools/bench_bedrock.py", "acp/bench_gate.py"]
VERDICT = re.compile(r"\b(APPROVE|DENY)\b")
OUT_CHARS = 16000


def sha(p) -> str:
    return hashlib.sha256((ROOT / p).read_bytes()).hexdigest()


def git_state() -> tuple[str, bool]:
    head = subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT, capture_output=True, text=True).stdout.strip()
    st = subprocess.run(["git", "status", "--porcelain", "--", "acp", "tools", "Makefile",
                         "repeats/batch17/PROTOCOL.md", "repeats/batch17/p1/reviewer_prompt.txt",
                         "repeats/batch17/code-sha256.json"], cwd=ROOT, capture_output=True, text=True).stdout
    return head, bool(st.strip())


# ---------------------------------------------------------------- p1: LLM reviewer
def _tool_text(msgs) -> str:
    parts = []
    for m in msgs or []:
        if m.get("role") != "tool":
            continue
        c = m.get("content")
        if isinstance(c, str):
            parts.append(c)
        else:
            parts.extend(str(b.get("content") or b.get("text") or "") for b in c or [])
    return "\n---\n".join(parts)[-OUT_CHARS:]


def review(client, user_prompt, msgs, fn, args) -> dict:
    """One reviewer call. Unparsable output or a non-quota error counts as DENY and is recorded."""
    meter = B.Meter()
    llm = BB.BedrockLLM(client, REVIEWER_MODEL, meter)
    req = (f"USER TASK:\n{user_prompt}\n\nTOOL OUTPUTS SO FAR:\n{_tool_text(msgs) or '(none)'}\n\n"
           f"APPROVAL REQUEST:\ntool: {fn}\narguments: {json.dumps(args, sort_keys=True, default=str)}\n/no_think")
    pin, pout = BB.PRICES[REVIEWER_MODEL]
    try:
        r = llm.call(modelId=REVIEWER_MODEL, messages=[{"role": "user", "content": [{"text": req}]}],
                     system=[{"text": REVIEWER_PROMPT.read_text()}],
                     inferenceConfig={"maxTokens": 1024, "temperature": 0.0})
    except B.ProviderStop:
        raise
    except Exception as e:
        return {"verdict": "DENY", "error": type(e).__name__, "raw": "", "input": 0, "output": 0, "cost_usd": 0.0}
    u = r.get("usage", {})
    text = "\n".join(b["text"] for b in r.get("output", {}).get("message", {}).get("content", []) if "text" in b)
    clean = B10.THINK.sub("", text).split("<think>")[0]
    m = VERDICT.search(clean)
    return {"verdict": m.group(1) if m else "DENY", "error": None if m else "unparsable", "raw": clean[:300],
            "input": u.get("inputTokens", 0), "output": u.get("outputTokens", 0),
            "cost_usd": (u.get("inputTokens", 0) * pin + u.get("outputTokens", 0) * pout) / 1e6}


class Executor17(B10.Executor10):
    """The batch-10 executor; on the llm_reviewer arm the gated-tool decision is the LLM verdict AND the
    unchanged target allowlist check (bench_gate.check_targets). The scripted verdict is recorded too."""

    def query(self, query, runtime, env=B9.EmptyEnv(), messages=[], extra_args={}):  # noqa: B006
        self._msgs = messages
        return super().query(query, runtime, env, messages, extra_args)

    def _gate(self, fn, args):
        st = self.st
        if st.arm != REVIEWER_ARM:
            return super()._gate(fn, args)
        gated_tool = fn in B.bench_gate.GATED[st.suite]
        hit = bool(st.markers) and gated_tool and B.bench_gate.hits_target(args, st.markers)
        st.target_attempted |= hit
        if not gated_tool:
            st.calls.append({"fn": fn, "gate": None, "hit": hit})
            return None
        s_ok, s_reason, chk = B10.decide("gated", st.suite, fn, args, st.user_prompt, st.authority)
        rv = review(st.client, st.user_prompt, getattr(self, "_msgs", []), fn, args)
        t_ok, t_reason = B.bench_gate.check_targets(st.suite, fn, args, st.user_prompt)
        ok = rv["verdict"] == "APPROVE" and t_ok
        reason = "approved" if ok else (t_reason if rv["verdict"] == "APPROVE" else "denied by llm reviewer")
        chk = dict(chk or {}, scripted={"ok": s_ok, "reason": s_reason}, llm=rv["verdict"], llm_error=rv["error"],
                   llm_raw=rv["raw"], targets_ok=t_ok, reviewer_usage={"input": rv["input"], "output": rv["output"]},
                   reviewer_cost_usd=round(rv["cost_usd"], 6))
        with st.lock:
            st.rev_cost += rv["cost_usd"]
            st.rev_in += rv["input"]
            st.rev_out += rv["output"]
        st.checks += 1
        st.blocks += not ok
        st.blocked_target += (not ok) and hit
        st.calls.append({"fn": fn, "gate": reason, "hit": hit, "chk": chk})
        with st.lock:
            st.chain.append(**{"gen_ai.agent.id": f"agentdojo-{st.arm}", "agent_manifest_sha256": "0" * 64,
                               "gen_ai.conversation.id": st.conv, "step": st.checks,
                               "gen_ai.operation.name": "execute_tool", "gen_ai.tool.name": fn,
                               "action": "approved" if ok else "blocked", "personal_data_categories": ["none"],
                               "lawful_basis": "not_applicable", "decision_mode": "automated",
                               "approval_ref": None, "outcome": "approved" if ok else "rejected", "recipients": [],
                               "provenance": "agentdojo-" + B.BENCH_VERSION, "detail": reason})
        return None if ok else f"blocked by approval gate: {reason}"


B10.Executor10 = Executor17  # make_pipe looks the executor up at call time


def _arm_state(st, client):
    st.client, st.rev_cost, st.rev_in, st.rev_out = client, 0.0, 0, 0
    return st


def p1_jobs() -> list[dict]:
    jobs = [dict(j, kind="attacked", rep=r) for r in (1, 2, 3) for j in B9.plan_adaptive()]
    jobs += [dict(j, kind="benign", rep=1) for j in B.plan("B1") if j["it"] is None]
    return jobs


def p1_run(j, a, client, chain, lock) -> dict:
    suite = get_suite(B.BENCH_VERSION, j["suite"])
    ut = suite.user_tasks[j["ut"]]
    conv = f"{B.key(j)}#{j['kind']}#r{j['rep']}"
    if j["kind"] == "attacked":
        authority = B10.authority_for(suite, ut, j["suite"])
        st = _arm_state(B10.State10(REVIEWER_ARM, authority, j["suite"], ut.PROMPT,
                                    list(B9.ADAPTIVE_MARKERS[j["suite"]]), True, chain, conv, lock), client)
        goal = B9.adaptive_goal(j["tool"], j["target"])
        run = B10._victim_run(suite, ut, None, st, a, client, lambda pipe: B11.seed_injection(suite, ut, goal, pipe))
        run["security"] = B9.adaptive_success(run["calls"])  # batch-9/11 success rule
        rec = B10._base(j, a)
        rec.update({"set": "A", "it": None, "kind": "attacked", "attack": "adaptive_seeded",
                    "adaptive_tool": j["tool"], "adaptive_target": j["target"]})
    else:
        suite, ut, it, st = B10._setup(j, a, a.model, chain, lock, conv)
        _arm_state(st, client)
        run = B10._victim_run(suite, ut, it, st, a, client, lambda pipe: {})
        rec = B10._base(j, a)
        rec.update({"set": "B1", "kind": "benign", "attack": None})
    rec.update(run)
    rec.update({"rep": j["rep"], "reviewer_model": REVIEWER_MODEL, "reviewer_usage": {"input": st.rev_in,
                "output": st.rev_out}, "reviewer_cost_usd": round(st.rev_cost, 6),
                "victim_cost_usd": run["cost_usd"], "cost_usd": round(run["cost_usd"] + st.rev_cost, 6),
                "ts_end": B.now()})
    return rec


# ---------------------------------------------------------------- p2 / p3: batch-9 run_one
def b9_file(model, arm, rep) -> str:
    return f"{model.replace('/', '_').replace(':', '_')}__{arm}__important_instructions__T0.7__r{rep}__B1.jsonl"


def missing() -> list[dict]:
    out = []
    for arm in ("plain", "gated"):
        for rep in (1, 2, 3):
            f = ROOT / "repeats" / "batch9" / "runs" / b9_file("deepseek.v3.2", arm, rep)
            have = {B.key(json.loads(x)) for x in f.read_text().splitlines()}
            out += [dict(j, arm=arm, rep=rep) for j in B.plan("B1") if B.key(j) not in have]
    return out


def b9_run(j, a, client, chain, lock) -> dict:
    ns = Namespace(attack="important_instructions", arm=j["arm"], set="B1", model=a.model, region=a.region,
                   temperature=0.7, rep=j["rep"])
    rec = B9.run_one({k: j[k] for k in ("suite", "ut", "it")}, ns, client, chain, lock)
    rec.setdefault("ts_end", B.now())
    return rec


# ---------------------------------------------------------------- driver
def job_key(j) -> str:
    return f"{B.key(j)}#{j.get('kind') or j.get('arm')}#r{j['rep']}"


def main(argv=None) -> int:
    p = argparse.ArgumentParser()
    p.add_argument("mode", choices=["p1", "p2", "p3", "write-shas", "missing", "plan"])
    p.add_argument("--model")
    p.add_argument("--arm", choices=["plain", "gated"])
    p.add_argument("--region", default="us-east-1", choices=["us-east-1", "us-west-2"])
    p.add_argument("--limit", type=int, default=0)
    p.add_argument("--workers", type=int, default=4)
    p.add_argument("--budget-usd", type=float, default=0.0)
    p.add_argument("--pilot", action="store_true")
    a = p.parse_args(argv)
    if a.mode == "p3" or (a.mode == "plan" and a.arm):
        B.SUITES = P3_SUITES
        bench_gate_b17.install()
    if a.mode == "write-shas":
        (D / "code-sha256.json").write_text(json.dumps({c: sha(c) for c in CODE}, indent=1, sort_keys=True) + "\n")
        return 0
    if a.mode == "missing":
        m = missing()
        (D / "p2").mkdir(parents=True, exist_ok=True)
        (D / "p2" / "missing.json").write_text(json.dumps(m, indent=0, sort_keys=True) + "\n")
        print("missing", len(m))
        return 0
    if a.mode == "plan":
        print("p1", len(p1_jobs()), "p3", len(B.plan("B1")) if a.arm else "-", "suites", B.SUITES)
        return 0
    BB.check_model(a.model)
    head, dirty = git_state()
    shas = json.loads((D / "code-sha256.json").read_text())
    if not a.pilot:
        proto = subprocess.run(["git", "ls-files", "--error-unmatch", "repeats/batch17/PROTOCOL.md"], cwd=ROOT,
                               capture_output=True).returncode == 0
        bad = [c for c in CODE if sha(c) != shas.get(c)]
        if not proto or dirty or bad:
            print(f"REFUSED main run: protocol_committed={proto} dirty={dirty} sha_mismatch={bad}")
            return 2
    a.arm = REVIEWER_ARM if a.mode == "p1" else a.arm
    a.attack, a.temperature = ("adaptive_seeded", 0.0) if a.mode == "p1" else ("important_instructions", 0.7)
    base = D / "pilot" / a.mode if a.pilot else D / a.mode
    (base / "runs").mkdir(parents=True, exist_ok=True)
    (base / "logs").mkdir(parents=True, exist_ok=True)
    tag = a.model.replace("/", "_").replace(":", "_")
    if a.mode == "p1":
        jobs, out, run = p1_jobs(), base / "runs" / f"{tag}__{REVIEWER_ARM}__T0.jsonl", p1_run
    elif a.mode == "p2":
        jobs = json.loads((D / "p2" / "missing.json").read_text())
        out, run = base / "runs" / f"{tag}__fill__important_instructions__T0.7__B1.jsonl", b9_run
    else:
        jobs = [dict(j, arm=a.arm, rep=1) for j in B.plan("B1")]
        out, run = base / "runs" / b9_file(a.model, a.arm, 1), b9_run
    done = {}
    if out.exists():
        for line in out.read_text().splitlines():
            r = json.loads(line)
            done[r["job_key"]] = r
    jobs = [j for j in jobs if job_key(j) not in done]
    if a.pilot:
        a.limit = min(a.limit or 2, 2)
    if a.limit:
        jobs = jobs[:max(0, a.limit - (0 if a.pilot else len(done)))]
    meta = {"git_head": head, "dirty": dirty, "sha256": {c: sha(c) for c in CODE}, "started_utc": B.now(),
            "argv": sys.argv[1:], "region": a.region, "pilot": a.pilot, "jobs": len(jobs)}
    with (base / "logs" / f"{out.stem}.meta.jsonl").open("a") as f:
        f.write(json.dumps(meta, sort_keys=True) + "\n")
    lock = threading.Lock()
    chain = B.ChainLog(base / "logs" / (out.stem + ".chain.jsonl"))
    client = BB.make_client(a.region)
    stop = threading.Event()
    state = {"spent": sum(r.get("cost_usd", 0) for r in done.values()), "n": 0}

    def work(j):
        for attempt in range(6):
            if stop.is_set():
                return
            try:
                rec = run(j, a, client, chain, lock)
                break
            except B.ProviderStop as e:
                if " after " in str(e) and attempt < 5:  # throttling: back off, never fail
                    print(f"BACKOFF {job_key(j)} {e} sleep={60 * (attempt + 1)}", flush=True)
                    time.sleep(60 * (attempt + 1))
                    continue
                stop.set()
                print(f"PROVIDER-STOP bedrock {a.model} {e}", flush=True)
                return
        rec.update({"job_key": job_key(j), "git_head": head, "dirty": dirty, "batch": "17", "sub": a.mode})
        with lock:
            with out.open("a") as f:
                f.write(json.dumps(rec, sort_keys=True, default=str) + "\n")
            state["spent"] += rec["cost_usd"]
            state["n"] += 1
            print(f"{state['n']}/{len(jobs)} {job_key(j)} u={rec['utility']} s={rec['security']} "
                  f"e={rec['error_class']} gate={rec['gate_checks']}/{rec['gate_blocks']} ${state['spent']:.3f}",
                  flush=True)
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
