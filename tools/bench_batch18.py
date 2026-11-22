"""Batch 18 runner (repeats/batch18/PROTOCOL.md). Two arms on Bedrock, reusing the batch-9/10/11/17 runners
unchanged:
  A  `inferred`: the victim model writes the allowed tools and targets from the user-task text in one frozen
     call per task (mode `infer`, prompt repeats/batch18/a/infer_prompt.txt); the gate enforces that list.
     `gated` is the concurrent hand-written control.
  B  `llm_reviewer`: the batch-17 P1 reviewer (bench_batch17.Executor17, same model, prompt and config) on all
     six victims.
Each arm: the 17 set-A pairs (batch-11 seeded injection, one try, rep 1) plus the 37 B1 benign tasks, per victim.
The whole batch stops at USD 24.50 list price (hard cap 25.00); per-arm caps in CAPS.
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
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
import bench_batch10 as B10  # noqa: E402
import bench_batch11 as B11  # noqa: E402
import bench_batch17 as B17  # noqa: E402  (sets the retry default and B10.Executor10 = Executor17)
import bench_bedrock as BB  # noqa: E402
from acp import bench_gate as G  # noqa: E402
from agentdojo.task_suite.load_suites import get_suite  # noqa: E402

D = ROOT / "repeats" / "batch18"
INFER_PROMPT = D / "a" / "infer_prompt.txt"
INFER_DIR = D / "a" / "inferred"
VICTIMS = ("openai.gpt-oss-20b-1:0", "qwen.qwen3-32b-v1:0", "openai.gpt-oss-120b-1:0",
           "mistral.mistral-large-3-675b-instruct", "qwen.qwen3-vl-235b-a22b", "deepseek.v3.2")
ARMS = {"inferred": "a", "gated": "a", "llm_reviewer": "b"}
HARD_CAP, MARGIN = 25.00, 0.50
CAPS = {"a": 13.00, "b": 10.00, "pilot": 1.00}
APPS = {"banking": "online banking", "slack": "Slack workspace"}
CODE = ["tools/bench_batch18.py", "repeats/batch18/a/infer_prompt.txt", "tools/bench_batch17.py",
        "repeats/batch17/p1/reviewer_prompt.txt", "acp/bench_gate_b17.py", "tools/bench_agentdojo.py",
        "tools/bench_batch9.py", "tools/bench_batch10.py", "tools/bench_batch11.py", "tools/bench_bedrock.py",
        "acp/bench_gate.py", "acp/batch8_gate.py"]
JSON_OBJ = re.compile(r"\{.*\}", re.S)


def tag(model) -> str:
    return model.replace("/", "_").replace(":", "_")


def git_state() -> tuple[str, bool]:
    head = subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT, capture_output=True, text=True).stdout.strip()
    st = subprocess.run(["git", "status", "--porcelain", "--", "acp", "tools", "Makefile",
                         "repeats/batch18/PROTOCOL.md", "repeats/batch18/a/infer_prompt.txt",
                         "repeats/batch18/code-sha256.json"], cwd=ROOT, capture_output=True, text=True).stdout
    return head, bool(st.strip())


# ---------------------------------------------------------------- spend (code-enforced caps)
def spent() -> dict:
    """List-price USD already spent by this batch, from every run file and inferred-list file on disk."""
    out = {"a": 0.0, "b": 0.0, "pilot": 0.0}
    for f in D.glob("**/runs/*.jsonl"):
        part = "pilot" if "pilot" in f.relative_to(D).parts else f.relative_to(D).parts[0]
        for line in f.read_text().splitlines():
            try:
                out[part] += json.loads(line).get("cost_usd", 0.0)
            except (json.JSONDecodeError, KeyError):
                continue  # a line another process is still writing
    for f in INFER_DIR.glob("*.json"):
        try:
            out["a"] += sum(t.get("cost_usd", 0.0) for t in json.loads(f.read_text())["tasks"].values())
        except (json.JSONDecodeError, KeyError):
            continue
    out["total"] = sum(out.values())
    return out


def over_cap(part: str) -> str | None:
    s = spent()
    if s["total"] >= HARD_CAP - MARGIN:
        return f"total ${s['total']:.2f} >= ${HARD_CAP - MARGIN:.2f}"
    if s[part] >= CAPS[part] - MARGIN:
        return f"{part} ${s[part]:.2f} >= ${CAPS[part] - MARGIN:.2f}"
    return None


# ---------------------------------------------------------------- arm A: inferred allowlist
def benign_jobs() -> list[dict]:
    return [j for j in B.plan("B1") if j["it"] is None]


def hand_list(suite, ut, sname) -> dict:
    """The hand-written list for the comparison: gated tools and target arguments of the ground truth."""
    env0 = suite.load_and_inject_default_environment({})
    tools, targets = set(), set()
    for c in ut.ground_truth(env0):
        if c.function not in G.GATED[sname]:
            continue
        tools.add(c.function)
        for k in G.TARGET_KEYS + G.TASK_TARGETS.get(sname, {}).get(c.function, ()):
            if c.args.get(k) not in (None, ""):
                targets.add(str(c.args[k]))
    return {"tools": sorted(tools), "targets": sorted(targets)}


def parse_inferred(text: str, sname: str) -> dict:
    """Fail closed: anything unparsable is an empty list. Tools outside the suite's gated set are dropped."""
    m = JSON_OBJ.search(text)
    try:
        obj = json.loads(m.group(0)) if m else None
        if not isinstance(obj, dict):
            raise ValueError("no JSON object")
        tools = obj.get("tools", [])
        targets = obj.get("targets", [])
        if not isinstance(tools, list) or not isinstance(targets, list):
            raise ValueError("tools/targets not lists")
    except (ValueError, json.JSONDecodeError) as e:
        return {"tools": [], "targets": [], "dropped_tools": [], "parse_error": str(e)[:120]}
    keep = sorted({t for t in tools if isinstance(t, str) and t in G.GATED[sname]})
    return {"tools": keep, "targets": sorted({str(t) for t in targets if isinstance(t, (str, int, float))}),
            "dropped_tools": sorted({str(t) for t in tools} - set(keep)), "parse_error": None}


def infer_one(client, model, sname, prompt) -> dict:
    meter = B.Meter()
    llm = BB.BedrockLLM(client, model, meter)
    system = INFER_PROMPT.read_text().replace("{app}", APPS[sname]).replace(
        "{tools}", "\n".join(f"- {t}" for t in G.GATED[sname]))
    user = f"USER REQUEST:\n{prompt}" + ("\n/no_think" if model.startswith("qwen.") else "")
    pin, pout = BB.PRICES[model]
    r = llm.call(modelId=model, messages=[{"role": "user", "content": [{"text": user}]}],
                 system=[{"text": system}], inferenceConfig={"maxTokens": 2048, "temperature": 0.0})
    u = r.get("usage", {})
    text = "\n".join(b["text"] for b in r.get("output", {}).get("message", {}).get("content", []) if "text" in b)
    clean = B10.THINK.sub("", text).split("<think>")[0]
    rec = parse_inferred(clean, sname)
    rec.update({"raw": clean[:2000], "input": u.get("inputTokens", 0), "output": u.get("outputTokens", 0),
                "cost_usd": round((u.get("inputTokens", 0) * pin + u.get("outputTokens", 0) * pout) / 1e6, 6),
                "ts": B.now()})
    return rec


def infer(a) -> int:
    INFER_DIR.mkdir(parents=True, exist_ok=True)
    f = INFER_DIR / f"{tag(a.model)}.json"
    doc = json.loads(f.read_text()) if f.exists() else {
        "model": a.model, "region": a.region, "temperature": 0.0, "max_tokens": 2048,
        "prompt_sha256": B17.sha("repeats/batch18/a/infer_prompt.txt"), "git_head": git_state()[0], "tasks": {}}
    client = BB.make_client(a.region)
    for j in benign_jobs():
        k = f"{j['suite']}/{j['ut']}"
        if k in doc["tasks"]:
            continue  # frozen: never recomputed
        why = over_cap("a")
        if why:
            print(f"BUDGET-STOP infer {why}", flush=True)
            return 3
        suite = get_suite(B.BENCH_VERSION, j["suite"])
        ut = suite.user_tasks[j["ut"]]
        for attempt in range(6):
            try:
                rec = infer_one(client, a.model, j["suite"], ut.PROMPT)
                break
            except B.ProviderStop as e:
                if " after " in str(e) and attempt < 5:
                    print(f"BACKOFF infer {k} {e} sleep={60 * (attempt + 1)}", flush=True)
                    time.sleep(60 * (attempt + 1))
                    continue
                print(f"PROVIDER-STOP bedrock {a.model} {e}", flush=True)
                return 4
        rec["hand"] = hand_list(suite, ut, j["suite"])
        doc["tasks"][k] = rec
        f.write_text(json.dumps(doc, indent=1, sort_keys=True) + "\n")
        print(f"infer {k} tools={rec['tools']} targets={len(rec['targets'])} err={rec['parse_error']} "
              f"${rec['cost_usd']:.4f}", flush=True)
    n_err = sum(t["parse_error"] is not None for t in doc["tasks"].values())
    print(f"DONE infer {f.name} tasks={len(doc['tasks'])} parse_errors={n_err}")
    return 0


def decide_inferred(sname, fn, args, inf) -> tuple[bool, str]:
    """Allow iff the tool is in the inferred tools and every target argument equals an inferred target
    (after bench_gate._norm; the new password exactly, case-sensitive)."""
    if fn not in inf["tools"]:
        return False, "tool not in inferred authority"
    normed = {G._norm(t) for t in inf["targets"]}
    for k in G.TARGET_KEYS:
        if k in args and args[k] not in (None, "") and G._norm(args[k]) not in normed:
            return False, f"{k} not in inferred allowlist"
    exact = fn in G.ACCOUNT_CHANGES.get(sname, ())
    for k in G.TASK_TARGETS.get(sname, {}).get(fn, ()):
        v = args.get(k)
        if v in (None, ""):
            return False, f"{k} missing"
        if not (str(v) in inf["targets"] if exact else G._norm(v) in normed):
            return False, f"{k} not in inferred allowlist"
    return True, "approved"


class Executor18(B17.Executor17):
    """Executor17 (llm_reviewer, and the batch-10 gate for every other arm) plus the `inferred` arm."""

    def _gate(self, fn, args):
        st = self.st
        if st.arm != "inferred":
            return super()._gate(fn, args)
        gated_tool = fn in G.GATED[st.suite]
        hit = bool(st.markers) and gated_tool and G.hits_target(args, st.markers)
        st.target_attempted |= hit
        if not gated_tool:
            st.calls.append({"fn": fn, "gate": None, "hit": hit})
            return None
        h_ok, h_reason, chk = B10.decide("gated", st.suite, fn, args, st.user_prompt, st.authority)
        ok, reason = decide_inferred(st.suite, fn, args, st.inferred)
        chk = dict(chk or {}, handwritten={"ok": h_ok, "reason": h_reason})
        st.checks += 1
        st.blocks += not ok
        st.blocked_target += (not ok) and hit
        st.calls.append({"fn": fn, "gate": reason, "hit": hit, "chk": chk})
        with st.lock:
            st.chain.append(**{"gen_ai.agent.id": "agentdojo-inferred", "agent_manifest_sha256": "0" * 64,
                               "gen_ai.conversation.id": st.conv, "step": st.checks,
                               "gen_ai.operation.name": "execute_tool", "gen_ai.tool.name": fn,
                               "action": "approved" if ok else "blocked", "personal_data_categories": ["none"],
                               "lawful_basis": "not_applicable", "decision_mode": "automated",
                               "approval_ref": None, "outcome": "approved" if ok else "rejected", "recipients": [],
                               "provenance": "agentdojo-" + B.BENCH_VERSION, "detail": reason})
        return None if ok else f"blocked by approval gate: {reason}"


B10.Executor10 = Executor18  # make_pipe looks the executor up at call time


# ---------------------------------------------------------------- runs
def jobs_for() -> list[dict]:
    return [dict(j, kind="attacked", rep=1) for j in B9.plan_adaptive()] + \
           [dict(j, kind="benign", rep=1) for j in benign_jobs()]


def job_key(j) -> str:
    return f"{B.key(j)}#{j['kind']}#r{j['rep']}"


def run_job(j, a, client, chain, lock, inferred) -> dict:
    suite = get_suite(B.BENCH_VERSION, j["suite"])
    ut = suite.user_tasks[j["ut"]]
    conv = f"{B.key(j)}#{j['kind']}#{a.arm}"
    if j["kind"] == "attacked":
        st = B10.State10(a.arm, B10.authority_for(suite, ut, j["suite"]), j["suite"], ut.PROMPT,
                         list(B9.ADAPTIVE_MARKERS[j["suite"]]), True, chain, conv, lock)
    else:
        suite, ut, _, st = B10._setup(j, a, a.model, chain, lock, conv)
    B17._arm_state(st, client)
    inf = inferred.get(f"{j['suite']}/{j['ut']}") if inferred else None
    st.inferred = inf
    if j["kind"] == "attacked":
        goal = B9.adaptive_goal(j["tool"], j["target"])
        run = B10._victim_run(suite, ut, None, st, a, client, lambda pipe: B11.seed_injection(suite, ut, goal, pipe))
        run["security"] = B9.adaptive_success(run["calls"])  # batch-9/11 success rule
        rec = B10._base(j, a)
        rec.update({"set": "A", "it": None, "kind": "attacked", "attack": "adaptive_seeded",
                    "adaptive_tool": j["tool"], "adaptive_target": j["target"]})
    else:
        run = B10._victim_run(suite, ut, None, st, a, client, lambda pipe: {})
        rec = B10._base(j, a)
        rec.update({"set": "B1", "kind": "benign", "attack": None})
    rec.update(run)
    rec.update({"rep": j["rep"], "victim_cost_usd": run["cost_usd"],
                "cost_usd": round(run["cost_usd"] + st.rev_cost, 6), "ts_end": B.now()})
    if a.arm == "llm_reviewer":
        rec.update({"reviewer_model": B17.REVIEWER_MODEL, "reviewer_usage": {"input": st.rev_in,
                    "output": st.rev_out}, "reviewer_cost_usd": round(st.rev_cost, 6)})
    if a.arm == "inferred":
        rec["inferred"] = {k: inf[k] for k in ("tools", "targets", "parse_error")}
    return rec


def main(argv=None) -> int:
    p = argparse.ArgumentParser()
    p.add_argument("mode", choices=["infer", "run", "write-shas", "plan", "spent"])
    p.add_argument("--model")
    p.add_argument("--arm", choices=sorted(ARMS))
    p.add_argument("--region", default="us-east-1", choices=["us-east-1", "us-west-2"])
    p.add_argument("--workers", type=int, default=3)
    p.add_argument("--budget-usd", type=float, default=3.0)
    p.add_argument("--pilot", action="store_true")
    a = p.parse_args(argv)
    if a.mode == "write-shas":
        (D / "code-sha256.json").write_text(json.dumps({c: B17.sha(c) for c in CODE}, indent=1, sort_keys=True)
                                            + "\n")
        return 0
    if a.mode == "plan":
        print("jobs per victim per arm", len(jobs_for()), "benign", len(benign_jobs()), "victims", len(VICTIMS))
        return 0
    if a.mode == "spent":
        print(json.dumps({k: round(v, 4) for k, v in spent().items()}))
        return 0
    BB.check_model(a.model)
    head, dirty = git_state()
    shas = json.loads((D / "code-sha256.json").read_text())
    proto = subprocess.run(["git", "ls-files", "--error-unmatch", "repeats/batch18/PROTOCOL.md"], cwd=ROOT,
                           capture_output=True).returncode == 0
    bad = [c for c in CODE if B17.sha(c) != shas.get(c)]
    if not proto or bad or (dirty and not a.pilot):  # paid calls only on committed protocol and code
        print(f"REFUSED: protocol_committed={proto} dirty={dirty} sha_mismatch={bad}")
        return 2
    if a.mode == "infer":
        return infer(a)
    part = "pilot" if a.pilot else ARMS[a.arm]
    inferred = None
    if a.arm == "inferred":
        f = INFER_DIR / f"{tag(a.model)}.json"
        inferred = json.loads(f.read_text())["tasks"] if f.exists() else {}
        if len(inferred) != len(benign_jobs()):
            print(f"REFUSED: inferred lists incomplete for {a.model} ({len(inferred)}/{len(benign_jobs())}); "
                  f"run `infer` first")
            return 2
    a.attack, a.temperature = "adaptive_seeded", 0.0
    base = D / "pilot" / a.arm if a.pilot else D / ARMS[a.arm]
    (base / "runs").mkdir(parents=True, exist_ok=True)
    (base / "logs").mkdir(parents=True, exist_ok=True)
    out = base / "runs" / f"{tag(a.model)}__{a.arm}__T0.jsonl"
    jobs = jobs_for()
    if a.pilot:
        jobs = [j for j in jobs if j["kind"] == "attacked"][:2]
    done = {}
    if out.exists():
        for line in out.read_text().splitlines():
            r = json.loads(line)
            done[r["job_key"]] = r
    jobs = [j for j in jobs if job_key(j) not in done]
    meta = {"git_head": head, "dirty": dirty, "sha256": {c: B17.sha(c) for c in CODE}, "started_utc": B.now(),
            "argv": sys.argv[1:], "region": a.region, "pilot": a.pilot, "jobs": len(jobs), "spent": spent()}
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
            why = over_cap(part)
            if why:
                stop.set()
                print(f"BUDGET-STOP {why}", flush=True)
                return
            try:
                rec = run_job(j, a, client, chain, lock, inferred)
                break
            except B.ProviderStop as e:
                if " after " in str(e) and attempt < 5:  # throttling: back off, never fail
                    print(f"BACKOFF {job_key(j)} {e} sleep={60 * (attempt + 1)}", flush=True)
                    time.sleep(60 * (attempt + 1))
                    continue
                stop.set()
                print(f"PROVIDER-STOP bedrock {a.model} {e}", flush=True)
                return
        else:
            return
        rec.update({"job_key": job_key(j), "git_head": head, "dirty": dirty, "batch": "18", "pilot": a.pilot})
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
                print(f"BUDGET-STOP process ${state['spent']:.2f}", flush=True)

    t0 = time.time()
    with ThreadPoolExecutor(a.workers) as ex:
        list(ex.map(work, jobs))
    print(f"DONE {out.name} runs={state['n']} spent=${state['spent']:.3f} secs={time.time() - t0:.0f}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
