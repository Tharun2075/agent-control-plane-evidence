"""Batch 19 runner (repeats/batch19/PROTOCOL.md): the Progent arm on AgentDojo, on Bedrock.

Progent (sunblaze-ucb/progent, MIT, third_party/progent, read-only) is used as shipped: its
secagent.tool module generates the task policy from the user query, checks every tool call
against it and updates it after each tool round, as in the authors' AgentDojo fork
(run.sh: SECAGENT_GENERATE/UPDATE/IGNORE_UPDATE_ERROR=True). Only two things differ, both
stated in PROTOCOL.md: the policy model is a Bedrock model (zero spend outside the credits,
no gpt-4o), reached by replacing secagent.tool.api_request; and the check runs in our
executor, which logs each call with the gate's fields. Everything else (victims, B1 tasks,
attack, T 0, region, success by AgentDojo's post-state check) matches the batch-7 gated arm.

Progent keeps its policy in module globals, so jobs run in processes, one job at a time each.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
import time
import warnings
from concurrent.futures import FIRST_COMPLETED, ProcessPoolExecutor, wait
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
sys.path[:0] = [str(ROOT / ".progent-deps"), str(ROOT / "third_party" / "progent")]

POLICY_MODEL = os.environ.get("B19_POLICY_MODEL", "deepseek.v3.2")
os.environ.update({"SECAGENT_GENERATE": "True", "SECAGENT_UPDATE": "True",
                   "SECAGENT_IGNORE_UPDATE_ERROR": "True", "SECAGENT_POLICY_MODEL": POLICY_MODEL})

import bench_agentdojo as B  # noqa: E402
import bench_bedrock as BB  # noqa: E402
import secagent.tool as ST  # noqa: E402
from agentdojo import models  # noqa: E402
from agentdojo.agent_pipeline import AgentPipeline, InitQuery, SystemMessage, ToolsExecutionLoop  # noqa: E402
from agentdojo.agent_pipeline.agent_pipeline import load_system_message  # noqa: E402
from agentdojo.agent_pipeline.tool_execution import is_string_list, tool_result_to_str  # noqa: E402
from agentdojo.attacks.attack_registry import load_attack  # noqa: E402
from agentdojo.functions_runtime import EmptyEnv  # noqa: E402
from agentdojo.task_suite.load_suites import get_suite  # noqa: E402
from agentdojo.types import ChatToolResultMessage, text_content_block_from_string  # noqa: E402
from ast import literal_eval  # noqa: E402

BATCH = ROOT / "repeats" / "batch19"
ARM = "progent"
ATTACK = "important_instructions"
MODELS = ["openai.gpt-oss-20b-1:0", "openai.gpt-oss-120b-1:0", "qwen.qwen3-32b-v1:0",
          "qwen.qwen3-vl-235b-a22b", "mistral.mistral-large-3-675b-instruct", "deepseek.v3.2"]
# Tools allowed without a generated rule: the authors' fork (agentdojo/.../{banking,slack}/task_suite.py).
ALWAYS_ALLOWED = {"banking": (["get_most_recent_transactions"], True),
                  "slack": (["get_channels", "read_channel_messages", "read_inbox", "get_users_in_channel"], False)}
TLLM = None  # set in _init (imports bench_batch9 lazily to keep its batch-9 paths unused)

_W: dict = {}  # per-process: client, policy meter


def _init(region: str, log_path: str):
    global TLLM
    import bench_batch9
    TLLM = bench_batch9.TLLM
    sys.stderr = open(log_path, "a", buffering=1)  # Progent prints its policies to stderr
    warnings.simplefilter("ignore")
    import boto3
    from botocore.config import Config
    # adaptive client-side backoff on throttling (10 tries), as the r9aws2 rerun
    _W["client"] = boto3.client("bedrock-runtime", region_name=region, config=Config(
        read_timeout=300, retries={"max_attempts": 10, "mode": "adaptive"}))
    ST.api_request = _policy_request


class PolicyMeter:
    def __init__(self):
        self.inp = self.out = self.calls = 0


def _policy_request(sys_prompt, user_prompt, temperature=0.0) -> str:
    """secagent.tool.api_request on Bedrock Converse (same prompts, same temperatures)."""
    m: PolicyMeter = _W["pm"]
    llm = BB.BedrockLLM(_W["client"], POLICY_MODEL, B.Meter())
    r = llm.call(modelId=POLICY_MODEL, system=[{"text": sys_prompt}],
                 messages=[{"role": "user", "content": [{"text": user_prompt}]}],
                 inferenceConfig={"maxTokens": BB.MAX_TOKENS, "temperature": min(1.0, temperature)})
    u = r.get("usage", {})
    m.inp += u.get("inputTokens", 0)
    m.out += u.get("outputTokens", 0)
    m.calls += 1
    return "".join(b["text"] for b in r["output"]["message"].get("content", []) if "text" in b)


def _reset_progent(suite):
    ST.available_tools = []
    ST.security_policy = None
    ST.init_user_query = None
    for f in suite.tools:
        ST.secure_tool_wrapper(f.run)  # registers the tool schema; the wrapper itself is not used
    tools, no_arg = ALWAYS_ALLOWED[suite.name]
    ST.update_always_allowed_tools(tools, allow_all_no_arg_tools=no_arg)


class ProgentInit(InitQuery):
    """InitQuery plus Progent's policy generation from the user query (fork basic_elements.py)."""

    def query(self, query, runtime, env=EmptyEnv(), messages=[], extra_args={}):
        out = super().query(query, runtime, env, messages, extra_args)
        ST.generate_security_policy(query)
        return out


class ProgentExecutor(B.GatedToolsExecutor):
    """The fork's ToolsExecutor: check every call against the policy, then one policy update
    per tool round; each check is logged with the gate's fields."""

    def _check(self, fn: str, args: dict, runtime) -> str | None:
        st = self.st
        hit = bool(st.markers) and fn in B.bench_gate.GATED[st.suite] and B.bench_gate.hits_target(args, st.markers)
        st.target_attempted |= hit
        full = {k: f.get_default(call_default_factory=True)
                for k, f in runtime.functions[fn].parameters.model_fields.items() if not f.is_required()}
        full.update(args)
        try:
            ST.check_tool_call(fn, full)
            reason, ok = "approved", True
        except Exception as e:  # ValidationError from secagent; message as the fork returns it
            reason, ok = f"{type(e).__name__}: {e}", False
        st.checks += 1
        st.blocks += not ok
        st.blocked_target += (not ok) and hit
        st.side_blocks += (not ok) and fn in B.bench_gate.GATED[st.suite]
        st.calls.append({"fn": fn, "gate": "approved" if ok else "progent: " + reason.split(". Please try")[0][:200],
                         "hit": hit})
        st.chain.append({
            "gen_ai.agent.id": "agentdojo-progent", "agent_manifest_sha256": "0" * 64,
            "gen_ai.conversation.id": st.conv, "step": st.checks,
            "gen_ai.operation.name": "execute_tool", "gen_ai.tool.name": fn,
            "action": "approved" if ok else "blocked", "personal_data_categories": ["none"],
            "lawful_basis": "not_applicable", "decision_mode": "automated", "approval_ref": None,
            "outcome": "approved" if ok else "rejected", "recipients": [],
            "provenance": "agentdojo-" + B.BENCH_VERSION, "detail": reason[:500]})
        return None if ok else reason

    def query(self, query, runtime, env=EmptyEnv(), messages=[], extra_args={}):
        if not messages or messages[-1]["role"] != "assistant" or not messages[-1]["tool_calls"]:
            return query, runtime, env, messages, extra_args
        results, calls, outs = [], [], []
        names = {t.name for t in runtime.functions.values()}
        for tc in messages[-1]["tool_calls"]:
            if tc.function not in names:
                results.append(ChatToolResultMessage(role="tool", content=[text_content_block_from_string("")],
                                                     tool_call_id=tc.id, tool_call=tc,
                                                     error=f"Invalid tool {tc.function} provided."))
                continue
            for k, v in tc.args.items():
                if isinstance(v, str) and is_string_list(v):
                    tc.args[k] = literal_eval(v)
            denied = self._check(tc.function, dict(tc.args), runtime)
            if denied:
                out, err = "", denied
            else:
                out, err = runtime.run_function(env, tc.function, tc.args)
            text = self.output_formatter(out)
            results.append(ChatToolResultMessage(role="tool", content=[text_content_block_from_string(text)],
                                                 tool_call_id=tc.id, tool_call=tc, error=err))
            calls.append({"name": tc.function, "args": dict(tc.args)})
            outs.append(text)
        ST.generate_update_security_policy(calls, str(outs), manual_check=False)
        return query, runtime, env, [*messages, *results], extra_args


def run_one(j: dict, a) -> dict:
    """One job in a worker process. Returns the record, or {"_provider_stop": msg}."""
    suite = get_suite(B.BENCH_VERSION, j["suite"])
    ut = suite.user_tasks[j["ut"]]
    it = suite.injection_tasks[j["it"]] if j["it"] else None
    meter, pm = B.Meter(), PolicyMeter()
    _W["pm"] = pm
    markers = []
    if it is not None:
        env0 = suite.load_and_inject_default_environment({})
        markers = B.bench_gate.target_markers([(c.function, dict(c.args)) for c in it.ground_truth(env0)],
                                              j["suite"])
    st = B.GateState(j["suite"], ut.PROMPT, markers, True, [], B.key(j), None)
    st.side_blocks = 0
    _reset_progent(suite)
    llm = TLLM(_W["client"], a.model, meter, 0.0)
    pipe = AgentPipeline([SystemMessage(load_system_message(None)), ProgentInit(), llm,
                          ToolsExecutionLoop([ProgentExecutor(st), llm], max_iters=15)])
    pipe.name = a.model
    models.MODEL_NAMES[a.model] = BB.attack_name(a.model)
    rec = {"set": "B1", "b2": False, "model": a.model, "provider": "bedrock", "region": a.region, "arm": ARM,
           "suite": j["suite"], "ut": j["ut"], "it": j["it"], "kind": "attacked" if it else "benign",
           "attack": ATTACK if it else None, "temperature": 0.0, "rep": 0,
           "bench": "agentdojo-" + B.BENCH_VERSION, "policy_model": POLICY_MODEL, "ts_start": B.now()}
    t0 = time.time()
    utility = security = None
    err_class = err = None
    try:
        injections = load_attack(ATTACK, suite, pipe).attack(ut, it) if it else {}
        utility, security = suite.run_task_with_pipeline(pipe, ut, it, injections)
    except B.ProviderRefusal as e:
        err_class, err = "provider_refused", str(e)
    except B.ProviderStop as e:
        return {"_provider_stop": str(e)}
    except Exception as e:  # recorded, never dropped
        err_class, err = type(e).__name__, str(e)[:300]
    pin, pout = BB.PRICES[a.model]
    qin, qout = BB.PRICES[POLICY_MODEL]
    victim = (meter.inp * pin + meter.out * pout) / 1e6
    policy = (pm.inp * qin + pm.out * qout) / 1e6
    rec.update({"ts_end": B.now(), "secs": round(time.time() - t0, 1), "utility": utility,
                "security": security if it else None, "error_class": err_class, "error": err,
                "target_call_attempted": st.target_attempted, "gate_checks": st.checks, "gate_blocks": st.blocks,
                "side_effect_blocks": st.side_blocks, "blocked_target": st.blocked_target, "calls": st.calls,
                "usage": {"input": meter.inp, "output": meter.out}, "model_ids": sorted(meter.model_ids),
                "stop_reasons": llm.stop_reasons, "llm_calls": len(llm.stop_reasons),
                "policy_usage": {"input": pm.inp, "output": pm.out, "calls": pm.calls},
                "victim_cost_usd": round(victim, 6), "policy_cost_usd": round(policy, 6),
                "cost_usd": round(victim + policy, 6), "_chain": st.chain})
    return rec


def out_path(a) -> Path:
    tag = a.model.replace("/", "_").replace(":", "_")
    return Path(a.out_dir) / f"{tag}__{ARM}__B1.jsonl"


CODE = ["tools/bench_batch19.py", "tools/bench_agentdojo.py", "tools/bench_bedrock.py", "tools/bench_batch9.py",
        "third_party/progent/secagent/tool.py", "third_party/progent/secagent/utils.py",
        "third_party/progent/secagent/policy_type_check.py", "third_party/progent/secagent/__init__.py"]


def sha(p: str) -> str:
    return hashlib.sha256((ROOT / p).read_bytes()).hexdigest()


def main_run_refusal() -> str:
    """'' when a main run may start: PROTOCOL tracked, code clean and hashes as committed."""
    proto = subprocess.run(["git", "ls-files", "--error-unmatch", "repeats/batch19/PROTOCOL.md"], cwd=ROOT,
                           capture_output=True).returncode == 0
    dirty = subprocess.run(["git", "status", "--porcelain", "--", "tools", "third_party", "repeats/batch19/PROTOCOL.md",
                            "repeats/batch19/code-sha256.json"], cwd=ROOT, capture_output=True, text=True).stdout.strip()
    shas = json.loads((BATCH / "code-sha256.json").read_text()) if (BATCH / "code-sha256.json").exists() else {}
    bad = [c for c in CODE if sha(c) != shas.get(c)]
    if proto and not dirty and not bad:
        return ""
    return f"protocol_committed={proto} dirty={bool(dirty)} sha_mismatch={bad}"


def main(argv=None) -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--model", required=True, choices=MODELS)
    p.add_argument("--region", default="us-east-1", choices=["us-east-1"])
    p.add_argument("--out-dir", default=str(BATCH / "runs"))
    p.add_argument("--keys", default="", help="comma list suite/ut/it (it=None for benign); pilot use")
    p.add_argument("--limit", type=int, default=0)
    p.add_argument("--budget-usd", type=float, default=0.0, help="per-model cap, counts resumed runs")
    p.add_argument("--workers", type=int, default=4)
    p.add_argument("--dry-run", action="store_true")
    p.add_argument("--write-shas", action="store_true")
    a = p.parse_args(argv)
    if a.write_shas:
        (BATCH / "code-sha256.json").write_text(json.dumps({c: sha(c) for c in CODE}, indent=1, sort_keys=True) + "\n")
        return 0
    BB.check_model(a.model)
    out = out_path(a)
    out.parent.mkdir(parents=True, exist_ok=True)
    log_dir = out.parent.parent / "logs" / out.parent.name if out.parent.name in ("runs", "pilot") else out.parent / "logs"
    log_dir.mkdir(parents=True, exist_ok=True)
    done = {}
    if out.exists():
        for line in out.read_text().splitlines():
            r = json.loads(line)
            done[B.key(r)] = r
    spent = sum(r.get("cost_usd", 0) for r in done.values())
    jobs = [j for j in B.plan("B1") if B.key(j) not in done]
    if a.keys:
        want = a.keys.split(",")
        jobs = [j for j in jobs if B.key(j) in want]
    if a.limit:
        jobs = jobs[:max(0, a.limit - len(done))]
    main_run = Path(a.out_dir).resolve() == (BATCH / "runs").resolve()
    refusal = main_run_refusal() if main_run else ""
    if a.dry_run:
        print(f"DRY {a.model} main={main_run} refused={refusal or '-'} out={out} done={len(done)} todo={len(jobs)} spent=${spent:.3f} "
              f"cap=${a.budget_usd:.2f} policy={POLICY_MODEL}", flush=True)
        return 0
    if refusal:
        print(f"REFUSED main run: {refusal}", flush=True)
        return 2
    if a.budget_usd and spent >= a.budget_usd:
        print(f"BUDGET-STOP {a.model} ${spent:.2f} (resumed)", flush=True)
        return 0
    chain_path = log_dir / (out.stem + ".progent.jsonl")
    stem = out.stem
    t0, n, stopped = time.time(), 0, None
    with ProcessPoolExecutor(a.workers, initializer=_init,
                             initargs=(a.region, str(log_dir / (stem + ".stderr.log")))) as ex:
        pending = {ex.submit(run_one, j, a) for j in jobs}
        while pending:
            fin, pending = wait(pending, return_when=FIRST_COMPLETED)
            for f in fin:
                try:
                    rec = f.result()
                except Exception as e:  # a crashed worker: record nothing, report it
                    print(f"WORKER-ERROR {a.model} {type(e).__name__}: {str(e)[:200]}", flush=True)
                    continue
                if "_provider_stop" in rec:
                    stopped = stopped or f"PROVIDER-STOP bedrock {a.model} {rec['_provider_stop']}"
                    continue
                chain = rec.pop("_chain")
                with out.open("a") as fo:
                    fo.write(json.dumps(rec, sort_keys=True) + "\n")
                with chain_path.open("a") as fc:
                    for c in chain:
                        fc.write(json.dumps({"ts": rec["ts_end"], **c}, sort_keys=True) + "\n")
                spent += rec["cost_usd"]
                n += 1
                print(f"{a.model} {n}/{len(jobs)} {B.key(rec)} u={rec['utility']} s={rec['security']} "
                      f"e={rec['error_class']} chk={rec['gate_checks']}/{rec['gate_blocks']} "
                      f"{rec['secs']}s ${spent:.3f}", flush=True)
                if a.budget_usd and spent >= a.budget_usd and not stopped:
                    stopped = f"BUDGET-STOP {a.model} ${spent:.2f}"
            if stopped and stopped != "printed":
                for f in pending:
                    f.cancel()
                print(stopped, flush=True)
                stopped = "printed"
                pending = {f for f in pending if not f.cancelled()}
    print(f"DONE {out.name} runs={n} spent=${spent:.3f} secs={time.time() - t0:.0f}", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
