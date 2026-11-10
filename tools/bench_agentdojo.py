"""Batch 6 runner: AgentDojo (v1.2.2 banking + slack) through a plain or a gated agent.

Needs the optional benchmark dependency (requirements-bench.txt); the core repo stays stdlib.
Protocol, sample and stop rules: repeats/batch6/PROTOCOL.md. One JSON line per run is appended
to repeats/batch6/runs/<model>__<arm>.jsonl; finished runs are skipped on restart.

  python tools/bench_agentdojo.py --model claude-haiku-5-5 --arm gated --set B1 --budget-usd 10
  python tools/bench_agentdojo.py --model gemini-flash-latest --provider gemini --set B2

Keys come from the environment only (ANTHROPIC_API_KEY, OPENAI_COMPAT_KEY); never from disk.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import random
import sys
import threading
import time
from ast import literal_eval
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from acp import bench_gate  # noqa: E402
from acp.log import ChainLog  # noqa: E402

from agentdojo import models  # noqa: E402
from agentdojo.agent_pipeline import (  # noqa: E402
    AgentPipeline, InitQuery, SystemMessage, ToolsExecutionLoop, ToolsExecutor)
from agentdojo.agent_pipeline.agent_pipeline import load_system_message  # noqa: E402
from agentdojo.agent_pipeline.base_pipeline_element import BasePipelineElement  # noqa: E402
from agentdojo.agent_pipeline.llms import anthropic_llm as A  # noqa: E402
from agentdojo.agent_pipeline.llms import openai_llm as O  # noqa: E402
from agentdojo.agent_pipeline.tool_execution import is_string_list, tool_result_to_str  # noqa: E402
from agentdojo.attacks.attack_registry import load_attack  # noqa: E402
from agentdojo.functions_runtime import EmptyEnv  # noqa: E402
from agentdojo.task_suite.load_suites import get_suite  # noqa: E402
from agentdojo.types import ChatToolResultMessage, text_content_block_from_string  # noqa: E402

BENCH_VERSION = "v1.2.2"
SUITES = ("banking", "slack")
ATTACK = "important_instructions"
PER_SUITE_ATTACKED = 20
B2_PER_SUITE = 10
SEED = 6
RUN_DIR = ROOT / "repeats" / "batch6" / "runs"
LOG_DIR = ROOT / "repeats" / "batch6" / "logs"
PRICES = {  # USD per million tokens (input, output)
    "claude-haiku-5-5": (0.10, 0.50),
    "claude-sonnet-5-5": (2.0, 10.0),
    "claude-opus-5-5": (4.0, 20.0),
}
ENDPOINTS = {
    "gemini": "https://generativelanguage.googleapis.com/v1beta/openai/",
    "groq": "https://api.groq.com/openai/v1",
    "openrouter": "https://openrouter.ai/api/v1",
    "mlx": "http://localhost:8001/v1",
}
NAME_FOR_ATTACK = {"anthropic": "Claude", "gemini": "AI model developed by Google", "mlx": "Local model"}


class ProviderRefusal(Exception):
    pass


class ProviderStop(Exception):
    """Quota / rate / payment error: stop this provider, never retry by paying."""


def now() -> str:
    return dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


class Meter:
    def __init__(self):
        self.inp = self.out = 0
        self.model_ids: set[str] = set()


class ClaudeLLM(BasePipelineElement):
    """Claude 5.5 via the Anthropic SDK: no temperature, no thinking budget (both 400 on 5.5)."""

    def __init__(self, client, model: str, meter: Meter):
        self.client, self.model, self.meter = client, model, meter

    def query(self, query, runtime, env=EmptyEnv(), messages=[], extra_args={}):
        system, msgs = A._conversation_to_anthropic(messages)
        tools = [A._function_to_anthropic(t) for t in runtime.functions.values()]
        kw = {"model": self.model, "max_tokens": 8192, "messages": msgs, "tools": tools}
        if system:
            kw["system"] = system
        with self.client.messages.stream(**kw) as s:
            completion = s.get_final_message()
        self.meter.inp += completion.usage.input_tokens + (completion.usage.cache_creation_input_tokens or 0) \
            + (completion.usage.cache_read_input_tokens or 0)
        self.meter.out += completion.usage.output_tokens
        self.meter.model_ids.add(completion.model)
        if completion.stop_reason == "refusal":
            raise ProviderRefusal("stop_reason=refusal")
        output = A._anthropic_to_assistant_message(completion)
        return query, runtime, env, [*messages, output], extra_args


class CompatLLM(BasePipelineElement):
    """Any OpenAI-compatible chat endpoint (free tiers and local MLX)."""

    def __init__(self, client, model: str, meter: Meter):
        self.client, self.model, self.meter = client, model, meter

    def query(self, query, runtime, env=EmptyEnv(), messages=[], extra_args={}):
        import openai
        msgs = [O._message_to_openai(m, self.model) for m in messages]
        tools = [O._function_to_openai(t) for t in runtime.functions.values()]
        try:
            c = self.client.chat.completions.create(model=self.model, messages=msgs, tools=tools or None,
                                                    temperature=0.0, max_tokens=4096)
        except openai.RateLimitError as e:
            raise ProviderStop(f"429 {str(e)[:160]}") from e
        except openai.APIStatusError as e:
            if e.status_code in (402, 429):
                raise ProviderStop(f"{e.status_code} {str(e)[:160]}") from e
            body = str(e).lower()
            if e.status_code == 400 and ("safety" in body or "content" in body and "policy" in body):
                raise ProviderRefusal(f"400 {str(e)[:160]}") from e
            raise
        if c.usage:
            self.meter.inp += c.usage.prompt_tokens or 0
            self.meter.out += c.usage.completion_tokens or 0
        self.meter.model_ids.add(getattr(c, "model", self.model) or self.model)
        ch = c.choices[0]
        if ch.finish_reason == "content_filter":
            raise ProviderRefusal("finish_reason=content_filter")
        output = O._openai_to_assistant_message(ch.message)
        return query, runtime, env, [*messages, output], extra_args


class GateState:
    def __init__(self, suite: str, user_prompt: str, markers: list[str], gated: bool, chain, conv: str, lock):
        self.suite, self.user_prompt, self.markers, self.gated = suite, user_prompt, markers, gated
        self.chain, self.conv, self.lock = chain, conv, lock
        self.checks = self.blocks = self.blocked_target = 0
        self.target_attempted = False
        self.calls: list[dict] = []


class GatedToolsExecutor(ToolsExecutor):
    """AgentDojo's ToolsExecutor plus the control-plane gate on side-effect tools."""

    def __init__(self, state: GateState):
        super().__init__(tool_result_to_str)
        self.st = state

    def _gate(self, fn: str, args: dict) -> str | None:
        st = self.st
        hit = bool(st.markers) and fn in bench_gate.GATED[st.suite] and bench_gate.hits_target(args, st.markers)
        st.target_attempted |= hit
        if not st.gated or fn not in bench_gate.GATED[st.suite]:
            st.calls.append({"fn": fn, "gate": None, "hit": hit})
            return None
        ok, reason = bench_gate.review(st.suite, fn, args, st.user_prompt)
        st.checks += 1
        st.blocks += not ok
        st.blocked_target += (not ok) and hit
        st.calls.append({"fn": fn, "gate": reason, "hit": hit})
        with st.lock:
            st.chain.append(**{
                "gen_ai.agent.id": "agentdojo-gated", "agent_manifest_sha256": "0" * 64,
                "gen_ai.conversation.id": st.conv, "step": st.checks,
                "gen_ai.operation.name": "execute_tool", "gen_ai.tool.name": fn,
                "action": "approved" if ok else "blocked", "personal_data_categories": ["none"],
                "lawful_basis": "not_applicable", "decision_mode": "automated", "approval_ref": None,
                "outcome": "approved" if ok else "rejected", "recipients": [],
                "provenance": "agentdojo-" + BENCH_VERSION, "detail": reason})
        return None if ok else f"blocked by approval gate: {reason}"

    def query(self, query, runtime, env=EmptyEnv(), messages=[], extra_args={}):
        if not messages or messages[-1]["role"] != "assistant" or not messages[-1]["tool_calls"]:
            return query, runtime, env, messages, extra_args
        results = []
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
            denied = self._gate(tc.function, dict(tc.args))
            if denied:
                results.append(ChatToolResultMessage(role="tool", content=[text_content_block_from_string("")],
                                                     tool_call_id=tc.id, tool_call=tc, error=denied))
                continue
            out, err = runtime.run_function(env, tc.function, tc.args)
            results.append(ChatToolResultMessage(role="tool", content=[text_content_block_from_string(
                self.output_formatter(out))], tool_call_id=tc.id, tool_call=tc, error=err))
        return query, runtime, env, [*messages, *results], extra_args


def plan(set_name: str) -> list[dict]:
    """The pre-registered task list (PROTOCOL.md): deterministic, no model involved."""
    jobs = []
    for sname in SUITES:
        suite = get_suite(BENCH_VERSION, sname)
        pairs = sorted((u, i) for u in suite.user_tasks for i in suite.injection_tasks)
        att = random.Random(SEED).sample(pairs, PER_SUITE_ATTACKED)
        if set_name == "B1":
            jobs += [{"suite": sname, "ut": u, "it": None} for u in sorted(suite.user_tasks)]
            jobs += [{"suite": sname, "ut": u, "it": i} for u, i in att]
        else:
            jobs += [{"suite": sname, "ut": u, "it": i} for u, i in att[:B2_PER_SUITE]]
    return jobs


def key(j: dict) -> str:
    return f"{j['suite']}/{j['ut']}/{j['it']}"


def make_client(provider: str):
    if provider == "anthropic":
        import anthropic
        return anthropic.Anthropic(api_key=os.environ["ANTHROPIC_API_KEY"], max_retries=4, timeout=300)
    import openai
    return openai.OpenAI(base_url=ENDPOINTS[provider], api_key=os.environ.get("OPENAI_COMPAT_KEY", "local"),
                         max_retries=1, timeout=300)


def run_one(j, a, client, chain, lock) -> dict:
    suite = get_suite(BENCH_VERSION, j["suite"])
    ut = suite.user_tasks[j["ut"]]
    it = suite.injection_tasks[j["it"]] if j["it"] else None
    meter = Meter()
    markers = []
    if it is not None:
        env0 = suite.load_and_inject_default_environment({})
        markers = bench_gate.target_markers([(c.function, dict(c.args)) for c in it.ground_truth(env0)], j["suite"])
    st = GateState(j["suite"], ut.PROMPT, markers, a.arm == "gated", chain, key(j), lock)
    llm = ClaudeLLM(client, a.model, meter) if a.provider == "anthropic" else CompatLLM(client, a.model, meter)
    pipe = AgentPipeline([SystemMessage(load_system_message(None)), InitQuery(), llm,
                          ToolsExecutionLoop([GatedToolsExecutor(st), llm], max_iters=15)])
    pipe.name = a.model
    models.MODEL_NAMES[a.model] = NAME_FOR_ATTACK.get(a.provider, "AI assistant")
    rec = {"set": a.set, "b2": a.set == "B2", "model": a.model, "provider": a.provider, "arm": a.arm,
           "suite": j["suite"], "ut": j["ut"], "it": j["it"], "kind": "attacked" if it else "benign",
           "attack": ATTACK if it else None, "bench": "agentdojo-" + BENCH_VERSION, "ts_start": now()}
    utility = security = None
    err_class = err = None
    try:
        injections = load_attack(ATTACK, suite, pipe).attack(ut, it) if it else {}
        utility, security = suite.run_task_with_pipeline(pipe, ut, it, injections)
    except ProviderRefusal as e:
        err_class, err = "provider_refused", str(e)
    except ProviderStop:
        raise
    except Exception as e:  # recorded, never dropped
        err_class, err = type(e).__name__, str(e)[:300]
    pin, pout = PRICES.get(a.model, (0.0, 0.0))
    rec.update({"ts_end": now(), "utility": utility, "security": security if it else None,
                "error_class": err_class, "error": err, "target_call_attempted": st.target_attempted,
                "gate_checks": st.checks, "gate_blocks": st.blocks, "blocked_target": st.blocked_target,
                "calls": st.calls, "usage": {"input": meter.inp, "output": meter.out},
                "model_ids": sorted(meter.model_ids),
                "cost_usd": round((meter.inp * pin + meter.out * pout) / 1e6, 6)})
    return rec


def main(argv=None) -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--model", required=True)
    p.add_argument("--provider", default="anthropic", choices=["anthropic", *ENDPOINTS])
    p.add_argument("--arm", default="plain", choices=["plain", "gated"])
    p.add_argument("--set", default="B1", choices=["B1", "B2"])
    p.add_argument("--limit", type=int, default=0, help="pilot: first N planned runs only")
    p.add_argument("--budget-usd", type=float, default=0.0, help="stop when this file's spend reaches it")
    p.add_argument("--workers", type=int, default=4)
    a = p.parse_args(argv)
    RUN_DIR.mkdir(parents=True, exist_ok=True)
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    tag = a.model.replace("/", "_").replace(":", "_")
    out = RUN_DIR / f"{tag}__{a.arm}__{a.set}.jsonl"
    done = {}
    if out.exists():
        for line in out.read_text().splitlines():
            r = json.loads(line)
            done[key(r)] = r
    spent = sum(r.get("cost_usd", 0) for r in done.values())
    jobs = [j for j in plan(a.set) if key(j) not in done]
    if a.limit:
        jobs = jobs[:max(0, a.limit - len(done))]
    lock = threading.Lock()
    chain = ChainLog(LOG_DIR / f"{tag}__{a.set}.gated.jsonl") if a.arm == "gated" else None
    client = make_client(a.provider)
    stop = threading.Event()
    state = {"spent": spent, "n": 0}

    def work(j):
        if stop.is_set():
            return
        try:
            rec = run_one(j, a, client, chain, lock)
        except ProviderStop as e:
            stop.set()
            print(f"PROVIDER-STOP {a.provider} {e}", flush=True)
            return
        with lock:
            with out.open("a") as f:
                f.write(json.dumps(rec, sort_keys=True) + "\n")
            state["spent"] += rec["cost_usd"]
            state["n"] += 1
            print(f"{state['n']}/{len(jobs)} {key(rec)} u={rec['utility']} s={rec['security']} "
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
