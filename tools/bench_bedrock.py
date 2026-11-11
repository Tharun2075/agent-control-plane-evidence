"""Batch 7 runner: the batch 6 AgentDojo benchmark on open-weight models via Amazon Bedrock.

Reuses tools/bench_agentdojo.py unchanged (task plan, gate, executor, attack); only the model
element is new: BedrockLLM speaks the Converse API with toolConfig. Protocol, sample and stop
rules: repeats/batch7/PROTOCOL.md. One JSON line per run goes to
repeats/batch7/runs/<model>__<arm>__<set>.jsonl; finished runs are skipped on restart.

  python tools/bench_bedrock.py --probe --model qwen.qwen3-32b-v1:0
  python tools/bench_bedrock.py --model openai.gpt-oss-120b-1:0 --arm gated --set B1 --budget-usd 10

Credentials come from the environment only (AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY);
never from disk. Anthropic models are refused here by design.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import bench_agentdojo as B  # noqa: E402

from agentdojo import models  # noqa: E402
from agentdojo.agent_pipeline import AgentPipeline, InitQuery, SystemMessage, ToolsExecutionLoop  # noqa: E402
from agentdojo.agent_pipeline.agent_pipeline import load_system_message  # noqa: E402
from agentdojo.agent_pipeline.base_pipeline_element import BasePipelineElement  # noqa: E402
from agentdojo.attacks.attack_registry import load_attack  # noqa: E402
from agentdojo.functions_runtime import EmptyEnv, FunctionCall  # noqa: E402
from agentdojo.task_suite.load_suites import get_suite  # noqa: E402
from agentdojo.types import ChatAssistantMessage, text_content_block_from_string  # noqa: E402

RUN_DIR = ROOT / "repeats" / "batch7" / "runs"
LOG_DIR = ROOT / "repeats" / "batch7" / "logs"
PROBE_FILE = ROOT / "repeats" / "batch7" / "probe.jsonl"
MAX_TOKENS = 4096
EMPTY = "(empty)"  # Converse rejects blank text blocks
# USD per million tokens (input, output), AWS Price List AmazonBedrock us-east-1,
# publication 2026-11-06T18:45:38Z (on-demand, standard tier).
PRICES = {
    "openai.gpt-oss-20b-1:0": (0.07, 0.30),
    "openai.gpt-oss-120b-1:0": (0.15, 0.60),
    "qwen.qwen3-32b-v1:0": (0.15, 0.60),
    "qwen.qwen3-vl-235b-a22b": (0.53, 2.66),
    "google.gemma-3-4b-it": (0.04, 0.08),
    "google.gemma-3-27b-it": (0.23, 0.38),
    "mistral.mistral-large-3-675b-instruct": (0.50, 1.50),
    "deepseek.v3.2": (0.62, 1.85),
    "us.meta.llama4-maverick-17b-instruct-v1:0": (0.24, 0.97),
}
ALLOWED = tuple(PRICES)
VENDOR = {"openai": "OpenAI", "qwen": "Alibaba", "google": "Google", "mistral": "Mistral AI",
          "deepseek": "DeepSeek", "meta": "Meta"}
STOP_MARKERS = ("unsupported countries", "operation not allowed", "not authorized", "model access",
                "don't have access", "do not have access", "quota", "billing", "payment")


def vendor(model: str) -> str:
    part = model.split(".")
    return VENDOR.get(part[1] if part[0] == "us" else part[0], "AI assistant")


def attack_name(model: str) -> str:
    return f"AI model developed by {vendor(model)}"


def check_model(model: str) -> None:
    if "anthropic" in model.lower() or "claude" in model.lower():
        raise SystemExit("refused: batch 7 never calls Anthropic models on Bedrock")
    if model not in ALLOWED:
        raise SystemExit(f"refused: {model} is not on the batch 7 allow list")


def tool_spec(f) -> dict:
    return {"toolSpec": {"name": f.name, "description": f.description or f.name,
                         "inputSchema": {"json": f.parameters.model_json_schema()}}}


def _text(blocks) -> str:
    return "\n".join(b["content"] for b in (blocks or []) if b.get("content")) if blocks else ""


# Bedrock's Converse API accepts toolUse.name and toolUseId only if they match this pattern;
# a name outside it in the replayed history fails the whole next request (ValidationException).
NAME_OK = re.compile(r"^[a-zA-Z0-9_-]{1,64}$")


def clean_name(name, known: frozenset | set = frozenset(), fallback: str = "invalid_tool") -> str:
    """Map a model-emitted tool name onto a Converse-safe one.

    gpt-oss can append harmony channel tokens ("get_webpage<|channel|>commentary") or a namespace
    ("functions.get_webpage"); both reach the history as is and Bedrock rejects the next turn.
    Known tool names win; anything else is reduced to the allowed characters, and the tools
    executor then answers it with AgentDojo's own "Invalid tool" error."""
    raw = str(name or "")
    n = raw.split("<|")[0].strip().strip("\"'` ")
    if n in known:
        return n
    head = n.split("(")[0].strip()
    head = head.split()[0] if head.split() else ""
    if head.rsplit(".", 1)[-1] in known:
        return head.rsplit(".", 1)[-1]
    if NAME_OK.match(n):
        return n
    n = re.sub(r"[^a-zA-Z0-9_-]+", "_", n).strip("_")[:64]
    return n or (re.sub(r"[^a-zA-Z0-9_-]+", "_", raw).strip("_")[:64] or fallback)


def as_object(args) -> dict:
    """Converse wants toolUse.input as a JSON object; models sometimes emit a JSON string or a list."""
    if isinstance(args, dict):
        return dict(args)
    if isinstance(args, str):
        try:
            v = json.loads(args)
        except ValueError:
            return {}
        return dict(v) if isinstance(v, dict) else {}
    try:
        return dict(args or {})
    except (TypeError, ValueError):
        return {}


def to_converse(messages: list) -> tuple[list, list]:
    """AgentDojo chat messages -> (system blocks, Converse messages with same-role turns merged)."""
    system, out = [], []
    for m in messages:
        role = m["role"]
        if role == "system":
            t = _text(m["content"])
            if t:
                system.append({"text": t})
            continue
        if role == "user":
            blocks, crole = [{"text": _text(m["content"]) or EMPTY}], "user"
        elif role == "assistant":
            t = _text(m["content"])
            blocks = [{"text": t}] if t.strip() else []
            for tc in m.get("tool_calls") or []:
                blocks.append({"toolUse": {"toolUseId": clean_name(tc.id, fallback="call"),
                                           "name": clean_name(tc.function), "input": as_object(tc.args)}})
            blocks, crole = blocks or [{"text": EMPTY}], "assistant"
        elif role == "tool":
            err = m.get("error")
            body = err or _text(m["content"]) or EMPTY
            blocks = [{"toolResult": {"toolUseId": clean_name(m["tool_call_id"], fallback="call"), "content": [{"text": body}],
                                      "status": "error" if err else "success"}}]
            crole = "user"
        else:
            raise ValueError(f"unknown role {role}")
        if out and out[-1]["role"] == crole:
            out[-1]["content"].extend(blocks)
        else:
            out.append({"role": crole, "content": blocks})
    return system, out


def from_converse(message: dict, known: frozenset | set = frozenset()) -> ChatAssistantMessage:
    """Converse output message -> AgentDojo assistant message. reasoningContent is dropped.
    Tool names are cleaned (see clean_name) so a malformed name cannot poison the next request."""
    texts, calls = [], []
    for b in message.get("content", []):
        if "text" in b:
            texts.append(b["text"])
        elif "toolUse" in b:
            u = b["toolUse"]
            calls.append(FunctionCall(function=clean_name(u.get("name"), known), args=as_object(u.get("input")),
                                      id=clean_name(u.get("toolUseId"), fallback="call")))
    content = [text_content_block_from_string("\n".join(texts))] if texts else None
    return ChatAssistantMessage(role="assistant", content=content, tool_calls=calls or None)


def classify_error(code: str, msg: str) -> str:
    """'stop' (account/region/quota: stop the model), 'retry' (throttle), or 'record'."""
    low = msg.lower()
    if code in ("AccessDeniedException", "ServiceQuotaExceededException", "UnrecognizedClientException",
                "ExpiredTokenException", "ResourceNotFoundException"):
        return "stop"
    if code in ("ThrottlingException", "ServiceUnavailableException", "TooManyRequestsException"):
        return "retry"
    if code == "ValidationException" and any(s in low for s in STOP_MARKERS):
        return "stop"
    return "record"


class BedrockLLM(BasePipelineElement):
    """A Bedrock model through Converse with toolConfig; temperature 0, bounded throttle retries."""

    def __init__(self, client, model: str, meter: B.Meter, tries: int = 6):
        self.client, self.model, self.meter, self.tries = client, model, meter, tries
        self.stop_reasons: list[str] = []

    def call(self, **kw) -> dict:
        from botocore.exceptions import ClientError
        for n in range(self.tries):
            try:
                return self.client.converse(**kw)
            except ClientError as e:
                code = e.response.get("Error", {}).get("Code", "")
                msg = e.response.get("Error", {}).get("Message", str(e))
                kind = classify_error(code, msg)
                if kind == "stop":
                    raise B.ProviderStop(f"{code} {msg[:200]}") from e
                if kind == "retry" and n + 1 < self.tries:
                    time.sleep(min(60, 2 ** n * 2))
                    continue
                if kind == "retry":
                    raise B.ProviderStop(f"{code} after {self.tries} tries") from e
                raise
        raise AssertionError("unreachable")

    def query(self, query, runtime, env=EmptyEnv(), messages=[], extra_args={}):
        system, msgs = to_converse(messages)
        kw = {"modelId": self.model, "messages": msgs,
              "inferenceConfig": {"maxTokens": MAX_TOKENS, "temperature": 0.0}}
        if system:
            kw["system"] = system
        tools = [tool_spec(t) for t in runtime.functions.values()]
        if tools:
            kw["toolConfig"] = {"tools": tools}
        r = self.call(**kw)
        u = r.get("usage", {})
        self.meter.inp += u.get("inputTokens", 0)
        self.meter.out += u.get("outputTokens", 0)
        self.meter.model_ids.add(self.model)
        reason = r.get("stopReason", "")
        self.stop_reasons.append(reason)
        if reason in ("guardrail_intervened", "content_filtered"):
            raise B.ProviderRefusal(f"stopReason={reason}")
        output = from_converse(r["output"]["message"], {t.name for t in runtime.functions.values()})
        return query, runtime, env, [*messages, output], extra_args


def make_client(region: str):
    import boto3
    from botocore.config import Config
    return boto3.client("bedrock-runtime", region_name=region,
                        config=Config(read_timeout=300, retries={"max_attempts": 2, "mode": "standard"}))


def run_one(j, a, client, chain, lock) -> dict:
    """Same record as batch 6 (bench_agentdojo.run_one) plus region and stop reasons."""
    suite = get_suite(B.BENCH_VERSION, j["suite"])
    ut = suite.user_tasks[j["ut"]]
    it = suite.injection_tasks[j["it"]] if j["it"] else None
    meter = B.Meter()
    markers = []
    if it is not None:
        env0 = suite.load_and_inject_default_environment({})
        markers = B.bench_gate.target_markers([(c.function, dict(c.args)) for c in it.ground_truth(env0)],
                                              j["suite"])
    st = B.GateState(j["suite"], ut.PROMPT, markers, a.arm == "gated", chain, B.key(j), lock)
    llm = BedrockLLM(client, a.model, meter)
    pipe = AgentPipeline([SystemMessage(load_system_message(None)), InitQuery(), llm,
                          ToolsExecutionLoop([B.GatedToolsExecutor(st), llm], max_iters=15)])
    pipe.name = a.model
    models.MODEL_NAMES[a.model] = attack_name(a.model)
    rec = {"set": a.set, "b2": a.set == "B2", "model": a.model, "provider": "bedrock", "region": a.region,
           "arm": a.arm, "suite": j["suite"], "ut": j["ut"], "it": j["it"],
           "kind": "attacked" if it else "benign", "attack": B.ATTACK if it else None,
           "bench": "agentdojo-" + B.BENCH_VERSION, "ts_start": B.now()}
    utility = security = None
    err_class = err = None
    try:
        injections = load_attack(B.ATTACK, suite, pipe).attack(ut, it) if it else {}
        utility, security = suite.run_task_with_pipeline(pipe, ut, it, injections)
    except B.ProviderRefusal as e:
        err_class, err = "provider_refused", str(e)
    except B.ProviderStop:
        raise
    except Exception as e:  # recorded, never dropped
        err_class, err = type(e).__name__, str(e)[:300]
    pin, pout = PRICES[a.model]
    rec.update({"ts_end": B.now(), "utility": utility, "security": security if it else None,
                "error_class": err_class, "error": err, "target_call_attempted": st.target_attempted,
                "gate_checks": st.checks, "gate_blocks": st.blocks, "blocked_target": st.blocked_target,
                "calls": st.calls, "usage": {"input": meter.inp, "output": meter.out},
                "model_ids": sorted(meter.model_ids), "stop_reasons": llm.stop_reasons,
                "cost_usd": round((meter.inp * pin + meter.out * pout) / 1e6, 6)})
    return rec


def probe(a) -> dict:
    """One tiny Converse call with one tool: can this model call tools here?"""
    rec = {"model": a.model, "region": a.region, "ts": B.now()}
    kw = {"modelId": a.model, "inferenceConfig": {"maxTokens": 512, "temperature": 0.0},
          "messages": [{"role": "user", "content": [{"text": "What time is it? Use the tool."}]}],
          "toolConfig": {"tools": [{"toolSpec": {"name": "get_time", "description": "Current time.",
                                                 "inputSchema": {"json": {"type": "object", "properties": {}}}}}]}}
    try:
        r = make_client(a.region).converse(**kw)
        u = r.get("usage", {})
        blocks = r["output"]["message"].get("content", [])
        pin, pout = PRICES[a.model]
        rec.update({"ok": True, "stop_reason": r.get("stopReason"),
                    "tool_use": any("toolUse" in b for b in blocks),
                    "blocks": sorted({k for b in blocks for k in b}),
                    "usage": {"input": u.get("inputTokens", 0), "output": u.get("outputTokens", 0)},
                    "cost_usd": round((u.get("inputTokens", 0) * pin + u.get("outputTokens", 0) * pout) / 1e6, 6)})
    except Exception as e:  # the reason is the result
        code = getattr(e, "response", {}).get("Error", {}).get("Code", type(e).__name__)
        rec.update({"ok": False, "error_class": code, "error": str(e)[:300]})
    PROBE_FILE.parent.mkdir(parents=True, exist_ok=True)
    with PROBE_FILE.open("a") as f:
        f.write(json.dumps(rec, sort_keys=True) + "\n")
    return rec


def main(argv=None) -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--model", required=True)
    p.add_argument("--region", default="us-east-1", choices=["us-east-1", "us-west-2"])
    p.add_argument("--arm", default="plain", choices=["plain", "gated"])
    p.add_argument("--set", default="B1", choices=["B1", "B2"])
    p.add_argument("--limit", type=int, default=0, help="pilot: first N planned runs only")
    p.add_argument("--budget-usd", type=float, default=0.0, help="stop when this file's spend reaches it")
    p.add_argument("--workers", type=int, default=4)
    p.add_argument("--probe", action="store_true")
    a = p.parse_args(argv)
    check_model(a.model)
    if a.probe:
        print(json.dumps(probe(a), sort_keys=True))
        return 0
    RUN_DIR.mkdir(parents=True, exist_ok=True)
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    tag = a.model.replace("/", "_").replace(":", "_")
    out = RUN_DIR / f"{tag}__{a.arm}__{a.set}.jsonl"
    done = {}
    if out.exists():
        for line in out.read_text().splitlines():
            r = json.loads(line)
            done[B.key(r)] = r
    spent = sum(r.get("cost_usd", 0) for r in done.values())
    jobs = [j for j in B.plan(a.set) if B.key(j) not in done]
    if a.limit:
        jobs = jobs[:max(0, a.limit - len(done))]
    lock = threading.Lock()
    chain = B.ChainLog(LOG_DIR / f"{tag}__{a.set}.gated.jsonl") if a.arm == "gated" else None
    client = make_client(a.region)
    stop = threading.Event()
    state = {"spent": spent, "n": 0}

    def work(j):
        if stop.is_set():
            return
        try:
            rec = run_one(j, a, client, chain, lock)
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
