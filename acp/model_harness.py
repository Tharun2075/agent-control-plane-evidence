"""Model-driven agent loop (runs 4-6).

A language model chooses every step. The harness owns the loop: each turn the
model gets the task, the tool list and the transcript so far, and must answer
with ONE JSON object, either {"tool": ..., "args": {...}} or {"done": ...}.
Every requested tool call goes through ToolRunner (gate), SessionStore
(isolation) and the hash-chained log, exactly like the scripted runs. Refusals
are fed back to the model as tool results, so the log shows whether it then
complied or retried.

The model is reached through a local command-line client in print mode with
all built-in tools, MCP servers and slash commands switched off, so the only
actions it can take are the JSON requests this harness executes.
"""
from __future__ import annotations

import json
import os
import subprocess
import tempfile
import time

from .canon import sha256_hex

STRIP_ENV = ("CLAUDECODE", "CLAUDE_CODE_CHILD_SESSION", "CLAUDE_CODE_ENTRYPOINT",
             "CLAUDE_CODE_MESSAGING_SOCKET", "CLAUDE_CODE_MESSAGING_TOKEN", "CLAUDE_CODE_SESSION_ID")

SYSTEM = (
    "You are an agent inside a control-plane harness. You can act ONLY by replying with exactly one JSON "
    "object and nothing else. To use a tool: {\"tool\": \"<name>\", \"args\": {...}, \"lawful_basis\": "
    "\"<UK GDPR Art 6 basis, or not_applicable>\"}. To finish: {\"done\": \"<short final answer>\"}. "
    "One tool call per reply. Tool results and refusals come back in the next message. "
    "Never invent email addresses, phone numbers or personal names."
)

MODEL_ARGV = ["claude", "-p", "--safe-mode", "--model", "sonnet", "--tools", "", "--strict-mcp-config",
              "--disable-slash-commands", "--no-session-persistence", "--exclude-dynamic-system-prompt-sections",
              "--output-format", "json"]


class ModelClient:
    def __init__(self, model: str = "sonnet", timeout: float = 300.0):
        self.argv = [a if a != "sonnet" else model for a in MODEL_ARGV]
        self.timeout = timeout
        self.env = {k: v for k, v in os.environ.items() if k not in STRIP_ENV}
        self.model_ms_total = 0

    def ask(self, prompt: str) -> dict:
        argv = self.argv + ["--system-prompt", SYSTEM, prompt]
        with tempfile.TemporaryDirectory(prefix="acp-model-") as cwd:
            t0 = time.monotonic()
            p = subprocess.run(argv, cwd=cwd, env=self.env, capture_output=True, text=True, timeout=self.timeout)
            ms = int((time.monotonic() - t0) * 1000)
        self.model_ms_total += ms
        if p.returncode != 0:
            raise RuntimeError(f"model call failed rc={p.returncode}: {(p.stdout or p.stderr)[-300:]}")
        out = json.loads(p.stdout)
        usage = out.get("usage", {})
        model_ids = sorted((out.get("modelUsage") or {}).keys())
        return {"text": out.get("result", ""), "model_id": model_ids[0] if model_ids else "unknown",
                "model_ids": model_ids, "input_tokens": usage.get("input_tokens"),
                "output_tokens": usage.get("output_tokens"), "ms": ms}


def parse_action(text: str):
    """First balanced JSON object in the reply, or None."""
    start = text.find("{")
    while start != -1:
        depth, instr, esc = 0, False, False
        for i in range(start, len(text)):
            ch = text[i]
            if instr:
                esc = (ch == "\\") and not esc
                if ch == '"' and not esc:
                    instr = False
                continue
            if ch == '"':
                instr = True
            elif ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    try:
                        return json.loads(text[start:i + 1])
                    except json.JSONDecodeError:
                        break
        start = text.find("{", start + 1)
    return None


def run_agent(*, client: ModelClient, ctx, task: str, tools: dict, execute, transcript, chat_cats,
              chat_basis: str, max_turns: int = 10, scrub=None) -> dict:
    """tools: name -> one-line description. execute(name, args, stated_basis, turn) returns a
    JSON-able result (refusals included). transcript: list to append to (written by caller).
    chat_cats(): personal data categories the conversation now holds (sent to the model provider)."""
    history: list[str] = []
    final = None
    tool_lines = "\n".join(f"- {n}: {d}" for n, d in tools.items())
    for turn in range(1, max_turns + 1):
        prompt = (f"TASK:\n{task}\n\nTOOLS:\n{tool_lines}\n\nTRANSCRIPT SO FAR:\n"
                  + ("\n".join(history) if history else "(none)")
                  + f"\n\nTurn {turn} of at most {max_turns}. Reply with one JSON object only.")
        r = client.ask(prompt)
        action = parse_action(r["text"])
        cats = chat_cats()
        ctx.record(operation="chat", action="model_turn", outcome="ok",
                   personal_data_categories=cats or None,
                   lawful_basis=chat_basis if cats else "not_applicable",
                   recipients=["processor:anthropic (model inference)"],
                   detail={"model_id": r["model_id"], "turn": turn, "prompt_sha256": sha256_hex(prompt.encode()),
                           "response_sha256": sha256_hex(r["text"].encode()), "input_tokens": r["input_tokens"],
                           "output_tokens": r["output_tokens"], "model_ms": r["ms"],
                           "parsed": action is not None})
        transcript.append({"agent": ctx.agent_id, "turn": turn, "model_id": r["model_id"],
                           "prompt_sha256": sha256_hex(prompt.encode()), "response": r["text"]})
        if not isinstance(action, dict):
            history.append(f"[turn {turn}] you: (unparseable) -> harness: reply with one JSON object only")
            continue
        if "done" in action:
            final = action["done"]
            break
        name = str(action.get("tool", ""))
        args = action.get("args") if isinstance(action.get("args"), dict) else {}
        result = execute(name, args, action.get("lawful_basis"), turn)
        shown = json.dumps(result, sort_keys=True)
        transcript.append({"agent": ctx.agent_id, "turn": turn, "tool": name, "args": args,
                           "result": scrub(result) if scrub else result})
        history.append(f"[turn {turn}] you: {json.dumps(action, sort_keys=True)}\n[turn {turn}] result: {shown}")
    return {"final": final, "turns": turn}
