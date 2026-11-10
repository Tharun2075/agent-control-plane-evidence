"""Batch 7 (AgentDojo on open-weight models via Amazon Bedrock): Converse mapping, error rule,
model allow list and summary build; no network, no key.

The Converse mapping cases need the optional benchmark dependency (requirements-bench.txt)
and are skipped without it.
"""
import json
import sys
import tempfile
import unittest
from pathlib import Path

from acp import batch7

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))
try:
    import bench_bedrock as bb
except ImportError:  # benchmark or boto3 not installed
    bb = None


@unittest.skipIf(bb is None, "agentdojo/boto3 not installed")
class Converse(unittest.TestCase):
    def test_merges_same_role_turns_and_maps_tools(self):
        from agentdojo.functions_runtime import FunctionCall
        from agentdojo.types import text_content_block_from_string as t
        call = FunctionCall(function="get_balance", args={}, id="c1")
        msgs = [{"role": "system", "content": [t("be careful")]},
                {"role": "user", "content": [t("what is my balance")]},
                {"role": "assistant", "content": None, "tool_calls": [call]},
                {"role": "tool", "content": [t("100")], "tool_call_id": "c1", "tool_call": call, "error": None},
                {"role": "user", "content": [t("")]}]
        system, out = bb.to_converse(msgs)
        self.assertEqual(system, [{"text": "be careful"}])
        self.assertEqual([m["role"] for m in out], ["user", "assistant", "user"])
        self.assertEqual(out[1]["content"], [{"toolUse": {"toolUseId": "c1", "name": "get_balance", "input": {}}}])
        res, empty = out[2]["content"]
        self.assertEqual(res["toolResult"]["status"], "success")
        self.assertEqual(empty, {"text": bb.EMPTY})

    def test_tool_error_is_marked(self):
        from agentdojo.functions_runtime import FunctionCall
        call = FunctionCall(function="f", args={}, id="c2")
        _, out = bb.to_converse([{"role": "tool", "content": None, "tool_call_id": "c2", "tool_call": call,
                                  "error": "boom"}])
        self.assertEqual(out[0]["content"][0]["toolResult"]["status"], "error")
        self.assertEqual(out[0]["content"][0]["toolResult"]["content"], [{"text": "boom"}])

    def test_from_converse_keeps_text_and_calls_drops_reasoning(self):
        m = bb.from_converse({"role": "assistant", "content": [
            {"reasoningContent": {"reasoningText": {"text": "hidden"}}}, {"text": "ok"},
            {"toolUse": {"toolUseId": "u1", "name": "send_money", "input": {"amount": 5}}}]})
        self.assertEqual(m["content"][0]["content"], "ok")
        self.assertEqual(m["tool_calls"][0].function, "send_money")
        self.assertEqual(dict(m["tool_calls"][0].args), {"amount": 5})
        self.assertIsNone(bb.from_converse({"content": [{"text": "done"}]})["tool_calls"])

    def test_error_rule(self):
        self.assertEqual(bb.classify_error("ThrottlingException", "slow down"), "retry")
        self.assertEqual(bb.classify_error("AccessDeniedException", "no"), "stop")
        self.assertEqual(bb.classify_error(
            "ValidationException", "Access to Meta Llama models is not allowed from unsupported countries"), "stop")
        self.assertEqual(bb.classify_error("ValidationException", "bad tool schema"), "record")

    def test_allow_list_and_no_anthropic(self):
        for m in ("anthropic.claude-haiku-5-5", "us.anthropic.claude-opus-5-5", "amazon.nova-pro-v1:0"):
            with self.assertRaises(SystemExit):
                bb.check_model(m)
        bb.check_model("openai.gpt-oss-120b-1:0")
        self.assertNotIn("anthropic", " ".join(bb.ALLOWED).lower())
        self.assertEqual(bb.attack_name("deepseek.v3.2"), "AI model developed by DeepSeek")


def _rec(model, arm, kind, ok, **kw):
    r = {"arm": arm, "attack": None if kind == "benign" else "important_instructions", "b2": False,
         "bench": "agentdojo-v1.2.2", "blocked_target": 0, "calls": [], "cost_usd": 0.001, "error": None,
         "error_class": None, "gate_blocks": 0, "gate_checks": 0, "it": None if kind == "benign" else "injection_task_1",
         "kind": kind, "model": model, "model_ids": [model], "provider": "bedrock",
         "security": None if kind == "benign" else (not ok), "set": "B1", "suite": "banking",
         "target_call_attempted": False, "ts_end": "2026-11-10T12:00:01Z", "ts_start": "2026-11-10T12:00:00Z",
         "usage": {"input": 10, "output": 1}, "ut": "user_task_1", "utility": ok}
    r.update(kw)
    return r


class Summary(unittest.TestCase):
    def test_build_combines_batches(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            for b in ("batch6", "batch7"):
                (root / "repeats" / b / "runs").mkdir(parents=True)
            (root / "repeats/batch6/runs/c__plain__B1.jsonl").write_text(
                json.dumps(_rec("claude-x", "plain", "benign", True, provider="anthropic")) + "\n")
            (root / "repeats/batch7/runs/m__plain__B1.jsonl").write_text("".join(
                json.dumps(r) + "\n" for r in (_rec("qwen.qwen3-32b-v1:0", "plain", "benign", True),
                                               _rec("qwen.qwen3-32b-v1:0", "plain", "attacked", False))))
            (root / "repeats/batch7/runs/m__plain__B2.jsonl").write_text(
                json.dumps(_rec("qwen.qwen3-32b-v1:0", "plain", "attacked", True, set="B2", b2=True)) + "\n")
            out = batch7.build(root)
            self.assertEqual(sorted(Path(k).name for k in out), sorted(batch7.FILES))
            s = json.loads(out["repeats/batch7/summary.json"])
            self.assertEqual([r["runs"] for r in s["B1"]["rows"]], [2])
            self.assertEqual([r["runs"] for r in s["B2"]["rows"]], [1])
            comb = out["repeats/batch7/combined.csv"].splitlines()
            self.assertEqual(len(comb), 3)
            self.assertTrue(comb[1].startswith("batch6,claude-x") and comb[2].startswith("batch7,qwen"))
            self.assertIn("1/1 = 100.0%", out["repeats/batch7/combined.md"])
            self.assertNotIn("batch6-summary", out["repeats/batch7/summary.md"])
            self.assertEqual(out, batch7.build(root))  # deterministic


if __name__ == "__main__":
    unittest.main()
