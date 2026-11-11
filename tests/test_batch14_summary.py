"""Batch 14 summary (acp/batch14.py): per-control attribution, would-block counts, gpt-oss-20b error
table and the file layout, from synthetic run records; no network, no key."""
import json
import sys
import tempfile
import unittest
from pathlib import Path

from acp import batch14

M = "openai.gpt-oss-20b-1:0"
OK = {"action": True, "allowlist": True}


def _rec(arm, kind, ok, **kw):
    r = {"arm": arm, "attack": "none" if kind == "benign" else "important_instructions", "bench": "agentdojo-v1.2.2",
         "blocked_target": 0, "calls": [], "cost_usd": 0.001, "error": None, "error_class": None,
         "gate_blocks": 0, "gate_checks": 0, "it": None if kind == "benign" else "injection_task_1",
         "kind": kind, "model": M, "provider": "bedrock", "rep": 0, "temperature": 0.0,
         "security": None if kind == "benign" else (not ok), "set": "B1", "suite": "banking",
         "target_call_attempted": False, "ts_end": "2026-11-11T12:00:01Z", "ts_start": "2026-11-11T12:00:00Z",
         "usage": {"input": 10, "output": 1}, "ut": "user_task_1", "utility": ok}
    r.update(kw)
    return r


def _call(gate, hit=True, **chk):
    return {"fn": "send_money", "gate": gate, "hit": hit, "chk": {**OK, **chk}}


class Category(unittest.TestCase):
    def test_blocks_by_reason(self):
        cases = {"action not in user task": "blocked_action", "recipient not in allowlist": "blocked_allowlist",
                 "recipient not in user task (allowlist)": "blocked_allowlist",
                 "password missing (approval)": "blocked_approval", "something else": "blocked_other"}
        for reason, want in cases.items():
            r = _rec("b14-gated", "attacked", True, calls=[_call(reason)])
            self.assertEqual(batch14.category(r), want, reason)

    def test_first_blocked_target_call_decides(self):
        r = _rec("b14-gated", "attacked", True,
                 calls=[_call("action not in user task", hit=False), _call("recipient not in allowlist")])
        self.assertEqual(batch14.category(r), "blocked_allowlist")

    def test_success_approved_unchecked_none(self):
        self.assertEqual(batch14.category(_rec("b14-gated", "attacked", False, calls=[_call("approved")])),
                         "succeeded")
        self.assertEqual(batch14.category(_rec("b14-gated", "attacked", True, calls=[_call("approved")])),
                         "approved_no_effect")
        self.assertEqual(batch14.category(_rec("b14-plain", "attacked", True, calls=[_call(None)])),
                         "unchecked_target_call")
        self.assertEqual(batch14.category(_rec("b14-gated", "attacked", True)), "no_target_call")

    def test_errors_first(self):
        self.assertEqual(batch14.category(_rec("b14-gated", "attacked", True, error="x", error_class="throttled")),
                         "error")
        self.assertEqual(batch14.category(_rec("b14-gated", "attacked", True, error="x",
                                               error_class="provider_refused")), "provider_refused")


class Tables(unittest.TestCase):
    def test_would_block_counts_chk_only(self):
        rs = [_rec("b14-plain", "attacked", True, calls=[_call(None, allowlist=False), _call(None, action=False),
                                                         {"fn": "send_money", "gate": None, "hit": True}])]
        (row,) = batch14.would_block_rows(rs)
        self.assertEqual((row["target_calls"], row["action_fails"], row["allowlist_fails"],
                          row["only_allowlist_fails"]), (2, 1, 1, 1))

    def test_error_rows_by_arm(self):
        rs = [_rec("v1.2-gated", "benign", False, error="x", error_class="tool_name"),
              _rec("v1.2-gated", "benign", True), _rec("b14-gated", "benign", True)]
        rows = {r["arm"]: r for r in batch14.error_rows(rs)}
        self.assertEqual(rows["v1.2-gated"]["errors"], 1)
        self.assertEqual(rows["v1.2-gated"]["error_classes"], "tool_name=1")
        self.assertEqual(rows["b14-gated"]["errors"], 0)


class Build(unittest.TestCase):
    def test_layout_and_labels(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            for sub in ("batch14", "batch7"):
                (root / "repeats" / sub / "runs").mkdir(parents=True)
            old = [_rec("gated", "attacked", False, calls=[_call("approved")])]
            (root / "repeats/batch7/runs/openai.gpt-oss-20b-1_0__gated__B1.jsonl").write_text(
                "".join(json.dumps({k: v for k, v in r.items()}) + "\n" for r in old))
            new = [_rec("gated", "attacked", True, calls=[_call("recipient not in allowlist")]),
                   _rec("gated", "benign", True)]
            (root / "repeats/batch14/runs/openai.gpt-oss-20b-1_0__gated__B1.jsonl").write_text(
                "".join(json.dumps(r) + "\n" for r in new))
            files = batch14.build(root)
            self.assertEqual(sorted(files), sorted("repeats/batch14/" + f for f in (
                "summary.json", "summary.md", "summary.csv", "attribution.csv", "would_block.csv",
                "gpt_oss_20b_errors.csv")))
            s = json.loads(files["repeats/batch14/summary.json"])
            self.assertEqual(s["runs"], 2)
            att = {r["arm"]: r for r in s["attribution"]}
            self.assertEqual(att["v1.2-gated"]["succeeded"], 1)
            self.assertEqual(att["b14-gated"]["blocked_allowlist"], 1)
            self.assertIn(batch14.GENERATOR, files["repeats/batch14/summary.md"])
            self.assertEqual(s["cost_usd"], {"bedrock": 0.002})


class Wrapper(unittest.TestCase):
    def test_wrapper_points_runners_at_batch14(self):
        try:
            sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
            import bench_batch14 as W
        except ImportError as e:  # agentdojo / anthropic not installed in this venv
            self.skipTest(str(e))
        self.assertTrue(str(W.B.RUN_DIR).endswith("repeats/batch14/runs"))
        self.assertIs(W.B.GatedToolsExecutor, W.Gated14)


if __name__ == "__main__":
    unittest.main()
