"""Batch 9 summary (acp/batch9.py): run grouping, adaptive k/n, gate-verdict counts and the
batch 6 + 7 + 9 table, from synthetic run records; no network, no key."""
import json
import tempfile
import unittest
from pathlib import Path

from acp import batch9
from acp.repeats import wilson

M = "qwen.qwen3-32b-v1:0"


def _rec(arm, kind, ok, **kw):
    r = {"arm": arm, "attack": None if kind == "benign" else "important_instructions", "b2": False,
         "bench": "agentdojo-v1.2.2", "blocked_target": 0, "calls": [], "cost_usd": 0.001, "error": None,
         "error_class": None, "gate_blocks": 0, "gate_checks": 0, "it": None if kind == "benign" else "injection_task_1",
         "kind": kind, "model": M, "model_ids": [M], "provider": "bedrock", "rep": 0, "temperature": 0.0,
         "security": None if kind == "benign" else (not ok), "set": "B1", "suite": "banking",
         "target_call_attempted": False, "ts_end": "2026-11-10T12:00:01Z",
         "ts_start": "2026-11-10T12:00:00Z", "usage": {"input": 10, "output": 1}, "ut": "user_task_1", "utility": ok}
    r.update(kw)
    return r


def _ad(arm, success, **kw):
    kw = {"set": "A", "attack": "allowlist_reuse", "it": None, "security": success, **kw}
    return _rec(arm, "attacked", True, **kw)


def _write(root, batch, name, recs):
    d = root / "repeats" / batch / "runs"
    d.mkdir(parents=True, exist_ok=True)
    (d / name).write_text("".join(json.dumps(r) + "\n" for r in recs))


class Labels(unittest.TestCase):
    def test_kind_and_label(self):
        cases = [(_rec("def-spotlighting", "attacked", True), "defences", "def-spotlighting"),
                 (_rec("gated", "attacked", True, attack="tool_knowledge"), "tool_knowledge", "gated/tool_knowledge"),
                 (_rec("plain", "benign", True, temperature=0.7, rep=2), "repeats", "plain/T0.7/r2"),
                 (_ad("gated", True), "adaptive", "gated/allowlist_reuse")]
        for r, kind, lab in cases:
            self.assertEqual((batch9.kind_of(r), batch9.label(r)), (kind, lab))


class Build(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        root = self.root = Path(self.tmp.name)
        _write(root, "batch6", "c__plain__B1.jsonl", [_rec("plain", "benign", True, model="claude-x")])
        _write(root, "batch7", "m__gated__B1.jsonl", [
            _rec("gated", "attacked", True, calls=[{"fn": "send_money", "gate": "action not in user task"}])])
        _write(root, "batch9", "m__def-tool_filter.jsonl", [_rec("def-tool_filter", "benign", True),
                                                             _rec("def-tool_filter", "attacked", False)])
        _write(root, "batch9", "m__rep.jsonl", [_rec("plain", "attacked", False, temperature=0.7, rep=r)
                                                for r in (1, 2, 3)])
        _write(root, "batch9", "m__ad.jsonl", [
            _ad("gated", True, calls=[{"fn": "send_money", "gate": "approved", "hit": True}]),
            _ad("gated", False, gate_blocks=1, calls=[{"fn": "send_money", "gate": "recipient not in allowlist"}]),
            _ad("gated", False, error_class="provider_refused", security=None),
            _ad("plain", True)])
        self.out = batch9.build(root)

    def tearDown(self):
        self.tmp.cleanup()

    def test_files_and_determinism(self):
        names = {Path(k).name for k in self.out}
        self.assertEqual(names, {"summary.json", "summary.md", "adaptive.csv", "gate_verdicts.csv", "combined.csv",
                                 "combined.md", "defences.csv", "tool_knowledge.csv", "repeats.csv"})
        self.assertEqual(self.out, batch9.build(self.root))
        self.assertNotIn("batch6-summary", self.out["repeats/batch9/summary.md"])

    def test_adaptive_counts_keep_refusals_in_n(self):
        ad = {r["arm"]: r for r in json.loads(self.out["repeats/batch9/summary.json"])["adaptive"]}
        self.assertEqual((ad["gated"]["k"], ad["gated"]["n"], ad["gated"]["provider_refused"]), (1, 3, 1))
        self.assertEqual(ad["gated"]["gate_blocks"], 1)
        self.assertEqual([ad["gated"]["lo"], ad["gated"]["hi"]], [round(x, 4) for x in wilson(1, 3)])
        self.assertEqual((ad["plain"]["k"], ad["plain"]["n"]), (1, 1))

    def test_gate_verdicts(self):
        rows = json.loads(self.out["repeats/batch9/summary.json"])["gate_verdicts"]
        by = {(r["batch"], r["arm"]): r for r in rows}
        self.assertEqual(by[("batch7", "gated")]["action_not_in_task"], 1)
        a = by[("batch9", "gated/allowlist_reuse")]
        self.assertEqual((a["gated_calls"], a["approved"], a["target_not_in_allowlist"]), (2, 1, 1))

    def test_repeats_and_combined(self):
        s = json.loads(self.out["repeats/batch9/summary.json"])
        arms = {r["arm"]: r["runs"] for r in s["repeats"]["rows"]}
        self.assertEqual(arms, {"gated/T0/r0": 1, "plain/T0.7/r1": 1, "plain/T0.7/r2": 1, "plain/T0.7/r3": 1,
                                "plain/T0.7/pooled": 3})
        comb = self.out["repeats/batch9/combined.csv"].splitlines()[1:]
        self.assertEqual(sorted({c.split(",")[0] for c in comb}), ["batch6", "batch7", "batch9"])
        self.assertFalse(any("allowlist_reuse" in c for c in comb))
        self.assertEqual(s["runs"], 9)


if __name__ == "__main__":
    unittest.main()
