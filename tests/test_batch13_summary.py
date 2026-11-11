"""Batch 13 summary (acp.batch13): rep labels, pooled reps, issued-call rate and the two
pre-registered change tests (order flip, rep 0 outside the pooled interval). No network."""
import json
import tempfile
import unittest
from pathlib import Path

from acp import batch13

M = "claude-haiku-5-5"


def _rec(arm, rep, kind, utility=False, security=False, target=False, error_class=None, model=M):
    return {"model": model, "arm": arm, "rep": rep, "kind": kind, "set": "B1", "suite": "banking",
            "ut": "user_task_0", "it": None if kind == "benign" else "injection_task_0",
            "utility": utility, "security": security, "target_call_attempted": target,
            "error_class": error_class, "cost_usd": 0.001, "gate_checks": 0, "gate_blocks": 0,
            "blocked_target": False, "ts_start": "2026-11-11T03:00:00Z", "ts_end": "2026-11-11T03:00:01Z"}


def _set(arm, rep, n_ok, n_att_succ, n_att_target, n=10):
    out = [_rec(arm, rep, "benign", utility=i < n_ok) for i in range(n)]
    out += [_rec(arm, rep, "attacked", security=i < n_att_succ,
                 target=n_att_succ <= i < n_att_succ + n_att_target) for i in range(n)]
    return out


def _labelled(recs):
    return [{**r, "arm": batch13.label(r), "base_arm": r["arm"]} for r in recs]


def _cmp(s, arm, metric):
    return next(c for c in batch13.compare(s) if c["model"] == M and c["arm"] == arm and c["metric"] == metric)


class Summary(unittest.TestCase):
    def test_pooled_and_issued(self):
        recs = _labelled(_set("plain", 0, 8, 2, 1) + _set("plain", 1, 8, 2, 1) + _set("plain", 2, 6, 0, 3)
                         + [_rec("plain", 3, "attacked", error_class="provider_refused")])
        s = batch13.summarize(recs)
        pooled = batch13._row(s, M, "plain/pooled")
        self.assertEqual((pooled["asr"]["k"], pooled["asr"]["n"]), (2, 21))  # refusal stays in n
        self.assertEqual(pooled["issued_call"]["k"], 2 + 1 + 3)
        self.assertEqual(batch13._row(s, M, "plain/r3")["not_run"], batch13.PLANNED - 1)

    def test_order_flip_changes_conclusion(self):
        recs = _labelled(_set("plain", 0, 9, 5, 0) + _set("gated", 0, 5, 0, 0)
                         + _set("plain", 1, 9, 0, 0) + _set("gated", 1, 5, 3, 0))
        s = batch13.summarize(recs)
        c = _cmp(s, "plain", "asr")
        self.assertEqual(c["order_flip_reps"], "r1")
        self.assertTrue(c["conclusion_changes"])
        self.assertIsNone(_cmp(s, "plain", "issued_call")["conclusion_changes"])

    def test_stable_reps_no_change(self):
        recs = _labelled(sum((_set(a, k, 8, 0, 0) for a in ("plain", "gated") for k in (0, 1, 2, 3)), []))
        s = batch13.summarize(recs)
        for arm in ("plain", "gated"):
            for metric in ("asr", "benign_utility"):
                c = _cmp(s, arm, metric)
                self.assertTrue(c["r0_in_pooled_ci"])
                self.assertFalse(c["conclusion_changes"])

    def test_build_reads_batch6_and_batch13(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            (root / "repeats/batch6/runs").mkdir(parents=True)
            (root / "repeats/batch13/runs/r1").mkdir(parents=True)
            b6 = [{k: v for k, v in r.items() if k != "rep"} for r in _set("plain", 0, 8, 1, 0)]
            b6.append({**b6[0], "model": "gemini-2.5-flash"})  # non-Claude B2-style row is left out
            (root / "repeats/batch6/runs/x.jsonl").write_text("".join(json.dumps(r) + "\n" for r in b6))
            b13 = _set("plain", 1, 7, 0, 0)
            (root / "repeats/batch13/runs/r1/y.jsonl").write_text("".join(json.dumps(r) + "\n" for r in b13))
            files = batch13.build(root)
            self.assertEqual(set(files), {"repeats/batch13/" + f for f in
                                          ("summary.json", "summary.md", "repeats.csv", "compare.csv")})
            self.assertIn("`python3 tools/batch13_summary.py`", files["repeats/batch13/summary.md"])
            rows = json.loads(files["repeats/batch13/summary.json"])["repeats"]["rows"]
            self.assertEqual(sorted(r["arm"] for r in rows), ["plain/pooled", "plain/r0", "plain/r1"])
            self.assertTrue(all(r["model"] == M for r in rows))


if __name__ == "__main__":
    unittest.main()
