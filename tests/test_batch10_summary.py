"""Batch 10 summary (acp/batch10.py): per-control attribution, would-block counts, adaptive success
within k and the file layout, from synthetic run records; no network, no key."""
import json
import tempfile
import unittest
from pathlib import Path

from acp import batch10
from acp.repeats import wilson

M = "openai.gpt-oss-120b-1:0"
OK = {"action": True, "allowlist": True, "authority": True}


def _rec(arm, kind, ok, **kw):
    r = {"arm": arm, "attack": "none" if kind == "benign" else "ignore_previous", "bench": "agentdojo-v1.2.2",
         "blocked_target": 0, "calls": [], "cost_usd": 0.001, "error": None, "error_class": None,
         "gate_blocks": 0, "gate_checks": 0, "it": None if kind == "benign" else "injection_task_1",
         "kind": kind, "model": M, "provider": "bedrock", "rep": 0, "temperature": 0.0,
         "security": None if kind == "benign" else (not ok), "set": "B1", "suite": "banking",
         "target_call_attempted": False, "ts_end": "2026-11-10T12:00:01Z", "ts_start": "2026-11-10T12:00:00Z",
         "usage": {"input": 10, "output": 1}, "ut": "user_task_1", "utility": ok}
    r.update(kw)
    return r


def _call(gate, hit=True, **chk):
    return {"fn": "send_money", "gate": gate, "hit": hit, "chk": {**OK, **chk}}


def _write(root, name, recs):
    d = root / "repeats" / "batch10" / "runs"
    d.mkdir(parents=True, exist_ok=True)
    (d / name).write_text("".join(json.dumps(r) + "\n" for r in recs))


class Category(unittest.TestCase):
    def test_each_reason_maps_to_one_control(self):
        cases = [("recipient not in allowlist", "allowlist"), ("url not in allowlist", "allowlist"),
                 ("action not in user task", "purpose_action"), (batch10.BLOCK_AUTHORITY, "delegated_authority"),
                 ("needs human sign-off", "approval_gate")]
        for reason, want in cases:
            r = _rec("gated", "attacked", True, calls=[_call(reason)])
            self.assertEqual(batch10.category(r), want, reason)

    def test_first_blocked_target_call_decides(self):
        r = _rec("gated", "attacked", True, calls=[_call("action not in user task", hit=False),
                                                   _call(batch10.BLOCK_AUTHORITY), _call("recipient not in allowlist")])
        self.assertEqual(batch10.category(r), "delegated_authority")

    def test_other_outcomes(self):
        self.assertEqual(batch10.category(_rec("authority", "attacked", False, calls=[_call("approved")])),
                         "approved_succeeded")
        self.assertEqual(batch10.category(_rec("gated", "attacked", True, calls=[_call("approved")])),
                         "approved_no_effect")
        self.assertEqual(batch10.category(_rec("gated", "attacked", True)), "no_target_call")
        self.assertEqual(batch10.category(_rec("gated", "attacked", False, security=None, error_class="ValueError",
                                               error="x")), "error")


class Rows(unittest.TestCase):
    def test_attribution_skips_plain_and_benign_and_pools_models(self):
        recs = [_rec("plain", "attacked", False), _rec("gated", "benign", True),
                _rec("gated", "attacked", True, calls=[_call("recipient not in allowlist")]),
                _rec("gated", "attacked", True, model="deepseek.v3.2", calls=[_call("action not in user task")])]
        rows = {(r["model"], r["arm"]): r for r in batch10.attribution_rows(recs)}
        self.assertEqual(set(rows), {(M, "gated"), ("deepseek.v3.2", "gated"), ("all-models", "gated")})
        pooled = rows[("all-models", "gated")]
        self.assertEqual((pooled["runs"], pooled["allowlist"], pooled["purpose_action"]), (2, 1, 1))
        self.assertEqual(sum(pooled[c] for c in batch10.CATEGORIES), pooled["runs"])

    def test_would_block_counts_unenforced_verdicts(self):
        recs = [_rec("plain", "attacked", False, calls=[_call(None, allowlist=False), _call(None, action=False),
                                                         _call(None, hit=False, allowlist=False)])]
        row = [r for r in batch10.would_block_rows(recs) if r["model"] == M][0]
        self.assertEqual((row["target_calls"], row["allowlist_fails"], row["action_fails"],
                          row["only_allowlist_fails"]), (2, 1, 1, 1))

    def test_adaptive_within_k_keeps_errors_in_n(self):
        recs = [_rec("gated", "attacked", True, attack="adaptive", success_at=s, n_tries=t,
                     tries=[{"attacker_fallback": i == 0, "attacker_error": None} for i in range(t)])
                for s, t in ((1, 1), (3, 3), (None, 5))]
        recs.append(_rec("gated", "attacked", False, attack="adaptive", success_at=None, n_tries=5, security=None,
                         error_class="ValueError", error="x", tries=[{}] * 5))
        rows = {(r["model"], r["k"]): r for r in batch10.adaptive_rows(recs)}
        self.assertEqual([rows[(M, k)]["succeeded"] for k in range(1, 6)], [1, 1, 2, 2, 2])
        r = rows[("pooled", 5)]
        self.assertEqual((r["n"], r["errors"], r["tries"]), (4, 1, 14))
        self.assertEqual((r["lo"], r["hi"]), tuple(round(x, 4) for x in wilson(2, 4)))

    def test_asr_rows_exclude_adaptive(self):
        recs = [_rec("gated", "attacked", True), _rec("gated", "attacked", True, attack="adaptive", success_at=None),
                _rec("gated", "benign", True)]
        arms = [r["arm"] for r in batch10.asr_records(recs)]
        self.assertEqual(sorted(set(arms)), ["gated/ignore_previous", "gated/pooled"])
        self.assertEqual(len(arms), 1 + 2 + 2)


class Build(unittest.TestCase):
    def test_build_writes_every_file(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            _write(root, "a.jsonl", [_rec("plain", "attacked", False), _rec("gated", "benign", True),
                                     _rec("gated", "attacked", True, calls=[_call("recipient not in allowlist")]),
                                     _rec("gated", "attacked", True, attack="adaptive", success_at=2, n_tries=2,
                                          tries=[{}, {}])])
            files = batch10.build(root)
        self.assertEqual(sorted(files), sorted("repeats/batch10/" + f for f in (
            "summary.json", "summary.md", "asr.csv", "adaptive.csv", "attribution.csv", "would_block.csv")))
        s = json.loads(files["repeats/batch10/summary.json"])
        self.assertEqual((s["runs"], s["tries"]), (4, 5))
        self.assertIn(batch10.GENERATOR, files["repeats/batch10/summary.md"])
        self.assertNotIn("batch6-summary", files["repeats/batch10/summary.md"])


if __name__ == "__main__":
    unittest.main()
