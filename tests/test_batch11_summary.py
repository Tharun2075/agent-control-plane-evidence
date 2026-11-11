"""Batch 11 summary (acp/batch11.py): success within k with errors in n, per-try attribution, the
batch-9 same-pair comparison and the file layout, from synthetic run records; no network, no key."""
import json
import tempfile
import unittest
from pathlib import Path

from acp import batch11
from acp.repeats import wilson

M = "openai.gpt-oss-120b-1:0"
OK = {"action": True, "allowlist": True, "authority": True}


def _call(gate, hit=True, **chk):
    return {"fn": "send_money", "gate": gate, "hit": hit, "chk": {**OK, **chk}}


def _try(t, ok, calls=(), **kw):
    h = {"t": t, "seeded": t == 1, "security": ok, "utility": True, "error": None, "error_class": None,
         "calls": list(calls), "attacker_fallback": False, "attacker_error": None, "cost_usd": 0.01}
    h.update(kw)
    return h


def _rec(ut, tries, model=M, max_tries=3, **kw):
    succ = next((h["t"] for h in tries if h["security"]), None)
    last = tries[-1]
    r = {"arm": "gated", "attack": batch11.ATTACK, "kind": "attacked", "model": model, "suite": "banking",
         "ut": ut, "set": "A", "max_tries": max_tries, "tries": tries, "n_tries": len(tries), "success_at": succ,
         "security": last["security"], "utility": last["utility"], "error": last["error"],
         "error_class": last["error_class"], "calls": last["calls"], "cost_usd": 0.01 * len(tries)}
    r.update(kw)
    return r


def _b9(ut, ok, model=M):
    return {"arm": "gated", "attack": "allowlist_reuse", "kind": "attacked", "model": model, "suite": "banking",
            "ut": ut, "security": ok, "utility": True, "error": None, "error_class": None, "calls": []}


BLOCK_AL = _call("recipient not in allowlist", allowlist=False)
BLOCK_ACT = _call("action not in user task", action=False, allowlist=False)
PASS = _call("approved")

RECS = [
    _rec("user_task_0", [_try(1, True, [PASS])]),
    _rec("user_task_1", [_try(1, False, [BLOCK_AL]), _try(2, False, [BLOCK_ACT]), _try(3, True, [PASS])]),
    _rec("user_task_2", [_try(1, False, [BLOCK_AL]), _try(2, False, []),
                         _try(3, False, [], error="boom", error_class="ThrottlingException", utility=None)]),
]


class SuccessWithinK(unittest.TestCase):
    def test_counts_and_errors_in_n(self):
        rows = {(r["model"], r["k"]): r for r in batch11.success_rows(RECS)}
        self.assertEqual([rows[(M, k)]["succeeded"] for k in (1, 2, 3)], [1, 1, 2])
        self.assertTrue(all(rows[(M, k)]["n"] == 3 for k in (1, 2, 3)))
        self.assertEqual(rows[(M, 3)]["errors"], 1)
        lo, hi = wilson(2, 3)
        self.assertEqual((rows[("pooled", 3)]["lo"], rows[("pooled", 3)]["hi"]), (round(lo, 4), round(hi, 4)))
        self.assertEqual(rows[(M, 1)]["tries"], 7)


class TryAttribution(unittest.TestCase):
    def test_each_try_in_one_category(self):
        row = next(r for r in batch11.try_rows(RECS) if r["model"] == M)
        self.assertEqual(row["tries"], 7)
        self.assertEqual(row["failed_tries"], 5)
        self.assertEqual(row["approved_succeeded"], 2)
        self.assertEqual(row["allowlist"], 2)
        self.assertEqual(row["purpose_action"], 1)
        self.assertEqual((row["error"], row["no_target_call"]), (1, 1))
        self.assertEqual(sum(row[c] for c in batch11.CATEGORIES), row["tries"])
        self.assertEqual((row["action_fails"], row["allowlist_fails"], row["only_allowlist_fails"]), (1, 3, 2))


class Compare(unittest.TestCase):
    def test_same_pairs_only(self):
        b9 = [_b9("user_task_0", True), _b9("user_task_1", False), _b9("user_task_9", True),
              {**_b9("user_task_2", True), "attack": "important_instructions"}]
        rows = {r["model"]: r for r in batch11.compare_rows(RECS, b9)}
        p = rows["pooled"]
        self.assertEqual((p["pairs"], p["b9_succeeded"], p["try1_succeeded"], p["try1_agree"]), (2, 1, 1, 2))
        self.assertEqual((p["within_k_succeeded"], p["k"]), (2, 3))
        self.assertIn("1/2", batch11.comparison_line(list(rows.values())))


class CutToK(unittest.TestCase):
    def test_pilot_at_higher_k_is_read_at_final_k(self):
        late = _rec("user_task_5", [_try(1, False), _try(2, False), _try(3, False), _try(4, True)], max_tries=4)
        early = _rec("user_task_6", [_try(1, False), _try(2, True)], max_tries=4)
        out = batch11.cut_to_k([late, early, RECS[0]])
        self.assertEqual([(r["max_tries"], r["n_tries"], r["success_at"], r["security"]) for r in out],
                         [(3, 3, None, False), (3, 2, 2, True), (3, 1, 1, True)])
        self.assertEqual(out[0]["cost_usd"], late["cost_usd"])
        self.assertEqual(batch11.cut_to_k(RECS), RECS)


class Build(unittest.TestCase):
    def test_files_and_attack_filter(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            for sub, name, recs in (("batch11", "m__gated__adaptive_seeded__T0.jsonl", RECS + [
                    {**RECS[0], "attack": "other"}]), ("batch9", "m__gated__allowlist_reuse__T0__r0__A.jsonl",
                                                       [_b9("user_task_0", True)])):
                p = root / "repeats" / sub / "runs"
                p.mkdir(parents=True)
                (p / name).write_text("".join(json.dumps(r) + "\n" for r in recs))
            files = batch11.build(root)
            self.assertEqual(sorted(files), sorted("repeats/batch11/" + f for f in (
                "summary.json", "summary.md", "success.csv", "tries.csv", "compare.csv")))
            s = json.loads(files["repeats/batch11/summary.json"])
            self.assertEqual((s["runs"], s["max_tries"], s["n_tries"]), (3, 3, 7))
            self.assertIn("Success within k", files["repeats/batch11/summary.md"])


if __name__ == "__main__":
    unittest.main()
