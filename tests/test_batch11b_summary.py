"""Batch 11b summary (acp.batch11b): error counts of the new tries only, pairs left by a budget stop,
the batch-11 (YAML bug) result on the same pairs, and the generated files. No network."""
import json
import tempfile
import unittest
from pathlib import Path

from acp import batch11, batch11b
from tests.test_batch11_summary import BLOCK_AL, M, PASS, _b9, _call, _rec, _try

M2 = "qwen.qwen3-32b-v1:0"


def _t1(ok, **kw):
    return _try(1, ok, [BLOCK_AL] if not ok else [PASS], reused_from="batch11", **kw)


def _new(ut, tries, model=M, **kw):
    return _rec(ut, tries, model=model, max_tries=8, batch="11b", try1_reused=True,
                cost_new_usd=0.01 * (len(tries) - 1), **kw)


def _old(ut, tries, model=M):
    return _rec(ut, tries, model=model, max_tries=8)


PARSER = dict(error="yaml", error_class="ParserError")


class ErrorRows(unittest.TestCase):
    def test_counts_new_tries_only_and_pairs_not_run(self):
        recs = [_new("user_task_0", [_t1(False, error_class="ParserError"),  # reused: not counted
                                     _try(2, False, [BLOCK_AL]),
                                     _try(3, False, error="bad tool", error_class="ValidationException")]),
                _new("user_task_1", [_t1(True)])]
        planned = [_old("user_task_0", [_try(1, False)]), _old("user_task_1", [_try(1, True)]),
                   _old("user_task_2", [_try(1, False)])]
        rows = {r["model"]: r for r in batch11b.error_rows(recs, planned)}
        p = rows["pooled"]
        self.assertEqual((p["pairs_planned"], p["pairs_run"], p["pairs_not_run"]), (3, 2, 1))
        self.assertEqual((p["new_tries"], p["parser_errors"], p["validation_errors"], p["other_errors"]),
                         (2, 0, 1, 0))
        self.assertAlmostEqual(p["cost_new_usd"], 0.02)
        self.assertEqual(rows[M]["pairs_not_run"], 1)


class Batch11Rows(unittest.TestCase):
    def test_same_pairs_old_against_new(self):
        old = [_old("user_task_0", [_try(1, False), _try(2, False, **PARSER), _try(3, False, **PARSER)]),
               _old("user_task_1", [_try(1, True)]),
               _old("user_task_2", [_try(1, False), _try(2, True)])]  # not run in 11b: left out
        recs = [_new("user_task_0", [_t1(False), _try(2, False), _try(3, True, [_call("approved")])]),
                _new("user_task_1", [_t1(True)])]
        r = {x["model"]: x for x in batch11b.b11_rows(recs, old)}["pooled"]
        self.assertEqual((r["pairs"], r["b11_succeeded"], r["b11_parser_errors"], r["b11b_succeeded"], r["k"]),
                         (2, 1, 2, 2, 8))


class Build(unittest.TestCase):
    def test_build_files_and_keys(self):
        new = [_new("user_task_0", [_t1(False), _try(2, False, [BLOCK_AL]), _try(3, True, [PASS])]),
               _new("user_task_1", [_t1(True)]),
               _new("user_task_0", [_t1(False), _try(2, False, [BLOCK_AL])], model=M2)]
        old = [_old("user_task_0", [_try(1, False), _try(2, False, **PARSER)]), _old("user_task_1", [_try(1, True)]),
               _old("user_task_0", [_try(1, False), _try(2, False, **PARSER)], model=M2),
               _old("user_task_1", [_try(1, False)], model=M2)]
        b9 = [_b9("user_task_0", False), _b9("user_task_1", True), _b9("user_task_0", False, model=M2),
              _b9("user_task_1", False, model=M2)]
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            for sub, rs in (("batch11b", new), ("batch11", old), ("batch9", b9)):
                p = root / "repeats" / sub / "runs"
                p.mkdir(parents=True)
                (p / "x.jsonl").write_text("".join(json.dumps(r) + "\n" for r in rs))
            out = batch11b.build(root)
        self.assertEqual(sorted(out), sorted("repeats/batch11b/" + f for f in (
            "summary.json", "summary.md", "success.csv", "tries.csv", "compare.csv", "errors.csv",
            "batch11.csv")))
        s = json.loads(out["repeats/batch11b/summary.json"])
        for k in ("success", "tries", "compare", "comparison", "errors", "batch11", "runs", "max_tries",
                  "n_tries", "cost_usd", "cost_new_usd"):
            self.assertIn(k, s)
        self.assertEqual(s["runs"], 3)
        pooled = next(r for r in s["errors"] if r["model"] == "pooled")
        self.assertEqual((pooled["pairs_not_run"], pooled["parser_errors"]), (1, 0))
        md = out["repeats/batch11b/summary.md"]
        self.assertIn(batch11b.GENERATOR, md)
        self.assertNotIn(batch11.GENERATOR + "`", md)
        self.assertIn("ParserError 0", md)


if __name__ == "__main__":
    unittest.main()
