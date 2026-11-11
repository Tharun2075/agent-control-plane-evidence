"""Batch 13 runner (tools/bench_batch13.py): folders per rep, rep tags, fixed provider and set,
driven by a fake run_one; no network, no key.

Needs the optional benchmark dependency (requirements-bench.txt); skipped without it.
"""
import contextlib
import io
import json
import sys
import tempfile
import unittest
import unittest.mock
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))
try:
    import bench_agentdojo as B
    import bench_batch13 as b13
    import batch13_drive as D
except ImportError:  # benchmark not installed
    B = b13 = D = None


@unittest.skipIf(b13 is None, "agentdojo not installed (requirements-bench.txt)")
class Batch13Runner(unittest.TestCase):
    def setUp(self):
        self.saved = (B.RUN_DIR, B.LOG_DIR, B.run_one, B.make_client, b13.BASE)
        self.tmp = tempfile.TemporaryDirectory()
        b13.BASE = Path(self.tmp.name)
        self.calls = []

        def fake_run_one(j, a, client, chain, lock):
            self.calls.append((B.key(j), a.model, a.arm, a.set, a.provider))
            return {**j, "model": a.model, "arm": a.arm, "cost_usd": 0.001, "utility": True,
                    "security": False, "error_class": None, "gate_checks": 0, "gate_blocks": 0}

        B.run_one = fake_run_one
        B.make_client = lambda provider: object()

    def tearDown(self):
        B.RUN_DIR, B.LOG_DIR, B.run_one, B.make_client, b13.BASE = self.saved
        self.tmp.cleanup()

    def run_main(self, argv):
        with contextlib.redirect_stdout(io.StringIO()) as out:
            rc = b13.main(argv)
        return rc, out.getvalue()

    def test_plan_is_batch6_b1(self):
        jobs = B.plan("B1")
        self.assertEqual(len(jobs), 77)
        self.assertEqual(sum(j["it"] is None for j in jobs), 37)

    def test_rep_folder_and_tags(self):
        rc, out = self.run_main(["--rep", "2", "--model", "claude-haiku-5-5", "--arm", "plain", "--limit", "3",
                                 "--workers", "1"])
        self.assertEqual(rc, 0)
        f = b13.BASE / "runs" / "r2" / "claude-haiku-5-5__plain__B1.jsonl"
        recs = [json.loads(x) for x in f.read_text().splitlines()]
        self.assertEqual(len(recs), 3)
        for r in recs:
            self.assertEqual((r["rep"], r["batch"], r["sampling"]), (2, 13, "provider-default"))
        self.assertEqual({c[3:] for c in self.calls}, {("B1", "anthropic")})
        self.assertIn("DONE claude-haiku-5-5__plain__B1.jsonl runs=3", out)

    def test_resume_fills_only_missing(self):
        argv = ["--rep", "1", "--model", "claude-opus-5-5", "--arm", "gated", "--workers", "1"]
        self.run_main(argv + ["--limit", "2"])
        self.run_main(argv + ["--limit", "5"])
        keys = [c[0] for c in self.calls]
        self.assertEqual(len(keys), 5)
        self.assertEqual(len(set(keys)), 5)
        self.assertTrue((b13.BASE / "logs" / "r1" / "claude-opus-5-5__B1.gated.jsonl").parent.is_dir())

    def test_wrapper_not_stacked(self):
        b13.configure(1)
        b13.configure(3)
        rec = B.run_one({"suite": "banking", "ut": "user_task_0", "it": None},
                        type("A", (), {"model": "m", "arm": "plain", "set": "B1", "provider": "anthropic"})(),
                        None, None, None)
        self.assertEqual(rec["rep"], 3)
        self.assertEqual(len(self.calls), 1)

    def test_refuses_other_models_reps_and_overrides(self):
        bad = [["--rep", "1", "--model", "openai.gpt-oss-20b-1:0"],
               ["--rep", "0", "--model", "claude-haiku-5-5"],
               ["--rep", "4", "--model", "claude-haiku-5-5"],
               ["--rep", "1", "--model", "claude-haiku-5-5", "--provider", "groq"],
               ["--rep", "1", "--model", "claude-haiku-5-5", "--set=B2"]]
        for argv in bad:
            with self.subTest(argv=argv), contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit):
                    b13.main(argv)
        self.assertEqual(self.calls, [])



@unittest.skipIf(b13 is None, "agentdojo not installed (requirements-bench.txt)")
class Batch13Driver(unittest.TestCase):
    """Budget rules of tools/batch13_drive.py, with a fake secret-get and a fake child runner."""

    def setUp(self):
        self.saved = (D.BASE, D.subprocess.run)
        self.tmp = tempfile.TemporaryDirectory()
        D.BASE = Path(self.tmp.name)
        self.children = []

        def fake_run(cmd, **kw):
            if "secret-get" in cmd[0]:
                return type("R", (), {"stdout": "test-key\n", "returncode": 0})()
            self.children.append((cmd, kw["env"]))
            i = cmd.index
            f = D.BASE / "runs" / f"r{cmd[i('--rep') + 1]}" / f"{cmd[i('--model') + 1]}__{cmd[i('--arm') + 1]}__B1.jsonl"
            f.parent.mkdir(parents=True, exist_ok=True)
            f.write_text(json.dumps({"cost_usd": self.cost[cmd[i('--model') + 1]]}) + "\n")
            return type("R", (), {"returncode": 0})()

        D.subprocess.run = fake_run

    def tearDown(self):
        D.BASE, D.subprocess.run = self.saved
        self.tmp.cleanup()

    def drive(self, cost):
        self.cost = cost
        out = io.StringIO()
        with contextlib.redirect_stdout(out), unittest.mock.patch.dict(
                D.os.environ, {"CLAUDE_CODE_OAUTH_TOKEN": "oauth"}):
            D.main(["--python", "py"])
        return out.getvalue()

    def test_three_reps_fit_and_key_only_in_child_env(self):
        log = self.drive({"claude-haiku-5-5": 0.1, "claude-sonnet-5-5": 1.7, "claude-opus-5-5": 3.3})
        self.assertEqual(len(self.children), 18)
        self.assertNotIn("REP-CUT", log)
        self.assertNotIn("test-key", log)
        for cmd, env in self.children:
            self.assertEqual(env["ANTHROPIC_API_KEY"], "test-key")
            self.assertNotIn("CLAUDE_CODE_OAUTH_TOKEN", env)
            self.assertNotIn("test-key", " ".join(cmd))

    def test_whole_rep_cut_when_projection_passes_cap(self):
        log = self.drive({"claude-haiku-5-5": 0.2, "claude-sonnet-5-5": 2.0, "claude-opus-5-5": 3.8})
        self.assertIn("REP-CUT r3", log)
        self.assertEqual(len(self.children), 12)  # reps 1 and 2 whole, rep 3 not started

    def test_file_budget_never_above_share_or_cap(self):
        self.drive({"claude-haiku-5-5": 0.1, "claude-sonnet-5-5": 1.7, "claude-opus-5-5": 3.3})
        for cmd, _ in self.children:
            budget = float(cmd[cmd.index("--budget-usd") + 1])
            self.assertLessEqual(budget, D.SHARE[cmd[cmd.index("--model") + 1]])

if __name__ == "__main__":
    unittest.main()
