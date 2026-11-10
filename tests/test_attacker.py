"""Batch 5 scripted attacker (acp/attacker.py): determinism, T6, ablation, oracle."""
import json
import shutil
import tempfile
import unittest
from pathlib import Path

from acp import attacker, gate
from acp.log import verify

ROOT = Path(__file__).resolve().parent.parent


class TestAttacker(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = Path(tempfile.mkdtemp())
        cls.on = attacker.run(cls.tmp / "on", ROOT, per_trick=2)["rows"]
        cls.off = attacker.run(cls.tmp / "off", ROOT, per_trick=2, ablate="all-off")["rows"]

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def test_plan_is_seeded(self):
        self.assertEqual(attacker.plan(3), attacker.plan(3))
        a = attacker.run(self.tmp / "s1", ROOT, per_trick=1, seed=7)["rows"]
        b = attacker.run(self.tmp / "s2", ROOT, per_trick=1, seed=7)["rows"]
        self.assertEqual([r["bypass"] for r in a], [r["bypass"] for r in b])
        self.assertEqual({f for f, _, _ in attacker.plan(1)}, set(attacker.FAMILIES))

    def test_every_attempt_leaves_a_gate_record(self):  # T6
        self.assertGreaterEqual(min(r["records"] for r in self.on), 1)
        self.assertEqual(attacker.summarise(self.on)["t6_min_records_per_attempt"],
                         min(r["records"] for r in self.on))

    def test_family_logs_verify(self):
        for fam in ("url", "approval", "delegation", "session"):  # logtamper logs are tampered on purpose
            p = self.tmp / "on" / fam / "log.jsonl"
            self.assertTrue(verify(p).ok, fam)

    def test_log_tamper_is_never_a_noop(self):  # PROTOCOL deviation D1
        # with the anchor fix, no ablation arm lets a log tamper verify: gate-off once scored
        # a no-op rewrite (record already "ok") as a bypass
        for arm in ("gate-off", "all-off"):
            rows = attacker.run(self.tmp / f"lt-{arm}", ROOT, per_trick=4, ablate=arm)["rows"]
            lt = [r for r in rows if r["family"] == "logtamper"]
            self.assertTrue(lt)
            self.assertFalse(any(r["bypass"] for r in lt), arm)

    def test_attempts_file_matches_rows(self):
        rows = [json.loads(x) for x in (self.tmp / "on" / "attempts.jsonl").read_text().splitlines()]
        self.assertEqual(len(rows), len(self.on))

    def test_ablation_weakens_and_restores(self):
        self.assertGreater(sum(r["bypass"] for r in self.off), sum(r["bypass"] for r in self.on))
        before = gate.check_url
        with attacker.ablation("all-off"):
            self.assertIsNot(gate.check_url, before)
        self.assertIs(gate.check_url, before)
        with self.assertRaises(ValueError):
            attacker.ablation("nope")

    def test_unfixable_classes_are_declared(self):
        for c in {r["class"] for r in self.on if r["bypass"]}:
            self.assertIn(c, attacker.FIXABLE)

    def test_wpt_cases_load(self):
        cases = attacker.wpt_cases()
        self.assertGreaterEqual(len(cases), 100)
        self.assertTrue(all(attacker.HOST in c["href"] for c in cases))

    def test_authority_off_lets_widened_delegation_bind(self):
        out = self.tmp / "rep"
        on = {r["action"]: r["outcome"] for r in attacker.replay(out / "on", ROOT, "all-on") if r["run"] == "6"}
        off = [r for r in attacker.replay(out / "off", ROOT, "authority-off") if r["action"] == "delegate"]
        self.assertIn("refused_delegation_exceeds_authority",
                      [r["outcome"] for r in attacker.replay(out / "on2", ROOT, "all-on") if r["action"] == "delegate"])
        self.assertTrue(all(r["executed"] for r in off))
        self.assertIn("delegate", on)

    def test_oracle_decodes_unreserved_only(self):
        self.assertTrue(attacker.oracle_ok("https://research.example.test/%63ompany/acme-widgets"))
        self.assertFalse(attacker.oracle_ok("https://research.example.test/company/acme-widgets%2F..%2Fx"))
        self.assertFalse(attacker.oracle_ok("https://evil.example.net/company/acme-widgets"))


if __name__ == "__main__":
    unittest.main()
