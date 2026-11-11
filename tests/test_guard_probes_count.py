"""tools/guard_probes_count.py: counts, and the refused-row cross-check against the verdicts."""
import os
import subprocess
import sys
import tempfile
import unittest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TOOL = os.path.join(REPO, "tools", "guard_probes_count.py")
FIX = os.path.join(REPO, "tests", "fixtures", "guard_probes")
VERDICTS = os.path.dirname(REPO)
HAVE_VERDICTS = os.path.exists(os.path.join(VERDICTS, "VERDICT-paper-C18.md"))


def run(table, verdict_dir=None):
    args = [sys.executable, TOOL, table] + ([verdict_dir] if verdict_dir else [])
    p = subprocess.run(args, capture_output=True, text=True, cwd=REPO)
    return p.returncode, p.stdout + p.stderr


def old_table(commit):
    p = subprocess.run(["git", "show", f"{commit}:docs/GUARD-PROBES.md"],
                       capture_output=True, text=True, cwd=REPO)
    if p.returncode:
        raise unittest.SkipTest(f"commit {commit} not in this clone")
    d = tempfile.mkdtemp()
    path = os.path.join(d, "GUARD-PROBES.md")
    with open(path, "w", encoding="utf-8") as f:
        f.write(p.stdout)
    return path


class FakeTables(unittest.TestCase):
    def fixture(self, name):
        d = os.path.join(FIX, name)
        return run(os.path.join(d, "GUARD-PROBES.md"), d)

    def test_f1_unsplit_refused(self):
        rc, out = self.fixture("f1-unsplit")
        self.assertEqual(rc, 1, out)
        self.assertIn("G064", out)
        self.assertIn("Fix:", out)

    def test_f2_all_caps(self):
        rc, out = self.fixture("f2-allcaps")
        self.assertEqual(rc, 1, out)
        self.assertIn("G064", out)

    def test_f3_other_order(self):
        rc, out = self.fixture("f3-otherorder")
        self.assertEqual(rc, 1, out)
        self.assertIn("G064", out)

    def test_f4_range_row(self):
        rc, out = self.fixture("f4-range")
        self.assertEqual(rc, 1, out)
        self.assertIn("G075", out)

    def test_f5_row_without_verdict_note(self):
        rc, out = self.fixture("f5-no-note")
        self.assertEqual(rc, 1, out)
        self.assertIn("G064", out)

    def test_f6_p1_not_matched_by_p11(self):
        rc, out = self.fixture("f6-p1-vs-p11")
        self.assertEqual(rc, 0, out)
        self.assertIn("refused_first_try=1", out)

    def test_no_verdicts_skips_cross_check(self):
        d = tempfile.mkdtemp()
        rc, out = run(os.path.join(FIX, "f1-unsplit", "GUARD-PROBES.md"), d)
        self.assertEqual(rc, 0, out)
        self.assertIn("verdict cross-check skipped", out)


@unittest.skipUnless(HAVE_VERDICTS, "verdict files not beside the repo (public clone)")
class RealTables(unittest.TestCase):
    def test_c24_rows_refused_when_verdict_unsplit(self):
        rc, out = run(old_table("6c9e4b40"), VERDICTS)
        self.assertEqual(rc, 1, out)
        for rid in ("G064", "G065", "G066", "G067"):
            self.assertIn(rid, out)
        self.assertIn("Fix:", out)

    def test_c23_row(self):
        rc, out = run(old_table("8d009c8d"), VERDICTS)
        self.assertEqual(rc, 1, out)
        self.assertIn("G075", out)

    def test_live_table_passes(self):
        rc, out = run(os.path.join(REPO, "docs", "GUARD-PROBES.md"), VERDICTS)
        self.assertEqual(rc, 0, out)
        for kv in ("routes_total=140", "refused_first_try=72", "held_first_try=19",
                   "did_not_get_through_first_try=91"):
            self.assertIn(kv, out)


if __name__ == "__main__":
    unittest.main()
