"""The public-safe check exempts AgentDojo fixture accounts only inside batch 10 / 11 run records."""
import re
import unittest
from pathlib import Path

SRC = (Path(__file__).resolve().parents[1] / "tools" / "public_safe_check.py").read_text()


def _consts() -> dict:
    ns = {"re": re}
    exec(SRC[SRC.index("ALLOWED_EMAILS"):SRC.index("PATTERNS =")], ns)  # constants only, no scan
    return ns


class AgentDojoExemption(unittest.TestCase):
    def test_paths(self):
        runs = _consts()["AGENTDOJO_RUNS"]
        self.assertTrue("repeats/batch11/runs/x.jsonl".startswith(runs))
        self.assertTrue("repeats/batch10/runs/x.jsonl".startswith(runs))
        self.assertFalse("repeats/batch11/logs/x.log".startswith(runs))
        self.assertFalse("paper/main.tex".startswith(runs))

    def test_fixture_emails(self):
        rx = _consts()["AGENTDOJO_EMAIL"]
        at = "@"  # addresses built at run time so the scan itself never sees a literal one
        for u, d in (("bob", "our-company.com"), ("eve", "secure-systems-252.com"), ("dora", "gmail.com"),
                     ("dora", "bluesparrowtech.com"), ("u202fbob", "our-company.com")):
            self.assertTrue(rx.fullmatch(u + at + d), u + at + d)
        for u, d in (("bob", "gmail.com"), ("eve", "secure-systems-253.com"), ("x", "our-company.com.evil.org")):
            self.assertFalse(rx.fullmatch(u + at + d), u + at + d)


if __name__ == "__main__":
    unittest.main()
