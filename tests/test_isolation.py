"""T-c: a read outside the session namespace is refused and logged."""
import os
import tempfile
import unittest
from pathlib import Path

from acp.isolation import IsolationError, SessionStore
from acp.log import verify
from tests.helpers import ctx, lines


class IsolationTest(unittest.TestCase):
    def setUp(self):
        self.td = tempfile.TemporaryDirectory()
        self.tmp = Path(self.td.name)
        self.a, self.log = ctx(self.tmp, sid="session-a")
        self.b, _ = ctx(self.tmp, sid="session-b", log=self.log)
        self.sa = SessionStore(self.tmp / "sessions", self.a)
        self.sb = SessionStore(self.tmp / "sessions", self.b)
        self.sa.write("secret.txt", "a's data")

    def tearDown(self):
        self.td.cleanup()

    def test_own_read_ok(self):
        self.assertEqual(self.sa.read("secret.txt"), "a's data")

    def test_cross_session_read_refused_and_logged(self):
        for path in ("../session-a/secret.txt", self.sa.dir / "secret.txt"):
            with self.assertRaises(IsolationError):
                self.sb.read(path)
            last = lines(self.log.path)[-1]
            self.assertEqual(last["outcome"], "refused_outside_session")
            self.assertEqual(last["gen_ai.conversation.id"], "session-b")
            self.assertEqual(last["detail"]["requested"], "session-a/secret.txt")
        self.assertTrue(verify(self.log.path).ok)

    def test_symlink_escape_refused(self):
        os.symlink(self.sa.dir / "secret.txt", self.sb.dir / "link.txt")
        with self.assertRaises(IsolationError):
            self.sb.read("link.txt")

    def test_handoff_is_the_logged_route(self):
        self.sa.handoff("secret.txt", self.sb)
        self.assertEqual(self.sb.read("secret.txt"), "a's data")
        h = [r for r in lines(self.log.path) if r["action"] == "handoff"][0]
        self.assertEqual(h["recipients"], ["agent:acp.outreach-agent"])
        self.assertEqual(h["detail"]["to_session"], "session-b")


if __name__ == "__main__":
    unittest.main()
