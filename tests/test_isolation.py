"""T-c: a read outside the session namespace is refused and logged."""
import os
import tempfile
import unittest
from pathlib import Path

from acp.gate import PermissionDenied
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


class StoreAuthorityTest(unittest.TestCase):
    """Regression (batch-4 red-team probe): store and handoff go through gate.authorise()."""
    def setUp(self):
        self.td = tempfile.TemporaryDirectory()
        self.tmp = Path(self.td.name)

    def tearDown(self):
        self.td.cleanup()

    def _refused(self, fn, outcome, log, action):
        with self.assertRaises(PermissionDenied) as cm:
            fn()
        self.assertEqual(cm.exception.outcome, outcome)
        last = lines(log.path)[-1]
        self.assertEqual((last["action"], last["outcome"]), (action, outcome))
        self.assertTrue(verify(log.path).ok)

    def test_expired_write_read_handoff_refused_and_logged(self):
        a, log = ctx(self.tmp, sid="old", expires="2026-11-09T00:00:00Z")
        b, _ = ctx(self.tmp, sid="new", log=log)
        sa, sb = SessionStore(self.tmp / "sessions", a), SessionStore(self.tmp / "sessions", b)
        (sa.dir / "x.txt").write_text("planted")
        self._refused(lambda: sa.write("y.txt", "data"), "refused_authority_expired", log, "write")
        self.assertFalse((sa.dir / "y.txt").exists())
        self._refused(lambda: sa.read("x.txt"), "refused_authority_expired", log, "read")
        self._refused(lambda: sa.handoff("x.txt", sb), "refused_authority_expired", log, "handoff")
        self.assertFalse((sb.dir / "x.txt").exists())

    def test_undelegated_store_refused(self):
        a, log = ctx(self.tmp, sid="d")
        a.manifest["current_task"]["delegated_authority"] = ["classify"]
        sa = SessionStore(self.tmp / "sessions", a)
        self._refused(lambda: sa.write("y.txt", "data"), "refused_not_permitted", log, "write")


if __name__ == "__main__":
    unittest.main()
