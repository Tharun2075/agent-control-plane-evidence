"""T-b: outbound action blocked and logged without approval; proceeds to a local stub with it."""
import tempfile
import unittest
from pathlib import Path

from acp.gate import ApprovalRequired, PermissionDenied, Rejected, ToolRunner, write_approval
from acp.log import verify
from tests.helpers import ctx, lines

CATS = ["identifier:name"]


class GateTest(unittest.TestCase):
    def setUp(self):
        self.td = tempfile.TemporaryDirectory()
        self.tmp = Path(self.td.name)
        self.c, self.log = ctx(self.tmp)
        self.tr = ToolRunner(self.c, self.tmp / "approvals")
        self.outbox = []

    def tearDown(self):
        self.td.cleanup()

    def send(self, payload):
        def fn():
            self.outbox.append(payload)  # local stub, never a real send
            return None, {"stub": True}
        return self.tr.call("email_send", "send_email", fn, payload=payload, personal_data_categories=CATS,
                            lawful_basis="legitimate_interests", recipients=["contact:c-001"])

    def test_blocked_without_approval_and_logged(self):
        with self.assertRaises(ApprovalRequired):
            self.send({"to": "contact:c-001", "body": "hello"})
        self.assertEqual(self.outbox, [])
        last = lines(self.log.path)[-1]
        self.assertEqual(last["outcome"], "blocked_pending_approval")
        self.assertEqual(last["detail"]["gate"], "blocked")
        self.assertTrue(verify(self.log.path).ok)

    def test_proceeds_with_approval(self):
        p = {"to": "contact:c-001", "body": "hello"}
        with self.assertRaises(ApprovalRequired) as e:
            self.send(p)
        write_approval(self.tmp / "approvals", e.exception.action_sha256, approver="tester")
        self.send(p)
        self.assertEqual(self.outbox, [p])
        last = lines(self.log.path)[-1]
        self.assertEqual((last["outcome"], last["decision_mode"]), ("ok", "human_approved"))
        self.assertEqual(last["detail"]["approver"], "tester")
        self.assertIsNotNone(last["approval_ref"])

    def test_approval_does_not_cover_changed_payload(self):
        with self.assertRaises(ApprovalRequired) as e:
            self.send({"to": "contact:c-001", "body": "hello"})
        write_approval(self.tmp / "approvals", e.exception.action_sha256, approver="tester")
        with self.assertRaises(ApprovalRequired):
            self.send({"to": "contact:c-002", "body": "hello"})
        self.assertEqual(self.outbox, [])

    def test_rejection_logged(self):
        p = {"to": "contact:c-001", "body": "hello"}
        with self.assertRaises(ApprovalRequired) as e:
            self.send(p)
        write_approval(self.tmp / "approvals", e.exception.action_sha256, approver="tester", decision="reject")
        with self.assertRaises(Rejected):
            self.send(p)
        self.assertEqual(lines(self.log.path)[-1]["decision_mode"], "human_rejected")
        self.assertEqual(self.outbox, [])

    def test_undeclared_tool_refused_and_logged(self):
        with self.assertRaises(PermissionDenied):
            self.tr.call("shell_exec", "rm", lambda: (None, None))
        self.assertEqual(lines(self.log.path)[-1]["outcome"], "refused_not_permitted")

    def test_non_outbound_tool_not_gated(self):
        v = self.tr.call("crm_read", "read", lambda: ("x", {"source": "t"}), personal_data_categories=CATS,
                         lawful_basis="legitimate_interests")
        self.assertEqual(v, "x")
        self.assertEqual(lines(self.log.path)[-1]["decision_mode"], "automated")


if __name__ == "__main__":
    unittest.main()
