"""Stage C: approval records carry an HMAC from a key only the gate process holds."""
import json
import tempfile
import unittest
from pathlib import Path

from acp import gate
from acp.attacker import forge_approval
from acp.canon import canonical
from acp.gate import ApprovalRequired, ToolRunner, approval_path, write_approval
from tests.helpers import ctx, lines

CATS = ["identifier:name"]


class ApprovalHmacTest(unittest.TestCase):
    def setUp(self):
        self.td = tempfile.TemporaryDirectory()
        self.tmp = Path(self.td.name)
        self.c, self.log = ctx(self.tmp)
        self.ap = self.tmp / "approvals"
        self.ap.mkdir()
        self.tr = ToolRunner(self.c, self.ap)
        self.outbox = []

    def tearDown(self):
        self.td.cleanup()

    def send(self, payload):
        def fn():
            self.outbox.append(payload)
            return None, {"stub": True}
        return self.tr.call("email_send", "send_email", fn, payload=payload, personal_data_categories=CATS,
                            lawful_basis="legitimate_interests", recipients=["contact:c-001"])

    def digest(self, payload):
        with self.assertRaises(ApprovalRequired) as e:
            self.send(payload)
        return e.exception.action_sha256

    def last_reason(self):
        return lines(self.log.path)[-1]["detail"].get("reason")

    def test_signed_approval_runs_once(self):
        a = self.digest({"to": "x"})
        write_approval(self.ap, a, approver="tester")
        self.send({"to": "x"})
        self.assertEqual(len(self.outbox), 1)
        with self.assertRaises(ApprovalRequired):
            self.send({"to": "x"})
        self.assertEqual(len(self.outbox), 1)

    def test_unsigned_file_refused(self):
        a = self.digest({"to": "x"})
        rec = {"action_sha256": a, "approver": "admin", "decision": "approve", "note": "", "simulated": False, "at": ""}
        approval_path(self.ap, a).write_bytes(canonical(rec) + b"\n")
        with self.assertRaises(ApprovalRequired):
            self.send({"to": "x"})
        self.assertEqual(self.outbox, [])
        self.assertEqual(self.last_reason(), "approval MAC invalid")

    def test_attacker_key_refused(self):
        a = self.digest({"to": "x"})
        forge_approval(self.ap, a, approver="dpo")
        with self.assertRaises(ApprovalRequired):
            self.send({"to": "x"})
        self.assertEqual(self.outbox, [])
        self.assertEqual(self.last_reason(), "approval MAC invalid")

    def test_tampered_field_refused(self):
        a = self.digest({"to": "x"})
        p = write_approval(self.ap, a, approver="tester", decision="reject")
        rec = json.loads(p.read_bytes())
        rec["decision"] = "approve"  # flip a reject to approve, keep the old MAC
        p.write_bytes(canonical(rec) + b"\n")
        with self.assertRaises(ApprovalRequired):
            self.send({"to": "x"})
        self.assertEqual(self.outbox, [])

    def test_mac_moved_to_other_action_refused(self):
        a = self.digest({"to": "x"})
        b = self.digest({"to": "y"})
        rec = json.loads(write_approval(self.ap, a, approver="tester").read_bytes())
        rec["action_sha256"] = b  # a valid MAC for action a, pasted onto action b
        approval_path(self.ap, b).write_bytes(canonical(rec) + b"\n")
        with self.assertRaises(ApprovalRequired):
            self.send({"to": "y"})
        self.assertEqual(self.outbox, [])

    def test_key_never_on_disk(self):
        a = self.digest({"to": "x"})
        write_approval(self.ap, a, approver="tester")
        self.send({"to": "x"})
        key = gate._APPROVAL_KEY
        self.assertEqual(len(key), 32)
        for f in self.tmp.rglob("*"):
            if f.is_file():
                data = f.read_bytes()
                self.assertNotIn(key, data, f)
                self.assertNotIn(key.hex().encode(), data, f)


if __name__ == "__main__":
    unittest.main()
