"""Fail-closed controls (security review findings 1-3)."""
import json
import os
import tempfile
import time
import unittest
from pathlib import Path

from acp.agent import AgentContext
from acp.gate import ApprovalRequired, PermissionDenied, ToolRunner, approval_path, write_approval
from acp.isolation import IsolationError, SessionStore
from acp.log import ChainLog, FixedStepClock, verify
from acp.manifest import bind_session, load
from tests.helpers import ROOT, ctx, lines

EXP = "2026-11-10T23:59:59Z"
CATS = ["identifier:name"]


class Tmp(unittest.TestCase):
    def setUp(self):
        self.td = tempfile.TemporaryDirectory()
        self.tmp = Path(self.td.name)

    def tearDown(self):
        self.td.cleanup()


class DelegationTest(Tmp):
    """Finding 1: delegated authority fails closed."""

    def worker(self):
        return load(ROOT / "manifests" / "worker.json")

    def test_delegation_needs_explicit_authority(self):
        with self.assertRaises(ValueError):
            bind_session(self.worker(), session_id="s", task="t", expires=EXP, delegated_by="acp.orchestrator")

    def test_delegator_must_be_accepted(self):
        with self.assertRaises(ValueError):
            bind_session(self.worker(), session_id="s", task="t", expires=EXP,
                         delegated_by="acp.research-agent", delegated_authority=["classify"])

    def test_authority_cannot_exceed_allowed_tools(self):
        with self.assertRaises(ValueError):
            bind_session(self.worker(), session_id="s", task="t", expires=EXP,
                         delegated_by="acp.orchestrator", delegated_authority=["classify", "email_send"])

    def test_explicit_empty_authority_is_respected(self):
        m = bind_session(self.worker(), session_id="s", task="t", expires=EXP,
                         delegated_by="acp.orchestrator", delegated_authority=[])
        self.assertEqual(m["current_task"]["delegated_authority"], [])

    def test_gate_denies_when_authority_missing(self):
        c, log = ctx(self.tmp)
        del c.manifest["current_task"]["delegated_authority"]
        with self.assertRaises(PermissionDenied):
            ToolRunner(c, self.tmp / "ap").call("crm_read", "read", lambda: ("x", {"source": "t"}),
                                                personal_data_categories=CATS, lawful_basis="legitimate_interests")
        self.assertEqual(lines(log.path)[-1]["outcome"], "refused_not_permitted")


class ExpiryAndReplayTest(Tmp):
    """Finding 2: expiry enforced; approvals are single-use."""

    def test_expiry_required(self):
        with self.assertRaises(ValueError):
            bind_session(load(ROOT / "manifests" / "outreach-agent.json"), session_id="s", task="t", expires=None)

    def test_call_after_expiry_refused_and_logged(self):
        log = ChainLog(self.tmp / "log.jsonl", clock=FixedStepClock("2026-11-10T09:00:00Z"), durable=False)
        m = bind_session(load(ROOT / "manifests" / "outreach-agent.json"), session_id="s", task="t",
                         expires="2026-11-10T09:00:02Z")
        c = AgentContext(log, m, "s")
        tr = ToolRunner(c, self.tmp / "ap")
        read = lambda: tr.call("crm_read", "read", lambda: ("x", {"source": "t"}),
                               personal_data_categories=CATS, lawful_basis="legitimate_interests")
        read(); read()  # records at 09:00:00 and 09:00:01
        with self.assertRaises(PermissionDenied):
            read()      # 09:00:02 is not before expiry
        last = lines(log.path)[-1]
        self.assertEqual(last["outcome"], "refused_authority_expired")
        self.assertEqual(last["detail"]["expires"], "2026-11-10T09:00:02Z")
        self.assertTrue(verify(log.path).ok)

    def test_invalid_expires_logged_then_raises(self):
        log = ChainLog(self.tmp / "log.jsonl", clock=FixedStepClock("2026-11-10T09:00:00Z"), durable=False)
        m = bind_session(load(ROOT / "manifests" / "outreach-agent.json"), session_id="s", task="t",
                         expires="garbage")
        tr = ToolRunner(AgentContext(log, m, "s"), self.tmp / "ap")
        with self.assertRaises(PermissionDenied):
            tr.call("crm_read", "read", lambda: ("x", {"source": "t"}),
                    personal_data_categories=CATS, lawful_basis="legitimate_interests")
        last = lines(log.path)[-1]
        self.assertEqual(last["outcome"], "refused_authority_expired")
        self.assertEqual(last["detail"]["reason"], "invalid expires")
        self.assertTrue(verify(log.path).ok)

    def test_naive_expires_refused_whatever_the_host_tz(self):  # batch 5 E1 class naive-tz
        old = os.environ.get("TZ")
        os.environ["TZ"] = "America/Los_Angeles"
        time.tzset()
        try:
            log = ChainLog(self.tmp / "log.jsonl", clock=FixedStepClock("2026-11-10T09:00:00Z"), durable=False)
            # 08:00 naive is in the past in UTC but in the future read as Los Angeles time
            m = bind_session(load(ROOT / "manifests" / "outreach-agent.json"), session_id="s", task="t",
                             expires="2026-11-10T08:00:00")
            tr = ToolRunner(AgentContext(log, m, "s"), self.tmp / "ap")
            with self.assertRaises(PermissionDenied):
                tr.call("crm_read", "read", lambda: ("x", {"source": "t"}),
                        personal_data_categories=CATS, lawful_basis="legitimate_interests")
            self.assertEqual(lines(log.path)[-1]["detail"]["reason"], "invalid expires")
        finally:
            if old is None:
                os.environ.pop("TZ", None)
            else:
                os.environ["TZ"] = old
            time.tzset()

    def test_approval_cannot_be_replayed(self):
        c, log = ctx(self.tmp)
        tr = ToolRunner(c, self.tmp / "ap")
        outbox = []
        p = {"to": "contact:c-001", "body": "hello"}

        def send():
            return tr.call("email_send", "send_email", lambda: (outbox.append(p), {"stub": True}), payload=p,
                           personal_data_categories=CATS, lawful_basis="legitimate_interests",
                           recipients=["contact:c-001"])
        with self.assertRaises(ApprovalRequired) as e:
            send()
        write_approval(self.tmp / "ap", e.exception.action_sha256, approver="tester")
        send()
        with self.assertRaises(ApprovalRequired):
            send()
        self.assertEqual(len(outbox), 1)
        last = lines(log.path)[-1]
        self.assertEqual(last["detail"]["reason"], "approval already used")
        appr = json.loads(approval_path(self.tmp / "ap", e.exception.action_sha256).read_bytes())
        self.assertTrue(appr["consumed"])
        self.assertEqual(appr["consumed_by"]["log_seq"], last["seq"] - 1)


class HandoffTest(Tmp):
    """Finding 3: handoff cannot write outside the recipient's namespace."""

    def setUp(self):
        super().setUp()
        self.a, self.log = ctx(self.tmp, sid="session-a")
        self.b, _ = ctx(self.tmp, sid="session-b", log=self.log)
        self.sa = SessionStore(self.tmp / "sessions", self.a)
        self.sb = SessionStore(self.tmp / "sessions", self.b)
        self.outside = self.tmp / "outside"
        self.outside.mkdir()
        (self.outside / "victim.txt").write_text("original")

    def last(self):
        return lines(self.log.path)[-1]

    def test_dotdot_name_refused_and_logged(self):
        (self.sb.dir / "secret.txt").write_text("b's data")
        with self.assertRaises(IsolationError):
            self.sa.handoff("../session-b/secret.txt", self.sb)
        self.assertEqual(self.last()["outcome"], "refused_outside_session")
        self.assertEqual(self.last()["action"], "handoff")

    def test_symlink_at_destination_refused(self):
        self.sa.write("victim.txt", "attacker data")
        os.symlink(self.outside / "victim.txt", self.sb.dir / "victim.txt")
        with self.assertRaises(IsolationError):
            self.sa.handoff("victim.txt", self.sb)
        self.assertEqual((self.outside / "victim.txt").read_text(), "original")
        self.assertEqual(self.last()["detail"]["reason"], "destination is a symlink")

    def test_symlinked_directory_escape_refused(self):
        (self.sa.dir / "d").mkdir()
        self.sa.write("d/victim.txt", "attacker data")
        os.symlink(self.outside, self.sb.dir / "d")
        with self.assertRaises(IsolationError):
            self.sa.handoff("d/victim.txt", self.sb)
        self.assertEqual((self.outside / "victim.txt").read_text(), "original")
        self.assertEqual(self.last()["detail"]["reason"], "destination outside recipient session")
        self.assertTrue(verify(self.log.path).ok)


if __name__ == "__main__":
    unittest.main()
