"""Round 4: approvals are claimed atomically before the tool runs (F4); URLs are
checked by parsed, normalised parts, not by raw string (F5)."""
import json
import tempfile
import threading
import time
import unittest
from pathlib import Path

from acp.gate import ApprovalRequired, PermissionDenied, ToolRunner, approval_path, check_url, write_approval
from acp.log import ChainLog, FixedStepClock, verify
from tests.helpers import ctx, lines

CATS = ["identifier:name"]
P = {"to": "contact:c-001", "body": "hello"}
HOST = "https://find-and-update.company-information.service.gov.uk"
ALLOW = [HOST + "/company/02557590"]
BLOCK = ["/officers", "/persons-with-significant-control", "/filing-history"]


def send(tr, fn):
    return tr.call("email_send", "send_email", fn, payload=P, personal_data_categories=CATS,
                   lawful_basis="legitimate_interests", recipients=["contact:c-001"])


class ClaimTest(unittest.TestCase):
    def setUp(self):
        self.td = tempfile.TemporaryDirectory()
        self.tmp = Path(self.td.name)
        self.ap = self.tmp / "ap"

    def tearDown(self):
        self.td.cleanup()

    def approve(self, tr):
        with self.assertRaises(ApprovalRequired) as e:
            send(tr, lambda: (None, None))
        write_approval(self.ap, e.exception.action_sha256, approver="tester")
        return e.exception.action_sha256

    def test_race_exactly_one_executes(self):
        # Two callers for the same agent and session, each with its own log (as two
        # processes would have), share one approvals directory and race one approval.
        runners, logs = [], []
        for i in range(2):
            log = ChainLog(self.tmp / f"log{i}.jsonl", clock=FixedStepClock(), durable=False)
            c, _ = ctx(self.tmp, log=log)
            runners.append(ToolRunner(c, self.ap))
            logs.append(log)
        a = self.approve(runners[0])
        outbox, results, gate = [], [None, None], threading.Barrier(2)

        def tool():
            time.sleep(0.05)  # widen the window between check and use
            outbox.append(P)
            return None, {"stub": True}

        def worker(i):
            gate.wait()
            try:
                send(runners[i], tool)
                results[i] = "ok"
            except ApprovalRequired:
                results[i] = "refused"
        ts = [threading.Thread(target=worker, args=(i,)) for i in range(2)]
        for t in ts:
            t.start()
        for t in ts:
            t.join()
        self.assertEqual(sorted(results), ["ok", "refused"])
        self.assertEqual(len(outbox), 1)
        loser = results.index("refused")
        last = lines(logs[loser].path)[-1]
        self.assertEqual(last["outcome"], "blocked_pending_approval")
        self.assertEqual(last["detail"]["reason"], "approval already used")
        appr = json.loads(approval_path(self.ap, a).read_bytes())
        self.assertTrue(appr["consumed"])
        self.assertEqual(appr["consumed_by"]["outcome"], "ok")
        self.assertTrue(all(verify(l.path).ok for l in logs))

    def test_tool_error_consumes_approval(self):
        c, log = ctx(self.tmp)
        tr = ToolRunner(c, self.ap)
        a = self.approve(tr)
        outbox = []

        def boom():
            raise ConnectionError("smtp down")
        with self.assertRaises(ConnectionError):
            send(tr, boom)
        err = lines(log.path)[-1]
        self.assertEqual(err["outcome"], "error")
        appr = json.loads(approval_path(self.ap, a).read_bytes())
        self.assertTrue(appr["consumed"])
        self.assertEqual(appr["consumed_by"], {"log_seq": err["seq"], "log_hash": err["hash"], "outcome": "error"})
        with self.assertRaises(ApprovalRequired):
            send(tr, lambda: (outbox.append(P), {"stub": True}))
        self.assertEqual(outbox, [])
        self.assertEqual(lines(log.path)[-1]["detail"]["reason"], "approval already used")

    def test_claim_marker_alone_refuses(self):
        # If the process dies after claiming but before writing consumed, the
        # marker still blocks reuse (fail closed).
        c, log = ctx(self.tmp)
        tr = ToolRunner(c, self.ap)
        a = self.approve(tr)
        p = approval_path(self.ap, a)
        p.with_name(p.name + ".claimed").write_text("{}")
        with self.assertRaises(ApprovalRequired):
            send(tr, lambda: (None, {"stub": True}))


class UrlCheckTest(unittest.TestCase):
    CASES = [
        # (url, allowed?)
        (HOST + "/company/02557590", True),
        (HOST + "/company/02557590/", True),
        (HOST + "/company/02557590x", False),                      # not a whole segment
        (HOST + "/company/02557590x/officers", False),
        (HOST + "/company/02557590%2Fofficers", False),            # encoded slash
        (HOST + "/company/02557590%2fOFFICERS", False),            # encoded, upper case
        (HOST + "/company/02557590/OFFICERS", False),
        (HOST + "/company/02557590/officers;x=1", False),          # path parameter
        (HOST + "/company/02557590/%252Fofficers", False),         # double encoded
        (HOST.replace("find-and-update", "FIND-and-UPDATE") + "/company/02557590", True),  # host case
        ("HTTPS://" + HOST[8:] + "/company/02557590", True),       # scheme case
        (HOST + "/company/02557590/a/../officers", False),         # dot segments
        (HOST + "/company/02557590/a/../../02557591", False),
        (HOST + "/company/02557590/./x", False),                  # dot segment refused, not rewritten
        (HOST + "/COMPANY/02557590", False),                       # allowlist path is case-sensitive
        (HOST + "/company/02557590/%2e%2e/02557591", False),
        (HOST + "/company/02557590?next=/officers", False),        # old substring rule kept
        (HOST + "/company/02557590/officers-list", False),
        (HOST + ":443/company/02557590", True),                    # default port stripped
        (HOST + ":8443/company/02557590", False),
        ("https://user@" + HOST[8:] + "/company/02557590", False), # userinfo
        ("https://" + HOST[8:] + "@evil.example/company/02557590", False),
        ("http://" + HOST[8:] + ":80/company/02557590", False),    # http not in the https allowlist
        ("ftp://" + HOST[8:] + "/company/02557590", False),
        ("https://evil.example/company/02557590", False),
        (HOST + "\\company/02557590/officers", False),
    ]

    def test_cases(self):
        for url, ok in self.CASES:
            with self.subTest(url=url):
                self.assertEqual(check_url(url, ALLOW, BLOCK) is None, ok)

    def test_http_default_port(self):
        allow = ["http://example.org/a"]
        self.assertIsNone(check_url("http://EXAMPLE.org:80/a/b", allow, BLOCK))
        self.assertIsNotNone(check_url("http://example.org:80/a/officers", allow, BLOCK))
        self.assertIsNotNone(check_url("http://user" + "@example.org:80/a", allow, BLOCK))

    def test_blocklist_without_allowlist(self):
        self.assertIsNotNone(check_url(HOST + "/company/02557590/%2fOfficers", None, ["/officers"]))
        self.assertIsNone(check_url(HOST + "/company/02557590", None, ["/officers"]))

    def test_gate_rechecks_final_url(self):
        td = tempfile.TemporaryDirectory()
        self.addCleanup(td.cleanup)
        c, log = ctx(Path(td.name), name="research-agent-model")
        tr = ToolRunner(c, Path(td.name) / "ap")
        redirected = lambda: ("officer list", {"source": "t"}, {"detail": {"final_url": HOST + "/company/02557590/officers"}})
        with self.assertRaises(PermissionDenied):
            tr.call("mcp_fetch", "fetch", redirected, payload={"url": ALLOW[0]})
        last = lines(log.path)[-1]
        self.assertEqual(last["outcome"], "refused_purpose_limitation")
        self.assertEqual(last["detail"]["matched"], ["/officers"])
        same = lambda: ("overview", {"source": "t"}, {"detail": {"final_url": ALLOW[0] + "/"}})
        self.assertEqual(tr.call("mcp_fetch", "fetch", same, payload={"url": ALLOW[0]}), "overview")

    def test_log_shows_normalised_url_only_when_it_differs(self):
        td = tempfile.TemporaryDirectory()
        self.addCleanup(td.cleanup)
        c, log = ctx(Path(td.name), name="research-agent-model")
        tr = ToolRunner(c, Path(td.name) / "ap")
        ok = lambda: ("overview", {"source": "t"})
        tr.call("mcp_fetch", "fetch", ok, payload={"url": ALLOW[0]})
        self.assertNotIn("normalised_url", lines(log.path)[-1]["detail"])
        odd = HOST.upper() + ":443/company/%30%32557590"
        tr.call("mcp_fetch", "fetch", ok, payload={"url": odd})
        self.assertEqual(lines(log.path)[-1]["detail"]["normalised_url"], ALLOW[0])
        self.assertTrue(verify(log.path).ok)


if __name__ == "__main__":
    unittest.main()
