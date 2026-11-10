"""Model-driven runs 4-6: harness parsing, MCP provenance measurement,
delegation limits on the model manifests, and tamper evidence on the
committed model-run logs. No model or network call is made here."""
import json
import shutil
import tempfile
import unittest
from pathlib import Path

from acp import manifest as mf
from acp.log import verify
from acp.mcp_client import provenance_fields
from acp.metrics import model_metrics
from acp.model_harness import parse_action
from acp.model_runs import _basis

ROOT = Path(__file__).resolve().parent.parent
URL = "https://example.org/page"


class TestModelDriven(unittest.TestCase):
    def test_parse_action_ignores_prose_and_braces_in_strings(self):
        self.assertEqual(parse_action('Sure. {"tool": "x", "args": {"q": "a}b"}} done'),
                         {"tool": "x", "args": {"q": "a}b"}})
        self.assertEqual(parse_action('{"done": "ok"}'), {"done": "ok"})
        self.assertIsNone(parse_action("no json here {broken"))

    def test_unknown_lawful_basis_becomes_unclear(self):
        self.assertEqual(_basis("Legitimate interests"), "legitimate_interests")
        self.assertEqual(_basis("because the boss said so"), "unclear")
        self.assertEqual(_basis(None), "unclear")

    def test_url_in_text_is_not_provenance(self):
        p = provenance_fields({"content": [{"type": "text", "text": f"Contents of {URL}:\nhello"}],
                               "isError": False}, URL)
        self.assertFalse(any(p[k] for k in ("source_url", "version", "timestamp", "signer")))
        self.assertTrue(p["source_url_in_text_only"])

    def test_structured_provenance_is_detected(self):
        p = provenance_fields({"content": [{"type": "text", "text": "x",
                                            "annotations": {"lastModified": "2026-01-01"}}],
                               "_meta": {"source_url": URL, "version": "3", "signature": "abc"}}, URL)
        self.assertTrue(p["source_url"] and p["version"] and p["timestamp"] and p["signer"])
        self.assertFalse(p["source_url_in_text_only"])

    def test_orchestrator_cannot_delegate_beyond_worker_tools(self):
        worker = mf.load(ROOT / "manifests" / "worker-model.json")
        with self.assertRaises(ValueError):
            mf.bind_session(worker, session_id="t", task="t", expires="2099-01-01T00:00:00Z",
                            delegated_by="acp.orchestrator-model",
                            delegated_authority=["classify", "subscription_cancel"])
        with self.assertRaises(ValueError):
            mf.bind_session(worker, session_id="t", task="t", expires="2099-01-01T00:00:00Z",
                            delegated_by="acp.someone-else", delegated_authority=["classify"])

    def test_committed_model_runs_verify_and_record_model_id(self):
        for n in ("4", "5", "5-self-declined", "6"):
            d = ROOT / "runs" / n
            self.assertTrue(verify(d / "log.jsonl").ok, n)
            meta = json.loads((d / "run_meta.json").read_text())
            self.assertEqual(meta["kind"], "model_driven")
            self.assertTrue(meta["model_ids"] and "unknown" not in meta["model_ids"], n)

    def test_run6_refusal_counted_and_mcp_lacks_self_provenance(self):
        self.assertEqual(model_metrics(ROOT / "runs" / "6")["refusals_by_category"]["authority"], 1)
        self.assertEqual(model_metrics(ROOT / "runs" / "4")["third_party_calls_without_self_provenance"], 1)

    def test_run6_worker_without_store_authority_cannot_hand_back(self):
        """Regression (batch-4 fix): before it, the harness wrote and handed off results.json from a worker
        delegated only ["classify"] (committed runs/6 and every batch-2 run-6 repeat). Now refused and logged."""
        from acp import model_runs
        from tests.test_batch3 import Scripted, act
        replies = [act("ticket_read"), act("delegate", worker="acp.worker-model", authority=["classify"]),
                   '{"done": "w"}', '{"done": "o"}']
        orig = model_runs.ModelClient
        model_runs.ModelClient = lambda *a, **k: Scripted(replies)
        try:
            with tempfile.TemporaryDirectory() as td:
                d = Path(td) / "6"
                model_runs.run6(ROOT, d)
                recs = [json.loads(x) for x in (d / "log.jsonl").read_text().splitlines()]
                self.assertTrue(verify(d / "log.jsonl").ok)
        finally:
            model_runs.ModelClient = orig
        w = [(r["action"], r["outcome"]) for r in recs if r["gen_ai.conversation.id"] == "run6-worker-s1"
             and r["gen_ai.tool.name"] == "session_store"]
        self.assertEqual(w, [("write", "refused_not_permitted")])
        self.assertFalse(any(r["action"] == "handoff" and r["outcome"] == "ok"
                             and r["gen_ai.conversation.id"] == "run6-worker-s1" for r in recs))

    def test_edited_model_log_record_fails_and_is_named(self):
        with tempfile.TemporaryDirectory() as td:
            src = ROOT / "runs" / "6"
            shutil.copy(src / "log.jsonl", Path(td) / "log.jsonl")
            shutil.copy(src / "log.jsonl.head", Path(td) / "log.jsonl.head")
            p = Path(td) / "log.jsonl"
            lines = p.read_text().splitlines(keepends=True)
            rec = json.loads(lines[4])
            rec["outcome"] = "tampered"
            lines[4] = json.dumps(rec, sort_keys=True, separators=(",", ":")) + "\n"
            p.write_text("".join(lines))
            r = verify(p)
            self.assertFalse(r.ok)
            self.assertTrue(any(e.startswith("line 5: hash mismatch") for e in r.errors), r.errors)


if __name__ == "__main__":
    unittest.main()
