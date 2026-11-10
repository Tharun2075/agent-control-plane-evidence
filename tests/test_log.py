"""T-a2: four processes, each with its own ChainLog on one file, keep one chain."""
import multiprocessing
import os
import tempfile
import time
import unittest
from pathlib import Path

from acp.canon import canonical
from acp.log import GENESIS, ChainLog, FixedStepClock, read_records, record_hash, verify

PROCS, EACH = 4, 50
FIELDS = dict(
    **{"gen_ai.agent.id": "a", "agent_manifest_sha256": "0" * 64, "gen_ai.conversation.id": "s",
       "gen_ai.operation.name": "execute_tool", "gen_ai.tool.name": "crm_read"},
    step=0, action="read", personal_data_categories=["none"], lawful_basis="not_applicable",
    decision_mode="automated", approval_ref=None, outcome="ok", recipients=[], provenance={}, detail={},
)


def _child(path: str, i: int, start) -> None:
    start.wait()
    time.sleep(0.002 * i)  # later children build their ChainLog on a file others are appending to
    log = ChainLog(path, clock=FixedStepClock(), durable=False)
    for k in range(EACH):
        log.append(**{**FIELDS, "detail": {"proc": i, "k": k}})
    os._exit(0)


@unittest.skipUnless(hasattr(os, "fork"), "needs fork")
class MultiProcessTest(unittest.TestCase):
    def test_four_processes_keep_one_chain(self):
        mp = multiprocessing.get_context("fork")
        with tempfile.TemporaryDirectory() as td:
            path = str(Path(td) / "log.jsonl")
            start = mp.Barrier(PROCS)
            ps = [mp.Process(target=_child, args=(path, i, start)) for i in range(PROCS)]
            for p in ps:
                p.start()
            for p in ps:
                p.join(60)
            self.assertEqual([p.exitcode for p in ps], [0] * PROCS)
            r = verify(path)
            self.assertTrue(r.ok, r.errors[:3])
            seqs = [rec["seq"] for rec in read_records(path)]
            self.assertEqual(seqs, list(range(PROCS * EACH)))


class AnchorTest(unittest.TestCase):  # batch 5 E1 classes log-truncate-head-rewrite, log-full-rewrite
    def _log(self, td):
        log = ChainLog(Path(td) / "log.jsonl", clock=FixedStepClock(), durable=False)
        for k in range(5):
            log.append(**{**FIELDS, "detail": {"k": k}})
        recs = read_records(log.path)
        return log, recs, (len(recs), recs[-1]["hash"])

    def _write(self, log, recs):
        prev, out = GENESIS, []
        for i, r in enumerate(recs):
            r = {k: v for k, v in r.items() if k != "hash"}
            r["seq"], r["prev_hash"] = i, prev
            r["hash"] = prev = record_hash(r)
            out.append(r)
        log.path.write_bytes(b"".join(canonical(r) + b"\n" for r in out))
        log.head_path.write_bytes(canonical({"count": len(out), "last_hash": prev}) + b"\n")

    def test_anchor_catches_what_the_head_cannot(self):
        with tempfile.TemporaryDirectory() as td:
            log, recs, anchor = self._log(td)
            self.assertTrue(verify(log.path, anchor=anchor).ok)
            self._write(log, recs[:2] + recs[3:])  # drop one record, rehash, rewrite head
            self.assertTrue(verify(log.path).ok)  # the local head alone is fooled
            self.assertFalse(verify(log.path, anchor=anchor).ok)
            self._write(log, recs[:3])  # truncate and rewrite head
            self.assertFalse(verify(log.path, anchor=anchor).ok)

    def test_records_after_the_anchor_are_fine(self):
        with tempfile.TemporaryDirectory() as td:
            log, recs, anchor = self._log(td)
            log.append(**FIELDS)
            self.assertTrue(verify(log.path, anchor=anchor).ok)


if __name__ == "__main__":
    unittest.main()
