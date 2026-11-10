"""T-a2: four processes, each with its own ChainLog on one file, keep one chain."""
import multiprocessing
import os
import tempfile
import time
import unittest
from pathlib import Path

from acp.log import ChainLog, FixedStepClock, read_records, verify

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


if __name__ == "__main__":
    unittest.main()
