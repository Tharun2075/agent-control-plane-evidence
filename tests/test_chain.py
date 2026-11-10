"""T-a: chain verify passes unchanged and fails on edit, delete, reorder, tail delete."""
import json
import tempfile
import unittest
from pathlib import Path

from acp.log import ChainError, ChainLog, verify
from tests.helpers import ctx


class ChainTest(unittest.TestCase):
    def setUp(self):
        self.td = tempfile.TemporaryDirectory()
        self.tmp = Path(self.td.name)
        c, self.log = ctx(self.tmp)
        for i in range(6):
            c.record(operation="execute_tool", tool="crm_read", action=f"a{i}", outcome="ok",
                     personal_data_categories=["identifier:name"], lawful_basis="legitimate_interests")
        self.path = self.log.path
        self.lines = self.path.read_bytes().splitlines(keepends=True)

    def tearDown(self):
        self.td.cleanup()

    def _write(self, ls):
        self.path.write_bytes(b"".join(ls))

    def test_unchanged_passes(self):
        r = verify(self.path)
        self.assertTrue(r.ok, r.errors)
        self.assertEqual(r.records, 6)

    def test_edited_fails(self):
        rec = json.loads(self.lines[2])
        rec["lawful_basis"] = "consent"
        ls = list(self.lines)
        ls[2] = json.dumps(rec, sort_keys=True, separators=(",", ":")).encode() + b"\n"
        self._write(ls)
        r = verify(self.path)
        self.assertFalse(r.ok)
        self.assertTrue(any("hash mismatch" in e for e in r.errors), r.errors)

    def test_whitespace_only_edit_is_not_a_false_alarm(self):
        ls = list(self.lines)
        ls[2] = json.dumps(json.loads(ls[2]), indent=1).replace("\n", "").encode() + b"\n"
        self._write(ls)
        self.assertTrue(verify(self.path).ok)

    def test_deleted_fails(self):
        self._write(self.lines[:3] + self.lines[4:])
        self.assertFalse(verify(self.path).ok)

    def test_reordered_fails(self):
        ls = list(self.lines)
        ls[2], ls[3] = ls[3], ls[2]
        self._write(ls)
        self.assertFalse(verify(self.path).ok)

    def test_tail_deleted_fails_via_head(self):
        self._write(self.lines[:-1])
        r = verify(self.path)
        self.assertFalse(r.ok)
        self.assertTrue(any("head mismatch" in e for e in r.errors))

    def test_inserted_fails(self):
        self._write(self.lines[:2] + [self.lines[1]] + self.lines[2:])
        self.assertFalse(verify(self.path).ok)

    def test_logger_refuses_to_extend_tampered_log(self):
        self._write(self.lines[:3] + self.lines[4:])
        with self.assertRaises(ChainError):
            ChainLog(self.path)

    def test_lawful_basis_rules_enforced(self):
        (self.tmp / "x").mkdir()
        c, _ = ctx(self.tmp / "x", sid="s2")
        with self.assertRaises(ChainError):
            c.record(operation="x", action="y", outcome="ok", personal_data_categories=["identifier:name"])
        with self.assertRaises(ChainError):
            c.record(operation="x", action="y", outcome="ok", lawful_basis="consent")
        with self.assertRaises(ChainError):
            c.record(operation="x", action="y", outcome="ok", personal_data_categories=["identifier:name"],
                     lawful_basis="because")


if __name__ == "__main__":
    unittest.main()
