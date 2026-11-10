import json
import unittest

from acp import manifest
from acp.log import verify
from tests.helpers import ROOT


class ManifestTest(unittest.TestCase):
    def test_templates_valid(self):
        for p in (ROOT / "manifests").glob("*.json"):
            self.assertEqual(manifest.validate(manifest.load(p)), [], p.name)

    def test_digest_changes_with_delegated_authority(self):
        t = manifest.load(ROOT / "manifests" / "worker.json")
        kw = dict(session_id="s", task="t", expires="2026-11-10T23:59:59Z")
        a = manifest.bind_session(t, delegated_authority=["classify"], **kw)
        b = manifest.bind_session(t, delegated_authority=["classify", "session_store"], **kw)
        self.assertNotEqual(manifest.manifest_digest(a), manifest.manifest_digest(b))

    def test_committed_runs_verify_and_match_manifests(self):
        for n in ("1", "2", "3"):
            d = ROOT / "runs" / n
            self.assertTrue(verify(d / "log.jsonl").ok, n)
            digests = {manifest.manifest_digest(manifest.load(p)) for p in (d / "manifests").glob("*.json")}
            for line in (d / "log.jsonl").read_bytes().splitlines():
                self.assertIn(json.loads(line)["agent_manifest_sha256"], digests)


if __name__ == "__main__":
    unittest.main()
