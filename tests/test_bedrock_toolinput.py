"""Converse adapter: gpt-oss-120b empty-key tool inputs no longer reach Bedrock.

gpt-oss-120b sometimes answers a no-argument tool call with toolUse.input = {"": {}}. Bedrock hands
that back to us, then rejects the replayed assistant turn with "The format of the value at
messages.1.content.0.toolUse.input is invalid" (live probe 2026-11-11: an empty key is refused at any
depth, also inside lists; other odd keys such as "a b" are accepted). This test replays every
recorded gpt-oss-120b toolUse.input error of batches 7-14 offline: the assistant reply is rebuilt in
the recorded shape, passed through from_converse and to_converse, and the request that would be sent
must carry no empty key and pass botocore's Converse parameter validation. No network, no key.
"""
import glob
import json
import re
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))
try:
    import bench_bedrock as bb
except ImportError:  # benchmark or boto3 not installed
    bb = None

PATH = re.compile(r"messages\.(\d+)\.content\.(\d+)\.toolUse\.input is invalid")
# shapes the replayed reply carries; the first is the one captured in the 2026-11-11 reproduction
BAD = [{"": {}}, {"": None}, {"": {}, "x": 1}, {"x": {"": 1}}, {"x": [{"": 1}, 2]}]
CLEAN = [{}, {}, {"x": 1}, {"x": {}}, {"x": [{}, 2]}]


def recorded_errors():
    """(batch, message index, block index) for every recorded gpt-oss-120b toolUse.input error."""
    out = []
    for f in sorted(glob.glob(str(ROOT / "repeats" / "batch*" / "runs" / "*gpt-oss-120b*"))):
        for line in open(f, encoding="utf-8"):
            row = json.loads(line)  # a row with tries holds one error per refused try; its top error repeats the last
            for err in ([t.get("error") for t in row["tries"]] if row.get("tries") else [row.get("error")]):
                m = PATH.search(err or "")
                if m:
                    out.append((Path(f).parts[-3], int(m.group(1)), int(m.group(2))))
    return out


def empty_keys(v, where="input"):
    if isinstance(v, dict):
        return [where] * ("" in v) + [p for k, x in v.items() for p in empty_keys(x, f"{where}.{k}")]
    if isinstance(v, list):
        return [p for i, x in enumerate(v) for p in empty_keys(x, f"{where}[{i}]")]
    return []


@unittest.skipIf(bb is None, "agentdojo/boto3 not installed")
class ToolInputReplay(unittest.TestCase):
    def _request(self, bad):
        """Replay: user task, the model's toolUse reply in the recorded shape, our tool result."""
        from agentdojo.types import text_content_block_from_string as t
        reply = {"role": "assistant", "content": [{"toolUse": {"toolUseId": "tooluse_rec1",
                                                               "name": "get_scheduled_transactions",
                                                               "input": bad}}]}
        msg = bb.from_converse(reply, {"get_scheduled_transactions"})
        call = msg["tool_calls"][0]
        hist = [{"role": "system", "content": [t("sys")]}, {"role": "user", "content": [t("task")]}, msg,
                {"role": "tool", "content": [t("[]")], "tool_call_id": call.id, "tool_call": call,
                 "error": None}]
        system, conv = bb.to_converse(hist)
        return {"modelId": "openai.gpt-oss-120b-1:0", "system": system, "messages": conv,
                "toolConfig": {"tools": [{"toolSpec": {"name": "get_scheduled_transactions",
                                                       "description": "d",
                                                       "inputSchema": {"json": {"type": "object",
                                                                                "properties": {}}}}}]}}

    def _assert_sendable(self, req):
        import botocore.session
        from botocore.validate import ParamValidator
        model = botocore.session.get_session().get_service_model("bedrock-runtime")
        report = ParamValidator().validate(req, model.operation_model("Converse").input_shape)
        self.assertFalse(report.has_errors(), report.generate_report())
        for m in req["messages"]:
            for b in m["content"]:
                if "toolUse" in b:
                    self.assertIsInstance(b["toolUse"]["input"], dict)
                    self.assertEqual(empty_keys(b["toolUse"]["input"]), [])

    def test_recorded_failures_replay_clean(self):
        errs = recorded_errors()
        self.assertEqual(len(errs), 92)  # refused calls: b7 5, b8 10, b9 30, b10 43, b14 4; all at messages.1.content.0
        self.assertEqual({(i, k) for _, i, k in errs}, {(1, 0)})
        for bad in BAD:
            with self.subTest(bad=bad):
                self.assertTrue(empty_keys(bad))  # the old adapter sent these verbatim
                req = self._request(bad)
                self.assertIn("toolUse", req["messages"][1]["content"][0])  # the recorded error path
                self._assert_sendable(req)

    def test_empty_keys_dropped_rest_unchanged(self):
        for bad, want in zip(BAD, CLEAN):
            with self.subTest(bad=bad):
                self.assertEqual(bb.as_object(bad), want)
                self.assertEqual(bb.as_object(json.dumps(bad)), want)

    def test_normal_inputs_unchanged(self):
        for good in [{}, {"amount": 1, "recipient": "x"}, {"a b": 1, "n": {"k": [1, {"z": None}]}}]:
            self.assertEqual(bb.as_object(good), good)


if __name__ == "__main__":
    unittest.main()
