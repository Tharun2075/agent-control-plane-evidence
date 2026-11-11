"""Converse adapter: malformed gpt-oss-20b tool names and inputs no longer reach Bedrock.

Replays the recorded gpt-oss-20b ValidationException runs of batches 7-11b offline: for each
recorded error path (messages.N.member.content.K.member.toolUse.name) a history of the same depth
is rebuilt with the name shapes gpt-oss emits, and every toolUse name, id and input that would be
sent must pass Bedrock's constraint. No network, no key.
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

PATTERN = re.compile(r"^[a-zA-Z0-9_-]{1,64}$")  # the pattern quoted in the recorded errors
PATH = re.compile(r"messages\.(\d+)\.member\.content\.(\d+)\.member\.toolUse\.name")
BAD = ["functions.get_webpage", "get_webpage<|channel|>commentary json", "", "send money",
       "repo_browser.open_file", "get_webpage<|constrain|>json", "functions.send_money(", "  "]
KNOWN = {"get_webpage", "send_money", "read_file", "get_channels"}


def recorded_errors():
    """(batch, path depth, block index) for every recorded gpt-oss-20b toolUse.name error."""
    out = []
    for f in sorted(glob.glob(str(ROOT / "repeats" / "batch*" / "runs" / "*gpt-oss-20b*"))):
        for line in open(f, encoding="utf-8"):
            r = json.loads(line)
            m = PATH.search(r.get("error") or "")
            if m:
                out.append((Path(f).parts[-3], int(m.group(1)), int(m.group(2))))
    return out


@unittest.skipIf(bb is None, "agentdojo/boto3 not installed")
class ToolNameReplay(unittest.TestCase):
    def _history(self, turns: int, bad: str):
        from agentdojo.functions_runtime import FunctionCall
        from agentdojo.types import text_content_block_from_string as t
        msgs = [{"role": "system", "content": [t("sys")]}, {"role": "user", "content": [t("task")]}]
        for i in range(turns):
            calls = [FunctionCall(function=bad, args={}, id=f"tooluse_{i}"),
                     FunctionCall(function="get_webpage", args={"url": "x"}, id=f"tooluse_{i}b")]
            msgs.append({"role": "assistant", "content": [t("thinking")], "tool_calls": calls})
            for c in calls:
                msgs.append({"role": "tool", "content": [t("ok")], "tool_call_id": c.id, "tool_call": c,
                             "error": None})
        return msgs

    def _assert_valid(self, conv):
        for m in conv:
            for b in m["content"]:
                if "toolUse" in b:
                    self.assertRegex(b["toolUse"]["name"], PATTERN)
                    self.assertRegex(b["toolUse"]["toolUseId"], PATTERN)
                    self.assertIsInstance(b["toolUse"]["input"], dict)
                    json.dumps(b["toolUse"]["input"])
                if "toolResult" in b:
                    self.assertRegex(b["toolResult"]["toolUseId"], PATTERN)

    def test_recorded_failures_replay_clean(self):
        errs = recorded_errors()
        self.assertEqual(len(errs), 391)  # 35 + 56 + 185 + 109 + 1 + 5 runs, batches 7-11b
        for depth, block in sorted({(d, k) for _, d, k in errs}):
            for bad in BAD:
                with self.subTest(depth=depth, block=block, bad=bad):
                    # the old adapter copied the name verbatim into the replayed history
                    self.assertFalse(PATTERN.match(bad))
                    # rebuild at least as many assistant turns as the recorded path needs
                    msgs = self._history(depth // 2 + 1, bad)
                    _, conv = bb.to_converse(msgs)
                    self.assertGreater(len(conv), depth)
                    self._assert_valid(conv)

    def test_known_names_recovered_from_reply(self):
        for bad, want in [("functions.get_webpage", "get_webpage"),
                          ("get_webpage<|channel|>commentary json", "get_webpage"),
                          ("send_money<|constrain|>json", "send_money"),
                          ("functions.send_money(", "send_money")]:
            msg = {"role": "assistant", "content": [{"toolUse": {"toolUseId": "t1", "name": bad, "input": {}}}]}
            self.assertEqual(bb.from_converse(msg, KNOWN)["tool_calls"][0].function, want)

    def test_unknown_names_become_valid_and_stay_unknown(self):
        for bad in BAD:
            msg = {"role": "assistant", "content": [{"toolUse": {"toolUseId": "t.1", "name": bad, "input": {}}}]}
            tc = bb.from_converse(msg)["tool_calls"][0]
            self.assertRegex(tc.function, PATTERN)
            self.assertRegex(tc.id, PATTERN)

    def test_valid_names_and_ids_unchanged(self):
        msg = {"role": "assistant", "content": [{"toolUse": {"toolUseId": "tooluse_AbC-1", "name": "send_money",
                                                             "input": {"amount": 1}}}]}
        tc = bb.from_converse(msg, KNOWN)["tool_calls"][0]
        self.assertEqual((tc.function, tc.id, dict(tc.args)), ("send_money", "tooluse_AbC-1", {"amount": 1}))

    def test_non_object_input_becomes_object(self):
        for raw, want in [('{"a": 1}', {"a": 1}), ("[1, 2]", {}), ("not json", {}), (None, {}), ([], {})]:
            msg = {"role": "assistant", "content": [{"toolUse": {"toolUseId": "t1", "name": "get_channels",
                                                                 "input": raw}}]}
            self.assertEqual(dict(bb.from_converse(msg, KNOWN)["tool_calls"][0].args), want)


if __name__ == "__main__":
    unittest.main()
