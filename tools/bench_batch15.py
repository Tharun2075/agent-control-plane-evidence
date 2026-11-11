"""Batch 15 runner: gpt-oss-120b B1 on Bedrock after the empty-key toolUse.input fix.

Same wrapper as tools/bench_batch14.py (same gate, same per-call `chk` verdicts); it only points the
Bedrock runner at repeats/batch15/ and refuses any other model or provider.
Protocol: repeats/batch15/PROTOCOL.md.

  python tools/bench_batch15.py --model openai.gpt-oss-120b-1:0 --arm plain --set B1
  python tools/bench_batch15.py --model openai.gpt-oss-120b-1:0 --arm gated --set B1

Keys come from the environment only, as in the wrapped runners.
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tools"))

import bench_agentdojo as B  # noqa: E402
from acp import batch8_gate as G8, bench_gate  # noqa: E402

OUT = ROOT / "repeats" / "batch15"
B.RUN_DIR, B.LOG_DIR = OUT / "runs", OUT / "logs"


class Gated15(B.GatedToolsExecutor):
    """The batch 6 executor; adds each control's verdict to the call it just logged."""

    def _gate(self, fn: str, args: dict) -> str | None:
        denied = super()._gate(fn, args)
        st = self.st
        if fn in bench_gate.GATED[st.suite]:
            st.calls[-1]["chk"] = {
                "action": G8.review_approval(st.suite, fn, args, st.user_prompt)[0],
                "allowlist": G8.review_allowlist(st.suite, fn, args, st.user_prompt)[0]}
        return denied


B.GatedToolsExecutor = Gated15


MODEL = "openai.gpt-oss-120b-1:0"


def main(argv=None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if "--provider" in argv:
        i = argv.index("--provider")
        if argv[i + 1] != "bedrock":
            raise SystemExit("batch 15 runs Bedrock only")
        del argv[i:i + 2]
    if "--model" not in argv or argv[argv.index("--model") + 1] != MODEL:
        raise SystemExit(f"batch 15 runs {MODEL} only")
    import bench_bedrock as BB
    BB.RUN_DIR, BB.LOG_DIR, BB.PROBE_FILE = OUT / "runs", OUT / "logs", OUT / "probe.jsonl"
    return BB.main(argv)


if __name__ == "__main__":
    raise SystemExit(main())
